//! QUIC handshake storm QA.
//!
//! N parallel clients dial one server within a tight time window. We only
//! measure handshake latency (time from `dial()` to protocol `connected`)
//! and per-client success/failure. Distinct from
//! `qa_quic_concurrent_sessions`, which also drives a steady ping workload —
//! here we want a clean look at the handshake path under burst load.
//!
//! Env overrides:
//!   QA_HS_CLIENTS         default 100
//!   QA_HS_TIMEOUT_S       default 20    (per-client handshake budget)
//!   QA_HS_MIN_SUCCESS     default 1.0   (required success ratio for PASS)
//!   QA_HS_MAX_P95_MS      default 0     (0 = report only; >0 = handshake p95
//!                                         must be <= this for PASS)
//!
//! Verdict PASS iff success/clients >= QA_HS_MIN_SUCCESS and (optionally) the
//! observed handshake p95 is within QA_HS_MAX_P95_MS.

use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use futures::channel::oneshot;
use quic_transport_qa::{env, runner::build_quic_service};
use tentacle::{
    ProtocolId, async_trait,
    builder::MetaBuilder,
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, ServiceAsyncControl, ServiceError, ServiceEvent,
        TargetProtocol,
    },
    traits::{ServiceHandle, ServiceProtocol},
};
use tokio::sync::Notify;

const PROTO_ID: ProtocolId = ProtocolId::new(1);

struct ServerNoop;
#[async_trait]
impl ServiceProtocol for ServerNoop {
    async fn init(&mut self, _: &mut ProtocolContext) {}
}
fn server_meta() -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(|| ProtocolHandle::Callback(Box::new(ServerNoop)))
        .build()
}

struct ClientProto {
    notify_connected: Arc<Notify>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _: &mut ProtocolContext) {}
    async fn connected(&mut self, _: ProtocolContextMutRef<'_>, _: &str) {
        self.notify_connected.notify_waiters();
    }
}
fn client_meta(notify: Arc<Notify>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ClientProto {
                notify_connected: notify,
            }))
        })
        .build()
}

struct DisconnectFlag(Arc<AtomicU64>);
#[async_trait]
impl ServiceHandle for DisconnectFlag {
    async fn handle_error(&mut self, _: &mut ServiceContext, err: ServiceError) {
        log::debug!("[svc-err] {err:?}");
    }
    async fn handle_event(&mut self, _: &mut ServiceContext, ev: ServiceEvent) {
        if let ServiceEvent::SessionClose { .. } = ev {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn pct(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let clients: usize = env::env_or("QA_HS_CLIENTS", 100);
    let budget = Duration::from_secs(env::env_or("QA_HS_TIMEOUT_S", 20u64));
    let min_success: f64 = env::env_or("QA_HS_MIN_SUCCESS", 1.0_f64);
    let max_p95_ms: u64 = env::env_or("QA_HS_MAX_P95_MS", 0u64);

    println!(
        "[driver] clients={clients} per_client_budget={budget:?} \
         min_success={min_success} max_p95_ms={max_p95_ms}"
    );

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        thread::Builder::new()
            .name("hs-server".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc =
                    build_quic_service(server_key, vec![server_meta()], (), QuicConfig::default());
                rt.block_on(async move {
                    let real = svc
                        .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                        .await
                        .expect("server listen");
                    *server_ctrl.lock().unwrap() = Some(svc.control().clone());
                    let _ = addr_tx.send(real);
                    svc.run().await;
                });
            })
            .unwrap();
    }

    let driver_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let server_addr = driver_rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), addr_rx)
            .await
            .expect("server addr timeout")
            .expect("server addr")
    });
    let dial_addr: Multiaddr = format!("{server_addr}/p2p/{}", server_pid.to_base58())
        .parse()
        .unwrap();
    println!("[driver] server={dial_addr}");

    // Each client gets its own Service + Notify. We spawn them as fast as we
    // can; the storm is real (no inter-client delay).
    let disc_flag = Arc::new(AtomicU64::new(0));
    let mut notifies: Vec<Arc<Notify>> = Vec::with_capacity(clients);
    let mut ctrls: Vec<Arc<Mutex<Option<ServiceAsyncControl>>>> = Vec::with_capacity(clients);
    let mut started: Vec<Instant> = Vec::with_capacity(clients);
    let storm_started = Instant::now();
    for i in 0..clients {
        let notify = Arc::new(Notify::new());
        let ctrl_slot: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
        let client_key = SecioKeyPair::secp256k1_generated();
        let dial_addr = dial_addr.clone();
        let notify_t = notify.clone();
        let ctrl_t = ctrl_slot.clone();
        let disc_t = disc_flag.clone();
        thread::Builder::new()
            .name(format!("hs-client-{i}"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc = build_quic_service(
                    client_key,
                    vec![client_meta(notify_t)],
                    DisconnectFlag(disc_t),
                    QuicConfig::default(),
                );
                rt.block_on(async move {
                    *ctrl_t.lock().unwrap() = Some(svc.control().clone());
                    if svc
                        .control()
                        .dial(dial_addr, TargetProtocol::All)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    svc.run().await;
                });
            })
            .unwrap();
        notifies.push(notify);
        ctrls.push(ctrl_slot);
        started.push(Instant::now());
    }
    let storm_window = storm_started.elapsed();

    // Collect handshake latencies in parallel.
    let latencies: Arc<Mutex<Vec<u128>>> = Arc::new(Mutex::new(Vec::with_capacity(clients)));
    let succeeded = Arc::new(AtomicUsize::new(0));

    driver_rt.block_on(async {
        let mut handles = Vec::with_capacity(clients);
        for (i, notify) in notifies.iter().enumerate() {
            let start = started[i];
            let notify = notify.clone();
            let latencies = latencies.clone();
            let succeeded = succeeded.clone();
            handles.push(tokio::spawn(async move {
                if tokio::time::timeout(budget, notify.notified())
                    .await
                    .is_ok()
                {
                    let lat = start.elapsed().as_nanos();
                    latencies.lock().unwrap().push(lat);
                    succeeded.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    });

    let n_ok = succeeded.load(Ordering::Relaxed);
    let ratio = n_ok as f64 / clients as f64;
    let mut samples = latencies.lock().unwrap().clone();
    samples.sort_unstable();
    let p50 = pct(&samples, 0.50) as f64 / 1e6;
    let p95 = pct(&samples, 0.95) as f64 / 1e6;
    let p99 = pct(&samples, 0.99) as f64 / 1e6;
    let disconnects = disc_flag.load(Ordering::Relaxed);

    // Best-effort shutdown.
    for c in ctrls.iter() {
        if let Some(ctrl) = c.lock().unwrap().clone() {
            let _ = driver_rt.block_on(ctrl.shutdown());
        }
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    println!("\n──────────── handshake-storm summary ────────────");
    println!(
        "clients={clients} storm_dispatch_window={:.2}ms success={n_ok}/{clients} ({:.1}%) \
         p50={:.2}ms p95={:.2}ms p99={:.2}ms post-connect-disconnects={disconnects}",
        storm_window.as_secs_f64() * 1e3,
        ratio * 100.0,
        p50,
        p95,
        p99,
    );
    println!("─────────────────────────────────────────────────");

    let mut fail = false;
    if ratio < min_success {
        fail = true;
        println!(
            "FAIL — success ratio {:.3} below required {:.3}",
            ratio, min_success
        );
    }
    if max_p95_ms > 0 && (p95 as u64) > max_p95_ms {
        fail = true;
        println!(
            "FAIL — handshake p95 {:.2}ms above cap {}ms",
            p95, max_p95_ms
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — handshake storm absorbed.");
        ExitCode::SUCCESS
    }
}
