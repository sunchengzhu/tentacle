//! Large-message throughput QA (TCP+yamux vs QUIC).
//!
//! Each transport runs the same workload: client sends N messages of M MiB
//! each, server echoes every message back. We measure end-to-end wall time
//! and goodput in MiB/s. The tentacle service-level `max_frame_length`
//! default is 8 MiB, so payloads up to a few MiB exercise the path without
//! having to tweak builders.
//!
//! This complements `qa_quic_vs_tcp_baseline` (which focuses on small-payload
//! latency at high request rates); the question here is the OTHER end of the
//! envelope — single big frames where yamux window flow control vs QUIC's
//! native streams produce visibly different shapes.
//!
//! Env overrides:
//!   QA_LM_SIZE_MIB    default 2     (per-message payload, MiB)
//!   QA_LM_COUNT       default 16    (number of messages per transport)
//!   QA_LM_TIMEOUT_S   default 60    (per-transport wall budget)
//!   QA_LM_RATIO_MAX   default 0     (0 = report-only; >0 = QUIC time must
//!                                     be <= TCP time * RATIO_MAX, else FAIL)
//!
//! Verdict PASS iff both transports echoed every message within budget,
//! observed zero failures, and (optionally) honoured the parity ratio.

use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::channel::oneshot;
use quic_transport_qa::{env, runner::build_quic_service};
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceAsyncControl, ServiceError, ServiceEvent,
        TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};
use tokio::sync::Notify;

const PROTO_ID: ProtocolId = ProtocolId::new(1);

// ─────────────── shared protocol pieces ───────────────

struct ServerEcho;
#[async_trait]
impl ServiceProtocol for ServerEcho {
    async fn init(&mut self, _: &mut ProtocolContext) {}
    async fn received(&mut self, ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let _ = ctx.send_message(data).await;
    }
}
fn server_meta() -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(|| ProtocolHandle::Callback(Box::new(ServerEcho)))
        .build()
}

struct ClientState {
    acked_bytes: AtomicUsize,
    acked_msgs: AtomicUsize,
    notify_connected: Notify,
    notify_done: Notify,
    target_msgs: AtomicUsize,
}

struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _: &mut ProtocolContext) {}
    async fn connected(&mut self, _: ProtocolContextMutRef<'_>, _: &str) {
        self.state.notify_connected.notify_waiters();
    }
    async fn received(&mut self, _: ProtocolContextMutRef<'_>, data: Bytes) {
        self.state
            .acked_bytes
            .fetch_add(data.len(), Ordering::Relaxed);
        let n = self.state.acked_msgs.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.state.target_msgs.load(Ordering::Relaxed) {
            self.state.notify_done.notify_waiters();
        }
    }
}
fn client_meta(state: Arc<ClientState>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(move || ProtocolHandle::Callback(Box::new(ClientProto { state })))
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

fn build_tcp_service<H>(
    key: SecioKeyPair,
    metas: Vec<ProtocolMeta>,
    handle: H,
) -> Service<H, SecioKeyPair>
where
    H: ServiceHandle + Unpin + 'static,
{
    let mut b = ServiceBuilder::default()
        .forever(true)
        .handshake_type(key.into());
    for m in metas {
        b = b.insert_protocol(m);
    }
    b.build(handle)
}

// ─────────────── per-transport run ───────────────

struct RunResult {
    label: &'static str,
    count: usize,
    bytes_each: usize,
    elapsed: Duration,
    failures: usize,
}

fn run_one(
    label: &'static str,
    listen: Multiaddr,
    count: usize,
    bytes_each: usize,
    budget: Duration,
    is_quic: bool,
) -> RunResult {
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        let listen = listen.clone();
        thread::Builder::new()
            .name(format!("lm-{label}-server"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc = if is_quic {
                    build_quic_service(server_key, vec![server_meta()], (), QuicConfig::default())
                } else {
                    build_tcp_service(server_key, vec![server_meta()], ())
                };
                rt.block_on(async move {
                    let real = svc.listen(listen).await.expect("server listen");
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

    let client_key = SecioKeyPair::secp256k1_generated();
    let state = Arc::new(ClientState {
        acked_bytes: AtomicUsize::new(0),
        acked_msgs: AtomicUsize::new(0),
        notify_connected: Notify::new(),
        notify_done: Notify::new(),
        target_msgs: AtomicUsize::new(count),
    });
    let disc_flag = Arc::new(AtomicU64::new(0));
    let client_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let client_ctrl = client_ctrl.clone();
        let state = state.clone();
        let disc_flag = disc_flag.clone();
        let dial_addr = dial_addr.clone();
        thread::Builder::new()
            .name(format!("lm-{label}-client"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc = if is_quic {
                    build_quic_service(
                        client_key,
                        vec![client_meta(state)],
                        DisconnectFlag(disc_flag),
                        QuicConfig::default(),
                    )
                } else {
                    build_tcp_service(
                        client_key,
                        vec![client_meta(state)],
                        DisconnectFlag(disc_flag),
                    )
                };
                rt.block_on(async move {
                    *client_ctrl.lock().unwrap() = Some(svc.control().clone());
                    svc.control()
                        .dial(dial_addr, TargetProtocol::All)
                        .await
                        .expect("client dial");
                    svc.run().await;
                });
            })
            .unwrap();
    }

    driver_rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), state.notify_connected.notified())
            .await
            .expect("client never connected");
    });

    let ctrl = client_ctrl.lock().unwrap().clone().expect("ctrl");
    let payload = Bytes::from(vec![0xAB_u8; bytes_each]);
    let mut failures = 0usize;
    let started = Instant::now();
    let outcome = driver_rt.block_on(async {
        for _ in 0..count {
            if ctrl
                .filter_broadcast(TargetSession::All, PROTO_ID, payload.clone())
                .await
                .is_err()
            {
                failures += 1;
            }
        }
        tokio::time::timeout(budget, state.notify_done.notified()).await
    });
    let elapsed = started.elapsed();
    if outcome.is_err() {
        failures += count.saturating_sub(state.acked_msgs.load(Ordering::Relaxed));
    }

    if let Some(c) = client_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    RunResult {
        label,
        count,
        bytes_each,
        elapsed,
        failures,
    }
}

fn print_run(r: &RunResult) {
    let total_bytes = (r.count * r.bytes_each) as f64;
    let mib_s = total_bytes / r.elapsed.as_secs_f64() / (1024.0 * 1024.0);
    println!(
        "[{:>4}] msgs={} size={}MiB elapsed={:.2}s goodput={:.2} MiB/s failures={}",
        r.label,
        r.count,
        r.bytes_each / (1024 * 1024),
        r.elapsed.as_secs_f64(),
        mib_s,
        r.failures,
    );
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let size_mib: usize = env::env_or("QA_LM_SIZE_MIB", 2);
    let count: usize = env::env_or("QA_LM_COUNT", 16);
    let budget = Duration::from_secs(env::env_or("QA_LM_TIMEOUT_S", 60u64));
    let ratio_max: f64 = env::env_or("QA_LM_RATIO_MAX", 0.0_f64);
    let bytes_each = size_mib * 1024 * 1024;

    println!(
        "[driver] count={count} per_msg={size_mib}MiB budget={budget:?} ratio_max={ratio_max}"
    );

    let tcp = run_one(
        "tcp",
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        count,
        bytes_each,
        budget,
        false,
    );
    let quic = run_one(
        "quic",
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        count,
        bytes_each,
        budget,
        true,
    );

    println!("\n──────────── large-message summary ────────────");
    print_run(&tcp);
    print_run(&quic);
    let ratio = if tcp.elapsed.as_secs_f64() > 0.0 {
        quic.elapsed.as_secs_f64() / tcp.elapsed.as_secs_f64()
    } else {
        0.0
    };
    println!("quic_time / tcp_time = {:.2}", ratio);
    println!("───────────────────────────────────────────────");

    let mut fail = false;
    for r in [&tcp, &quic] {
        if r.failures > 0 {
            fail = true;
            println!("FAIL — {} reported {} failure(s)", r.label, r.failures);
        }
        if r.elapsed > budget {
            fail = true;
            println!(
                "FAIL — {} exceeded budget {:?} (took {:?})",
                r.label, budget, r.elapsed
            );
        }
    }
    if ratio_max > 0.0 && ratio > ratio_max {
        fail = true;
        println!(
            "FAIL — quic/tcp time ratio {:.2} exceeded threshold {:.2}",
            ratio, ratio_max
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — both transports moved the payload within budget.");
        ExitCode::SUCCESS
    }
}
