//! TCP vs QUIC baseline.
//!
//! Runs the same request/response workload twice — once over `/ip4/127.0.0.1/tcp/0`
//! and once over `/ip4/127.0.0.1/udp/0/quic-v1`. A single tentacle `Service`
//! per transport sits between a client and a server, both in-process but in
//! their own threads.
//!
//! Workload: client sends `N` payloads of `SIZE` bytes; server echoes each
//! one back. Latency is measured from `send_message` to `received`. We report:
//!   - total wall time
//!   - throughput (req/s)
//!   - p50 / p95 / p99 latency
//!   - failure count (timeouts)
//!
//! Environment:
//!   QA_REQUESTS    default 2000
//!   QA_PAYLOAD     default 1024  (bytes)
//!   QA_TIMEOUT_MS  default 15000 (per-transport wall budget)
//!
//! PASS iff both transports finish within the wall budget and observe zero
//! round-trip failures. The numbers themselves are reported but never gate
//! the verdict.

use std::{
    process::ExitCode,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures::channel::oneshot;
use quic_transport_qa::{env, runner::build_quic_service};
use tentacle::{
    ProtocolId, async_trait,
    builder::MetaBuilder,
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, ServiceAsyncControl, TargetProtocol, TargetSession},
    traits::ServiceProtocol,
};
use tokio::sync::Notify;

const PROTO_ID: ProtocolId = ProtocolId::new(1);

// ─────────────── server ───────────────

struct ServerEcho;
#[async_trait]
impl ServiceProtocol for ServerEcho {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn received(&mut self, ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let _ = ctx.send_message(data).await;
    }
}
fn server_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || ProtocolHandle::Callback(Box::new(ServerEcho)))
        .build()
}

// ─────────────── client ───────────────

#[derive(Default)]
struct ClientState {
    samples_ns: Mutex<Vec<u64>>,
    in_flight_at: Mutex<Option<Instant>>,
    last_payload_len: Mutex<usize>,
    notify: Arc<Notify>,
}

struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, _ctx: ProtocolContextMutRef<'_>, _v: &str) {
        // Tell the driver we're ready.
        self.state.notify.notify_one();
    }
    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let Some(t0) = self.state.in_flight_at.lock().unwrap().take() else {
            return;
        };
        let ok_len = *self.state.last_payload_len.lock().unwrap();
        if data.len() != ok_len {
            // count as a failed sample by recording a sentinel; verdict treats
            // length mismatch as failure.
            self.state.samples_ns.lock().unwrap().push(u64::MAX);
        } else {
            let dt = t0.elapsed().as_nanos() as u64;
            self.state.samples_ns.lock().unwrap().push(dt);
        }
        self.state.notify.notify_one();
    }
}
fn client_meta(id: ProtocolId, state: Arc<ClientState>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ClientProto {
                state: state.clone(),
            }))
        })
        .build()
}

// ─────────────── per-transport runner ───────────────

struct Run {
    label: &'static str,
    requests: usize,
    payload: usize,
    elapsed: Duration,
    samples_ns: Vec<u64>,
    failures: usize,
}

fn pct(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn run_one(label: &'static str, listen: Multiaddr, requests: usize, payload: usize, budget: Duration) -> Run {
    // Server side
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (server_addr_tx, server_addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        thread::Builder::new()
            .name(format!("baseline-server-{label}"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc =
                    build_quic_service(server_key, vec![server_meta(PROTO_ID)], (), QuicConfig::default());
                rt.block_on(async move {
                    let real = svc.listen(listen).await.expect("server listen");
                    *server_ctrl.lock().unwrap() = Some(svc.control().clone());
                    let _ = server_addr_tx.send(real);
                    svc.run().await;
                });
            })
            .unwrap();
    }

    // Driver runtime (current thread)
    let driver_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let server_addr = driver_rt
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(10), server_addr_rx)
                .await
                .expect("server addr timeout")
                .expect("server addr")
        });
    let dial_addr: Multiaddr = format!("{server_addr}/p2p/{}", server_pid.to_base58())
        .parse()
        .unwrap();

    // Client side, also in its own thread
    let client_key = SecioKeyPair::secp256k1_generated();
    let state = Arc::new(ClientState {
        notify: Arc::new(Notify::new()),
        ..Default::default()
    });
    let client_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let client_ctrl = client_ctrl.clone();
        let state = state.clone();
        let dial_addr = dial_addr.clone();
        thread::Builder::new()
            .name(format!("baseline-client-{label}"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut svc = build_quic_service(
                    client_key,
                    vec![client_meta(PROTO_ID, state.clone())],
                    (),
                    QuicConfig::default(),
                );
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

    // Wait for the connect notification.
    driver_rt.block_on(async {
        let notify = state.notify.clone();
        tokio::time::timeout(Duration::from_secs(10), notify.notified())
            .await
            .expect("client never connected");
    });

    // Drive the workload from the driver runtime.
    let ctrl = client_ctrl.lock().unwrap().clone().expect("client ctrl");
    let payload_bytes = Bytes::from(vec![0xA5_u8; payload]);
    *state.last_payload_len.lock().unwrap() = payload;

    let start = Instant::now();
    let failures = driver_rt.block_on(async {
        let mut failures = 0usize;
        for _ in 0..requests {
            if start.elapsed() > budget {
                failures += requests; // hard-fail remainder
                break;
            }
            *state.in_flight_at.lock().unwrap() = Some(Instant::now());
            if ctrl
                .filter_broadcast(TargetSession::All, PROTO_ID, payload_bytes.clone())
                .await
                .is_err()
            {
                failures += 1;
                state.in_flight_at.lock().unwrap().take();
                continue;
            }
            let notify = state.notify.clone();
            // wait up to 2s for the echo.
            if tokio::time::timeout(Duration::from_secs(2), notify.notified())
                .await
                .is_err()
            {
                failures += 1;
                state.in_flight_at.lock().unwrap().take();
            }
        }
        failures
    });
    let elapsed = start.elapsed();

    // Tear down (best-effort).
    if let Some(c) = client_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    let mut samples = std::mem::take(&mut *state.samples_ns.lock().unwrap());
    let bad = samples.iter().filter(|n| **n == u64::MAX).count();
    samples.retain(|n| *n != u64::MAX);
    samples.sort_unstable();

    Run {
        label,
        requests,
        payload,
        elapsed,
        samples_ns: samples,
        failures: failures + bad,
    }
}

fn print_run(r: &Run) {
    let p50 = pct(&r.samples_ns, 0.50);
    let p95 = pct(&r.samples_ns, 0.95);
    let p99 = pct(&r.samples_ns, 0.99);
    let secs = r.elapsed.as_secs_f64();
    let rps = if secs > 0.0 { r.samples_ns.len() as f64 / secs } else { 0.0 };
    println!(
        "[{}] reqs={} payload={}B elapsed={:.2}s rps={:.1} p50={:.2}ms p95={:.2}ms p99={:.2}ms failures={}",
        r.label,
        r.requests,
        r.payload,
        secs,
        rps,
        p50 as f64 / 1e6,
        p95 as f64 / 1e6,
        p99 as f64 / 1e6,
        r.failures,
    );
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let requests: usize = env::env_or("QA_REQUESTS", 2000);
    let payload: usize = env::env_or("QA_PAYLOAD", 1024);
    let budget = Duration::from_millis(env::env_or("QA_TIMEOUT_MS", 15_000u64));

    println!("[driver] requests={requests} payload={payload} budget={budget:?}");

    let tcp = run_one(
        "tcp",
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        requests,
        payload,
        budget,
    );
    let quic = run_one(
        "quic",
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
        requests,
        payload,
        budget,
    );

    println!("\n──────────── baseline summary ────────────");
    print_run(&tcp);
    print_run(&quic);
    println!("──────────────────────────────────────────");

    let mut fail = false;
    for r in [&tcp, &quic] {
        if r.failures > 0 {
            fail = true;
            println!("FAIL — {} reported {} failure(s)", r.label, r.failures);
        }
        if r.elapsed > budget {
            fail = true;
            println!("FAIL — {} exceeded budget {:?} (took {:?})", r.label, budget, r.elapsed);
        }
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — both transports completed cleanly.");
        ExitCode::SUCCESS
    }
}
