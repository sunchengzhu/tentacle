//! QUIC jitter / reconnect QA.
//!
//! Models a server that intentionally goes away and comes back, like a node
//! restart in CKB / Fiber. The client must:
//!
//!   1. Notice the disconnect via `ServiceHandle::handle_event` / `handle_error`
//!      (or via its protocol's `disconnected` callback).
//!   2. Re-dial the same multiaddr and reattach to the protocol.
//!   3. Resume sending without panicking.
//!
//! The server lives in a dedicated thread that we tear down and re-spawn on
//! the **same** UDP port every `QA_CYCLE_SECS`. Because UDP socket reuse can
//! lose the in-flight QUIC state across restarts, the client's redial is the
//! contract under test, not message ordering across the gap.
//!
//! Env overrides:
//!   QA_CYCLES         default 3   (number of down/up cycles)
//!   QA_CYCLE_SECS     default 4   (server uptime per cycle)
//!   QA_DOWN_SECS      default 2   (server downtime per cycle)
//!   QA_PERIOD_MS      default 100 (client send period)
//!
//! Verdict PASS iff:
//!   * After every cycle, the client re-establishes the session within
//!     `QA_REDIAL_BUDGET_MS` (default 5000) of the server coming back.
//!   * Total acked messages after the run >= `QA_MIN_ACKED` (default
//!     ~30% of sent; reconnect inevitably drops some in-flight echoes).
//!   * No panics; the program exits cleanly.

use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use quic_transport_qa::{env, runner::build_quic_service};
use tentacle::{
    ProtocolId, async_trait,
    builder::MetaBuilder,
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::{Multiaddr, Protocol},
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, ServiceAsyncControl, ServiceError, ServiceEvent,
        TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};
use tokio::sync::Notify;

const PROTO_ID: ProtocolId = ProtocolId::new(1);

// ─────────────── server (lives per-cycle) ───────────────

struct ServerEcho;
#[async_trait]
impl ServiceProtocol for ServerEcho {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
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

/// Spawn one server thread bound to `bind_addr` (which carries the port we
/// want to keep). Returns its control plus the actual listen multiaddr.
fn spawn_server(
    key: SecioKeyPair,
    bind_addr: Multiaddr,
) -> (Arc<Mutex<Option<ServiceAsyncControl>>>, Multiaddr) {
    let ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = std::sync::mpsc::sync_channel::<Multiaddr>(1);
    let ctrl_for_thread = ctrl.clone();
    thread::Builder::new()
        .name("jitter-server".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let mut svc = build_quic_service(key, vec![server_meta()], (), QuicConfig::default());
            rt.block_on(async move {
                match svc.listen(bind_addr.clone()).await {
                    Ok(real) => {
                        *ctrl_for_thread.lock().unwrap() = Some(svc.control().clone());
                        let _ = tx.send(real);
                        svc.run().await;
                    }
                    Err(e) => {
                        eprintln!("[server] listen failed on {bind_addr}: {e:?}");
                    }
                }
            });
        })
        .unwrap();

    let real = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server listen timeout");
    (ctrl, real)
}

// ─────────────── client ───────────────

#[derive(Default)]
struct ClientState {
    connected: AtomicBool,
    last_connected_at: Mutex<Option<Instant>>,
    last_disconnected_at: Mutex<Option<Instant>>,
    sent: AtomicUsize,
    acked: AtomicUsize,
    reconnect_intervals_ms: Mutex<Vec<u64>>,
    notify_first_connect: Notify,
}

struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, _ctx: ProtocolContextMutRef<'_>, _v: &str) {
        let now = Instant::now();
        self.state.connected.store(true, Ordering::SeqCst);
        if let Some(t_disc) = self.state.last_disconnected_at.lock().unwrap().take() {
            let dt = now.duration_since(t_disc).as_millis() as u64;
            self.state.reconnect_intervals_ms.lock().unwrap().push(dt);
        }
        *self.state.last_connected_at.lock().unwrap() = Some(now);
        self.state.notify_first_connect.notify_one();
        println!("[client/proto] connected");
    }
    async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
        self.state.connected.store(false, Ordering::SeqCst);
        *self.state.last_disconnected_at.lock().unwrap() = Some(Instant::now());
        println!("[client/proto] disconnected");
    }
    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, _data: Bytes) {
        self.state.acked.fetch_add(1, Ordering::Relaxed);
    }
}
fn client_meta(state: Arc<ClientState>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ClientProto {
                state: state.clone(),
            }))
        })
        .build()
}

/// Service-level handle: counts dialer errors so we can confirm they don't
/// crash the runtime and reports session-close events.
struct ClientService {
    state: Arc<ClientState>,
    error_count: Arc<AtomicU64>,
}
#[async_trait]
impl ServiceHandle for ClientService {
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, err: ServiceError) {
        log::debug!("[client/svc] error: {err:?}");
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }
    async fn handle_event(&mut self, _ctx: &mut ServiceContext, ev: ServiceEvent) {
        if let ServiceEvent::SessionClose { .. } = &ev {
            self.state.connected.store(false, Ordering::SeqCst);
            *self.state.last_disconnected_at.lock().unwrap() = Some(Instant::now());
            log::debug!("[client/svc] session close");
        }
    }
}

fn force_quic_port(addr: &Multiaddr, port: u16) -> Multiaddr {
    addr.iter()
        .map(|p| match p {
            Protocol::Udp(_) => Protocol::Udp(port),
            other => other,
        })
        .collect()
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let cycles: u32 = env::env_or("QA_CYCLES", 3);
    let cycle_up = Duration::from_secs(env::env_or("QA_CYCLE_SECS", 4u64));
    let cycle_down = Duration::from_secs(env::env_or("QA_DOWN_SECS", 2u64));
    let period = Duration::from_millis(env::env_or("QA_PERIOD_MS", 100u64));
    let redial_budget = Duration::from_millis(env::env_or("QA_REDIAL_BUDGET_MS", 5_000u64));

    println!(
        "[driver] cycles={cycles} up={cycle_up:?} down={cycle_down:?} \
         period={period:?} redial_budget={redial_budget:?}"
    );

    // Server identity is stable across cycles so the client always dials the
    // same /p2p/<pid>.
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();

    // First boot — listen on ephemeral UDP port, capture it, then re-use that
    // exact port for every subsequent cycle.
    let (mut server_ctrl, first_listen) = spawn_server(
        server_key.clone(),
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
    );
    let server_port = first_listen
        .iter()
        .find_map(|p| if let Protocol::Udp(port) = p { Some(port) } else { None })
        .expect("first listen must contain /udp/<port>");
    let stable_listen = force_quic_port(&first_listen, server_port);
    let dial_addr: Multiaddr = format!("{stable_listen}/p2p/{}", server_pid.to_base58())
        .parse()
        .unwrap();
    println!(
        "[driver] server first booted on port {server_port}, stable dial = {dial_addr}"
    );

    // ── client ──
    let client_key = SecioKeyPair::secp256k1_generated();
    let state = Arc::new(ClientState::default());
    let svc_err = Arc::new(AtomicU64::new(0));
    let client_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let client_ctrl = client_ctrl.clone();
        let state = state.clone();
        let svc_err = svc_err.clone();
        let dial_addr = dial_addr.clone();
        thread::Builder::new()
            .name("jitter-client".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut cfg = QuicConfig::default();
                cfg.keep_alive_interval = Some(Duration::from_millis(500));
                cfg.max_idle_timeout = Duration::from_secs(2);
                let mut svc = build_quic_service(
                    client_key,
                    vec![client_meta(state.clone())],
                    ClientService {
                        state: state.clone(),
                        error_count: svc_err.clone(),
                    },
                    cfg,
                );
                rt.block_on(async move {
                    *client_ctrl.lock().unwrap() = Some(svc.control().clone());
                    // Initial dial.
                    let _ = svc.control().dial(dial_addr, TargetProtocol::All).await;
                    svc.run().await;
                });
            })
            .unwrap();
    }

    // Wait for first connect.
    let driver_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    driver_rt
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(10),
                state.notify_first_connect.notified(),
            )
            .await
        })
        .expect("client never made first connection");

    let ctrl = client_ctrl.lock().unwrap().clone().expect("client ctrl");

    // Background sender: pushes every `period` regardless of connected state.
    // When disconnected the broadcast simply fans out to zero sessions, which
    // is fine — re-dial logic below restores the session.
    let stop = Arc::new(AtomicBool::new(false));
    let sender_state = state.clone();
    let sender_ctrl = ctrl.clone();
    let sender_stop = stop.clone();
    let _sender = driver_rt.spawn(async move {
        let payload = Bytes::from_static(b"jitter-ping");
        while !sender_stop.load(Ordering::Relaxed) {
            let _ = sender_ctrl
                .filter_broadcast(TargetSession::All, PROTO_ID, payload.clone())
                .await;
            sender_state.sent.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(period).await;
        }
    });

    // Background re-dialer: whenever we're disconnected, re-issue a dial.
    let redial_ctrl = ctrl.clone();
    let redial_addr = dial_addr.clone();
    let redial_stop = stop.clone();
    let _redialer = driver_rt.spawn(async move {
        loop {
            if redial_stop.load(Ordering::Relaxed) {
                break;
            }
            // Unconditional redial; tentacle dedups when a session already
            // exists for this (addr, peer_id).
            let _ = redial_ctrl
                .dial(redial_addr.clone(), TargetProtocol::All)
                .await;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });

    // Drive `cycles` of (uptime, downtime, restart).
    for cycle in 0..cycles {
        println!("[driver] cycle {cycle}: server up for {cycle_up:?}");
        driver_rt.block_on(async { tokio::time::sleep(cycle_up).await });

        println!("[driver] cycle {cycle}: tearing down server");
        if let Some(c) = server_ctrl.lock().unwrap().take() {
            let _ = driver_rt.block_on(c.shutdown());
        }
        driver_rt.block_on(async { tokio::time::sleep(cycle_down).await });

        println!("[driver] cycle {cycle}: respawning server on port {server_port}");
        let (new_ctrl, _new_listen) = spawn_server(server_key.clone(), stable_listen.clone());
        server_ctrl = new_ctrl;
    }

    // Final uptime tail so the last cycle has time to reconnect.
    println!("[driver] tail uptime {cycle_up:?}");
    driver_rt.block_on(async { tokio::time::sleep(cycle_up).await });

    stop.store(true, Ordering::Relaxed);
    driver_rt.block_on(async { tokio::time::sleep(Duration::from_millis(300)).await });

    let sent = state.sent.load(Ordering::Relaxed);
    let acked = state.acked.load(Ordering::Relaxed);
    let svc_errors = svc_err.load(Ordering::Relaxed);
    let intervals = state.reconnect_intervals_ms.lock().unwrap().clone();

    // Best-effort shutdown.
    if let Some(c) = client_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    println!("\n──────────── jitter/reconnect summary ────────────");
    println!("sent={sent} acked={acked} svc_errors={svc_errors}");
    println!("reconnect intervals (ms): {intervals:?}");
    println!("──────────────────────────────────────────────────");

    let mut fail = false;
    // Expect at least (cycles) reconnects.
    if intervals.len() < cycles as usize {
        fail = true;
        println!(
            "FAIL — only {} reconnect(s) observed, expected >= {cycles}",
            intervals.len()
        );
    }
    let budget_ms = redial_budget.as_millis() as u64;
    for (i, &ms) in intervals.iter().enumerate() {
        if ms > budget_ms {
            fail = true;
            println!(
                "FAIL — reconnect #{i} took {ms} ms, exceeds budget {budget_ms} ms"
            );
        }
    }
    let min_acked: usize = env::env_or(
        "QA_MIN_ACKED",
        (sent as f64 * 0.30) as usize,
    );
    if acked < min_acked {
        fail = true;
        println!(
            "FAIL — acked={acked} < min_acked={min_acked} (sent={sent})"
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — client survived {cycles} server restart cycle(s).");
        ExitCode::SUCCESS
    }
}
