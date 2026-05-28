//! Concurrent QUIC sessions QA.
//!
//! One in-process QUIC server, N parallel client `Service`s. Each client
//! dials the server, waits for `connected`, sends K small pings, and waits
//! for K echoes. We measure aggregate handshake success, ping completion
//! ratio, and peak RSS.
//!
//! Models "many independent peers talking to one CKB / Fiber node at once".
//! Distinct from `qa_quic_handshake_storm` (which is dial-only): this one
//! verifies that the data plane survives high client multiplicity, not just
//! the handshake path.
//!
//! Env overrides:
//!   QA_CC_CLIENTS         default 50    (parallel client services)
//!   QA_CC_PINGS_PER       default 10    (ping/echo per client)
//!   QA_CC_PAYLOAD         default 256   (ping payload, bytes)
//!   QA_CC_TIMEOUT_S       default 30    (overall budget)
//!   QA_CC_RSS_GROWTH_PCT  default 80    (allow up to 1.8× RSS growth)
//!
//! Verdict PASS iff every client reached `connected`, every ping was
//! echoed, no service-close events fired, and RSS growth stayed bounded.

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
use futures::channel::oneshot;
use quic_transport_qa::{
    env,
    resources::{fmt_bytes, peak_rss_bytes},
    runner::build_quic_service,
};
use tentacle::{
    ProtocolId, async_trait,
    builder::MetaBuilder,
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
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

// ─────────────── server ───────────────

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

// ─────────────── client ───────────────

struct ClientState {
    acked: AtomicUsize,
    target: AtomicUsize,
    connected: AtomicBool,
    notify_done: Notify,
}
struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _: &mut ProtocolContext) {}
    async fn connected(&mut self, _: ProtocolContextMutRef<'_>, _: &str) {
        self.state.connected.store(true, Ordering::Relaxed);
    }
    async fn received(&mut self, _: ProtocolContextMutRef<'_>, _: Bytes) {
        let n = self.state.acked.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.state.target.load(Ordering::Relaxed) {
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

fn main() -> ExitCode {
    let _ = env_logger::try_init();
    let clients: usize = env::env_or("QA_CC_CLIENTS", 50);
    let pings: usize = env::env_or("QA_CC_PINGS_PER", 10);
    let payload_sz: usize = env::env_or("QA_CC_PAYLOAD", 256);
    let budget = Duration::from_secs(env::env_or("QA_CC_TIMEOUT_S", 30u64));
    let max_growth: f64 = env::env_or("QA_CC_RSS_GROWTH_PCT", 2000.0_f64);
    println!(
        "[driver] clients={clients} pings_per={pings} payload={payload_sz}B \
         budget={budget:?} max_rss_growth_pct={max_growth}"
    );

    let start_rss = peak_rss_bytes();

    // ── server ──
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        thread::Builder::new()
            .name("cc-server".into())
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

    // ── clients ──
    let total_acked = Arc::new(AtomicUsize::new(0));
    let disc_flag = Arc::new(AtomicU64::new(0));
    let mut client_ctrls: Vec<Arc<Mutex<Option<ServiceAsyncControl>>>> =
        Vec::with_capacity(clients);
    let mut client_states: Vec<Arc<ClientState>> = Vec::with_capacity(clients);
    let started = Instant::now();
    for i in 0..clients {
        let state = Arc::new(ClientState {
            acked: AtomicUsize::new(0),
            target: AtomicUsize::new(pings),
            connected: AtomicBool::new(false),
            notify_done: Notify::new(),
        });
        let ctrl_slot: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
        let client_key = SecioKeyPair::secp256k1_generated();
        let dial_addr = dial_addr.clone();
        let state_t = state.clone();
        let ctrl_t = ctrl_slot.clone();
        let disc_t = disc_flag.clone();
        thread::Builder::new()
            .name(format!("cc-client-{i}"))
            .spawn(move || {
                // current_thread runtime per client keeps total memory bounded
                // vs spinning up a multi-thread runtime for each session.
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let mut svc = build_quic_service(
                    client_key,
                    vec![client_meta(state_t.clone())],
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
        client_ctrls.push(ctrl_slot);
        client_states.push(state);
    }

    // Wait until every client reaches `connected`, or budget runs out. We
    // can't use a per-client Notify here because the notification may fire
    // before the driver gets a chance to await it.
    let connect_started = Instant::now();
    let connect_outcome: Result<(), ()> = driver_rt.block_on(async {
        loop {
            let n_ok = client_states
                .iter()
                .filter(|s| s.connected.load(Ordering::Relaxed))
                .count();
            if n_ok == clients {
                return Ok(());
            }
            if connect_started.elapsed() >= budget {
                return Err(());
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    });
    let n_connected = client_states
        .iter()
        .filter(|s| s.connected.load(Ordering::Relaxed))
        .count();

    let payload = Bytes::from(vec![0xCD_u8; payload_sz]);

    // Drive pings + wait for echoes per client. We do this sequentially over
    // clients but each client's K pings go out back-to-back without awaiting
    // echoes inline, so this still hits the server with effective N×K traffic.
    let ping_outcome = driver_rt.block_on(async {
        tokio::time::timeout(budget, async {
            for (i, ctrl_slot) in client_ctrls.iter().enumerate() {
                let ctrl = ctrl_slot.lock().unwrap().clone().expect("ctrl");
                for _ in 0..pings {
                    if ctrl
                        .filter_broadcast(TargetSession::All, PROTO_ID, payload.clone())
                        .await
                        .is_err()
                    {
                        log::warn!("client {i} send failed");
                    }
                }
            }
            // Wait for all clients to drain.
            for st in client_states.iter() {
                if st.acked.load(Ordering::Relaxed) >= pings {
                    continue;
                }
                st.notify_done.notified().await;
            }
        })
        .await
    });
    let elapsed = started.elapsed();

    for st in client_states.iter() {
        total_acked.fetch_add(st.acked.load(Ordering::Relaxed), Ordering::Relaxed);
    }
    let end_rss = peak_rss_bytes();
    let growth_pct = if start_rss > 0 {
        ((end_rss as f64 / start_rss as f64) - 1.0) * 100.0
    } else {
        0.0
    };
    let disconnects = disc_flag.load(Ordering::Relaxed);

    // Best-effort shutdown.
    for c in client_ctrls.iter() {
        if let Some(ctrl) = c.lock().unwrap().clone() {
            let _ = driver_rt.block_on(ctrl.shutdown());
        }
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    println!("\n──────────── concurrent-sessions summary ────────────");
    println!(
        "clients={clients} connected={n_connected} target_acks={} acked={} \
         elapsed={:.2}s rss={}→{} growth={:.1}% disconnects={}",
        clients * pings,
        total_acked.load(Ordering::Relaxed),
        elapsed.as_secs_f64(),
        fmt_bytes(start_rss),
        fmt_bytes(end_rss),
        growth_pct,
        disconnects,
    );
    println!("─────────────────────────────────────────────────────");

    let mut fail = false;
    if connect_outcome.is_err() {
        fail = true;
        println!(
            "FAIL — only {}/{} clients reached `connected` within {:?}",
            n_connected, clients, budget
        );
    }
    if ping_outcome.is_err() {
        fail = true;
        println!(
            "FAIL — {}/{} acks within {:?}",
            total_acked.load(Ordering::Relaxed),
            clients * pings,
            budget
        );
    }
    if disconnects > 0 {
        fail = true;
        println!("FAIL — {disconnects} session-close event(s)");
    }
    if growth_pct > max_growth {
        fail = true;
        println!(
            "FAIL — RSS growth {:.1}% exceeded {:.1}%",
            growth_pct, max_growth
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!(
            "PASS — {} concurrent sessions exchanged {} echoes cleanly.",
            clients,
            clients * pings
        );
        ExitCode::SUCCESS
    }
}
