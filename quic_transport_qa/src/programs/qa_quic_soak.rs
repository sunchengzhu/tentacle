//! QUIC soak: long-running steady-rate ping with stability assertions.
//!
//! One QUIC server + one QUIC client in-process. Client sends a small
//! timestamped payload every `QA_PERIOD_MS` for `QA_SOAK_SECS` seconds.
//! Server echoes. We continuously sample:
//!
//!   * sent / acked counters,
//!   * loss = sent - acked,
//!   * peak RSS (getrusage),
//!   * per-window throughput (we expect it to stay flat).
//!
//! Verdict PASS iff:
//!   * loss == 0 across the whole run,
//!   * no idle-timeout disconnect (we set max_idle_timeout=30s + keep-alive=1s),
//!   * RSS growth from min-window to max-window <= `QA_RSS_GROWTH_PCT`.
//!
//! Env overrides:
//!   QA_SOAK_SECS         default 30
//!   QA_PERIOD_MS         default 20  (=> ~50 req/s steady)
//!   QA_RSS_GROWTH_PCT    default 50  (allow 1.5x growth, generous; useful as
//!                                      leak smoke test, not a tight bound)

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

// ─────────────── client protocol ───────────────

struct ClientState {
    acked: AtomicUsize,
    notify_connected: Notify,
}

struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, _ctx: ProtocolContextMutRef<'_>, _v: &str) {
        self.state.notify_connected.notify_one();
    }
    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, _data: Bytes) {
        self.state.acked.fetch_add(1, Ordering::Relaxed);
    }
    async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
        log::warn!("[client] protocol disconnected during soak");
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

// ─────────────── service-level disconnect detection ───────────────

#[derive(Default)]
struct DisconnectFlag(Arc<AtomicU64>);
#[async_trait]
impl ServiceHandle for DisconnectFlag {
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, err: ServiceError) {
        log::warn!("[client/service] error: {err:?}");
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    async fn handle_event(&mut self, _ctx: &mut ServiceContext, ev: ServiceEvent) {
        if matches!(ev, ServiceEvent::SessionClose { .. }) {
            log::warn!("[client/service] session closed: {ev:?}");
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let secs = env::env_or::<u64>("QA_SOAK_SECS", 30);
    let period = Duration::from_millis(env::env_or("QA_PERIOD_MS", 20u64));
    let max_growth_pct: f64 = env::env_or("QA_RSS_GROWTH_PCT", 50.0_f64);

    println!(
        "[driver] soak={}s period={:?} max_rss_growth_pct={}",
        secs, period, max_growth_pct
    );

    // ── server ──
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (server_addr_tx, server_addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        thread::Builder::new()
            .name("soak-server".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let cfg = QuicConfig::default(); // 30s idle, 10s keepalive defaults are fine
                let mut svc = build_quic_service(server_key, vec![server_meta()], (), cfg);
                rt.block_on(async move {
                    let real = svc
                        .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                        .await
                        .expect("server listen");
                    *server_ctrl.lock().unwrap() = Some(svc.control().clone());
                    let _ = server_addr_tx.send(real);
                    svc.run().await;
                });
            })
            .unwrap();
    }

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

    // ── client ──
    let client_key = SecioKeyPair::secp256k1_generated();
    let state = Arc::new(ClientState {
        acked: AtomicUsize::new(0),
        notify_connected: Notify::new(),
    });
    let disc_flag = Arc::new(AtomicU64::new(0));
    let client_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let client_ctrl = client_ctrl.clone();
        let state = state.clone();
        let disc_flag = disc_flag.clone();
        let dial_addr = dial_addr.clone();
        thread::Builder::new()
            .name("soak-client".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut cfg = QuicConfig::default();
                cfg.keep_alive_interval = Some(Duration::from_secs(1));
                let mut svc = build_quic_service(
                    client_key,
                    vec![client_meta(state.clone())],
                    DisconnectFlag(disc_flag.clone()),
                    cfg,
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

    driver_rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), state.notify_connected.notified())
            .await
            .expect("client never connected");
    });

    // ── workload ──
    let ctrl = client_ctrl.lock().unwrap().clone().expect("client ctrl");
    let total_iters = (Duration::from_secs(secs).as_millis() / period.as_millis().max(1)) as usize;
    let mut window_rss = Vec::<u64>::new();
    let mut window_throughput = Vec::<f64>::new();
    let start_rss = peak_rss_bytes();
    println!("[driver] start RSS={}", fmt_bytes(start_rss));

    let payload = Bytes::from(vec![0xCC_u8; 64]);
    let sent = Arc::new(AtomicUsize::new(0));

    let outcome = driver_rt.block_on(async {
        let bucket = Duration::from_secs(2);
        let mut bucket_start = Instant::now();
        let mut bucket_at_start = 0usize;
        for i in 0..total_iters {
            if ctrl
                .filter_broadcast(TargetSession::All, PROTO_ID, payload.clone())
                .await
                .is_err()
            {
                return Err(format!("send failed at iter {i}"));
            }
            sent.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(period).await;

            if bucket_start.elapsed() >= bucket {
                let now_acked = state.acked.load(Ordering::Relaxed);
                let delta = now_acked - bucket_at_start;
                let tput = delta as f64 / bucket_start.elapsed().as_secs_f64();
                window_throughput.push(tput);
                window_rss.push(peak_rss_bytes());
                println!(
                    "[t+{:>5.1}s] sent={} acked={} loss={} rss={} window_tput={:.1}/s",
                    Instant::now().duration_since(bucket_start).as_secs_f64()
                        + (window_throughput.len() as f64 - 1.0) * bucket.as_secs_f64(),
                    sent.load(Ordering::Relaxed),
                    now_acked,
                    sent.load(Ordering::Relaxed).saturating_sub(now_acked),
                    fmt_bytes(*window_rss.last().unwrap()),
                    tput,
                );
                bucket_at_start = now_acked;
                bucket_start = Instant::now();
            }
        }
        Ok(())
    });

    // Drain a small grace window for outstanding echoes.
    driver_rt.block_on(async { tokio::time::sleep(Duration::from_millis(500)).await });

    let final_sent = sent.load(Ordering::Relaxed);
    let final_acked = state.acked.load(Ordering::Relaxed);
    let loss = final_sent.saturating_sub(final_acked);
    let disconnects = disc_flag.load(Ordering::Relaxed);
    let end_rss = peak_rss_bytes();
    let rss_min = *window_rss.iter().min().unwrap_or(&start_rss);
    let rss_max = *window_rss.iter().max().unwrap_or(&end_rss);
    let growth_pct = if rss_min > 0 {
        ((rss_max as f64 / rss_min as f64) - 1.0) * 100.0
    } else {
        0.0
    };

    // Best-effort shutdown.
    if let Some(c) = client_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    println!("\n──────────── soak summary ────────────");
    println!(
        "sent={} acked={} loss={} disconnects={} start_rss={} end_rss={} \
         rss_min_window={} rss_max_window={} growth={:.1}%",
        final_sent,
        final_acked,
        loss,
        disconnects,
        fmt_bytes(start_rss),
        fmt_bytes(end_rss),
        fmt_bytes(rss_min),
        fmt_bytes(rss_max),
        growth_pct,
    );
    if let Err(e) = &outcome {
        println!("send-side error: {e}");
    }
    println!("──────────────────────────────────────");

    let mut fail = outcome.is_err();
    if loss > 0 {
        fail = true;
        println!("FAIL — non-zero message loss");
    }
    if disconnects > 0 {
        fail = true;
        println!("FAIL — observed {disconnects} session-level disconnect events");
    }
    if growth_pct > max_growth_pct {
        fail = true;
        println!(
            "FAIL — RSS growth {:.1}% exceeded threshold {:.1}%",
            growth_pct, max_growth_pct
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — soak run stayed healthy.");
        ExitCode::SUCCESS
    }
}
