//! QUIC WAN stability QA.
//!
//! Real WAN environments differ from loopback in three ways: extra one-way
//! latency, packet loss, and per-packet jitter. This program inserts a UDP
//! relay between the client and the QUIC server (both still in-process) and
//! injects all three on every datagram that crosses it. The client sees a
//! `/ip4/127.0.0.1/udp/<relay>/quic-v1/...` address; the server sees what
//! looks like a single peer on the relay's port. tentacle's QUIC stack runs
//! end-to-end through the relay, including handshake, keep-alive, and 1-RTT
//! application data.
//!
//! This is **not** a substitute for real cross-region testing, but it
//! catches the obvious regressions cheaply and in CI.
//!
//! Env overrides:
//!   QA_WAN_RTT_MS         default 80    (added round-trip latency in ms;
//!                                         each direction gets RTT/2)
//!   QA_WAN_JITTER_MS      default 20    (uniform jitter ±N ms per direction)
//!   QA_WAN_LOSS_PCT       default 1.0   (per-packet drop probability, %)
//!   QA_WAN_DURATION_SECS  default 30
//!   QA_WAN_PERIOD_MS      default 50    (client send period)
//!   QA_WAN_PAYLOAD        default 256   (bytes)
//!   QA_WAN_IDLE_TIMEOUT_S default 30    (QUIC max_idle_timeout)
//!   QA_WAN_KEEPALIVE_MS   default 2000  (QUIC keep_alive_interval)
//!   QA_WAN_MIN_DELIVERY   default 0.85  (acked/sent ratio required for PASS)
//!   QA_WAN_MAX_LAT_P95_MS default 0     (0 = report only; >0 = hard cap on
//!                                         observed p95 round-trip)
//!
//! Verdict PASS iff:
//!   * No service-level disconnects fired during the run.
//!   * acked/sent >= QA_WAN_MIN_DELIVERY.
//!   * If QA_WAN_MAX_LAT_P95_MS > 0, measured p95 <= that bound.

use std::{
    net::SocketAddr,
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
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
        TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};
use tokio::{net::UdpSocket, sync::Notify};

const PROTO_ID: ProtocolId = ProtocolId::new(1);

// ─────────────── tiny xorshift PRNG (so we don't pull in `rand`) ───────────────

#[derive(Clone)]
struct XorShift(Arc<AtomicU64>);
impl XorShift {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        Self(Arc::new(AtomicU64::new(seed)))
    }
    fn next_u64(&self) -> u64 {
        // xorshift64*
        let mut x = self.0.load(Ordering::Relaxed);
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0.store(x, Ordering::Relaxed);
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform float in [0, 1).
    fn next_f64(&self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Uniform jitter in [-jitter_ms, +jitter_ms].
    fn jitter_ms(&self, jitter_ms: u64) -> i64 {
        if jitter_ms == 0 {
            return 0;
        }
        let span = (jitter_ms as i64) * 2 + 1;
        (self.next_u64() % span as u64) as i64 - jitter_ms as i64
    }
}

// ─────────────── UDP WAN relay ───────────────

#[derive(Clone)]
struct WanCfg {
    one_way_ms: u64,
    jitter_ms: u64,
    loss_pct: f64,
}

/// Bind a UDP socket on 127.0.0.1:0, forward everything to `upstream`, return
/// the bound port. Latency/loss/jitter applied per packet in both directions.
async fn spawn_wan_relay(upstream: SocketAddr, cfg: WanCfg) -> std::io::Result<u16> {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let port = sock.local_addr()?.port();
    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let rng = XorShift::new();

    let sock_r = sock.clone();
    let client_r = client_addr.clone();
    let rng_r = rng.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock_r.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("[wan-relay] recv_from: {e:?}");
                    break;
                }
            };
            let pkt = buf[..n].to_vec();
            let dst = if src == upstream {
                *client_r.lock().unwrap()
            } else {
                // First-time / refresh client mapping.
                *client_r.lock().unwrap() = Some(src);
                Some(upstream)
            };
            let Some(dst) = dst else { continue };

            if rng_r.next_f64() * 100.0 < cfg.loss_pct {
                continue;
            }
            let extra = cfg.one_way_ms as i64 + rng_r.jitter_ms(cfg.jitter_ms);
            let delay = Duration::from_millis(extra.max(0) as u64);
            let sock_send = sock_r.clone();
            tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let _ = sock_send.send_to(&pkt, dst).await;
            });
        }
    });

    Ok(port)
}

// ─────────────── tentacle wiring ───────────────

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

struct ClientState {
    acked: AtomicUsize,
    rtt_samples_ns: Mutex<Vec<u128>>,
    notify_connected: Notify,
}

struct ClientProto {
    state: Arc<ClientState>,
}
#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, _ctx: ProtocolContextMutRef<'_>, _ver: &str) {
        self.state.notify_connected.notify_waiters();
    }
    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        if data.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[..16]);
            let sent_ns = u128::from_be_bytes(buf);
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            if now_ns > sent_ns {
                self.state
                    .rtt_samples_ns
                    .lock()
                    .unwrap()
                    .push(now_ns - sent_ns);
            }
        }
        self.state.acked.fetch_add(1, Ordering::Relaxed);
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
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, err: ServiceError) {
        log::debug!("[svc-err] {err:?}");
    }
    async fn handle_event(&mut self, _ctx: &mut ServiceContext, ev: ServiceEvent) {
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

    let rtt_ms: u64 = env::env_or("QA_WAN_RTT_MS", 80);
    let jitter_ms: u64 = env::env_or("QA_WAN_JITTER_MS", 20);
    let loss_pct: f64 = env::env_or("QA_WAN_LOSS_PCT", 1.0_f64);
    let secs: u64 = env::env_or("QA_WAN_DURATION_SECS", 30);
    let period = Duration::from_millis(env::env_or("QA_WAN_PERIOD_MS", 50u64));
    let payload_sz: usize = env::env_or("QA_WAN_PAYLOAD", 256);
    let idle_s: u64 = env::env_or("QA_WAN_IDLE_TIMEOUT_S", 30);
    let keepalive_ms: u64 = env::env_or("QA_WAN_KEEPALIVE_MS", 2000);
    let min_delivery: f64 = env::env_or("QA_WAN_MIN_DELIVERY", 0.85_f64);
    let max_p95_ms: u64 = env::env_or("QA_WAN_MAX_LAT_P95_MS", 0u64);

    println!(
        "[driver] rtt={}ms jitter=±{}ms loss={}% duration={}s period={:?} \
         payload={}B idle={}s keepalive={}ms min_delivery={} max_p95_ms={}",
        rtt_ms,
        jitter_ms,
        loss_pct,
        secs,
        period,
        payload_sz,
        idle_s,
        keepalive_ms,
        min_delivery,
        max_p95_ms,
    );

    // ── server ──
    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (server_addr_tx, server_addr_rx) = oneshot::channel::<Multiaddr>();
    let server_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let server_ctrl = server_ctrl.clone();
        let idle_s = idle_s;
        let keepalive_ms = keepalive_ms;
        thread::Builder::new()
            .name("wan-server".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut cfg = QuicConfig::default();
                cfg.max_idle_timeout = Duration::from_secs(idle_s);
                cfg.keep_alive_interval = Some(Duration::from_millis(keepalive_ms));
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
    let server_addr = driver_rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), server_addr_rx)
            .await
            .expect("server addr timeout")
            .expect("server addr")
    });

    // Parse the upstream UDP port out of the server multiaddr (last `udp/<n>` component).
    let server_str = server_addr.to_string();
    let server_port: u16 = server_str
        .split('/')
        .collect::<Vec<_>>()
        .windows(2)
        .find_map(|w| (w[0] == "udp").then(|| w[1].parse::<u16>().ok()).flatten())
        .expect("parse server udp port");
    let upstream: SocketAddr = format!("127.0.0.1:{server_port}").parse().unwrap();

    // ── relay ──
    let relay_port = driver_rt
        .block_on(spawn_wan_relay(
            upstream,
            WanCfg {
                one_way_ms: rtt_ms / 2,
                jitter_ms,
                loss_pct,
            },
        ))
        .expect("relay bind");

    let dial_addr: Multiaddr = format!(
        "/ip4/127.0.0.1/udp/{relay_port}/quic-v1/p2p/{}",
        server_pid.to_base58()
    )
    .parse()
    .unwrap();
    println!("[driver] server_port={server_port} relay_port={relay_port} dial={dial_addr}");

    // ── client ──
    let client_key = SecioKeyPair::secp256k1_generated();
    let state = Arc::new(ClientState {
        acked: AtomicUsize::new(0),
        rtt_samples_ns: Mutex::new(Vec::new()),
        notify_connected: Notify::new(),
    });
    let disc_flag = Arc::new(AtomicU64::new(0));
    let client_ctrl: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
    {
        let client_ctrl = client_ctrl.clone();
        let state = state.clone();
        let disc_flag = disc_flag.clone();
        let dial_addr = dial_addr.clone();
        let idle_s = idle_s;
        let keepalive_ms = keepalive_ms;
        thread::Builder::new()
            .name("wan-client".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let mut cfg = QuicConfig::default();
                cfg.max_idle_timeout = Duration::from_secs(idle_s);
                cfg.keep_alive_interval = Some(Duration::from_millis(keepalive_ms));
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

    // The QUIC handshake itself eats ~1 RTT through the relay; allow generous
    // budget so handshake delay alone never causes the run to fail.
    let handshake_budget =
        Duration::from_millis((rtt_ms * 4).max(5_000)).min(Duration::from_secs(30));
    driver_rt.block_on(async {
        tokio::time::timeout(handshake_budget, state.notify_connected.notified())
            .await
            .expect("client never connected through relay");
    });

    // ── workload ──
    let ctrl = client_ctrl.lock().unwrap().clone().expect("client ctrl");
    let total_iters = (Duration::from_secs(secs).as_millis() / period.as_millis().max(1)) as usize;
    let sent = Arc::new(AtomicUsize::new(0));

    let workload_outcome = driver_rt.block_on(async {
        let mut bucket_start = Instant::now();
        let bucket = Duration::from_secs(5);
        let mut bucket_at_start = 0usize;
        for i in 0..total_iters {
            // Each payload is [u128 BE send_ts_ns][padding..] so we can measure RTT.
            let ts_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let mut buf = vec![0u8; payload_sz.max(16)];
            buf[..16].copy_from_slice(&ts_ns.to_be_bytes());
            if ctrl
                .filter_broadcast(TargetSession::All, PROTO_ID, Bytes::from(buf))
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
                println!(
                    "[t+{:>5.1}s] sent={} acked={} loss_so_far={} window_tput={:.1}/s",
                    Instant::now().duration_since(bucket_start).as_secs_f64(),
                    sent.load(Ordering::Relaxed),
                    now_acked,
                    sent.load(Ordering::Relaxed).saturating_sub(now_acked),
                    tput,
                );
                bucket_at_start = now_acked;
                bucket_start = Instant::now();
            }
        }
        Ok(())
    });

    // Drain a few RTTs worth of outstanding echoes (5× RTT, min 1s, capped 10s).
    let drain = Duration::from_millis((rtt_ms * 5).max(1_000)).min(Duration::from_secs(10));
    driver_rt.block_on(async { tokio::time::sleep(drain).await });

    let final_sent = sent.load(Ordering::Relaxed);
    let final_acked = state.acked.load(Ordering::Relaxed);
    let loss = final_sent.saturating_sub(final_acked);
    let delivery_ratio = if final_sent > 0 {
        final_acked as f64 / final_sent as f64
    } else {
        0.0
    };
    let disconnects = disc_flag.load(Ordering::Relaxed);
    let mut samples = state.rtt_samples_ns.lock().unwrap().clone();
    samples.sort_unstable();
    let p50_ms = pct(&samples, 0.50) as f64 / 1e6;
    let p95_ms = pct(&samples, 0.95) as f64 / 1e6;
    let p99_ms = pct(&samples, 0.99) as f64 / 1e6;

    // Best-effort shutdown.
    if let Some(c) = client_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }
    if let Some(c) = server_ctrl.lock().unwrap().clone() {
        let _ = driver_rt.block_on(c.shutdown());
    }

    println!("\n──────────── wan-stability summary ────────────");
    println!(
        "sent={} acked={} loss={} delivery={:.3} disconnects={} \
         p50={:.2}ms p95={:.2}ms p99={:.2}ms (samples={})",
        final_sent,
        final_acked,
        loss,
        delivery_ratio,
        disconnects,
        p50_ms,
        p95_ms,
        p99_ms,
        samples.len(),
    );
    if let Err(e) = &workload_outcome {
        println!("send-side error: {e}");
    }
    println!("──────────────────────────────────────────────");

    let mut fail = workload_outcome.is_err();
    if disconnects > 0 {
        fail = true;
        println!("FAIL — observed {disconnects} session-close event(s) under WAN profile");
    }
    if delivery_ratio < min_delivery {
        fail = true;
        println!(
            "FAIL — delivery {:.3} below threshold {:.3}",
            delivery_ratio, min_delivery
        );
    }
    if max_p95_ms > 0 && (p95_ms as u64) > max_p95_ms {
        fail = true;
        println!(
            "FAIL — p95 {:.2}ms exceeded threshold {}ms",
            p95_ms, max_p95_ms
        );
    }
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — QUIC stayed healthy under WAN profile.");
        ExitCode::SUCCESS
    }
}
