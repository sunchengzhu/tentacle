//! Real-WAN client. Dials a remote `qa_wan_server` and measures one of:
//!   * latency : N small pings paced by QA_PERIOD_MS, prints RTT p50/p95/p99.
//!   * bulk    : N echoes of M MiB each, prints goodput.
//!   * soak    : keep pinging for QA_DURATION_SECS, prints progress every 5 s.
//!
//! Pick the same binary on the other AWS machine; flip `QA_MODE`. The dial
//! string is whatever `qa_wan_server` printed at startup.
//!
//! Required env:
//!   QA_SERVER_ADDR    full multiaddr including /p2p/<peerid>, e.g.
//!                     /ip4/18.x.y.z/udp/9443/quic-v1/p2p/QmServer...
//!
//! Common env:
//!   QA_MODE           latency | bulk | soak       default latency
//!   QA_PAYLOAD        bytes per message           default 256
//!   QA_COUNT          number of messages          default 200
//!   QA_PERIOD_MS      gap between sends (latency) default 50
//!   QA_BULK_SIZE_MIB  per-message size in bulk    default 2
//!   QA_BULK_COUNT     messages in bulk mode       default 8
//!   QA_DURATION_SECS  soak duration               default 120
//!   QA_SOAK_PERIOD_MS soak send period            default 100
//!   QA_CONNECT_TIMEOUT_S                          default 30
//!   QA_RUN_TIMEOUT_S  overall safety timeout      default 600
//!   QA_IDLE_TIMEOUT_S QUIC idle timeout           default 60
//!   QA_KEEPALIVE_MS   QUIC keep-alive             default 5000
//!   QA_MAX_FRAME_MIB  protocol frame cap          default 16
//!
//! Pass/fail thresholds (any breach -> exit 1):
//!   QA_MIN_DELIVERY   ack ratio (acked / sent)    default 0.95
//!   QA_MAX_P95_MS     p95 RTT cap (latency/soak)  default 0 (off)
//!   QA_MIN_BULK_MBPS  goodput floor in bulk mode  default 0 (off)

use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use quic_transport_qa::env;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent, TargetProtocol, TargetSession,
    },
    traits::{ServiceHandle, ServiceProtocol},
};

const PROTO_ID: ProtocolId = ProtocolId::new(1);

#[derive(Default)]
struct State {
    sent: AtomicUsize,
    acked: AtomicUsize,
    disconnects: AtomicU64,
    connected: AtomicBool,
    shutting_down: AtomicBool,
    rtt_ns: Mutex<Vec<u128>>,
    bulk_bytes_received: AtomicUsize,
}

struct Proto {
    state: Arc<State>,
}
#[async_trait]
impl ServiceProtocol for Proto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _ver: &str) {
        log::info!("[client] connected to {}", ctx.session.address);
        self.state.connected.store(true, Ordering::Release);
    }
    async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
        log::warn!("[client] disconnected");
        self.state.connected.store(false, Ordering::Release);
    }
    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        self.state
            .bulk_bytes_received
            .fetch_add(data.len(), Ordering::Relaxed);
        if data.len() >= 16 {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&data[..16]);
            let sent_ns = u128::from_be_bytes(buf);
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            if now_ns > sent_ns {
                self.state.rtt_ns.lock().unwrap().push(now_ns - sent_ns);
            }
        }
        self.state.acked.fetch_add(1, Ordering::Relaxed);
    }
}

fn proto_meta(state: Arc<State>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(move || ProtocolHandle::Callback(Box::new(Proto { state })))
        .build()
}

struct Watcher(Arc<State>);
#[async_trait]
impl ServiceHandle for Watcher {
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, err: ServiceError) {
        log::warn!("[client] service error: {err:?}");
    }
    async fn handle_event(&mut self, _ctx: &mut ServiceContext, ev: ServiceEvent) {
        if let ServiceEvent::SessionClose { .. } = ev {
            if !self.0.shutting_down.load(Ordering::Acquire) {
                self.0.disconnects.fetch_add(1, Ordering::Relaxed);
            }
            self.0.connected.store(false, Ordering::Release);
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

fn make_payload(size: usize, ts_ns: u128) -> Bytes {
    let mut v = vec![0u8; size.max(16)];
    v[..16].copy_from_slice(&ts_ns.to_be_bytes());
    Bytes::from(v)
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let addr_str = match std::env::var("QA_SERVER_ADDR") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "[client] QA_SERVER_ADDR is required (e.g. /ip4/<ip>/udp/9443/quic-v1/p2p/<pid>)"
            );
            return ExitCode::FAILURE;
        }
    };
    let server_addr: Multiaddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[client] bad QA_SERVER_ADDR {addr_str:?}: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let mode: String = env::env_or("QA_MODE", "latency".to_string());
    let payload: usize = env::env_or("QA_PAYLOAD", 256usize);
    let count: usize = env::env_or("QA_COUNT", 200usize);
    let period_ms: u64 = env::env_or("QA_PERIOD_MS", 50u64);
    let bulk_size_mib: usize = env::env_or("QA_BULK_SIZE_MIB", 2usize);
    let bulk_count: usize = env::env_or("QA_BULK_COUNT", 8usize);
    let soak_secs: u64 = env::env_or("QA_DURATION_SECS", 120u64);
    let soak_period_ms: u64 = env::env_or("QA_SOAK_PERIOD_MS", 100u64);
    let connect_timeout_s: u64 = env::env_or("QA_CONNECT_TIMEOUT_S", 30u64);
    let run_timeout_s: u64 = env::env_or("QA_RUN_TIMEOUT_S", 600u64);
    let idle_s: u64 = env::env_or("QA_IDLE_TIMEOUT_S", 60u64);
    let keepalive_ms: u64 = env::env_or("QA_KEEPALIVE_MS", 5000u64);
    let max_frame_mib: usize = env::env_or("QA_MAX_FRAME_MIB", 16usize);
    let max_frame = max_frame_mib * 1024 * 1024;

    let min_delivery: f64 = env::env_or("QA_MIN_DELIVERY", 0.95f64);
    let max_p95_ms: u64 = env::env_or("QA_MAX_P95_MS", 0u64);
    let min_bulk_mbps: f64 = env::env_or("QA_MIN_BULK_MBPS", 0f64);

    println!("[driver] dial={addr_str}");
    println!(
        "[driver] mode={mode} payload={payload} count={count} period_ms={period_ms} \
         bulk_size_mib={bulk_size_mib} bulk_count={bulk_count} soak_secs={soak_secs} \
         soak_period_ms={soak_period_ms} connect_timeout_s={connect_timeout_s} \
         run_timeout_s={run_timeout_s} idle_s={idle_s} keepalive_ms={keepalive_ms} \
         max_frame_mib={max_frame_mib}"
    );
    println!(
        "[driver] thresholds: min_delivery={min_delivery} max_p95_ms={max_p95_ms} \
         min_bulk_mbps={min_bulk_mbps}"
    );

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[client] failed to build runtime: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    let state = Arc::new(State::default());
    let key = SecioKeyPair::secp256k1_generated();
    let mode_for_task = mode.clone();
    let state_for_task = state.clone();

    let outcome = rt.block_on(async move {
        let mode = mode_for_task;
        let state = state_for_task;
        let mut cfg = QuicConfig::default();
        cfg.max_idle_timeout = Duration::from_secs(idle_s);
        cfg.keep_alive_interval = Some(Duration::from_millis(keepalive_ms));

        let mut svc = ServiceBuilder::default()
            .forever(true)
            .handshake_type(key.into())
            .quic_config(cfg)
            .max_frame_length(max_frame)
            .insert_protocol(proto_meta(state.clone()))
            .build(Watcher(state.clone()));
        let control = svc.control().clone();

        // Pick a local outbound listen so the service drives.
        // For dial-only clients tentacle still needs the service running.
        let _ = svc
            .dial(server_addr.clone(), TargetProtocol::All)
            .await
            .map_err(|e| format!("dial failed: {e:?}"))?;

        let driver_state = state.clone();
        let driver_handle = tokio::spawn(async move {
            svc.run().await;
            log::info!("[client] service driver returned");
            let _ = driver_state;
        });

        // Wait for the protocol-open event.
        let connect_deadline = Instant::now() + Duration::from_secs(connect_timeout_s);
        while !state.connected.load(Ordering::Acquire) {
            if Instant::now() >= connect_deadline {
                return Err::<Duration, String>(format!(
                    "did not connect within {connect_timeout_s}s"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        println!("[driver] connected");

        let run_deadline = Instant::now() + Duration::from_secs(run_timeout_s);
        let started = Instant::now();

        match mode.as_str() {
            "latency" => {
                for _ in 0..count {
                    if Instant::now() > run_deadline {
                        break;
                    }
                    if !state.connected.load(Ordering::Acquire) {
                        break;
                    }
                    let msg = make_payload(payload, now_ns());
                    if control
                        .filter_broadcast(TargetSession::All, PROTO_ID, msg)
                        .await
                        .is_ok()
                    {
                        state.sent.fetch_add(1, Ordering::Relaxed);
                    }
                    tokio::time::sleep(Duration::from_millis(period_ms)).await;
                }
                // Wait briefly for in-flight echoes.
                let drain_until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < drain_until {
                    if state.acked.load(Ordering::Relaxed) >= state.sent.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            "bulk" => {
                let size = bulk_size_mib * 1024 * 1024;
                for _ in 0..bulk_count {
                    if Instant::now() > run_deadline {
                        break;
                    }
                    let msg = make_payload(size, now_ns());
                    if control
                        .filter_broadcast(TargetSession::All, PROTO_ID, msg)
                        .await
                        .is_ok()
                    {
                        state.sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let drain_until = Instant::now() + Duration::from_secs(60);
                while Instant::now() < drain_until {
                    if state.acked.load(Ordering::Relaxed) >= state.sent.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
            "soak" => {
                let soak_deadline = Instant::now() + Duration::from_secs(soak_secs);
                let mut last_report = Instant::now();
                while Instant::now() < soak_deadline && Instant::now() < run_deadline {
                    if state.connected.load(Ordering::Acquire) {
                        let msg = make_payload(payload, now_ns());
                        if control
                            .filter_broadcast(TargetSession::All, PROTO_ID, msg)
                            .await
                            .is_ok()
                        {
                            state.sent.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if last_report.elapsed() >= Duration::from_secs(5) {
                        let sent = state.sent.load(Ordering::Relaxed);
                        let acked = state.acked.load(Ordering::Relaxed);
                        let disc = state.disconnects.load(Ordering::Relaxed);
                        println!(
                            "[soak] t={:>5.1}s sent={sent} acked={acked} disc={disc}",
                            started.elapsed().as_secs_f64()
                        );
                        last_report = Instant::now();
                    }
                    tokio::time::sleep(Duration::from_millis(soak_period_ms)).await;
                }
                let drain_until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < drain_until {
                    if state.acked.load(Ordering::Relaxed) >= state.sent.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            other => {
                return Err::<Duration, String>(format!(
                    "unknown QA_MODE={other:?} (expected latency|bulk|soak)"
                ));
            }
        }

        let elapsed = started.elapsed();
        state.shutting_down.store(true, Ordering::Release);
        let _ = control.shutdown().await;
        let _ = driver_handle.await;

        Ok::<_, String>(elapsed)
    });

    let elapsed = match outcome {
        Ok(e) => e,
        Err(msg) => {
            eprintln!("[FAIL] {msg}");
            return ExitCode::FAILURE;
        }
    };

    let sent = state.sent.load(Ordering::Relaxed);
    let acked = state.acked.load(Ordering::Relaxed);
    let disc = state.disconnects.load(Ordering::Relaxed);
    let recv_bytes = state.bulk_bytes_received.load(Ordering::Relaxed);
    let delivery = if sent == 0 {
        0.0
    } else {
        acked as f64 / sent as f64
    };

    let mut rtts = state.rtt_ns.lock().unwrap().clone();
    rtts.sort_unstable();
    let p50 = pct(&rtts, 0.50) as f64 / 1_000_000.0;
    let p95 = pct(&rtts, 0.95) as f64 / 1_000_000.0;
    let p99 = pct(&rtts, 0.99) as f64 / 1_000_000.0;

    println!(
        "sent={sent} acked={acked} delivery={:.3} disconnects={disc} elapsed={:.2}s",
        delivery,
        elapsed.as_secs_f64()
    );
    if !rtts.is_empty() {
        println!(
            "rtt samples={} p50={:.2}ms p95={:.2}ms p99={:.2}ms",
            rtts.len(),
            p50,
            p95,
            p99
        );
    }
    if mode == "bulk" {
        let mibs = recv_bytes as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64().max(0.001);
        println!("bulk_received={recv_bytes}B goodput={:.2} MiB/s", mibs);
    }

    // Verdict.
    let mut fail = false;
    if disc > 0 {
        println!("[fail] {disc} disconnect(s) during run");
        fail = true;
    }
    if delivery < min_delivery {
        println!("[fail] delivery {:.3} < min {:.3}", delivery, min_delivery);
        fail = true;
    }
    if max_p95_ms > 0 && p95 > max_p95_ms as f64 {
        println!("[fail] p95 {:.2}ms > cap {}ms", p95, max_p95_ms);
        fail = true;
    }
    if mode == "bulk" && min_bulk_mbps > 0.0 {
        let mibs = recv_bytes as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64().max(0.001);
        if mibs < min_bulk_mbps {
            println!(
                "[fail] bulk goodput {:.2} MiB/s < floor {:.2}",
                mibs, min_bulk_mbps
            );
            fail = true;
        }
    }

    if fail {
        println!("FAIL");
        ExitCode::FAILURE
    } else {
        println!("PASS");
        ExitCode::SUCCESS
    }
}
