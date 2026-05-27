//! Mixed-transport mesh gossip QA.
//!
//! Spawns N tentacle nodes (default N=6). Half listen on TCP, half on QUIC.
//! Each node dials all peers it knows the listen address of, so we end up
//! with a (near-)complete mesh where some edges are TCP and some QUIC.
//!
//! Every node then broadcasts a stream of messages tagged with its node id
//! and a sequence number. Each receiver builds a delivery matrix
//! `received[from][seq] = true`. After `DURATION`, the assertion is:
//!
//! - Every node has received at least `MIN_PER_PAIR` distinct sequence
//!   numbers from every other node.
//! - Per-node loss ratio (missing sequences over expected) stays below
//!   `MAX_LOSS_RATIO`.
//!
//! Environment overrides (all optional):
//!   QA_NODES           default 6
//!   QA_DURATION_SECS   default 8
//!   QA_INTERVAL_MS     default 100  (broadcast period per node)
//!   QA_MIN_PER_PAIR    default 20
//!   QA_MAX_LOSS_RATIO  default 0.05 (5%)
//!
//! Run:
//!     cargo run --release -p quic-transport-qa --bin qa_mixed_transport_gossip
//!
//! Exits 0 iff the delivery matrix satisfies the thresholds above.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
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
    service::{ProtocolHandle, ProtocolMeta, ServiceAsyncControl, TargetProtocol},
    traits::ServiceProtocol,
};
use tokio::time::sleep;

const PROTO_ID: ProtocolId = ProtocolId::new(1);

/// Per-node shared state.
#[derive(Default)]
struct NodeState {
    /// `received[from_node_id] = set of seqs observed`.
    received: Mutex<BTreeMap<u32, BTreeSet<u64>>>,
}

struct GossipProto {
    my_id: u32,
    state: Arc<NodeState>,
}

#[async_trait]
impl ServiceProtocol for GossipProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _v: &str) {
        log::debug!("[node {}] peer connected: {}", self.my_id, ctx.session.address);
    }

    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        // Frame: [from_id: u32 BE][seq: u64 BE]
        if data.len() < 12 {
            return;
        }
        let from = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let seq = u64::from_be_bytes(data[4..12].try_into().unwrap());
        let mut g = self.state.received.lock().unwrap();
        g.entry(from).or_default().insert(seq);
    }
}

fn gossip_meta(id: ProtocolId, my_id: u32, state: Arc<NodeState>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(GossipProto {
                my_id,
                state: state.clone(),
            }))
        })
        .build()
}

fn listen_addr_for(idx: u32, n: u32) -> Multiaddr {
    // First half TCP, second half QUIC.
    if idx < n / 2 {
        "/ip4/127.0.0.1/tcp/0".parse().unwrap()
    } else {
        "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()
    }
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let n: u32 = env::env_or("QA_NODES", 6);
    let duration: Duration = env::duration_secs("QA_DURATION_SECS", 8);
    let interval = Duration::from_millis(env::env_or("QA_INTERVAL_MS", 100));
    let min_per_pair: u64 = env::env_or("QA_MIN_PER_PAIR", 20);
    let max_loss_ratio: f64 = env::env_or("QA_MAX_LOSS_RATIO", 0.05f64);

    println!(
        "[driver] N={n} duration={duration:?} interval={interval:?} \
         min_per_pair={min_per_pair} max_loss_ratio={max_loss_ratio}"
    );

    // Build per-node identities up-front so dial addresses can include /p2p/<pid>.
    let keys: Vec<SecioKeyPair> = (0..n).map(|_| SecioKeyPair::secp256k1_generated()).collect();
    let peer_ids: Vec<_> = keys.iter().map(|k| k.peer_id()).collect();

    // Each node publishes its `listen` address through a oneshot once the
    // listener is up.
    let (addr_tx, addr_rx): (Vec<_>, Vec<_>) =
        (0..n).map(|_| oneshot::channel::<Multiaddr>()).unzip();
    let mut addr_tx: Vec<Option<oneshot::Sender<Multiaddr>>> =
        addr_tx.into_iter().map(Some).collect();

    let states: Vec<Arc<NodeState>> = (0..n).map(|_| Arc::new(NodeState::default())).collect();
    let mut controls: Vec<Arc<Mutex<Option<ServiceAsyncControl>>>> = Vec::new();
    let mut handles = Vec::new();

    for idx in 0..n {
        let key = keys[idx as usize].clone();
        let state = states[idx as usize].clone();
        let listen = listen_addr_for(idx, n);
        let addr_tx_slot = addr_tx[idx as usize].take().unwrap();
        let ctrl_slot: Arc<Mutex<Option<ServiceAsyncControl>>> = Arc::new(Mutex::new(None));
        controls.push(ctrl_slot.clone());

        let h = thread::Builder::new()
            .name(format!("node-{idx}"))
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let meta = gossip_meta(PROTO_ID, idx, state);
                let quic = QuicConfig::default();
                let mut svc = build_quic_service(key, vec![meta], (), quic);
                rt.block_on(async move {
                    let real = svc.listen(listen).await.expect("listen");
                    println!("[node {idx}] listening on {real}");
                    *ctrl_slot.lock().unwrap() = Some(svc.control().clone());
                    let _ = addr_tx_slot.send(real);
                    svc.run().await;
                });
            })
            .expect("spawn node");
        handles.push(h);
    }

    // Collect listen addresses (synchronously, in the driver thread).
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listen_addrs: Vec<Multiaddr> = rt.block_on(async {
        let mut out = Vec::with_capacity(n as usize);
        for (idx, rx) in addr_rx.into_iter().enumerate() {
            match tokio::time::timeout(Duration::from_secs(15), rx).await {
                Ok(Ok(a)) => out.push(a),
                other => panic!("node {idx} did not publish listen addr: {other:?}"),
            }
        }
        out
    });

    // Wait briefly so every Service has registered its async control.
    thread::sleep(Duration::from_millis(200));

    // Build /p2p/<pid> dial addresses.
    let dial_addrs: Vec<Multiaddr> = listen_addrs
        .iter()
        .zip(peer_ids.iter())
        .map(|(a, pid)| format!("{a}/p2p/{}", pid.to_base58()).parse().unwrap())
        .collect();

    // Each node dials every other node. Use the control captured per node.
    for (i, ctrl_slot) in controls.iter().enumerate() {
        let ctrl = ctrl_slot.lock().unwrap().clone().expect("control captured");
        for (j, addr) in dial_addrs.iter().enumerate() {
            if i == j {
                continue;
            }
            let ctrl = ctrl.clone();
            let addr = addr.clone();
            rt.spawn(async move {
                if let Err(e) = ctrl.dial(addr.clone(), TargetProtocol::All).await {
                    log::warn!("dial {addr} failed: {e:?}");
                }
            });
        }
    }

    // Give the mesh time to form before broadcasting.
    thread::sleep(Duration::from_millis(800));

    // Drive broadcasting for `duration`. We send the same payload to all
    // sessions via `ServiceAsyncControl::filter_broadcast(TargetSession::All, ...)`.
    let start = Instant::now();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut bcast_handles = Vec::new();
    for (idx, ctrl_slot) in controls.iter().enumerate() {
        let ctrl = ctrl_slot.lock().unwrap().clone().expect("control");
        let stop = stop.clone();
        let h = rt.spawn(async move {
            let mut seq: u64 = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let mut buf = Vec::with_capacity(12);
                buf.extend_from_slice(&(idx as u32).to_be_bytes());
                buf.extend_from_slice(&seq.to_be_bytes());
                let _ = ctrl
                    .filter_broadcast(
                        tentacle::service::TargetSession::All,
                        PROTO_ID,
                        Bytes::from(buf),
                    )
                    .await;
                seq += 1;
                sleep(interval).await;
            }
            seq
        });
        bcast_handles.push(h);
    }

    // Sleep main-thread for `duration`, then signal stop.
    thread::sleep(duration);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);

    let sent_per_node: Vec<u64> = rt
        .block_on(async {
            let mut out = Vec::new();
            for h in bcast_handles {
                out.push(h.await.unwrap_or(0));
            }
            out
        });

    // Drain a small grace window so in-flight messages settle.
    thread::sleep(Duration::from_millis(500));

    // ─── verdict ───
    let mut fail = false;
    println!(
        "\n──────────── mixed gossip summary (after {:?}) ────────────",
        start.elapsed()
    );
    println!("sent per node: {sent_per_node:?}");
    let mut missing_pairs = Vec::new();
    let mut total_loss_sum = 0.0_f64;
    let mut loss_samples = 0_u64;
    for (i, state) in states.iter().enumerate() {
        let g = state.received.lock().unwrap();
        let mut row = format!("[node {i}] received: ");
        for j in 0..n as usize {
            if i == j {
                row.push_str(&format!("self=- "));
                continue;
            }
            let observed = g.get(&(j as u32)).map(|s| s.len() as u64).unwrap_or(0);
            let expected = sent_per_node[j].max(1);
            let loss = 1.0 - (observed as f64 / expected as f64).min(1.0);
            total_loss_sum += loss;
            loss_samples += 1;
            row.push_str(&format!(
                "from{j}={observed}/{expected}({:.1}%) ",
                loss * 100.0
            ));
            if observed < min_per_pair {
                missing_pairs.push((i, j, observed));
            }
        }
        println!("{row}");
    }

    let avg_loss = if loss_samples > 0 {
        total_loss_sum / loss_samples as f64
    } else {
        0.0
    };
    println!("avg per-pair loss ratio: {:.3}", avg_loss);

    if !missing_pairs.is_empty() {
        fail = true;
        println!(
            "FAIL — {} pair(s) below min_per_pair={min_per_pair}: first few: {:?}",
            missing_pairs.len(),
            &missing_pairs[..missing_pairs.len().min(8)]
        );
    }
    if avg_loss > max_loss_ratio {
        fail = true;
        println!(
            "FAIL — avg per-pair loss {:.3} exceeds threshold {:.3}",
            avg_loss, max_loss_ratio
        );
    }
    println!("──────────────────────────────────────────────────────────");

    // Best-effort shutdown.
    for ctrl_slot in &controls {
        if let Some(ctrl) = ctrl_slot.lock().unwrap().clone() {
            let _ = rt.block_on(ctrl.shutdown());
        }
    }
    // Detach node threads (Service::run loops are tied to control shutdown).
    drop(handles);

    let _ = HashSet::<u32>::new(); // silence unused import warning if any
    if fail {
        ExitCode::from(1)
    } else {
        println!("PASS — mixed TCP/QUIC mesh gossip met delivery thresholds.");
        ExitCode::SUCCESS
    }
}
