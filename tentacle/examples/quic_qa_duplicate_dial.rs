//! QA example: exact duplicate QUIC dials are suppressed.
//!
//! Covers PR #435's duplicate-dial regression fix. The client calls
//! `Service::dial` twice with the same QUIC multiaddr before running the
//! service loop. The first call should enqueue the dial; the second should be
//! a no-op because the address is already in `dial_protocols`.
//!
//! Run:
//!     cargo run --example quic_qa_duplicate_dial --features quic
//!
//! Exits 0 iff the server observes exactly one protocol connection during the
//! grace window.

use std::{
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use futures::channel::oneshot;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::{ServiceHandle, ServiceProtocol},
};

struct CountingServer {
    count: Arc<AtomicUsize>,
    connected_tx: mpsc::Sender<usize>,
}

#[async_trait]
impl ServiceProtocol for CountingServer {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "[server] protocol connected #{n} from {}",
            ctx.session.address
        );
        let _ = self.connected_tx.send(n);
    }
}

fn server_meta(
    id: ProtocolId,
    count: Arc<AtomicUsize>,
    connected_tx: mpsc::Sender<usize>,
) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(CountingServer {
                count: count.clone(),
                connected_tx: connected_tx.clone(),
            }))
        })
        .build()
}

struct QuietClient;

#[async_trait]
impl ServiceProtocol for QuietClient {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        println!("[client] connected to {}", ctx.session.address);
    }
}

fn client_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(|| ProtocolHandle::Callback(Box::new(QuietClient)))
        .build()
}

fn build_service<H>(key: SecioKeyPair, meta: ProtocolMeta, handle: H) -> Service<H, SecioKeyPair>
where
    H: ServiceHandle + Unpin + 'static,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .handshake_type(key.into())
        .quic_config(QuicConfig::default())
        .build(handle)
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();
    let (connected_tx, connected_rx) = mpsc::channel::<usize>();
    let connection_count = Arc::new(AtomicUsize::new(0));

    let server_count = connection_count.clone();
    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = server_meta(1.into(), server_count, connected_tx);
        let mut svc = build_service(server_key, meta, ());
        rt.block_on(async move {
            let listen = svc
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("listen quic");
            println!("[server] listening on {listen}");
            let _ = addr_tx.send(listen);
            svc.run().await
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    let listen_addr =
        match rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), addr_rx).await }) {
            Ok(Ok(addr)) => addr,
            other => {
                println!("FAIL — server did not publish listen address: {other:?}");
                return ExitCode::from(1);
            }
        };

    let dial_addr: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
        .parse()
        .unwrap();

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut svc = build_service(
            SecioKeyPair::secp256k1_generated(),
            client_meta(1.into()),
            (),
        );
        rt.block_on(async move {
            svc.dial(dial_addr.clone(), TargetProtocol::All)
                .await
                .expect("first dial");
            svc.dial(dial_addr, TargetProtocol::All)
                .await
                .expect("duplicate dial should be accepted as no-op");
            svc.run().await
        });
    });

    let first = connected_rx.recv_timeout(Duration::from_secs(10));
    let second = connected_rx.recv_timeout(Duration::from_secs(5));
    let observed = connection_count.load(Ordering::SeqCst);

    println!("\n──────────── summary ────────────");
    println!("  first connection observed: {}", first.is_ok());
    println!(
        "  second connection during grace window: {}",
        second.is_ok()
    );
    println!("  server connection count: {observed}");
    println!("─────────────────────────────────");

    if first.is_ok() && second.is_err() && observed == 1 {
        println!("PASS — exact duplicate QUIC dial was suppressed.");
        ExitCode::SUCCESS
    } else {
        println!("FAIL — duplicate QUIC dial opened more than one session.");
        ExitCode::from(1)
    }
}
