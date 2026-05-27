//! QA example: peer-id-based dial deduplication over QUIC.
//!
//! Covers PR #435's second dedup path. The server binds two distinct UDP
//! sockets and therefore exposes the same peer_id under two different
//! `/ip4/.../udp/<port>/quic-v1/p2p/<pid>` addresses. The client calls
//! `dial(addr_a)` then `dial(addr_b)`. The second call addresses a DIFFERENT
//! multiaddr but the SAME peer; PR #435 added the `extract_peer_id` branch in
//! `Service::dial` that must suppress the second dial.
//!
//! Run:
//!     cargo run --example quic_qa_peer_id_dedup --features quic
//!
//! Exits 0 iff the server observes exactly one protocol connection during the
//! grace window.

use std::{
    process::ExitCode,
    sync::{
        Arc, Mutex,
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
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    multiaddr::Multiaddr,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, TargetProtocol},
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

struct QuietClient {
    connected_tx: mpsc::Sender<Multiaddr>,
}

#[async_trait]
impl ServiceProtocol for QuietClient {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        println!("[client] connected to {}", ctx.session.address);
        let _ = self.connected_tx.send(ctx.session.address.clone());
    }
}

fn client_meta(id: ProtocolId, connected_tx: mpsc::Sender<Multiaddr>) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(QuietClient {
                connected_tx: connected_tx.clone(),
            }))
        })
        .build()
}

struct ErrorReporter {
    error_tx: Mutex<Option<mpsc::Sender<String>>>,
}

#[async_trait]
impl ServiceHandle for ErrorReporter {
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, error: ServiceError) {
        let summary = format!("{error:?}");
        println!("[client] service error: {summary}");
        if let Some(tx) = self.error_tx.lock().unwrap().take() {
            let _ = tx.send(summary);
        }
    }

    async fn handle_event(&mut self, _ctx: &mut ServiceContext, _event: ServiceEvent) {}
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
    let (addr_tx, addr_rx) = oneshot::channel::<(Multiaddr, Multiaddr)>();
    let (connected_tx, connected_rx) = mpsc::channel::<usize>();
    let connection_count = Arc::new(AtomicUsize::new(0));

    let server_count = connection_count.clone();
    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = server_meta(1.into(), server_count, connected_tx);
        let mut svc = build_service(server_key, meta, ());
        rt.block_on(async move {
            let listen_a = svc
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("listen quic A");
            let listen_b = svc
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("listen quic B");
            println!("[server] listening on A={listen_a}");
            println!("[server] listening on B={listen_b}");
            let _ = addr_tx.send((listen_a, listen_b));
            svc.run().await
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (listen_a, listen_b) =
        match rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), addr_rx).await }) {
            Ok(Ok(pair)) => pair,
            other => {
                println!("FAIL — server did not publish listen addresses: {other:?}");
                return ExitCode::from(1);
            }
        };
    if listen_a == listen_b {
        println!("FAIL — server bound the same address twice; cannot test peer dedup");
        return ExitCode::from(1);
    }

    let pid_s = server_pid.to_base58();
    let dial_a: Multiaddr = format!("{listen_a}/p2p/{pid_s}").parse().unwrap();
    let dial_b: Multiaddr = format!("{listen_b}/p2p/{pid_s}").parse().unwrap();
    println!("[driver] dial_a = {dial_a}");
    println!("[driver] dial_b = {dial_b}");

    let (client_connected_tx, client_connected_rx) = mpsc::channel::<Multiaddr>();
    let (client_error_tx, client_error_rx) = mpsc::channel::<String>();
    let expected_client_addr = dial_a.clone();

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = ErrorReporter {
            error_tx: Mutex::new(Some(client_error_tx)),
        };
        let mut svc = build_service(
            SecioKeyPair::secp256k1_generated(),
            client_meta(1.into(), client_connected_tx),
            handle,
        );
        rt.block_on(async move {
            svc.dial(dial_a, TargetProtocol::All)
                .await
                .expect("first dial");
            svc.dial(dial_b, TargetProtocol::All)
                .await
                .expect("second dial to same peer should be accepted as no-op");
            svc.run().await
        });
    });

    let first = connected_rx.recv_timeout(Duration::from_secs(10));
    let client_connected = client_connected_rx.recv_timeout(Duration::from_secs(10));
    let second = connected_rx.recv_timeout(Duration::from_secs(5));
    let client_error = client_error_rx
        .recv_timeout(Duration::from_millis(100))
        .ok();
    let observed = connection_count.load(Ordering::SeqCst);

    println!("\n──────────── summary ────────────");
    println!("  first connection observed: {}", first.is_ok());
    println!(
        "  client connected to first dial address: {}",
        client_connected
            .as_ref()
            .map(|addr| addr == &expected_client_addr)
            .unwrap_or(false)
    );
    println!(
        "  second connection during grace window: {}",
        second.is_ok()
    );
    println!(
        "  client service error observed: {}",
        client_error.is_some()
    );
    println!("  server connection count: {observed}");
    println!("─────────────────────────────────");

    if let Some(error) = client_error {
        println!("FAIL — second dial was not silently suppressed; client saw error: {error}");
        return ExitCode::from(1);
    }

    let client_connected_to_first = client_connected
        .as_ref()
        .map(|addr| addr == &expected_client_addr)
        .unwrap_or(false);

    if first.is_ok() && client_connected_to_first && second.is_err() && observed == 1 {
        println!("PASS — peer-id-based dial dedup suppressed the second QUIC dial.");
        ExitCode::SUCCESS
    } else {
        println!("FAIL — peer-id-based dedup did not prevent a duplicate session.");
        ExitCode::from(1)
    }
}
