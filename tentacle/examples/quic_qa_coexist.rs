//! QA example: TCP + QUIC coexistence within a single `Service`.
//!
//! Covers test analysis B1 / B7: enabling `quic_config` must NOT regress
//! the classic TCP path. The same `Service` listens on both
//! `/ip4/127.0.0.1/tcp/0` and `/ip4/127.0.0.1/udp/0/quic-v1` simultaneously,
//! and two independent clients (one TCP, one QUIC) connect and exchange
//! a ping/pong over the same protocol. The server's `SessionContext.address`
//! is inspected to verify each client landed on its expected transport.
//!
//! Run:
//!     cargo run --example quic_qa_coexist --features quic
//!
//! Exits 0 on success, 1 on timeout/transport mismatch.

use std::{
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use bytes::Bytes;
use futures::channel::oneshot;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::{Multiaddr, Protocol},
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol},
    traits::ServiceProtocol,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Tcp,
    Quic,
    Other,
}

fn classify(addr: &Multiaddr) -> Transport {
    let mut has_tcp = false;
    let mut has_quic = false;
    for p in addr.iter() {
        match p {
            Protocol::Tcp(_) => has_tcp = true,
            Protocol::QuicV1 => has_quic = true,
            _ => {}
        }
    }
    match (has_tcp, has_quic) {
        (_, true) => Transport::Quic,
        (true, false) => Transport::Tcp,
        _ => Transport::Other,
    }
}

// ─────────────── server protocol: classify + echo, signal on both ───────────────

struct ServerProto {
    saw_tcp: Arc<AtomicBool>,
    saw_quic: Arc<AtomicBool>,
    done_tx: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait]
impl ServiceProtocol for ServerProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        let kind = classify(&ctx.session.address);
        match kind {
            Transport::Tcp => {
                self.saw_tcp.store(true, Ordering::SeqCst);
                println!("[server] connected over TCP  : {}", ctx.session.address);
            }
            Transport::Quic => {
                self.saw_quic.store(true, Ordering::SeqCst);
                println!("[server] connected over QUIC : {}", ctx.session.address);
            }
            Transport::Other => {
                println!("[server] connected over OTHER: {}", ctx.session.address);
            }
        }
        if self.saw_tcp.load(Ordering::SeqCst) && self.saw_quic.load(Ordering::SeqCst) {
            if let Some(tx) = self.done_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        }
    }

    async fn received(&mut self, ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let _ = ctx.send_message(data).await;
    }
}

fn server_meta(
    id: ProtocolId,
    saw_tcp: Arc<AtomicBool>,
    saw_quic: Arc<AtomicBool>,
    done_tx: oneshot::Sender<()>,
) -> ProtocolMeta {
    let done = std::sync::Mutex::new(Some(done_tx));
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ServerProto {
                saw_tcp: saw_tcp.clone(),
                saw_quic: saw_quic.clone(),
                done_tx: std::sync::Mutex::new(done.lock().unwrap().take()),
            }))
        })
        .build()
}

// ─────────────── client protocol: ping, expect echo, signal ───────────────

struct ClientProto {
    label: &'static str,
    done_tx: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        let label = self.label;
        println!("[client/{label}] connected to {}", ctx.session.address);
        let _ = ctx.send_message(Bytes::from_static(b"ping")).await;
    }

    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let label = self.label;
        println!(
            "[client/{label}] received {} bytes back: {:?}",
            data.len(),
            data
        );
        if let Some(tx) = self.done_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

fn client_meta(id: ProtocolId, label: &'static str, done_tx: oneshot::Sender<()>) -> ProtocolMeta {
    let done = std::sync::Mutex::new(Some(done_tx));
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ClientProto {
                label,
                done_tx: std::sync::Mutex::new(done.lock().unwrap().take()),
            }))
        })
        .build()
}

fn build_service<H>(key: SecioKeyPair, meta: ProtocolMeta, handle: H) -> Service<H, SecioKeyPair>
where
    H: tentacle::traits::ServiceHandle + Unpin + 'static,
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

    let saw_tcp = Arc::new(AtomicBool::new(false));
    let saw_quic = Arc::new(AtomicBool::new(false));
    let (server_done_tx, server_done_rx) = oneshot::channel::<()>();

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let meta = server_meta(1.into(), saw_tcp.clone(), saw_quic.clone(), server_done_tx);

    let (tcp_addr_tx, tcp_addr_rx) = oneshot::channel::<Multiaddr>();
    let (quic_addr_tx, quic_addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut svc = build_service(server_key, meta, ());
        rt.block_on(async move {
            let tcp = svc
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .expect("listen tcp");
            let quic = svc
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("listen quic");
            let _ = tcp_addr_tx.send(tcp);
            let _ = quic_addr_tx.send(quic);
            svc.run().await
        });
    });

    let (tcp_client_done_tx, tcp_client_done_rx) = oneshot::channel::<()>();
    let (quic_client_done_tx, quic_client_done_rx) = oneshot::channel::<()>();

    // TCP client
    let server_pid_tcp = server_pid.clone();
    let _tcp_client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = client_meta(1.into(), "tcp", tcp_client_done_tx);
        let mut svc = build_service(SecioKeyPair::secp256k1_generated(), meta, ());
        rt.block_on(async move {
            let listen_addr = tcp_addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid_tcp.to_base58())
                .parse()
                .unwrap();
            svc.dial(dial, TargetProtocol::All).await.expect("tcp dial");
            svc.run().await
        });
    });

    // QUIC client
    let server_pid_quic = server_pid.clone();
    let _quic_client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = client_meta(1.into(), "quic", quic_client_done_tx);
        let mut svc = build_service(SecioKeyPair::secp256k1_generated(), meta, ());
        rt.block_on(async move {
            let listen_addr = quic_addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid_quic.to_base58())
                .parse()
                .unwrap();
            svc.dial(dial, TargetProtocol::All)
                .await
                .expect("quic dial");
            svc.run().await
        });
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    let timeout = Duration::from_secs(20);
    let ok = rt.block_on(async move {
        let server_wait = tokio::time::timeout(timeout, server_done_rx);
        let tcp_wait = tokio::time::timeout(timeout, tcp_client_done_rx);
        let quic_wait = tokio::time::timeout(timeout, quic_client_done_rx);
        let (s, t, q) = tokio::join!(server_wait, tcp_wait, quic_wait);
        s.is_ok() && t.is_ok() && q.is_ok()
    });

    println!("\n──────────── summary ────────────");
    println!(
        "  server observed TCP  session: {}",
        saw_tcp.load(Ordering::SeqCst)
    );
    println!(
        "  server observed QUIC session: {}",
        saw_quic.load(Ordering::SeqCst)
    );
    println!("  all ping/pong completed within {timeout:?}: {ok}");
    println!("─────────────────────────────────");

    if ok && saw_tcp.load(Ordering::SeqCst) && saw_quic.load(Ordering::SeqCst) {
        println!("PASS — TCP and QUIC coexist within one Service.");
        ExitCode::SUCCESS
    } else {
        println!("FAIL — coexistence check did not complete cleanly.");
        ExitCode::from(1)
    }
}
