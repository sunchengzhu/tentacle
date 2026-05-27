//! QA example: a failed QUIC handshake must not kill the listener.
//!
//! Covers PR #435's accept-loop regression fix. One client first dials the
//! server with a deliberately wrong `/p2p/<peer_id>` pin, forcing the QUIC TLS
//! verifier to reject the handshake. A second client then dials the same
//! listener with the correct PeerId and must complete a normal protocol
//! ping/pong.
//!
//! Run:
//!     cargo run --example quic_qa_listener_survives_bad_handshake --features quic
//!
//! Exits 0 iff the bad dial reports an error and the later good dial succeeds.

use std::{
    process::ExitCode,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

use bytes::Bytes;
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

const GOOD_MESSAGE: &[u8] = b"ping-after-bad-handshake";

struct EchoServer;

#[async_trait]
impl ServiceProtocol for EchoServer {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        println!(
            "[server] accepted healthy session from {}",
            ctx.session.address
        );
    }

    async fn received(&mut self, ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        let _ = ctx.send_message(data).await;
    }
}

fn server_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(|| ProtocolHandle::Callback(Box::new(EchoServer)))
        .build()
}

struct PingClient {
    done_tx: Mutex<Option<mpsc::Sender<()>>>,
}

#[async_trait]
impl ServiceProtocol for PingClient {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _version: &str) {
        println!("[good-client] connected to {}", ctx.session.address);
        let _ = ctx.send_message(Bytes::from_static(GOOD_MESSAGE)).await;
    }

    async fn received(&mut self, _ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        println!("[good-client] received echo: {:?}", data);
        if data.as_ref() == GOOD_MESSAGE {
            if let Some(tx) = self.done_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        } else {
            println!(
                "[good-client] unexpected echo payload; expected {:?}",
                GOOD_MESSAGE
            );
        }
    }
}

fn good_client_meta(id: ProtocolId, done_tx: mpsc::Sender<()>) -> ProtocolMeta {
    let tx = Arc::new(Mutex::new(Some(done_tx)));
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(PingClient {
                done_tx: Mutex::new(tx.lock().unwrap().take()),
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
        println!("[bad-client] observed expected service error: {summary}");
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
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut svc = build_service(server_key, server_meta(1.into()), ());
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

    let wrong_pid = SecioKeyPair::secp256k1_generated().peer_id();
    let bad_dial: Multiaddr = format!("{}/p2p/{}", listen_addr, wrong_pid.to_base58())
        .parse()
        .unwrap();
    let (bad_error_tx, bad_error_rx) = mpsc::channel::<String>();

    let _bad_client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = ErrorReporter {
            error_tx: Mutex::new(Some(bad_error_tx)),
        };
        let mut svc = build_service(
            SecioKeyPair::secp256k1_generated(),
            server_meta(1.into()),
            handle,
        );
        rt.block_on(async move {
            svc.dial(bad_dial, TargetProtocol::All)
                .await
                .expect("bad dial should be queued, then fail asynchronously");
            svc.run().await
        });
    });

    let bad_error = match bad_error_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(summary) => summary,
        Err(err) => {
            println!("FAIL — bad client did not surface handshake error: {err}");
            return ExitCode::from(1);
        }
    };
    let bad_error_matches = bad_error.contains("QuicError")
        && bad_error.contains("expected peer_id")
        && bad_error.contains("got ");

    let good_dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
        .parse()
        .unwrap();
    let (good_done_tx, good_done_rx) = mpsc::channel::<()>();

    let _good_client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let meta = good_client_meta(1.into(), good_done_tx);
        let mut svc = build_service(SecioKeyPair::secp256k1_generated(), meta, ());
        rt.block_on(async move {
            svc.dial(good_dial, TargetProtocol::All)
                .await
                .expect("good dial");
            svc.run().await
        });
    });

    let good_ok = good_done_rx.recv_timeout(Duration::from_secs(10)).is_ok();

    println!("\n──────────── summary ────────────");
    println!("  bad handshake produced PeerId mismatch: {bad_error_matches}");
    println!("  good dial after bad handshake completed ping/pong: {good_ok}");
    println!("─────────────────────────────────");

    if bad_error_matches && good_ok {
        println!("PASS — listener survived a failed QUIC handshake.");
        ExitCode::SUCCESS
    } else {
        println!("FAIL — listener did not accept a healthy client after the bad handshake.");
        ExitCode::from(1)
    }
}
