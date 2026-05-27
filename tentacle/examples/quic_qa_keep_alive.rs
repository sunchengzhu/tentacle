//! QA example: client-side `keep_alive_interval` keeps QUIC session alive.
//!
//! Counterpart to `quic_qa_idle_timeout`. Same topology, same silence on the
//! application layer, but the client sets `keep_alive_interval = Some(1s)`
//! while still having `max_idle_timeout = 3s`. PR #435 fix #2 requires
//! `build_quinn_client_config` to apply BOTH knobs from `QuicConfig` (not
//! only the idle timeout). If keep-alive is honored, the session must stay
//! up well past the 3s idle timeout.
//!
//! Run:
//!     cargo run --example quic_qa_keep_alive --features quic
//!
//! Exits 0 iff NO disconnect is observed within a 10s grace window.

use std::{
    process::ExitCode,
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
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

struct ClientProto {
    at: Mutex<Option<Instant>>,
    connected_tx: Mutex<Option<mpsc::Sender<Multiaddr>>>,
    disconnect_tx: Mutex<Option<mpsc::Sender<Duration>>>,
}

#[async_trait]
impl ServiceProtocol for ClientProto {
    async fn init(&mut self, _: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _v: &str) {
        *self.at.lock().unwrap() = Some(Instant::now());
        println!(
            "[client] connected to {} — going silent, keep-alive PINGs should hold session",
            ctx.session.address
        );
        if let Some(tx) = self.connected_tx.lock().unwrap().take() {
            let _ = tx.send(ctx.session.address.clone());
        }
    }

    async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
        let elapsed = self
            .at
            .lock()
            .unwrap()
            .map(|t| t.elapsed())
            .unwrap_or_default();
        println!("[client] UNEXPECTED disconnect after {elapsed:?}");
        if let Some(tx) = self.disconnect_tx.lock().unwrap().take() {
            let _ = tx.send(elapsed);
        }
    }
}

fn client_meta(
    id: ProtocolId,
    connected_tx: mpsc::Sender<Multiaddr>,
    disconnect_tx: mpsc::Sender<Duration>,
) -> ProtocolMeta {
    let connected = Mutex::new(Some(connected_tx));
    let disconnected = Mutex::new(Some(disconnect_tx));
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ClientProto {
                at: Mutex::new(None),
                connected_tx: Mutex::new(connected.lock().unwrap().take()),
                disconnect_tx: Mutex::new(disconnected.lock().unwrap().take()),
            }))
        })
        .build()
}

fn silent_server_meta(id: ProtocolId) -> ProtocolMeta {
    struct Silent;
    #[async_trait]
    impl tentacle::traits::ServiceProtocol for Silent {
        async fn init(&mut self, _: &mut ProtocolContext) {}
        async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _v: &str) {
            println!("[server] connected from {}", ctx.session.address);
        }
        async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
            println!("[server] disconnected");
        }
    }
    MetaBuilder::new()
        .id(id)
        .service_handle(|| ProtocolHandle::Callback(Box::new(Silent)))
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

fn build<H>(
    key: SecioKeyPair,
    meta: ProtocolMeta,
    cfg: QuicConfig,
    h: H,
) -> Service<H, SecioKeyPair>
where
    H: ServiceHandle + Unpin + 'static,
{
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true)
        .handshake_type(key.into())
        .quic_config(cfg)
        .build(h)
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let server_key = SecioKeyPair::secp256k1_generated();
    let server_pid = server_key.peer_id();
    let (addr_tx, addr_rx) = oneshot::channel::<Multiaddr>();

    // Server: silent + no keep-alive — relies on client PINGs to stay alive.
    let server_cfg = QuicConfig {
        keep_alive_interval: None,
        ..QuicConfig::default()
    };

    let _server = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut svc = build(server_key, silent_server_meta(1.into()), server_cfg, ());
        rt.block_on(async move {
            let listen = svc
                .listen("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .await
                .expect("listen quic");
            let _ = addr_tx.send(listen);
            svc.run().await
        });
    });

    let (connected_tx, connected_rx) = mpsc::channel::<Multiaddr>();
    let (disc_tx, disc_rx) = mpsc::channel::<Duration>();
    let (error_tx, error_rx) = mpsc::channel::<String>();
    let client_meta = client_meta(1.into(), connected_tx, disc_tx);

    // Client: 3s idle timeout BUT 1s keep-alive. If PR #435 applied
    // `keep_alive_interval` to the client config, PINGs every 1s keep the
    // session well past the 3s idle timeout.
    let client_cfg = QuicConfig {
        max_idle_timeout: Duration::from_secs(3),
        keep_alive_interval: Some(Duration::from_secs(1)),
        ..QuicConfig::default()
    };

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = ErrorReporter {
            error_tx: Mutex::new(Some(error_tx)),
        };
        let mut svc = build(
            SecioKeyPair::secp256k1_generated(),
            client_meta,
            client_cfg,
            handle,
        );
        rt.block_on(async move {
            let listen_addr = addr_rx.await.unwrap();
            let dial: Multiaddr = format!("{}/p2p/{}", listen_addr, server_pid.to_base58())
                .parse()
                .unwrap();
            svc.dial(dial, TargetProtocol::All).await.expect("dial");
            svc.run().await
        });
    });

    let connected_addr = match connected_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(addr) => addr,
        Err(err) => {
            let service_error = error_rx.try_recv().ok();
            println!("\n──────────── summary ────────────");
            println!("FAIL — client never reached connected(): {err}");
            if let Some(error) = service_error {
                println!("  service error: {error}");
            }
            return ExitCode::from(1);
        }
    };
    println!("[driver] confirmed client connected to {connected_addr}");

    // Wait 10 seconds after a confirmed connection. We WANT this window to pass
    // without disconnects or service errors.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(elapsed) = disc_rx.try_recv() {
            println!("\n──────────── summary ────────────");
            println!(
                "FAIL — disconnect after {elapsed:?}; client `keep_alive_interval` was \
                 NOT honored. PR #435 fix #2 may be incomplete."
            );
            return ExitCode::from(1);
        }
        if let Ok(error) = error_rx.try_recv() {
            println!("\n──────────── summary ────────────");
            println!("FAIL — service error while waiting for keep-alive window: {error}");
            return ExitCode::from(1);
        }
        thread::sleep(Duration::from_millis(50));
    }

    println!("\n──────────── summary ────────────");
    println!(
        "PASS — confirmed connected, then no disconnect/service error within 10s; \
         client keep_alive_interval kept the session alive past max_idle_timeout(3s)."
    );
    ExitCode::SUCCESS
}
