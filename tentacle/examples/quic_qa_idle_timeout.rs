//! QA example: verify that `QuicConfig` is applied symmetrically to BOTH
//! server-side AND client-side (PR #435 fix: `build_quinn_client_config`
//! now mirrors `build_quinn_server_config`).
//!
//! Scenario:
//!   - server listens on a QUIC endpoint with `keep_alive_interval = None`
//!     (so it will not send PINGs).
//!   - client dials with `QuicConfig { max_idle_timeout: 3s,
//!                                     keep_alive_interval: None, .. }`.
//!   - neither side sends application data after `connected`.
//!   - **Expected:** client observes session disconnect within ~3–6 seconds.
//!     If PR 5 fix #2 were not applied, the client would fall back to the
//!     default 30s idle timeout and this example would hang ~30s before
//!     disconnecting (or never, with default 10s keep-alive on the client
//!     side actually keeping the connection alive forever).
//!
//! Run:
//!     cargo run --example quic_qa_idle_timeout --features quic
//!
//! Exits 0 iff the disconnect arrives between 2s and 10s.

use std::{
    process::ExitCode,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
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
    traits::ServiceHandle,
};

struct ConnectedAt {
    at: Mutex<Option<Instant>>,
    disconnect_tx: Mutex<Option<oneshot::Sender<Duration>>>,
}

#[async_trait]
impl tentacle::traits::ServiceProtocol for ConnectedAt {
    async fn init(&mut self, _: &mut ProtocolContext) {}

    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _v: &str) {
        *self.at.lock().unwrap() = Some(Instant::now());
        println!(
            "[client] connected to {} — going silent, expecting idle timeout ~3s",
            ctx.session.address
        );
    }

    async fn disconnected(&mut self, _ctx: ProtocolContextMutRef<'_>) {
        let elapsed = self
            .at
            .lock()
            .unwrap()
            .map(|t| t.elapsed())
            .unwrap_or_default();
        println!("[client] disconnected after {elapsed:?}");
        if let Some(tx) = self.disconnect_tx.lock().unwrap().take() {
            let _ = tx.send(elapsed);
        }
    }
}

fn proto_meta_silent(id: ProtocolId, disconnect_tx: oneshot::Sender<Duration>) -> ProtocolMeta {
    let tx = Mutex::new(Some(disconnect_tx));
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            ProtocolHandle::Callback(Box::new(ConnectedAt {
                at: Mutex::new(None),
                disconnect_tx: Mutex::new(tx.lock().unwrap().take()),
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

    // Server: keep-alive disabled so it stays completely silent.
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

    let (disc_tx, disc_rx) = oneshot::channel::<Duration>();
    let client_meta = proto_meta_silent(1.into(), disc_tx);

    // Client: tight idle timeout, no keep-alive. Drives PR 5 fix #2.
    let client_cfg = QuicConfig {
        max_idle_timeout: Duration::from_secs(3),
        keep_alive_interval: None,
        ..QuicConfig::default()
    };

    let _client = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut svc = build(
            SecioKeyPair::secp256k1_generated(),
            client_meta,
            client_cfg,
            (),
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

    let rt = tokio::runtime::Runtime::new().unwrap();
    let outcome =
        rt.block_on(async move { tokio::time::timeout(Duration::from_secs(15), disc_rx).await });

    println!("\n──────────── summary ────────────");
    match outcome {
        Ok(Ok(elapsed)) => {
            let low = Duration::from_secs(2);
            let high = Duration::from_secs(10);
            if elapsed >= low && elapsed <= high {
                println!(
                    "PASS — client-side QuicConfig honored: disconnect after {elapsed:?} \
                     (expected window {low:?}..{high:?})."
                );
                ExitCode::SUCCESS
            } else {
                println!(
                    "FAIL — disconnect occurred at {elapsed:?}, outside expected window \
                     {low:?}..{high:?}. Client QuicConfig may not be applied symmetrically."
                );
                ExitCode::from(1)
            }
        }
        Ok(Err(_canceled)) => {
            println!("FAIL — disconnect channel canceled before signal.");
            ExitCode::from(1)
        }
        Err(_) => {
            println!(
                "FAIL — no disconnect within 15s. If PR 5 fix #2 were reverted, \
                 the default 30s idle timeout would explain this. Investigate \
                 `build_quinn_client_config` in tentacle/src/quic/."
            );
            ExitCode::from(1)
        }
    }
}
