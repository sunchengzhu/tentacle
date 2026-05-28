//! Real-WAN QUIC/TCP echo server.
//!
//! Designed to run on a remote machine (e.g. an EC2 instance) so a peer in a
//! different region can dial it over the public internet. This is the
//! companion to `qa_wan_client`. Together they replace the in-process UDP
//! relay used by `qa_quic_wan_stability` with an actual cross-region link.
//!
//! Listens on a fixed UDP+TCP port (so security-group / firewall rules are
//! easy). Echoes every byte received on protocol id 1. Runs forever.
//!
//! Env overrides:
//!   QA_LISTEN_HOST       default 0.0.0.0
//!   QA_LISTEN_PORT       default 9443       (same port used for UDP+TCP)
//!   QA_TRANSPORT         default both       (quic | tcp | both)
//!   QA_ADVERTISE_HOST    default <listen>   (printed in the dial string;
//!                                            set to the instance's public IP)
//!   QA_SERVER_SEED       default random     (32-byte hex; fixes the PeerId
//!                                            so client config can be reused)
//!   QA_IDLE_TIMEOUT_S    default 60
//!   QA_KEEPALIVE_MS      default 5000
//!   QA_MAX_FRAME_MIB     default 16

use std::{process::ExitCode, sync::Arc, time::Duration};

use bytes::Bytes;
use quic_transport_qa::env;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent},
    traits::{ServiceHandle, ServiceProtocol},
};

const PROTO_ID: ProtocolId = ProtocolId::new(1);

struct Echo;
#[async_trait]
impl ServiceProtocol for Echo {
    async fn init(&mut self, _ctx: &mut ProtocolContext) {}
    async fn connected(&mut self, ctx: ProtocolContextMutRef<'_>, _ver: &str) {
        log::info!(
            "[server] session {} connected from {}",
            ctx.session.id,
            ctx.session.address
        );
    }
    async fn disconnected(&mut self, ctx: ProtocolContextMutRef<'_>) {
        log::info!("[server] session {} disconnected", ctx.session.id);
    }
    async fn received(&mut self, ctx: ProtocolContextMutRef<'_>, data: Bytes) {
        // Echo back on the same protocol; this lets the client measure RTT.
        let _ = ctx.send_message(data).await;
    }
}

fn echo_meta() -> ProtocolMeta {
    MetaBuilder::new()
        .id(PROTO_ID)
        .service_handle(|| ProtocolHandle::Callback(Box::new(Echo)))
        .build()
}

struct Logger;
#[async_trait]
impl ServiceHandle for Logger {
    async fn handle_error(&mut self, _ctx: &mut ServiceContext, err: ServiceError) {
        log::warn!("[server] service error: {err:?}");
    }
    async fn handle_event(&mut self, _ctx: &mut ServiceContext, ev: ServiceEvent) {
        log::info!("[server] service event: {ev:?}");
    }
}

fn parse_seed(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let host: String = env::env_or("QA_LISTEN_HOST", "0.0.0.0".to_string());
    let port: u16 = env::env_or("QA_LISTEN_PORT", 9443u16);
    let transport: String = env::env_or("QA_TRANSPORT", "both".to_string());
    let advertise: String = env::env_or("QA_ADVERTISE_HOST", host.clone());
    let idle_s: u64 = env::env_or("QA_IDLE_TIMEOUT_S", 60u64);
    let keepalive_ms: u64 = env::env_or("QA_KEEPALIVE_MS", 5000u64);
    let max_frame_mib: usize = env::env_or("QA_MAX_FRAME_MIB", 16usize);
    let max_frame = max_frame_mib * 1024 * 1024;

    let key = match std::env::var("QA_SERVER_SEED")
        .ok()
        .and_then(|s| parse_seed(&s))
    {
        Some(seed) => SecioKeyPair::secp256k1_raw_key(seed).expect("invalid QA_SERVER_SEED bytes"),
        None => SecioKeyPair::secp256k1_generated(),
    };
    let peer_id = key.peer_id();

    println!(
        "[server] listen_host={host} advertise_host={advertise} port={port} transport={transport}"
    );
    println!("[server] peer_id = {}", peer_id.to_base58());

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[server] failed to build runtime: {e:?}");
            return ExitCode::FAILURE;
        }
    };

    rt.block_on(async move {
        let mut cfg = QuicConfig::default();
        cfg.max_idle_timeout = Duration::from_secs(idle_s);
        cfg.keep_alive_interval = Some(Duration::from_millis(keepalive_ms));

        let mut svc = ServiceBuilder::default()
            .forever(true)
            .handshake_type(key.into())
            .quic_config(cfg)
            .max_frame_length(max_frame)
            .insert_protocol(echo_meta())
            .build(Logger);

        let want_tcp = matches!(transport.as_str(), "tcp" | "both");
        let want_quic = matches!(transport.as_str(), "quic" | "both");

        if want_quic {
            let listen = format!("/ip4/{}/udp/{}/quic-v1", host, port);
            match svc
                .listen(listen.parse().expect("bad listen multiaddr"))
                .await
            {
                Ok(real) => {
                    let dial = format!(
                        "/ip4/{}/udp/{}/quic-v1/p2p/{}",
                        advertise,
                        port,
                        peer_id.to_base58()
                    );
                    println!("[server] QUIC listening on {real}");
                    println!("[server] QUIC dial me at: {dial}");
                }
                Err(e) => {
                    eprintln!("[server] QUIC listen failed: {e:?}");
                    return ExitCode::FAILURE;
                }
            }
        }
        if want_tcp {
            let listen = format!("/ip4/{}/tcp/{}", host, port);
            match svc
                .listen(listen.parse().expect("bad listen multiaddr"))
                .await
            {
                Ok(real) => {
                    let dial = format!(
                        "/ip4/{}/tcp/{}/p2p/{}",
                        advertise,
                        port,
                        peer_id.to_base58()
                    );
                    println!("[server] TCP listening on {real}");
                    println!("[server] TCP dial me at: {dial}");
                }
                Err(e) => {
                    eprintln!("[server] TCP listen failed: {e:?}");
                    return ExitCode::FAILURE;
                }
            }
        }

        println!("[server] running. Ctrl-C to stop.");
        let _hold = Arc::new(()); // keep main task alive
        svc.run().await;
        ExitCode::SUCCESS
    })
}
