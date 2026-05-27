//! Shared service-build helper. Always enables QUIC; callers decide what to
//! `listen()` on.

use tentacle::{
    builder::ServiceBuilder,
    quic::config::QuicConfig,
    secio::SecioKeyPair,
    service::{ProtocolMeta, Service},
    traits::ServiceHandle,
};

pub fn build_quic_service<H>(
    key: SecioKeyPair,
    metas: Vec<ProtocolMeta>,
    handle: H,
    quic_cfg: QuicConfig,
) -> Service<H, SecioKeyPair>
where
    H: ServiceHandle + Unpin + 'static,
{
    let mut b = ServiceBuilder::default()
        .forever(true)
        .handshake_type(key.into())
        .quic_config(quic_cfg);
    for m in metas {
        b = b.insert_protocol(m);
    }
    b.build(handle)
}
