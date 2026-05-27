//! QA example: error contracts introduced by PR #435.
//!
//! Verifies that the four distinct (HandshakeType, quic_config) combinations
//! surface the precise error variants documented in the PR description:
//!
//! | Case | HandshakeType | quic_config | Action                         | Expected                                  |
//! |------|---------------|-------------|--------------------------------|-------------------------------------------|
//! | C1   | Noop          | absent      | dial /quic-v1                  | `TransportErrorKind::NotSupported`        |
//! | C2   | Secio         | absent      | dial /quic-v1                  | `QuicError(NotConfigured)` + hint text    |
//! | C3   | Noop          | present     | build Service                  | endpoint records `Misconfigured`; dial -> `QuicError(Misconfigured(_))` |
//! | C4   | Secio         | present     | dial /quic-v1 to dead port     | succeeds enter dial path (no early-reject), error surfaces async       |
//!
//! Run:
//!     cargo run --example quic_qa_error_matrix --features quic
//!
//! The program prints a PASS/FAIL table and exits non-zero if any case fails.

use std::{
    process::ExitCode,
    sync::{Arc, Mutex},
    time::Duration,
};

use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    error::{DialerErrorKind, TransportErrorKind},
    quic::{config::QuicConfig, error::QuicErrorKind},
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent, TargetProtocol},
    traits::ServiceHandle,
};

fn dummy_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(|| ProtocolHandle::None)
        .build()
}

struct Row {
    case: &'static str,
    description: &'static str,
    passed: bool,
}

fn record(case: &'static str, description: &'static str, passed: bool, detail: String) -> Row {
    let mark = if passed { "PASS" } else { "FAIL" };
    println!("[{mark}] {case} — {description}\n        {detail}");
    Row {
        case,
        description,
        passed,
    }
}

async fn run_cases() -> Vec<Row> {
    let mut rows = Vec::new();

    // ---------- C1: HandshakeType::Noop + no quic_config ----------
    {
        let mut service = ServiceBuilder::<SecioKeyPair>::default()
            .insert_protocol(dummy_meta(1.into()))
            .forever(true)
            // .handshake_type defaults to HandshakeType::Noop
            .build(());
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        let (ok, detail) = match res {
            Err(TransportErrorKind::NotSupported(_)) => (
                true,
                format!("got {:?}", "TransportErrorKind::NotSupported"),
            ),
            Err(e) => (false, format!("expected NotSupported, got {e:?}")),
            Ok(_) => (
                false,
                "expected NotSupported, but dial accepted".to_string(),
            ),
        };
        rows.push(record(
            "C1",
            "Noop + no quic_config dialing /quic-v1 -> NotSupported",
            ok,
            detail,
        ));
    }

    // ---------- C2: HandshakeType::Secio + no quic_config ----------
    {
        let key = SecioKeyPair::secp256k1_generated();
        let mut service = ServiceBuilder::default()
            .insert_protocol(dummy_meta(1.into()))
            .forever(true)
            .handshake_type(key.into())
            // no .quic_config(...)
            .build(());
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        let (ok, detail) = match res {
            Err(TransportErrorKind::QuicError(QuicErrorKind::NotConfigured)) => {
                // also check the human-readable message includes the actionable hint
                let msg = format!("{}", QuicErrorKind::NotConfigured);
                let hint_ok = msg.contains("ServiceBuilder::quic_config");
                (
                    hint_ok,
                    if hint_ok {
                        format!("got QuicError(NotConfigured) with hint: \"{msg}\"")
                    } else {
                        format!("got NotConfigured but hint missing in: \"{msg}\"")
                    },
                )
            }
            Err(e) => (
                false,
                format!("expected QuicError(NotConfigured), got {e:?}"),
            ),
            Ok(_) => (
                false,
                "expected QuicError(NotConfigured), but dial accepted".to_string(),
            ),
        };
        rows.push(record(
            "C2",
            "Secio + no quic_config dialing /quic-v1 -> QuicError(NotConfigured) with hint",
            ok,
            detail,
        ));
    }

    // ---------- C3: HandshakeType::Noop + quic_config(...) ----------
    {
        let mut service = ServiceBuilder::<SecioKeyPair>::default()
            .insert_protocol(dummy_meta(1.into()))
            .forever(true)
            .quic_config(QuicConfig::default())
            // .handshake_type defaults to HandshakeType::Noop -> misconfigured
            .build(());
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        let (ok, detail) = match res {
            Err(TransportErrorKind::QuicError(QuicErrorKind::Misconfigured(msg))) => {
                (true, format!("got QuicError(Misconfigured(\"{msg}\"))"))
            }
            Err(e) => (
                false,
                format!("expected QuicError(Misconfigured(_)), got {e:?}"),
            ),
            Ok(_) => (
                false,
                "expected QuicError(Misconfigured(_)), but dial accepted".to_string(),
            ),
        };
        rows.push(record(
            "C3",
            "Noop + quic_config(...) dialing /quic-v1 -> QuicError(Misconfigured(_))",
            ok,
            detail,
        ));
    }

    // ---------- C4 (regression check): Secio + quic_config dialing /quic-v1 enters dial path ----------
    // Address goes to a port nothing is listening on. We want to assert that
    // ServiceBuilder::dial does NOT reject synchronously — the configuration
    // is valid, so dispatch must accept the multiaddr and let the failure
    // surface later via the runtime.
    {
        let key = SecioKeyPair::secp256k1_generated();
        let mut service = ServiceBuilder::default()
            .insert_protocol(dummy_meta(1.into()))
            .forever(true)
            .handshake_type(key.into())
            .quic_config(QuicConfig::default())
            .build(());
        let res = service
            .dial(
                "/ip4/127.0.0.1/udp/65530/quic-v1".parse().unwrap(),
                TargetProtocol::All,
            )
            .await;
        let (ok, detail) = match res {
            Ok(_) => (
                true,
                "dial accepted synchronously (async failure expected later)".to_string(),
            ),
            Err(e) => (
                false,
                format!("dial unexpectedly rejected synchronously: {e:?}"),
            ),
        };
        rows.push(record(
            "C4",
            "Properly configured QUIC service does NOT synchronously reject dial",
            ok,
            detail,
        ));
    }

    // ---------- C5/C6/C7: malformed QUIC multiaddrs -> QuicError(InvalidAddress) ----------
    // These dispatch into the QUIC path (because `/quic-v1` is present and
    // `find_type` therefore routes them to QUIC), but `parse_quic_multiaddr`
    // rejects them. The error is delivered ASYNCHRONOUSLY via
    // `ServiceHandle::handle_error` — `service.dial(...)` only enqueues.
    let pid = SecioKeyPair::secp256k1_generated().peer_id();
    let c6_addr = format!(
        "/ip4/127.0.0.1/udp/4433/quic-v1/p2p/{}/p2p/{}",
        pid.to_base58(),
        pid.to_base58()
    );
    let malformed_cases: Vec<(&'static str, &'static str, String)> = vec![
        (
            "C5",
            "/ip4/127.0.0.1/tcp/4433/quic-v1 — /tcp/ instead of /udp/",
            "/ip4/127.0.0.1/tcp/4433/quic-v1".to_string(),
        ),
        (
            "C6",
            "/ip4/.../udp/.../quic-v1/p2p/X/p2p/Y — multiple /p2p/",
            c6_addr,
        ),
        (
            "C7",
            "/dns4/example.com/udp/4433/quic-v1 — DNS-form (v1 unsupported)",
            "/dns4/example.com/udp/4433/quic-v1".to_string(),
        ),
    ];

    for (case, description, addr_str) in malformed_cases {
        let (ok, detail) = run_malformed_addr(&addr_str).await;
        rows.push(record(case, description, ok, detail));
    }

    rows
}

/// Build a properly configured QUIC service, dial `addr_str`, and capture
/// the first `ServiceError` reported via `handle_error` (which is where
/// asynchronous dial failures surface). Returns whether the captured error
/// matched `QuicError(InvalidAddress(_))`.
async fn run_malformed_addr(addr_str: &str) -> (bool, String) {
    #[derive(Clone, Default)]
    struct ErrorSink(Arc<Mutex<Vec<ServiceError>>>);
    #[async_trait]
    impl ServiceHandle for ErrorSink {
        async fn handle_error(&mut self, _ctx: &mut ServiceContext, error: ServiceError) {
            self.0.lock().unwrap().push(error);
        }
        async fn handle_event(&mut self, _ctx: &mut ServiceContext, _event: ServiceEvent) {}
    }

    let addr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return (
                false,
                format!("address {addr_str:?} failed to parse: {e:?}"),
            );
        }
    };
    let sink = ErrorSink::default();
    let bucket = sink.0.clone();
    let key = SecioKeyPair::secp256k1_generated();
    let mut service = ServiceBuilder::default()
        .insert_protocol(dummy_meta(1.into()))
        .handshake_type(key.into())
        .quic_config(QuicConfig::default())
        .build(sink);

    if let Err(e) = service.dial(addr, TargetProtocol::All).await {
        // Synchronous rejection is also acceptable evidence — as long as
        // it is the right variant. (C2 and C3 follow this path.)
        return match e {
            TransportErrorKind::QuicError(QuicErrorKind::InvalidAddress(msg)) => (
                true,
                format!("synchronous QuicError(InvalidAddress(\"{msg}\"))"),
            ),
            other => (
                false,
                format!("synchronous error but wrong variant: {other:?}"),
            ),
        };
    }

    // Drive the service briefly so async dial errors flow to ErrorSink.
    let run = tokio::spawn(async move { service.run().await });
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let captured: Option<ServiceError> = loop {
        {
            let mut guard = bucket.lock().unwrap();
            if !guard.is_empty() {
                break Some(guard.remove(0));
            }
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    run.abort();

    match captured {
        Some(ServiceError::DialerError { error, .. }) => match error {
            DialerErrorKind::TransportError(TransportErrorKind::QuicError(
                QuicErrorKind::InvalidAddress(msg),
            )) => (true, format!("async QuicError(InvalidAddress(\"{msg}\"))")),
            other => (
                false,
                format!("got DialerError with wrong variant: {other:?}"),
            ),
        },
        Some(other) => (false, format!("got non-dialer ServiceError: {other:?}")),
        None => (
            false,
            "no ServiceError observed within 3s — async error never surfaced".to_string(),
        ),
    }
}

fn main() -> ExitCode {
    let _ = env_logger::try_init();

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let rows = rt.block_on(run_cases());

    println!("\n──────────── summary ────────────");
    let mut failed = 0usize;
    for r in &rows {
        let mark = if r.passed { "PASS" } else { "FAIL" };
        println!("  [{mark}] {} — {}", r.case, r.description);
        if !r.passed {
            failed += 1;
        }
    }
    println!("─────────────────────────────────");
    if failed == 0 {
        println!("All {} cases PASSED.", rows.len());
        ExitCode::SUCCESS
    } else {
        println!("{failed}/{} cases FAILED.", rows.len());
        ExitCode::from(1)
    }
}
