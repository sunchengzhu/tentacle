# quic_transport_qa

System-level QA programs that exercise tentacle's QUIC support **the way CKB
/ Fiber will actually use it as a transport** — many sessions, sustained
traffic, server churn, and TCP/QUIC parity. These are **separate from** the
contract-regression examples under `tentacle/examples/quic_qa_*.rs` (which
lock the behaviour of PR #435).

Each binary is self-asserting and returns a non-zero exit code on failure.

## Binaries

| Binary                            | What it proves                                           |
|-----------------------------------|----------------------------------------------------------|
| `qa_mixed_transport_gossip`       | N nodes in a TCP+QUIC mixed mesh; every node receives every broadcast within a loss budget. |
| `qa_quic_jitter_reconnect`        | Client re-establishes its session within budget after the server tears down/restarts on the same UDP port. |
| `qa_quic_soak`                    | Steady-rate ping for N seconds with 0 loss, 0 unexpected disconnects, bounded RSS growth. |
| `qa_quic_vs_tcp_baseline`         | Same workload runs over TCP and QUIC; reports RPS / p50 / p95 / p99 / failures side-by-side. |

## Running

```bash
# From the workspace root.
cargo run -q -p quic-transport-qa --bin qa_mixed_transport_gossip
cargo run -q -p quic-transport-qa --bin qa_quic_jitter_reconnect
cargo run -q -p quic-transport-qa --bin qa_quic_soak
cargo run -q -p quic-transport-qa --bin qa_quic_vs_tcp_baseline
```

Each program reads tunables from environment variables; defaults are sized
so the full suite runs comfortably inside CI minutes. See the header
comment of each binary for the full list. Common knobs:

```bash
QA_DURATION_SECS=20  cargo run -q -p quic-transport-qa --bin qa_mixed_transport_gossip
QA_CYCLES=5 QA_CYCLE_SECS=5 cargo run -q -p quic-transport-qa --bin qa_quic_jitter_reconnect
QA_SOAK_SECS=300     cargo run -q -p quic-transport-qa --bin qa_quic_soak
QA_REQUESTS=10000    cargo run -q -p quic-transport-qa --bin qa_quic_vs_tcp_baseline
```

## Known upstream issue surfaced

When a QUIC `Service` is shut down via `ServiceAsyncControl::shutdown()`,
tentacle currently panics inside one of its tokio worker threads at
`tentacle/src/quic/endpoint.rs:394` (`unwrap()` on `Elapsed`). The panics
do not affect this suite's verdicts (they happen on background threads
after the main thread has completed its assertions) but they are real and
worth tracking upstream. Search for "endpoint.rs:394" in the output of
`qa_quic_jitter_reconnect` to see them.

## Layout

```
quic_transport_qa/
├── Cargo.toml
└── src/
    ├── lib.rs          # re-exports helpers
    ├── env.rs          # tiny env-var parser
    ├── resources.rs    # peak-RSS sampler (getrusage)
    ├── runner.rs       # shared `build_quic_service()`
    └── programs/
        ├── qa_mixed_transport_gossip.rs
        ├── qa_quic_jitter_reconnect.rs
        ├── qa_quic_soak.rs
        └── qa_quic_vs_tcp_baseline.rs
```
