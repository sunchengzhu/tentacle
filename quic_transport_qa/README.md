# quic_transport_qa

System-level QA programs that exercise tentacle's QUIC support **the way CKB
/ Fiber will actually use it as a transport** — many sessions, sustained
traffic, server churn, and TCP/QUIC parity. These are **separate from** the
contract-regression examples under `tentacle/examples/quic_qa_*.rs` (which
lock the behaviour of
[nervosnetwork/tentacle#435](https://github.com/nervosnetwork/tentacle/pull/435)).

Most workload binaries are self-asserting and return a non-zero exit code on
failure. `qa_wan_server` is a long-running endpoint for real public-WAN runs;
`qa_wan_client` performs the assertions against it.

## Binaries

| Binary                            | What it proves                                           |
|-----------------------------------|----------------------------------------------------------|
| `qa_mixed_transport_gossip`       | N nodes in a TCP+QUIC mixed mesh; every node receives every broadcast within a loss budget. |
| `qa_quic_jitter_reconnect`        | Client re-establishes its session within budget after the server tears down/restarts on the same UDP port. |
| `qa_quic_soak`                    | Steady-rate ping for N seconds with 0 loss, 0 unexpected disconnects, bounded RSS growth. |
| `qa_quic_vs_tcp_baseline`         | Same workload runs over TCP and QUIC; reports RPS / p50 / p95 / p99 / failures side-by-side. |
| `qa_quic_wan_stability`           | Inserts an in-process UDP relay and injects RTT / jitter / loss to exercise QUIC under WAN-like datagram conditions. |
| `qa_large_message_throughput`      | Compares TCP+yamux vs QUIC goodput for MiB-scale echo payloads. |
| `qa_quic_concurrent_sessions`      | Runs many concurrent QUIC clients against one server and verifies connection + echo completion. |
| `qa_quic_handshake_storm`          | Bursts many QUIC clients into one server and reports handshake success ratio / latency distribution. |
| `qa_wan_server`                    | Runs a public-WAN echo endpoint on a remote machine for cross-region validation. |
| `qa_wan_client`                    | Connects to `qa_wan_server` over QUIC or TCP and runs latency / bulk / soak workloads. |

## Running

```bash
# From the workspace root.
cargo run -q -p quic-transport-qa --bin qa_mixed_transport_gossip
cargo run -q -p quic-transport-qa --bin qa_quic_jitter_reconnect
cargo run -q -p quic-transport-qa --bin qa_quic_soak
cargo run -q -p quic-transport-qa --bin qa_quic_vs_tcp_baseline
cargo run -q -p quic-transport-qa --bin qa_quic_wan_stability
cargo run -q -p quic-transport-qa --bin qa_large_message_throughput
cargo run -q -p quic-transport-qa --bin qa_quic_concurrent_sessions
cargo run -q -p quic-transport-qa --bin qa_quic_handshake_storm
```

Each program reads tunables from environment variables; defaults are sized
so the full suite runs comfortably inside CI minutes. See the header
comment of each binary for the full list.

For real public-WAN validation across two machines, use `qa_wan_server` and
`qa_wan_client`; deployment steps and security-group notes are in
[`REAL_WAN_DEPLOY.md`](./REAL_WAN_DEPLOY.md).

The acceptance report was produced with the following smoke profile:

```bash
# 1) Mixed TCP/QUIC gossip
QA_NODES=6 QA_DURATION_SECS=8 QA_INTERVAL_MS=100 \
QA_MIN_PER_PAIR=20 QA_MAX_LOSS_RATIO=0.05 \
cargo run -q -p quic-transport-qa --bin qa_mixed_transport_gossip

# 2) QUIC jitter / reconnect
QA_CYCLES=2 QA_CYCLE_SECS=4 QA_DOWN_SECS=2 QA_REDIAL_BUDGET_MS=8000 \
cargo run -q -p quic-transport-qa --bin qa_quic_jitter_reconnect

# 3) QUIC soak
QA_SOAK_SECS=10 QA_PERIOD_MS=25 \
cargo run -q -p quic-transport-qa --bin qa_quic_soak

# 4) TCP vs QUIC baseline
QA_REQUESTS=500 QA_PAYLOAD=512 QA_PARITY_P95_RATIO=5 \
cargo run -q -p quic-transport-qa --bin qa_quic_vs_tcp_baseline

# 5) WAN-like UDP fault injection
QA_WAN_DURATION_SECS=10 QA_WAN_RTT_MS=80 QA_WAN_JITTER_MS=20 QA_WAN_LOSS_PCT=1 \
cargo run -q -p quic-transport-qa --bin qa_quic_wan_stability

QA_WAN_DURATION_SECS=15 QA_WAN_RTT_MS=200 QA_WAN_JITTER_MS=30 \
QA_WAN_LOSS_PCT=5 QA_WAN_PERIOD_MS=100 \
cargo run -q -p quic-transport-qa --bin qa_quic_wan_stability

# 6) Large-message throughput
QA_LM_SIZE_MIB=2 QA_LM_COUNT=8 \
cargo run -q -p quic-transport-qa --bin qa_large_message_throughput

# 7) Concurrent QUIC sessions
QA_CC_CLIENTS=30 QA_CC_PINGS_PER=10 \
cargo run -q -p quic-transport-qa --bin qa_quic_concurrent_sessions

# 8) QUIC handshake storm
QA_HS_CLIENTS=80 \
cargo run -q -p quic-transport-qa --bin qa_quic_handshake_storm
```

Suggested nightly profile:

```bash
QA_DURATION_SECS=20 cargo run -q -p quic-transport-qa --bin qa_mixed_transport_gossip
QA_CYCLES=5 QA_CYCLE_SECS=10 QA_DOWN_SECS=3 cargo run -q -p quic-transport-qa --bin qa_quic_jitter_reconnect
QA_SOAK_SECS=600 cargo run -q -p quic-transport-qa --bin qa_quic_soak
QA_REQUESTS=10000 QA_PAYLOAD=1024 QA_PARITY_P95_RATIO=5 cargo run -q -p quic-transport-qa --bin qa_quic_vs_tcp_baseline
QA_WAN_RTT_MS=150 QA_WAN_LOSS_PCT=2 QA_WAN_DURATION_SECS=60 cargo run -q -p quic-transport-qa --bin qa_quic_wan_stability
QA_LM_SIZE_MIB=2 QA_LM_COUNT=64 cargo run -q -p quic-transport-qa --bin qa_large_message_throughput
QA_CC_CLIENTS=200 QA_CC_PINGS_PER=20 cargo run -q -p quic-transport-qa --bin qa_quic_concurrent_sessions
QA_HS_CLIENTS=500 cargo run -q -p quic-transport-qa --bin qa_quic_handshake_storm
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
        ├── qa_quic_vs_tcp_baseline.rs
        ├── qa_quic_wan_stability.rs
        ├── qa_large_message_throughput.rs
        ├── qa_quic_concurrent_sessions.rs
        ├── qa_quic_handshake_storm.rs
        ├── qa_wan_server.rs
        └── qa_wan_client.rs
```
