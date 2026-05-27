# Tentacle PR 435 QUIC QA 测试场景

> **测试目标**：覆盖 Tentacle PR 435 在 QUIC 传输上的 4 项契约修复
> （①错误分类与 hint、②客户端 `QuicConfig` 对称应用、③listener 在坏握手后存活、④dial 去重双分支）。
>
> **测试用例位置**：`sunchengzhu/tentacle` fork 的 `pr435_qa_examples` 分支 examples 目录：
> <https://github.com/sunchengzhu/tentacle/tree/pr435_qa_examples/tentacle/examples>
>
> 每个场景在 `tentacle/examples/quic_qa_*.rs` 下有可独立运行的自断言示例：
> `cargo run --features quic --example <name>` 退出码 0 即 PASS。

## 索引

| 分组 | 场景 | 触发时机 | 对应示例 |
| --- | --- | --- | --- |
| A. 错误契约 — 同步 | 1 / 2 / 3 | `service.dial(...)` 同步 `Err(...)` | `quic_qa_error_matrix` (C1–C3) |
| B. 正常路径 | 4 | `service.dial(...)` 同步 `Ok(_)` | `quic_qa_error_matrix` (C4) |
| C. 错误契约 — 畸形地址 | 5 / 6 / 7 | 当前为 `handle_error` → `DialerError`（同步也接受） | `quic_qa_error_matrix` (C5–C7) |
| D. TCP/QUIC 共存 | 8 | — | `quic_qa_coexist` |
| E. 客户端 QuicConfig 对称 | 9 / 10 | — | `quic_qa_idle_timeout` / `quic_qa_keep_alive` |
| F. listener 健壮性 | 11 | — | `quic_qa_listener_survives_bad_handshake` |
| G. dial 去重 | 12 / 13 | — | `quic_qa_duplicate_dial` / `quic_qa_peer_id_dedup` |

每个场景统一字段：**触发** / **预期** / **PR 关联**。

---

## A. 错误契约 — 同步返回

### 1. QUIC 未请求时拨 QUIC 地址

- **触发**：构造默认 `Noop` service，不调用 `.quic_config(...)`；dial `/ip4/127.0.0.1/udp/4433/quic-v1`。
- **预期**：`service.dial(...)` 同步返回 `Err(TransportErrorKind::NotSupported)` —— service 未声明 QUIC 能力。
- **PR 关联**：错误分类修复项 1，区分"未声明能力"与"声明了但配置错"。

### 2. 使用 Secio 但忘记启用 QUIC

- **触发**：使用 `SecioKeyPair`，**不**调用 `.quic_config(...)`；dial QUIC 地址。
- **预期**：同步返回 `Err(TransportErrorKind::QuicError(QuicErrorKind::NotConfigured))`，错误信息明确提示调用 `ServiceBuilder::quic_config(...)`。
- **PR 关联**：错误分类修复项 1（细分 NotConfigured），同时引入面向使用者的诊断 hint。

### 3. Noop service 错误配置 QUIC

- **触发**：使用 `HandshakeType::Noop`，但**调用了** `.quic_config(...)`。
- **预期**：同步返回 `Err(TransportErrorKind::QuicError(QuicErrorKind::Misconfigured(_)))`，错误信息说明 QUIC 的 TLS 证书需要绑定 secio identity。
- **PR 关联**：错误分类修复项 1（细分 Misconfigured），防止用户误以为 Noop 也能跑 QUIC。

## B. 正常路径

### 4. QUIC 正确配置后进入 dial 路径

- **触发**：`SecioKeyPair` + `.quic_config(QuicConfig::default())`；dial 一个**合法但未监听**的 `/ip4/127.0.0.1/udp/4433/quic-v1` 地址。
- **预期**：`service.dial(...)` **不**同步拒绝（返回 `Ok(_)`）—— 配置自检通过，调度进入实际的 QUIC dial future，后续连接失败属于运行时事件，不归本场景断言。
- **PR 关联**：与 1/2/3 一同验证"正确配置不会被新增的早期校验误伤"。

## C. 错误契约 — 畸形 QUIC 地址

> **注意**：以下三种地址因含 `/quic-v1` 被 `find_type` 首匹配路由进 QUIC 分支，再由 `parse_quic_multiaddr()` 拒绝。
> **当前实现表现为异步返回**：`service.dial(...)` 同步 `Ok(_)`，错误通过 `ServiceHandle::handle_error` 以 `ServiceError::DialerError { error: DialerErrorKind::TransportError(TransportErrorKind::QuicError(QuicErrorKind::InvalidAddress(_))), .. }` 抛出。
> 用例同时接受同步 `Err(QuicError(InvalidAddress(_)))`（若未来实现把校验提前到 dial 入口）作为 PASS——锁定的是"错误分类必须是 InvalidAddress"，而非具体的同步 / 异步时机。这一点和 A 组**只能同步**的错误必须区分。

### 5. 非法 QUIC 地址：TCP + quic-v1

- **触发**：dial `/ip4/127.0.0.1/tcp/4433/quic-v1`。
- **预期**：异步收到 `QuicError(InvalidAddress(_))`，错误信息指出 QUIC multiaddr 必须使用 `/udp/<port>` 而非 `/tcp/<port>`。
- **PR 关联**：错误分类修复项 1 的 InvalidAddress 子枚举。

### 6. 非法 QUIC 地址：多个 p2p

- **触发**：dial `/ip4/127.0.0.1/udp/4433/quic-v1/p2p/<pid>/p2p/<pid>`。
- **预期**：异步收到 `QuicError(InvalidAddress(_))`，错误信息指出 multiaddr 不允许重复 `/p2p/`。
- **PR 关联**：同上。

### 7. 非法 QUIC 地址：DNS 形式

- **触发**：dial `/dns4/example.com/udp/4433/quic-v1`。
- **预期**：异步收到 `QuicError(InvalidAddress(_))`，错误信息指出当前 `parse_quic_multiaddr` 仅接受 `/ip4` 或 `/ip6` 开头（DNS 形式尚未实现）。
- **PR 关联**：同上；显式说明"DNS 形式未实现"而非静默 fallback。

## D. TCP / QUIC 共存

### 8. 单 service 同时承载 TCP 与 QUIC

- **触发**：同一 server service `listen("/ip4/127.0.0.1/tcp/0")` 与 `listen("/ip4/127.0.0.1/udp/0/quic-v1")`；两个 client 分别 dial TCP / QUIC 地址，连接成功后各自发送 `"ping"`，server 通过 `received` 回 echo。
- **预期**：两个 client 均完成握手、触发 `connected`，**并完成 ping/pong 回环**；server 端通过 `session.address` 中的 `Protocol::Tcp` / `Protocol::QuicV1` 标记区分来源。
- **PR 关联**：验证 QUIC 引入不影响既有 TCP 能力，并且数据通路双向可用。

## E. 客户端 QuicConfig 对称应用

> Tentacle PR 435 修复项 2：`build_quinn_client_config` 需要镜像 server 端，把 `QuicConfig` 的 `max_idle_timeout` 和 `keep_alive_interval` **两个**字段都应用到 quinn `TransportConfig`，否则客户端仍走 quinn 默认 30s 空闲超时。
> 9 和 10 必须作为一对运行：单看任何一个都不足以证明对称应用。

### 9. 客户端 idle timeout 生效

- **触发**：server `keep_alive_interval = None`；client `QuicConfig { max_idle_timeout: 3s, keep_alive_interval: None, .. }`；连接建立后双方静默。
- **预期**：client 在 `connected` 后 **2s–10s** 窗口内收到 `disconnected` 回调（实测 ~3.0s）。窗口外（含 quinn 默认 30s）均判 FAIL。
- **PR 关联**：修复项 2 的 `max_idle_timeout` 一半。

### 10. 客户端 keepalive 生效

- **触发**：server `keep_alive_interval = None`；client `QuicConfig { max_idle_timeout: 3s, keep_alive_interval: Some(1s), .. }`；连接建立后双方静默。
- **预期**：先确认 client 已进入 `connected`；之后 10s 内**不**收到 `disconnected`，也不应出现 `ServiceError`。说明客户端 keep-alive PING 维持了会话，超过 3s idle 仍存活。
- **PR 关联**：修复项 2 的 `keep_alive_interval` 一半。

## F. listener 健壮性

### 11. 坏握手不影响 listener

- **触发**：server 启动 QUIC listener。client 1 用错误 `/p2p/<peer_id>` 发起连接触发 PeerId 校验失败；随后 client 2 用正确 PeerId 连接同一 listener。
- **预期**：client 1 收到包含 "expected peer_id ... got ..." 的 QUIC 错误；server listener **不**退出；client 2 完成握手并 `connected`。
- **PR 关联**：修复项 3 —— 把 verifier 的 PeerId mismatch 由 listener-fatal 改为 per-connection-fatal。

## G. dial 去重

> Tentacle PR 435 修复项 4：`Service::dial` 同时检查 ① `dial_protocols` 中是否已有完全相同 multiaddr；② 已 pending 地址里是否有相同 `peer_id`（经 `extract_peer_id`）。两条分支都需独立验证。

### 12. 完全相同 QUIC 地址重复 dial

- **触发**：client 对同一个 multiaddr 连续两次 `dial(addr, TargetProtocol::All)`。
- **预期**：第二次 dial 被 `dial_protocols.contains_key(&addr)` 命中而吞掉；server 在宽限期内只观察到 1 次 protocol `connected`。
- **PR 关联**：修复项 4 的 multiaddr 等价分支。

### 13. 相同 PeerId 的不同 QUIC 地址重复 dial

- **触发**：server 在同一 service 内 `listen` 两个不同 UDP 端口（同 PeerId）；client 先 dial `addr_a/p2p/<pid>`，再 dial `addr_b/p2p/<pid>`。
- **预期**：第二次 dial 被 `extract_peer_id` 分支命中而吞掉；server 只观察到 1 次 protocol `connected`，且无 `ServiceError`。
- **预期补充**：client 侧 `ProtocolContextMutRef::session.address` 必须指向 `addr_a`（首条入队的那个），用于排除"两条 dial 都失败、再 race 出一条新连接"的伪 PASS。
- **PR 关联**：修复项 4 的 peer_id 分支。

---

## 运行全套

```bash
cd tentacle
for ex in quic_qa_error_matrix quic_qa_coexist \
          quic_qa_idle_timeout quic_qa_keep_alive \
          quic_qa_listener_survives_bad_handshake \
          quic_qa_duplicate_dial quic_qa_peer_id_dedup; do
  echo "=== $ex ==="
  cargo run --features quic --example "$ex" || { echo "FAIL: $ex"; exit 1; }
done
```

任一示例非零退出即视为整体回归失败。
