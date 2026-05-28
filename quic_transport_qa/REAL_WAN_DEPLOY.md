# Real-WAN QUIC 测试部署手册（AWS EC2）

本文档讲怎么用 `qa_wan_server` + `qa_wan_client` 在**两台或更多台真实跨地域机器**上跑 tentacle PR #435 QUIC 的端到端验证。这是对 `qa_quic_wan_stability`（loopback 软仿真）的补充，覆盖软仿真**没有**模拟的真实 WAN 现象：跨地域物理时延、运营商/AWS 网络的真实抖动与丢包、真实 NAT/SG/PMTU 路径、IPv4/IPv6 双栈。

---

## 0. 一句话总览

- 在地域 A 的 EC2 上跑 `qa_wan_server` 当 echo 服务器；在地域 B 的 EC2 上跑 `qa_wan_client` 拨过去；两边对调再跑一遍验证双向对称。
- 两个 binary 都是同一份代码 build 出来的，**只用环境变量配置**，没有 CLI 参数。
- 客户端有 3 个 mode：`latency`（延迟分布）/ `bulk`（大消息吞吐）/ `soak`（长跑稳定性）。退出码 0=PASS，1=FAIL。

---

## 1. 推荐拓扑

最小：2 台 EC2，不同地域。例如：

| 节点 | AWS 地域 | 作用 |
|---|---|---|
| `wan-east` | `us-east-1`（Virginia） | server |
| `wan-tokyo` | `ap-northeast-1`（Tokyo） | client |

实际跨太平洋 RTT ≈ 150–180 ms，比较接近 CKB 真实矿工/全节点分布。

如果想验证 3 节点 mesh，再加一台 `eu-central-1`（Frankfurt），3 台两两互测即可。

实例类型用 `t3.small` 或 `c6i.large` 都够；带 ENA 的实例更接近生产网络。

---

## 2. 安全组（关键）

测试用同一个端口跑 QUIC（UDP）和 TCP，默认 `9443`。

server 实例的 Security Group 入站规则需要开两条：

| Protocol | Port range | Source |
|---|---|---|
| **UDP** | 9443 | client 公网 IP/32 |
| **TCP** | 9443 | client 公网 IP/32 |

⚠️ 常见踩坑：忘开 UDP，QUIC 握手会一直 timeout，但 TCP 能连。所以一旦 QUIC 失败 / TCP 成功，先检查 SG。

如果走 NAT 网关 / IPv6，把上面的 source 换成对应 CIDR。

OS 防火墙（如果你启用了 `ufw` / `firewalld`）也要放行同样两条。

---

## 3. 一次性环境准备（两台机器都做）

```bash
# Amazon Linux 2023 / Ubuntu 22.04 都行
sudo yum -y install git gcc pkgconfig openssl-devel || \
sudo apt-get update && sudo apt-get -y install git build-essential pkg-config libssl-dev

# 安装 Rust 1.88+ (rust-toolchain 钉死了版本)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
source "$HOME/.cargo/env"

# 拉测试分支
git clone -b quic_transport_qa https://github.com/sunchengzhu/tentacle.git
cd tentacle/quic_transport_qa

# 编译两个 bin（首次约 3–5 分钟，二次秒级）
cargo build --release --bin qa_wan_server --bin qa_wan_client
```

产出物：

```
../target/release/qa_wan_server
../target/release/qa_wan_client
```

> 也可以本地交叉编译再 scp 上去：
> `cargo build --release --target x86_64-unknown-linux-musl --bin qa_wan_server --bin qa_wan_client`

---

## 4. 启动 server（地域 A）

```bash
# 在 server 实例上
export QA_LISTEN_HOST=0.0.0.0
export QA_LISTEN_PORT=9443
export QA_ADVERTISE_HOST=<server 实例公网 IP>   # client 拨号要用这个
export QA_TRANSPORT=both                         # both | quic | tcp
export QA_IDLE_TIMEOUT_S=60
export QA_KEEPALIVE_MS=5000
export QA_MAX_FRAME_MIB=16

./target/release/qa_wan_server
```

启动后会打印（**复制 dial 字符串给 client**）：

```
[server] peer_id = QmXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[server] QUIC listening on /ip4/0.0.0.0/udp/9443/quic-v1
[server] QUIC dial me at: /ip4/<PUBLIC_IP>/udp/9443/quic-v1/p2p/QmXXXX...
[server] TCP  dial me at: /ip4/<PUBLIC_IP>/tcp/9443/p2p/QmXXXX...
[server] running. Ctrl-C to stop.
```

> 想让 PeerId 在多次重启之间稳定？设 `QA_SERVER_SEED=<64 字符 hex>`（32 字节 secp256k1 raw key）。否则每次启动 PeerId 都是新的，client 的 `QA_SERVER_ADDR` 要同步更新。

后台跑：

```bash
nohup ./target/release/qa_wan_server > server.log 2>&1 &
disown
```

或者用 systemd / tmux，随意。

---

## 5. 跑 client（地域 B）

把 server 打印的 `QUIC dial me at:` 那行整串贴进 `QA_SERVER_ADDR`。

### 5.1 延迟分布（小包，最接近 ping）

```bash
export QA_SERVER_ADDR="/ip4/<PUBLIC_IP>/udp/9443/quic-v1/p2p/QmXXXX..."
export QA_MODE=latency
export QA_COUNT=500          # 发 500 个 ping
export QA_PAYLOAD=256        # 每个 256 B
export QA_PERIOD_MS=50       # 间隔 50 ms
export QA_MIN_DELIVERY=0.99  # 跨地域要求 99% 到达
export QA_MAX_P95_MS=400     # p95 RTT 上限（跨太平洋给 400ms，跨欧美给 250ms）

./target/release/qa_wan_client
```

预期（us-east ↔ tokyo，RTT ≈ 160 ms）：

```
sent=500 acked=500 delivery=1.000 disconnects=0 elapsed=25.04s
rtt samples=500 p50=158.43ms p95=171.20ms p99=185.6ms
PASS
```

### 5.2 大消息吞吐

```bash
export QA_MODE=bulk
export QA_BULK_SIZE_MIB=2       # 每条 2 MiB
export QA_BULK_COUNT=16         # 总共 16 条 = 32 MiB
export QA_MAX_FRAME_MIB=16
export QA_MIN_BULK_MBPS=1.0     # 跨地域至少 1 MiB/s (~8 Mbps) 才算 PASS

./target/release/qa_wan_client
```

预期：

```
sent=16 acked=16 delivery=1.000 disconnects=0 elapsed=5.81s
bulk_received=33554432B goodput=5.51 MiB/s
PASS
```

这一条**重点看**：和 `qa_large_message_throughput` 在 loopback 上的 1/7 QUIC 劣势对照，在真实 BDP 大的链路上 QUIC 是否还落后于 TCP。把 `QA_TRANSPORT=tcp` 让 server 改成纯 TCP 模式，让 client 用 TCP dial 字符串再跑一次，直接对比。

### 5.3 长跑稳定性（soak）

```bash
export QA_MODE=soak
export QA_DURATION_SECS=1800   # 半小时
export QA_SOAK_PERIOD_MS=100   # 10 Hz
export QA_PAYLOAD=512
export QA_MIN_DELIVERY=0.99

./target/release/qa_wan_client
```

期间每 5 s 打印进度。跨地域链路偶发 microburst 丢包是正常的，QUIC 应该重传而不是断链。`disconnects=0` 是核心通过指标。

---

## 6. 推荐验收套件（在两台机器上各跑一遍 = 4 组）

| 方向 | mode | 关键参数 | PASS 标准 |
|---|---|---|---|
| A→B | latency | COUNT=500 PERIOD_MS=50 | delivery≥0.99，p95 在物理 RTT × 2 之内 |
| A→B | bulk    | BULK_COUNT=32 SIZE_MIB=2 | delivery=1.0，goodput 不为 0 |
| A→B | soak    | DURATION_SECS=1800 | disconnects=0，delivery≥0.99 |
| B→A | （同上，对调 server / client） |  |  |

如果 TCP+QUIC 双向各跑一遍，乘以 2。

---

## 7. 常见故障排查

| 现象 | 第一反应 |
|---|---|
| client 卡在 `did not connect within 30s` | 99% 是 SG 没开 UDP / TCP；用 `nc -zv <ip> 9443` 测 TCP，用 `nc -uvz <ip> 9443` 试 UDP（UDP 不可靠，只能间接验证）。 |
| QUIC 失败、TCP 成功 | UDP 被中间设备 ban（部分公司出口、运营商）；或 PMTU 太小（< 1200B）。切 `QA_TRANSPORT=tcp` 临时对比。 |
| 偶发 `disconnects>0` | 看 server.log，多半是 idle timeout 触发：调大 `QA_IDLE_TIMEOUT_S=120` 和 `QA_KEEPALIVE_MS=3000` 再来。 |
| 长跑结束 server 进程留下 panic 日志 | 已知 upstream bug `tentacle/src/quic/endpoint.rs:394`，shutdown 时后台 worker 必 panic，不影响数据正确性。 |
| bulk 吞吐特别低 (< 1 MiB/s) 且 RTT 高 | QUIC 默认拥塞控制 + 小 receive window 在高 BDP 链路上的已知短板。这正是要让开发同学看到的数据点，**记录下来报到 issue**。 |

---

## 8. CI 化（可选）

把这一套包到一个 GitHub Actions matrix：

- 用 2 个 self-hosted runner 分别在 `us-east-1`、`ap-northeast-1`；
- workflow 触发后：runner-A 启 server（上传 dial 字符串到 artifact 或 redis），runner-B 拉下来跑 client，反向再来一遍。

如果不想搞 self-hosted runner，本目录的 `qa_quic_wan_stability`（in-process WAN 仿真）足够当 CI 守门员，真机测试按需手动跑。
