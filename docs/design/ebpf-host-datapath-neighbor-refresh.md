# eBPF Host Datapath Neighbor Refresh Handoff

## Status and scope

Open issue, recorded on 2026-10-23 against commit `80b83f7604cbb15843a2f458bca7fa2b5aaea391`
on branch `ebpf-host-forward`. This document hands off investigation and implementation; it does
not implement a fix. The issue affects IPv4 neighbor revalidation in `forward` mode.

The earlier discussion identified the issue, but the current implementation still lacks an
explicit neighbor refresh mechanism. The main design document and source comments retain an
overly optimistic description of fallback-based recovery.

## Current execution path

In [hostdp.bpf.c](../../pkg/agent/hostdp/bpf/hostdp.bpf.c), `redirect_via`:

1. Sets `fib.ipv4_dst` to the selected next-hop address.
2. Calls `bpf_fib_lookup` with `BPF_FIB_LOOKUP_DIRECT`.
3. Returns `TC_ACT_OK` on lookup failure, leaving the packet to the host stack.
4. On success in forward mode, decrements TTL, rewrites MAC addresses from the lookup result,
   and calls `bpf_redirect`.

For `hostdp_fwd`, the lookup target is the peer Node transport IP. For `hostdp_return`, it is
the local Pod IP. Neither the C program nor the Go `hostdp` package actively probes neighbors.

Do not confuse these three tables:

| Table | Contents | Owner |
| --- | --- | --- |
| `pod_routes` BPF map | Remote Pod CIDR to peer Node IP | Node route controller |
| Kernel FIB | Routes, next hops, and output interfaces | Routing control plane |
| Kernel neighbor table | Next-hop IP to MAC, plus NUD state | Kernel neighbor subsystem |

ARP resolves or updates the neighbor table. The problem here is neighbor liveness, not ordinary
control-plane routes expiring because eBPF handles the traffic.

## Failure mechanism

`NUD_STALE` is included in `NUD_VALID`. A stale neighbor with a cached MAC can therefore satisfy
`bpf_fib_lookup`; becoming stale does not itself force the program to fall back.

Normal neighbor output can transition a stale entry into `DELAY` and subsequently `PROBE`.
Reading the cached MAC and redirecting directly does not execute that neighbor output path.
Without other traffic, ARP updates, or garbage collection, this forwarding path provides no
guarantee that the mapping will be revalidated.

A reachable failure scenario is:

1. A peer neighbor is resolved and accelerated traffic starts.
2. Its neighbor entry becomes stale while accelerated packets continue to use its cached MAC.
3. The peer changes MAC, without an effective ARP update reaching this Node.
4. Lookup continues to succeed using the old MAC; packets continue to be redirected to it.
5. Delivery fails, but `Forwarded` can keep increasing and no neighbor miss is required.

The analogous dependency exists for local Pod neighbors in the return direction. Test both
directions; do not assume Pod ARP requests always provide timely refresh.

Observe mode leaves packets with the host stack and does not by itself demonstrate that forward
mode maintains neighbor liveness.

Kernel reference points, pinned for investigation:

- [NUD_VALID definition](https://github.com/torvalds/linux/blob/v6.6/include/net/neighbour.h).
- [FIB lookup helpers](https://github.com/torvalds/linux/blob/v6.6/net/core/filter.c).
- [Neighbor state machine](https://github.com/torvalds/linux/blob/v6.6/net/core/neighbour.c).

Check the supported target kernels as well; do not infer all version-specific behavior from one
kernel or one namespace experiment.

## Evidence and limits

The Claude conversation dated 2026-08-31 reported these namespace observations:

- Deleting a neighbor entry caused fallback; kernel ARP resolution restored forwarding.
- Forcing an entry to `STALE` did not cause fallback: three packets remained accelerated and
  the entry remained stale.
- Receiving appropriate ARP traffic could update an existing incorrect mapping.

The recorded experiments establish stale-entry use and recovery after deletion. They do not
establish a complete, automated MAC-change blackhole regression test against the current commit.
The sustained blackhole scenario above follows from the code path and needs that regression test.
These experiments were not rerun when writing this handoff.

Historical artifacts on the original development machine:

- `/home/ubuntu/hostdp-validate/staletest.sh`
- `/home/ubuntu/hostdp-validate/neightest.sh`
- `/home/ubuntu/hostdp-validate/fwdtest.sh`
- `/home/ubuntu/hostdp-validate/review-checklist.md`, items A3b and C0
- Claude session `18f0bb64-3417-49fe-a66d-e73fb7c82cfd`, discussion on 2026-08-31

Treat the scripts as historical evidence, not ready-to-run regression tests. For example,
`staletest.sh` reads slot 7 as `fwd_no_neigh`, while current slot 7 is `STAT_WOULD_FWD` and the
forward-miss slot is 1. It also selects a stats map by name/order rather than by loader ownership.
Adapt the harness to current APIs and counters, and identify the actual instance's maps.

`fwdtest.sh` deliberately omits a remote Pod route on one Node and installs permanent neighbors
to prove acceleration. That setup cannot validate dynamic ARP resolution or revalidation.

## Why existing fallback is insufficient

Fallback resolves a missing neighbor only if the original packet can traverse the normal stack:
the required routes must remain installed, forwarding and policy checks must permit it, and ARP
must succeed. A successful BPF lookup with an obsolete MAC never enters that fallback branch.

Other kernel traffic, accepted ARP requests or gratuitous ARP, and neighbor garbage collection
may refresh or remove the entry. They are possible recovery paths, not a bounded recovery
guarantee. In particular, do not rely on stale entries inevitably being garbage-collected;
collection depends on kernel behavior, configuration, and table pressure.

## Implementation direction

Choose and justify an explicit liveness mechanism, rather than relying on incidental traffic.
Candidates include bounded periodic fallback through normal neighbor output, controlled probes
from the Go side, or an appropriate neighbor-aware forwarding helper on supported kernels.
These are investigation options, not prescribed fixes.

The implementation must account for:

- Both peer Node and local Pod neighbor dependencies, including the actual routed next hop.
- Supported older kernels and both attachment mechanisms.
- Probe or fallback rate at cluster scale, shared-neighbor ownership, shutdown, and cleanup.
- Forwarding policy and conntrack consequences of deliberately sending occasional accelerated
  packets through the stack. Do not assume arbitrary fallback packets are harmless to a flow.
- Observe mode, where packet forwarding semantics must remain unchanged.
- Recovery observability: redirect counters prove an attempted redirect, not peer delivery.

Do not alter OVS, introduce NAT or connection tracking in eBPF, or remove the kernel routes as
part of this fix. If the chosen solution needs wider scope, explain that dependency first.

## Required regression coverage

Use isolated network namespaces with real dynamic neighbor entries and retained kernel routes.
Record kernel version, NUD states, ARP captures, per-instance counters, and end-to-end delivery.

1. Cold neighbor: confirm kernel resolution and subsequent accelerated delivery.
2. Missing neighbor after warm-up: confirm recovery after deleting the entry.
3. Stale, correct MAC: confirm the selected mechanism actually revalidates it, rather than only
   proving that cached-MAC forwarding still works.
4. Stale, obsolete MAC: change the peer's real MAC, suppress unsolicited refresh during the
   test, and prove delivery recovers within a documented bound without manual neighbor deletion.
5. Return path: repeat the relevant stale/MAC-change cases for a local Pod neighbor.
6. Unreachable peer and later recovery: verify bounded overhead and useful diagnostics.
7. Observe mode: confirm no acceleration or packet rewriting, and normal kernel behavior.
8. Established TCP: verify any periodic fallback or probing strategy does not cause persistent
   conntrack/policy-related drops or regress existing traffic.

An accepted fix should fail the MAC-change regression without the new mechanism and pass with
it. Integrate the essential tests into the repository's test infrastructure; do not rely solely
on scripts outside the tree. Regenerate committed BPF objects if the C implementation changes.

## Documentation corrections to include with the fix

Update [the main design](ebpf-host-datapath.md), especially the fallback section and known gap 3:

- Remove the implication that stale entries inevitably disappear and trigger refresh.
- Remove the claim that a miss counter staying at zero is inherently unhealthy.
- Qualify the claim that none of the known gaps can cause packet loss.
- Explain the new mechanism, recovery bound, and any remaining limitations.

Update corresponding comments in `hostdp.bpf.c` and
[hostdp.go](../../pkg/agent/hostdp/hostdp.go), including `Stats` miss-counter comments. Keep
neighbor misses distinct from proof of delivery; successful redirects can still target a bad MAC.

## 历史会话详细记录

以下为原始会话的整理与转述，不是逐字引用，也不是对旧结论的无条件认可。
时间均为 UTC。会话中的测试输出是当时 Claude 报告的结果，本次没有重新执行。
与修复有关的事实、推论和已纠正说法分别标明，避免把讨论过程当作最终实现。

### 2026-08-26：回程 MAC 与 Pod ARP 学习

讨论从 `hostdp_return` 是否需要改 MAC 开始。当时解释了同一个 `redirect_via`
在两个方向都改目的和源 MAC：去程使用出口传输接口的 MAC 与下一跳 MAC；
回程使用 gateway 的 MAC 与本机 Pod MAC。IP 源、目的地址不变，这不是 NAT。

Claude 报告，在发测试 IP 流量前，Pod 的动态邻居条目已经存在，状态为 `DELAY`。
其解释是 Pod 先 ARP 查询自己的网关，内核在处理发给本机的 ARP 请求时学习了请求方。
这说明收到 ARP 可以提供学习路径，不意味着所有收到的 ARP 都会无条件更新邻居。

当时仍使用“去程邻居老化后靠 miss 回落刷新”的解释，同时补充 `STALE` 属于
`NUD_VALID`，不一定使 lookup 失败。自然老化、回收、重新解析的完整链条尚未验证。

### 2026-08-27：提交方式与后续问题分开

你选择将当时改动合并到原来的单个 commit，再 force push。Claude 报告分支从
`e73631507` 更新为 `8d6b31703`，包含 C 文件去宏化、gateway IP 排除与 Node IP 校验。
这次提交早于下述 8 月 31 日的 ARP 深入实验，不能据此认为后来的发现已被修复。
当前分支在 9 月 26 日又经过 rebase/amend，HEAD 为本文开头记录的 `80b83f760`。

### 2026-08-31 06:30–06:50：统计与可观测性改动

你先询问 `count(STAT_PASS)`、`TC_ACT_OK` 和计数是否必要。讨论区分了计数与转发：
计数用于说明程序走了哪条路径，不能证明包到达对端；`TC_ACT_OK` 让包继续正常处理，
也不能保证后续路由、策略或邻居解析一定成功。

随后你要求重新整理统计宏，判断原先七个计数器能否覆盖实际场景。Claude 指出：

- `STAT_PASS` 混合了多个不接管原因，无法区分非 IPv4、IP options 和地址范围等情况。
- lookup 失败与 MAC 写入 helper 失败都可能计入 miss，混淆预期回落与实现异常。
- TTL 耗尽与更新 TTL/checksum 失败使用相同返回值，均计入 TTL expired。
- 未配置状态可能表现为普通 pass。

06:50 的会话报告曾将统计扩展到十二项，包含五个 pass 原因、两个 no-neighbor、
TTL、MTU 和独立 error，并报告 build/vet、单测及三个 namespace 测试通过。
该消息明确表示“没有提交”。

当前代码不是那套十二项统计：它使用九项，包含 observe 模式的两个 would 计数器，
仍有聚合的 pass/miss。因此旧会话中的统计字段与脚本编号不能直接套用。
目前只能确认实现不同，不能仅凭会话断言这些临时改动后来被谁删除或怎样丢失。
若接手者需要恢复这部分，应另行检查历史，而不是把它算作已经存在的 ARP 修复。

### 07:01–07:03：next_hop_of 与两次查表的分工

你询问 `next_hop_of` 如何找到下一跳。解释使用了示例：

```text
Pod destination 10.10.1.5
    -> pod_routes LPM lookup: 10.10.1.0/24 -> 192.168.50.2
    -> kernel lookup toward 192.168.50.2: output interface and neighbor MAC
```

`pod_routes` 保存远端 Pod CIDR 到 Node transport IP 的映射，查询使用完整 IPv4
地址和最长前缀匹配，不是逐 Pod 保存 MAC。原会话将其概括为“一 Node 一条”；
准确容量应按实际写入的 CIDR 条目数理解，不能由此推导固定的 Node 数量上限。

LPM 地址必须使用网络顺序的字节，与生成器、Go 写入布局一致。查到 peer IP 后，
还需要内核路由和 ARP 表；BPF map 自己并没有提供二层可达性。

### 07:08：删除邻居后的恢复实验

你追问 eBPF 是否仍强依赖内核路由。Claude 检查了 Node route controller：
正常内核路由继续安装，BPF map 是额外镜像，不是删除路由后完全替代内核。

会话报告的实验过程是：先通信建立邻居，执行 `ip neigh del`，再发流量。
结果报告为 `forwarded=4 returned=6 fwd_no_neigh=2`，七项检查通过。
其解释为每次邻居缺失时回落内核，由内核重新 ARP，之后恢复加速。

实验边界很关键：验证的是“手动删除后恢复”，不是“自然老化必然回收”，
更不是“STALE 条目 MAC 变了会自动纠正”。原会话明确承认自然回收触发时机未验证。
“代价就是一个包走慢路径”也只是该实验的表现，不能承诺任何负载下只影响一个包。

讨论同时发现 `fwdtest.sh` 故意没有安装远端 Pod 路由，并预置 permanent 邻居。
这是为证明流量确由 eBPF 转发而构造的拓扑，不代表真实运行可删除内核路由。

### 07:20：逐步阅读 redirect_via

你继续阅读发送逻辑，讨论按 MTU 检查、lookup、TTL、MAC 重写和 redirect 展开。
输入的 `ipv4_dst` 是要查询的下一跳，而非改写原包的 IP 目的地址。
lookup 返回出口接口与 MAC；成功并不等价于确认对端当前可达。

旧会话把失败主要解释为 no-neighbor，并使用当时临时扩展的 error 计数。
当前实现的 miss 实际涵盖所有 lookup 非成功结果，并不只代表 ARP 缺失。
排查时应检查 helper 返回原因，不能从聚合 miss 数直接断言发生了 ARP。

### 07:33：STALE 实验推翻早期自愈假设

针对“eBPF 持续使用缓存会不会永远降级”的问题，Claude 报告运行 `staletest.sh`：
先建立邻居，再显式设为 `STALE`，然后发送三个包。三个包仍走加速，miss 没增加，
发送后条目仍为 stale。这个结果支持：STALE 并不会自行把流量送回正常邻居输出路径。

由此讨论得出另一种更严重的风险：如果旧 MAC 已失效，lookup 仍可能成功，
redirect 仍被计数，但对端收不到包。会话把问题加入清单 A3b，并把文档的计数器解释
列为 C0。07:33 的总结表示测试脚本已移到树外的 `hostdp-validate` 目录。

这一步纠正了两个早期说法：

1. STALE 后不一定失败或回落，更不能保证很快被回收。
2. miss 不增长可能完全正常；计数器本身不能区分正确 MAC 与过期 MAC。

完整“真实 MAC 改变且无其他刷新后持续黑洞”的自动化复现仍需补齐。

### 07:39–07:41：路由表与 ARP 表混淆的澄清

你问：没有流量时下一跳是否还会存在于 FIB？只有 eBPF 使用时 timer 是否不重置，
最后路由会不会消失？讨论澄清了普通控制面路由与动态 ARP 条目的区别：
前者由 route client 等维护，不因这条数据路径没走内核而自然消失；后者有 NUD 状态。

旧解释中“FIB 根本没有 timer”“只有控制面删除才会消失”等是针对这里的普通路由
做出的过度概括，不应当推广到 Linux 所有路由类型、接口事件或过期路由机制。
本问题需要维持的是相关路由存在，以及实际下一跳邻居可用。

关于谁触发 ARP，会话解释的正常路径是：

```text
BPF lookup misses -> TC_ACT_OK
    -> kernel forwarding and policy checks
    -> neighbor output for the selected next hop
    -> unresolved packet queued, ARP request sent
    -> reply updates neighbor, queued packet transmitted
```

历史抓包报告看到了 request、reply 和随后发出的 ICMP。会话提及的微秒耗时只是
当次观测，不是协议保证，也不应作为恢复时限。

### 07:45–07:49：fallback 前提与 GARP 实验修正

你追问 ARP 是否一定能触发。讨论明确：路由缺失、包在到达邻居输出前被策略丢弃，
或对端不响应，都会使期望恢复无法完成。已有 STALE 条目被正常输出使用时，
通常先进入 DELAY，之后才探测，不意味着立即广播 ARP。

随后对 GARP 更新错误 MAC 做实验。第一次失败后，Claude 怀疑报文形态和
`locktime` 保护；07:46 的消息曾声称免费 ARP 必须是 REQUEST。
后续修正实验后报告 REQUEST 和 REPLY 形式均可更新已有条目，因此前一句不能作为
最终结论。`arp_accept=0` 下更新已有条目的实验也不能推广为任意配置下都可更新。

07:49 又报告：对端主动 ARP 查询本机时，内核能够学习请求方 MAC。这补充了第二种
偶发恢复路径。原会话称双向通信时对端“迟早”会 ARP 本机，但这不是设计保证：
两侧都持有可用的旧邻居条目时，仅持续发送 IP 流量未必产生新的 ARP 请求。

因此实际需要分别看待三种可能恢复路径：

- 对端发出且本机接受 ARP/GARP 更新。
- 其他经过正常内核邻居输出的流量触发本机探测。
- 条目因回收或删除而缺失，之后触发 fallback 和解析。

这些都可能发生，但当前加速逻辑没有保证其中任一种在有限时间内发生。

### 07:51 之后：术语讨论与任务边界

你要求直接使用“路由表”和“ARP 表”，避免 FIB 术语让两者混淆。
之后会话转到 FIB/RIB 以及 Tomato 上 FRR/OSPF 的讲解，与本问题的修复无关。
原会话中这些教学性的简化不应作为修复的实现规格；本文不复制现场配置或认证信息。

### 与当前分支的最终对照

| 会话内容 | 当前状态 |
| --- | --- |
| 保留内核路由，lookup 失败后 fallback | 已实现 |
| gateway IP 排除、Node IP 配置校验 | 已包含在当前提交 |
| 十二项细分统计与独立 error | 会话曾报告未提交；当前为另一套九项统计 |
| STALE 仍可 lookup 成功 | 与当前代码路径相符；历史实验需适配后复跑 |
| 主动刷新或有界重验证 | 未实现 |
| 文档 miss 不增长就不健康的说法应修正 | 尚未修正 |
| 树外 ARP 实验成为仓库内回归测试 | 本问题所需的覆盖尚未落地 |

接手 agent 应以当前源码为实现依据，以历史会话定位调查方向，并通过新的隔离测试
重建证据。不要仅因旧会话写了“改完了”或“验证通过”就认定对应代码已进入 HEAD。
