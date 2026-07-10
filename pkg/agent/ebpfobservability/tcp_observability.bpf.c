// Copyright 2026 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]

#define AF_INET 2
#define IPPROTO_TCP 6

// Event types are shared with userspace. Each emitted record uses one of these
// values so the collector can distinguish connect, established, RTT, and
// retransmit events.
enum event_type {
	EVENT_TYPE_TCP_CONNECT = 1,
	EVENT_TYPE_TCP_ESTABLISHED = 2,
	EVENT_TYPE_TCP_STATE = 3,
	EVENT_TYPE_TCP_RTT = 4,
	EVENT_TYPE_TCP_RETRANSMIT = 5,
};

// tcp_event is the fixed-size payload written into the ring buffer.
// Userspace decodes the same layout and turns it into logs and metrics.
struct tcp_event {
	__u64 timestamp_ns;
	__u64 cgroup_id;
	__u64 socket_cookie;
	__u32 type;
	__u32 family;
	__u32 local_ip4;
	__u32 remote_ip4;
	__u32 local_port;
	__u32 remote_port;
	__u32 srtt_us;
	__u32 total_retrans;
	__u32 old_state;
	__u32 new_state;
	__u32 protocol;
	__u32 padding;
};

// Ring buffer used to hand events from eBPF to userspace.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Minimal helper declarations. In a real BPF C file these are usually pulled
// in through helper headers, but here we declare only what this prototype uses.
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *)BPF_FUNC_get_current_cgroup_id;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *)BPF_FUNC_get_socket_cookie;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *ctx, int flags) =
	(void *)BPF_FUNC_sock_ops_cb_flags_set;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_output;

static __u32 network_to_host_port(__u32 port)
{
	return __builtin_bswap32(port) >> 16;
}

static __u32 sockops_remote_port(__u32 port)
{
	return __builtin_bswap32(port);
}

// emit_sockops_event converts a sockops callback into the common tcp_event
// layout and pushes it into the ring buffer.
static void emit_sockops_event(struct bpf_sock_ops *ctx, enum event_type type)
{
	struct tcp_event event = {};

	if (ctx->family != AF_INET)
		return;

	event.timestamp_ns = bpf_ktime_get_ns();
	// Sockops callbacks can run outside the originating task context, and
	// Linux 5.15 does not allow cgroup helpers for this program type. Pod
	// attribution for these events uses the local IP in userspace.
	event.cgroup_id = 0;
	event.socket_cookie = bpf_get_socket_cookie(ctx);
	event.type = type;
	event.family = ctx->family;
	event.local_ip4 = ctx->local_ip4;
	event.remote_ip4 = ctx->remote_ip4;
	event.local_port = ctx->local_port;
	event.remote_port = sockops_remote_port(ctx->remote_port);
	event.srtt_us = ctx->srtt_us >> 3;
	event.total_retrans = ctx->total_retrans;
	event.protocol = IPPROTO_TCP;

	if (type == EVENT_TYPE_TCP_STATE) {
		event.old_state = ctx->args[0];
		event.new_state = ctx->args[1];
	}

	bpf_ringbuf_output(&events, &event, sizeof(event), 0);
}

// cgroup/connect4 runs before an IPv4 TCP connect is executed. This is the
// earliest point where we can observe the intended destination before the
// socket is established.
SEC("cgroup/connect4")
int observe_connect4(struct bpf_sock_addr *ctx)
{
	struct tcp_event event = {};

	event.timestamp_ns = bpf_ktime_get_ns();
	event.cgroup_id = bpf_get_current_cgroup_id();
	event.socket_cookie = bpf_get_socket_cookie(ctx);
	event.type = EVENT_TYPE_TCP_CONNECT;
	event.family = ctx->family;
	event.remote_ip4 = ctx->user_ip4;
	event.remote_port = network_to_host_port(ctx->user_port);
	event.protocol = ctx->protocol;
	bpf_ringbuf_output(&events, &event, sizeof(event), 0);

	// This is an enforcement-capable hook. Always allow the connection
	// because the Antrea program is observation-only.
	return 1;
}

// sockops observes TCP socket state transitions and timing callbacks after a
// connection exists. It gives us established, state, RTT, and retransmit
// telemetry that connect4 cannot see.
SEC("sockops")
int observe_sockops(struct bpf_sock_ops *ctx)
{
	if (ctx->family != AF_INET)
		return 0;

	switch (ctx->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(ctx,
			BPF_SOCK_OPS_RETRANS_CB_FLAG |
			BPF_SOCK_OPS_STATE_CB_FLAG |
			BPF_SOCK_OPS_RTT_CB_FLAG);
		emit_sockops_event(ctx, EVENT_TYPE_TCP_ESTABLISHED);
		break;
	case BPF_SOCK_OPS_STATE_CB:
		emit_sockops_event(ctx, EVENT_TYPE_TCP_STATE);
		break;
	case BPF_SOCK_OPS_RTT_CB:
		emit_sockops_event(ctx, EVENT_TYPE_TCP_RTT);
		break;
	case BPF_SOCK_OPS_RETRANS_CB:
		emit_sockops_event(ctx, EVENT_TYPE_TCP_RETRANSMIT);
		break;
	}

	return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
