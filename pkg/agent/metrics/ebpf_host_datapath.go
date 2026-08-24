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

package metrics

import (
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/hostdp"
)

// The values of the result label of antrea_agent_ebpf_host_datapath_packets_total, one per field of
// hostdp.Stats.
const (
	LabelEBPFHostDataPathForwarded    = "forwarded"
	LabelEBPFHostDataPathReturned     = "returned"
	LabelEBPFHostDataPathForwardMiss  = "forward_miss"
	LabelEBPFHostDataPathReturnMiss   = "return_miss"
	LabelEBPFHostDataPathPassed       = "passed"
	LabelEBPFHostDataPathTTLExpired   = "ttl_expired"
	LabelEBPFHostDataPathTooBig       = "too_big"
	LabelEBPFHostDataPathWouldForward = "would_forward"
	LabelEBPFHostDataPathWouldReturn  = "would_return"
)

var (
	ebpfHostDataPathPacketsDesc = metrics.NewDesc(
		metrics.BuildFQName(metricNamespaceAntrea, metricSubsystemAgent, "ebpf_host_datapath_packets_total"),
		"Number of packets seen by the eBPF host datapath, partitioned by what it did with them. The packets "+
			"it did not forward were forwarded by the host network stack instead.",
		[]string{"result"},
		nil,
		metrics.ALPHA,
		"",
	)
	ebpfHostDataPathModeDesc = metrics.NewDesc(
		metrics.BuildFQName(metricNamespaceAntrea, metricSubsystemAgent, "ebpf_host_datapath_mode"),
		"Mode of the eBPF host datapath: 0 when it observes and forwards nothing, 1 when it forwards.",
		nil,
		nil,
		metrics.ALPHA,
		"",
	)
)

// ebpfHostDataPathCollector reads the counters of the eBPF host datapath on every scrape. They live in a map
// the programs increment, so reading them when asked is what keeps them current without polling.
type ebpfHostDataPathCollector struct {
	metrics.BaseStableCollector

	hostDP hostdp.Interface
	mode   hostdp.Mode
}

func newEBPFHostDataPathCollector(hostDP hostdp.Interface, mode hostdp.Mode) *ebpfHostDataPathCollector {
	return &ebpfHostDataPathCollector{hostDP: hostDP, mode: mode}
}

func (c *ebpfHostDataPathCollector) DescribeWithStability(ch chan<- *metrics.Desc) {
	ch <- ebpfHostDataPathPacketsDesc
	ch <- ebpfHostDataPathModeDesc
}

func (c *ebpfHostDataPathCollector) CollectWithStability(ch chan<- metrics.Metric) {
	ch <- metrics.NewLazyConstMetric(ebpfHostDataPathModeDesc, metrics.GaugeValue, float64(c.mode))
	stats, err := c.hostDP.Stats()
	if err != nil {
		klog.ErrorS(err, "Failed to read the counters of the eBPF host datapath")
		return
	}
	for _, counter := range []struct {
		result string
		value  uint64
	}{
		{LabelEBPFHostDataPathForwarded, stats.Forwarded},
		{LabelEBPFHostDataPathReturned, stats.Returned},
		{LabelEBPFHostDataPathForwardMiss, stats.ForwardMisses},
		{LabelEBPFHostDataPathReturnMiss, stats.ReturnMisses},
		{LabelEBPFHostDataPathPassed, stats.Passed},
		{LabelEBPFHostDataPathTTLExpired, stats.TTLExpired},
		{LabelEBPFHostDataPathTooBig, stats.TooBig},
		{LabelEBPFHostDataPathWouldForward, stats.WouldForward},
		{LabelEBPFHostDataPathWouldReturn, stats.WouldReturn},
	} {
		ch <- metrics.NewLazyConstMetric(ebpfHostDataPathPacketsDesc, metrics.CounterValue, float64(counter.value),
			counter.result)
	}
}

// InitializeEBPFHostDataPathMetrics registers the metrics of the eBPF host datapath. It is only called once the
// datapath loaded, as there is nothing to count otherwise.
func InitializeEBPFHostDataPathMetrics(hostDP hostdp.Interface, mode hostdp.Mode) {
	if err := legacyregistry.CustomRegister(newEBPFHostDataPathCollector(hostDP, mode)); err != nil {
		klog.ErrorS(err, "Failed to register metrics with Prometheus", "metrics", "antrea_agent_ebpf_host_datapath")
	}
}
