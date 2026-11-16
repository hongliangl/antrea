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
	"sync"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/ebpf"
)

const (
	metricNamespaceAntrea = "antrea"
	metricSubsystemAgent  = "agent"
)

var once sync.Once

// The values of the result label of antrea_agent_ebpf_packets_total, one per field of
// ebpf.Stats.
const (
	LabelEBPFHostDataPathForwarded   = "host_dp_forwarded"
	LabelEBPFHostDataPathReturned    = "host_dp_returned"
	LabelEBPFHostDataPathForwardMiss = "host_dp_forward_miss"
	LabelEBPFHostDataPathReturnMiss  = "host_dp_return_miss"
	LabelEBPFHostDataPathPassed      = "host_dp_passed" // #nosec G101: Metric result label, not a credential.
	LabelEBPFHostDataPathTTLExpired  = "host_dp_ttl_expired"
	LabelEBPFHostDataPathTooBig      = "host_dp_too_big"
)

var (
	ebpfPacketsDesc = metrics.NewDesc(
		metrics.BuildFQName(metricNamespaceAntrea, metricSubsystemAgent, "ebpf_packets_total"),
		"Number of packets processed by Antrea eBPF programs, partitioned by result.",
		[]string{"result"},
		nil,
		metrics.ALPHA,
		"",
	)
)

// ebpfCollector exposes eBPF metrics.
type ebpfCollector struct {
	metrics.BaseStableCollector

	ebpfClient ebpf.Interface
}

func newEBPFCollector(ebpfClient ebpf.Interface) *ebpfCollector {
	return &ebpfCollector{ebpfClient: ebpfClient}
}

func (c *ebpfCollector) DescribeWithStability(ch chan<- *metrics.Desc) {
	ch <- ebpfPacketsDesc
}

func (c *ebpfCollector) CollectWithStability(ch chan<- metrics.Metric) {
	stats, err := c.ebpfClient.Stats()
	if err != nil {
		klog.ErrorS(err, "Failed to read eBPF counters")
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
	} {
		ch <- metrics.NewLazyConstMetric(ebpfPacketsDesc,
			metrics.CounterValue,
			float64(counter.value),
			counter.result)
	}
}

// Register adds the eBPF collector to the Prometheus registry.
func Register(ebpfClient ebpf.Interface) {
	once.Do(func() {
		klog.Infof("Registering Antrea eBPF Prometheus metrics")
		legacyregistry.CustomMustRegister(newEBPFCollector(ebpfClient))
	})
}
