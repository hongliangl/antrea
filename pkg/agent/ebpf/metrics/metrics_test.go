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
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/component-base/metrics/testutil"

	agentconfig "antrea.io/antrea/v2/pkg/agent/config"
	"antrea.io/antrea/v2/pkg/agent/ebpf"
)

// fakeEBPFClient implements ebpf.Interface whose counters are set by the test.
type fakeEBPFClient struct {
	stats    ebpf.Stats
	statsErr error
}

func (f *fakeEBPFClient) Initialize(nodeConfig *agentconfig.NodeConfig) error  { return nil }
func (f *fakeEBPFClient) Run(stopCh <-chan struct{})                           {}
func (f *fakeEBPFClient) AddPodRoute(podCIDR *net.IPNet, nextHop net.IP) error { return nil }
func (f *fakeEBPFClient) DeletePodRoute(podCIDR *net.IPNet) error              { return nil }
func (f *fakeEBPFClient) Stats() (ebpf.Stats, error)                           { return f.stats, f.statsErr }
func (f *fakeEBPFClient) Close() error                                         { return nil }

func TestEBPFCollector(t *testing.T) {
	tests := []struct {
		name           string
		stats          ebpf.Stats
		statsErr       error
		expectedOutput string
	}{
		{
			name: "forwarded traffic",
			// Every field has a value of its own, so that a field exported under the wrong label fails.
			stats: ebpf.Stats{
				Forwarded:     1,
				Returned:      2,
				ForwardMisses: 3,
				ReturnMisses:  4,
				Passed:        5,
				TTLExpired:    6,
				TooBig:        7,
			},
			expectedOutput: `
# HELP antrea_agent_ebpf_packets_total [ALPHA] Number of packets processed by Antrea eBPF programs, partitioned by result.
# TYPE antrea_agent_ebpf_packets_total counter
antrea_agent_ebpf_packets_total{result="host_dp_forwarded"} 1
antrea_agent_ebpf_packets_total{result="host_dp_returned"} 2
antrea_agent_ebpf_packets_total{result="host_dp_forward_miss"} 3
antrea_agent_ebpf_packets_total{result="host_dp_return_miss"} 4
antrea_agent_ebpf_packets_total{result="host_dp_passed"} 5
antrea_agent_ebpf_packets_total{result="host_dp_ttl_expired"} 6
antrea_agent_ebpf_packets_total{result="host_dp_too_big"} 7
`,
		},
		{
			// The counters are left out rather than reported as zero, which would read as a reset.
			name:     "counters unreadable",
			statsErr: fmt.Errorf("bad file descriptor"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := newEBPFCollector(&fakeEBPFClient{stats: tt.stats, statsErr: tt.statsErr})
			err := testutil.CustomCollectAndCompare(collector, strings.NewReader(tt.expectedOutput),
				"antrea_agent_ebpf_packets_total")
			assert.NoError(t, err)
		})
	}
}
