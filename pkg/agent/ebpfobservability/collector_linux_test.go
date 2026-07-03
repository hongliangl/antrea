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

//go:build linux

package ebpfobservability

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
)

func TestDecodeEvent(t *testing.T) {
	sample := make([]byte, eventSize)
	binary.NativeEndian.PutUint64(sample[0:8], 1234)
	binary.NativeEndian.PutUint64(sample[8:16], 5678)
	binary.NativeEndian.PutUint64(sample[16:24], 9012)
	binary.NativeEndian.PutUint32(sample[24:28], uint32(EventTypeTCPRTT))
	binary.NativeEndian.PutUint32(sample[28:32], 2)
	copy(sample[32:36], []byte{10, 10, 0, 2})
	copy(sample[36:40], []byte{10, 10, 0, 3})
	binary.NativeEndian.PutUint32(sample[40:44], 34567)
	binary.NativeEndian.PutUint32(sample[44:48], 8080)
	binary.NativeEndian.PutUint32(sample[48:52], 42000)
	binary.NativeEndian.PutUint32(sample[52:56], 3)
	binary.NativeEndian.PutUint32(sample[64:68], 6)

	event, err := decodeEvent(sample)
	require.NoError(t, err)
	assert.Equal(t, uint64(1234), event.TimestampNS)
	assert.Equal(t, uint64(5678), event.CgroupID)
	assert.Equal(t, uint64(9012), event.SocketCookie)
	assert.Equal(t, "10.10.0.2", event.LocalIP.String())
	assert.Equal(t, "10.10.0.3", event.RemoteIP.String())
	assert.Equal(t, uint16(34567), event.LocalPort)
	assert.Equal(t, uint16(8080), event.RemotePort)
	assert.Equal(t, uint32(42000), event.SRTTUS)
	assert.Equal(t, uint32(3), event.TotalRetrans)
	assert.Equal(t, uint32(6), event.Protocol)
	assert.Equal(t, EventTypeTCPRTT, event.Type)
}

func TestDecodeEventRejectsInvalidSize(t *testing.T) {
	_, err := decodeEvent(make([]byte, eventSize-1))
	require.Error(t, err)
}

func TestCollectorIntegration(t *testing.T) {
	if os.Getenv("ANTREA_EBPF_INTEGRATION_TEST") == "" {
		t.Skip("set ANTREA_EBPF_INTEGRATION_TEST to run the privileged integration test")
	}

	collector := NewCollector(interfacestore.NewInterfaceStore(), "integration-test")
	collector.cgroupPath = "/sys/fs/cgroup"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- collector.Run(ctx)
	}()

	// Wait for the program to be loaded and attached before triggering a
	// connect attempt. A refused connection still invokes cgroup/connect4.
	time.Sleep(500 * time.Millisecond)
	conn, _ := net.DialTimeout("tcp4", "127.0.0.1:1", time.Second)
	if conn != nil {
		conn.Close()
	}
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
		assert.Positive(t, collector.eventsProcessed.Load())
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the collector to stop")
	}
}
