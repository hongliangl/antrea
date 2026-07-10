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
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"k8s.io/klog/v2"

	"antrea.io/antrea/v2/pkg/agent/interfacestore"
	agentmetrics "antrea.io/antrea/v2/pkg/agent/metrics"
)

const (
	defaultCgroupPath = "/host/sys/fs/cgroup"
	eventSize         = 72
)

func (t EventType) String() string {
	switch t {
	case EventTypeTCPConnect:
		return "connect"
	case EventTypeTCPEstablished:
		return "established"
	case EventTypeTCPState:
		return "state"
	case EventTypeTCPRTT:
		return "rtt"
	case EventTypeTCPRetransmit:
		return "retransmit"
	default:
		return "unknown"
	}
}

// EventType identifies an observation emitted by an eBPF program.
type EventType uint32

const (
	// EventTypeTCPConnect identifies an IPv4 TCP connect attempt.
	EventTypeTCPConnect EventType = 1
	// EventTypeTCPEstablished identifies a completed TCP handshake.
	EventTypeTCPEstablished EventType = 2
	// EventTypeTCPState identifies a TCP state transition.
	EventTypeTCPState EventType = 3
	// EventTypeTCPRTT identifies an RTT sample.
	EventTypeTCPRTT EventType = 4
	// EventTypeTCPRetransmit identifies a TCP retransmission.
	EventTypeTCPRetransmit EventType = 5
)

// Event is the userspace representation of a raw eBPF observation.
type Event struct {
	TimestampNS  uint64
	CgroupID     uint64
	SocketCookie uint64
	Type         EventType
	Family       uint32
	LocalIP      net.IP
	RemoteIP     net.IP
	LocalPort    uint16
	RemotePort   uint16
	SRTTUS       uint32
	TotalRetrans uint32
	OldState     uint32
	NewState     uint32
	Protocol     uint32
}

// Collector loads eBPF programs, reads their events, and enriches them with
// local Antrea interface information.
type Collector struct {
	interfaceStore  interfacestore.InterfaceStore
	nodeName        string
	cgroupPath      string
	eventsProcessed atomic.Uint64
	identity        *identityResolver
}

// NewCollector creates an eBPF observability collector.
func NewCollector(interfaceStore interfacestore.InterfaceStore, nodeName string) *Collector {
	return &Collector{
		interfaceStore: interfaceStore,
		nodeName:       nodeName,
		cgroupPath:     defaultCgroupPath,
	}
}

// Run loads and attaches the eBPF program, then processes events until the
// context is canceled.
func (c *Collector) Run(ctx context.Context) error {
	c.identity = newIdentityResolver(c.interfaceStore, c.cgroupPath)
	if err := c.identity.refresh(); err != nil {
		klog.ErrorS(err, "Failed to initialize eBPF cgroup identity cache")
	}

	objects := tcpObservabilityObjects{}
	if err := loadTCPObservabilityObjects(&objects); err != nil {
		return err
	}
	defer objects.Close()

	programLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    c.cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objects.ObserveConnect4,
	})
	if err != nil {
		return fmt.Errorf("failed to attach eBPF connect program to %s: %w", c.cgroupPath, err)
	}
	defer programLink.Close()

	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    c.cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objects.ObserveSockops,
	})
	if err != nil {
		return fmt.Errorf("failed to attach eBPF sockops program to %s: %w", c.cgroupPath, err)
	}
	defer sockopsLink.Close()
	agentmetrics.EBPFProgramAttached.WithLabelValues("connect4").Set(1)
	agentmetrics.EBPFProgramAttached.WithLabelValues("sockops").Set(1)
	defer func() {
		agentmetrics.EBPFProgramAttached.WithLabelValues("connect4").Set(0)
		agentmetrics.EBPFProgramAttached.WithLabelValues("sockops").Set(0)
	}()

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		return fmt.Errorf("failed to create eBPF event reader: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	klog.InfoS("Started eBPF observability collector", "cgroupPath", c.cgroupPath)
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("failed to read eBPF event: %w", err)
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			klog.ErrorS(err, "Failed to decode eBPF observation")
			continue
		}
		c.eventsProcessed.Add(1)
		c.logEvent(event)
	}
}

func (c *Collector) logEvent(event Event) {
	ifConfig, found := c.identity.resolve(event)
	attributed := "false"
	podName := ""
	namespace := ""
	if found {
		attributed = "true"
		podName = ifConfig.PodName
		namespace = ifConfig.PodNamespace
	}
	agentmetrics.EBPFEventsTotal.WithLabelValues(event.Type.String(), attributed, podName, namespace).Inc()
	if event.Type == EventTypeTCPRTT && event.SRTTUS != 0 {
		agentmetrics.EBPFTCPSRTT.WithLabelValues(podName, namespace).Observe(float64(event.SRTTUS) / 1_000_000)
	}
	if !found {
		if event.Type == EventTypeTCPRTT {
			klog.V(4).InfoS("Observed TCP RTT without Pod attribution",
				"node", c.nodeName,
				"localIP", event.LocalIP,
				"remoteIP", event.RemoteIP,
				"socketCookie", event.SocketCookie,
				"srttUS", event.SRTTUS)
			return
		}
		klog.InfoS("Observed TCP event without Pod attribution",
			"eventType", event.Type,
			"node", c.nodeName,
			"localIP", event.LocalIP,
			"localPort", event.LocalPort,
			"remoteIP", event.RemoteIP,
			"remotePort", event.RemotePort,
			"cgroupID", event.CgroupID,
			"socketCookie", event.SocketCookie,
			"srttUS", event.SRTTUS,
			"totalRetrans", event.TotalRetrans,
			"oldState", event.OldState,
			"newState", event.NewState)
		return
	}
	if event.Type == EventTypeTCPRTT {
		klog.V(4).InfoS("Observed Pod TCP RTT",
			"node", c.nodeName,
			"namespace", ifConfig.PodNamespace,
			"pod", ifConfig.PodName,
			"localIP", event.LocalIP,
			"remoteIP", event.RemoteIP,
			"socketCookie", event.SocketCookie,
			"srttUS", event.SRTTUS)
		return
	}

	klog.InfoS("Observed Pod TCP event",
		"eventType", event.Type,
		"node", c.nodeName,
		"namespace", ifConfig.PodNamespace,
		"pod", ifConfig.PodName,
		"localIP", event.LocalIP,
		"localPort", event.LocalPort,
		"remoteIP", event.RemoteIP,
		"remotePort", event.RemotePort,
		"ovsInterface", ifConfig.InterfaceName,
		"ovsPort", ifConfig.OFPort,
		"cgroupID", event.CgroupID)
}

func decodeEvent(sample []byte) (Event, error) {
	if len(sample) != eventSize {
		return Event{}, fmt.Errorf("unexpected eBPF event size %d", len(sample))
	}
	return Event{
		TimestampNS:  binary.NativeEndian.Uint64(sample[0:8]),
		CgroupID:     binary.NativeEndian.Uint64(sample[8:16]),
		SocketCookie: binary.NativeEndian.Uint64(sample[16:24]),
		Type:         EventType(binary.NativeEndian.Uint32(sample[24:28])),
		Family:       binary.NativeEndian.Uint32(sample[28:32]),
		LocalIP:      net.IPv4(sample[32], sample[33], sample[34], sample[35]),
		RemoteIP:     net.IPv4(sample[36], sample[37], sample[38], sample[39]),
		LocalPort:    uint16(binary.NativeEndian.Uint32(sample[40:44])),
		RemotePort:   uint16(binary.NativeEndian.Uint32(sample[44:48])),
		SRTTUS:       binary.NativeEndian.Uint32(sample[48:52]),
		TotalRetrans: binary.NativeEndian.Uint32(sample[52:56]),
		OldState:     binary.NativeEndian.Uint32(sample[56:60]),
		NewState:     binary.NativeEndian.Uint32(sample[60:64]),
		Protocol:     binary.NativeEndian.Uint32(sample[64:68]),
	}, nil
}
