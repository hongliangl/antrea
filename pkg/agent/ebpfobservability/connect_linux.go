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
	"bytes"
	_ "embed"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

//go:embed connect_bpfel.o
var connectObject []byte

type connectObjects struct {
	ObserveConnect4 *ebpf.Program `ebpf:"observe_connect4"`
	ObserveSockops  *ebpf.Program `ebpf:"observe_sockops"`
	Events          *ebpf.Map     `ebpf:"events"`
}

func loadConnectObjects(objects *connectObjects) error {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(connectObject))
	if err != nil {
		return fmt.Errorf("failed to read embedded eBPF object: %w", err)
	}
	if err := spec.LoadAndAssign(objects, nil); err != nil {
		return fmt.Errorf("failed to load embedded eBPF object: %w", err)
	}
	return nil
}

func (o *connectObjects) Close() error {
	return errors.Join(o.ObserveConnect4.Close(), o.ObserveSockops.Close(), o.Events.Close())
}
