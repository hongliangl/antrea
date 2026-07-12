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

//go:build !linux

package hostdp

import (
	"errors"
	"net"
)

var errUnsupported = errors.New("eBPF host datapath is only supported on Linux")

type loader struct{}

// NewLoader returns a no-op eBPF host-datapath control surface on non-Linux platforms.
func NewLoader() Interface { return &loader{} }

func (l *loader) Load(transportIfIndex int) error               { return errUnsupported }
func (l *loader) Close() error                                  { return nil }
func (l *loader) SetNodeConfig(net.IP, int) error               { return errUnsupported }
func (l *loader) AddPodCIDR(*net.IPNet) error                   { return errUnsupported }
func (l *loader) DeletePodCIDR(*net.IPNet) error                { return errUnsupported }
func (l *loader) Stats() (map[string]uint64, error)             { return nil, errUnsupported }
