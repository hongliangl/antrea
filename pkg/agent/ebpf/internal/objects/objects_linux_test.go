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

package objects

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"antrea.io/antrea/v2/pkg/agent/ebpf/internal/bpf"
)

// TestObjectsMatchSource fails when bpf/host_datapath.bpf.c was changed without regenerating objects_linux.go. The
// instructions the Agent loads come from the generated file, so without this the two drift apart silently and
// the datapath keeps running the version of the C which happened to be compiled last.
func TestObjectsMatchSource(t *testing.T) {
	source, err := os.ReadFile("../../bpf/host_datapath.bpf.c")
	require.NoError(t, err)
	sum := sha256.Sum256(source)
	assert.Equal(t, SourceSHA256, hex.EncodeToString(sum[:]),
		"bpf/host_datapath.bpf.c changed since objects_linux.go was generated, run \"make bpf-objects\"")
}

// TestObjectsAreLoadable checks generated map definitions, instruction boundaries and relocations.
func TestObjectsAreLoadable(t *testing.T) {
	mapNames := make(map[string]struct{}, len(Maps))
	for _, m := range Maps {
		assert.LessOrEqual(t, len(m.Name), 15, "map %q exceeds the Linux name limit", m.Name)
		_, exists := mapNames[m.Name]
		assert.False(t, exists, "map name %q is duplicated", m.Name)
		mapNames[m.Name] = struct{}{}

		assert.NotZero(t, m.Type, "map %s has no type", m.Name)
		assert.NotZero(t, m.MaxEntries, "map %s has no entries", m.Name)
		assert.NotZero(t, m.KeySize, "map %s has no key size", m.Name)
		assert.NotZero(t, m.ValueSize, "map %s has no value size", m.Name)
	}

	for _, p := range Programs {
		assert.NotEmpty(t, p.Instructions, "program %s is empty", p.Name)
		assert.Zero(t, len(p.Instructions)%bpf.InstructionSize, "program %s is not a whole number of instructions", p.Name)
		assert.NotEmpty(t, p.Relocations, "program %s refers to no map, which cannot be", p.Name)
		for _, r := range p.Relocations {
			offset := int(r.Instruction) * bpf.InstructionSize
			require.Less(t, offset+2*bpf.InstructionSize, len(p.Instructions)+1,
				"program %s has a relocation past its end", p.Name)
			assert.EqualValues(t, 0x18, p.Instructions[offset],
				"program %s has a relocation on an instruction which is not a wide load", p.Name)
			assert.Less(t, int(r.MapIndex), len(Maps), "program %s refers to a map which does not exist", p.Name)
		}
	}
}
