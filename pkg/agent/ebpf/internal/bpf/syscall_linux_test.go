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

package bpf

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectName(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:  "normal name",
			input: "hostdp_fwd",
		},
		{
			name:  "15 bytes",
			input: "123456789012345",
		},
		{
			name:        "16 bytes",
			input:       "1234567890123456",
			expectedErr: "16 bytes, maximum is 15",
		},
		{
			name:        "long name",
			input:       "a_very_very_long_program",
			expectedErr: "maximum is 15",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := objectName(tt.input)
			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.input, trim(name))
			assert.Zero(t, name[len(tt.input)])
		})
	}
}

// TestObjectNameValidation verifies rejection before either operation calls the kernel.
func TestObjectNameValidation(t *testing.T) {
	name := strings.Repeat("a", bpfObjNameLen)
	fd, err := CreateMap(MapSpec{Name: name})
	require.ErrorContains(t, err, "maximum is 15")
	assert.Equal(t, -1, fd)

	fd, err = LoadProgram(name, make([]byte, InstructionSize))
	require.ErrorContains(t, err, "maximum is 15")
	assert.Equal(t, -1, fd)
}

func trim(name [bpfObjNameLen]byte) string {
	for i, c := range name {
		if c == 0 {
			return string(name[:i])
		}
	}
	return string(name[:])
}
