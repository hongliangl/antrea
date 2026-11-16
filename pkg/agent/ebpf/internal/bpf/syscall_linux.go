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

// Package bpf provides Linux BPF map, program and TC attachment operations.
package bpf

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// InstructionSize is the size of one BPF instruction in bytes.
const InstructionSize = 8

// Linux enum bpf_cmd values from include/uapi/linux/bpf.h.
// The bpf syscall uses these IDs to select an operation and its attribute layout.
const (
	bpfMapCreate     = 0  // BPF_MAP_CREATE
	bpfMapLookupElem = 1  // BPF_MAP_LOOKUP_ELEM
	bpfMapUpdateElem = 2  // BPF_MAP_UPDATE_ELEM
	bpfMapDeleteElem = 3  // BPF_MAP_DELETE_ELEM
	bpfProgLoad      = 5  // BPF_PROG_LOAD
	bpfLinkCreate    = 28 // BPF_LINK_CREATE

	// Linux enum bpf_prog_type values from include/uapi/linux/bpf.h.
	bpfProgTypeSchedCLS = 3 // BPF_PROG_TYPE_SCHED_CLS

	// Linux enum bpf_attach_type values from include/uapi/linux/bpf.h.
	bpfTCXIngress = 46 // BPF_TCX_INGRESS
	bpfTCXEgress  = 47 // BPF_TCX_EGRESS

	// bpfObjNameLen is Linux BPF_OBJ_NAME_LEN, including the terminating NUL byte.
	bpfObjNameLen = 16

	// verifierLogSize is the buffer the kernel writes its rejection into. The verifier stops with ENOSPC
	// when it does not fit, which loses the end of the log, where the reason is.
	verifierLogSize = 1 << 20
)

func bpf(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	ret, _, errno := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	// The attribute structure holds pointers to Go memory which the kernel reads during the call, and
	// which nothing else refers to. Keeping it alive until here stops the collector from moving or
	// freeing it while the kernel is reading it.
	runtime.KeepAlive(attr)
	if errno != 0 {
		return 0, errno
	}
	return ret, nil
}

// objectName encodes a NUL-terminated BPF object name, rejecting names beyond the kernel's limit.
func objectName(name string) ([bpfObjNameLen]byte, error) {
	var out [bpfObjNameLen]byte
	if len(name) >= bpfObjNameLen {
		return out, fmt.Errorf("BPF object name %q is %d bytes, maximum is %d", name, len(name), bpfObjNameLen-1)
	}
	copy(out[:], name)
	return out, nil
}

// progLoadAttr matches the BPF_PROG_LOAD fields in Linux union bpf_attr.
// The corresponding prefix in include/uapi/linux/bpf.h is:
//
//	struct { /* BPF_PROG_LOAD member of union bpf_attr */
//	    __u32 prog_type;
//	    __u32 insn_cnt;
//	    __aligned_u64 insns;
//	    __aligned_u64 license;
//	    __u32 log_level;
//	    __u32 log_size;
//	    __aligned_u64 log_buf;
//	    __u32 kern_version;
//	    __u32 prog_flags;
//	    char  prog_name[BPF_OBJ_NAME_LEN];
//	    __u32 prog_ifindex;
//	    /* Additional fields follow. */
//	};
//
// This Go structure passes only that prefix; omitted trailing attributes are zero.
// The uint64 fields preserve the alignment of Linux's __aligned_u64 fields.
type progLoadAttr struct {
	progType    uint32
	insnCnt     uint32
	insns       uint64
	license     uint64
	logLevel    uint32
	logSize     uint32
	logBuf      uint64
	kernVersion uint32
	progFlags   uint32
	progName    [bpfObjNameLen]byte
	progIfIndex uint32
}

// LoadProgram hands the instructions to the kernel, which verifies them and returns a file descriptor for the
// program. It is called twice when the program is rejected: the first call asks for no log, which is the
// cheap path taken every time it succeeds, and the second one asks for the log to report the rejection.
func LoadProgram(name string, instructions []byte) (int, error) {
	if len(instructions) == 0 || len(instructions)%InstructionSize != 0 {
		return -1, fmt.Errorf("program %s is %d bytes, not a whole number of instructions", name, len(instructions))
	}

	programName, err := objectName(name)
	if err != nil {
		return -1, fmt.Errorf("loading program %s: %w", name, err)
	}

	license := append([]byte("GPL"), 0)
	attr := progLoadAttr{
		progType: bpfProgTypeSchedCLS,
		insnCnt:  uint32(len(instructions) / InstructionSize),
		insns:    uint64(uintptr(unsafe.Pointer(&instructions[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
		progName: programName,
	}
	fd, err := bpf(bpfProgLoad, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	if err == nil {
		return int(fd), nil
	}

	err = fmt.Errorf("loading program %s: %w", name, err)
	if log := programLoadLog(&attr, instructions, license); log != "" {
		err = fmt.Errorf("%w; BPF load log: %s", err, log)
	}
	return -1, err
}

// programLoadLog retries a failed load with logging enabled and returns any text written by the kernel.
func programLoadLog(attr *progLoadAttr, instructions, license []byte) string {
	log := make([]byte, verifierLogSize)
	retry := *attr
	retry.logLevel = 1
	retry.logSize = uint32(len(log))
	retry.logBuf = uint64(uintptr(unsafe.Pointer(&log[0])))
	_, _ = bpf(bpfProgLoad, unsafe.Pointer(&retry), unsafe.Sizeof(retry))
	runtime.KeepAlive(instructions)
	runtime.KeepAlive(license)
	runtime.KeepAlive(log)
	if i := indexByte(log, 0); i >= 0 {
		log = log[:i]
	}
	return strings.TrimSpace(string(log))
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
