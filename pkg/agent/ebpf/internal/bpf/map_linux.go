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
	"fmt"
	"runtime"
	"unsafe"
)

// MapSpec supplies the metadata CreateMap needs to create an in-kernel BPF map.
// The caller fills it from objects.Maps, generated from the C bpf_map_def.
// CreateMap copies its fields into the Linux BPF_MAP_CREATE attributes. This Go
// structure itself is not passed to the kernel and need not match the C layout.
//
// When extending the C descriptor, update the generator, caller and CreateMap,
// then run make bpf-objects. Go key/value layouts must stay in sync with C,
// including field offsets, padding and byte order.
type MapSpec struct {
	// Name identifies the map and must fit within the kernel's 15-byte limit.
	Name string
	// Type is a Linux BPF_MAP_TYPE_* value, such as ARRAY or LPM_TRIE.
	Type uint32
	// KeySize and ValueSize are byte sizes, usually taken from sizeof in C.
	KeySize   uint32
	ValueSize uint32
	// MaxEntries is the capacity interpreted by Type: an entry count for ARRAY and LPM_TRIE.
	MaxEntries uint32
	// Flags contains BPF_F_* creation flags, such as BPF_F_NO_PREALLOC.
	Flags uint32
}

// mapCreateAttr matches the BPF_MAP_CREATE fields in Linux union bpf_attr.
// The corresponding prefix in include/uapi/linux/bpf.h is:
//
//	struct { /* BPF_MAP_CREATE member of union bpf_attr */
//	    __u32 map_type;
//	    __u32 key_size;
//	    __u32 value_size;
//	    __u32 max_entries;
//	    __u32 map_flags;
//	    __u32 inner_map_fd;
//	    __u32 numa_node;
//	    char  map_name[BPF_OBJ_NAME_LEN];
//	    __u32 map_ifindex;
//	    /* BTF fields and map_extra follow. */
//	};
//
// This Go structure passes only that prefix; omitted trailing attributes are zero.
// Its field offsets and sizes follow the Linux UAPI, independently of MapSpec.
type mapCreateAttr struct {
	mapType    uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	mapFlags   uint32
	innerMapFD uint32
	numaNode   uint32
	mapName    [bpfObjNameLen]byte
	mapIfIndex uint32
}

// mapElemAttr matches the BPF map element command fields in Linux union bpf_attr.
// The corresponding definition in include/uapi/linux/bpf.h is:
//
//	struct { /* BPF_MAP_*_ELEM member of union bpf_attr */
//	    __u32 map_fd;
//	    __aligned_u64 key;
//	    union {
//	        __aligned_u64 value;
//	        __aligned_u64 next_key;
//	    };
//	    __u64 flags;
//	};
//
// __aligned_u64 places key at offset 8, leaving four padding bytes after map_fd.
// The Go padding below preserves that layout. key and value hold userspace buffer
// addresses; the value field occupies the same bytes as the kernel's next_key union member.
type mapElemAttr struct {
	mapFD   uint32
	padding uint32
	key     uint64
	value   uint64
	flags   uint64
}

// CreateMap creates a BPF map and returns its file descriptor.
func CreateMap(def MapSpec) (int, error) {
	mapName, err := objectName(def.Name)
	if err != nil {
		return -1, fmt.Errorf("creating map %s: %w", def.Name, err)
	}
	attr := mapCreateAttr{
		mapType:    def.Type,
		keySize:    def.KeySize,
		valueSize:  def.ValueSize,
		maxEntries: def.MaxEntries,
		mapFlags:   def.Flags,
		mapName:    mapName,
	}
	fd, err := bpf(bpfMapCreate, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, fmt.Errorf("creating map %s: %w", def.Name, err)
	}
	return int(fd), nil
}

// UpdateMapElement updates the value associated with key in the map.
// key and value must point to buffers matching the map's key and value layouts.
func UpdateMapElement(fd int, key, value unsafe.Pointer, flags uint64) error {
	attr := mapElemAttr{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
		flags: flags,
	}
	_, err := bpf(bpfMapUpdateElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// LookupMapElement looks up key in the map and stores its value in value.
// key and value must point to buffers matching the map's key and value layouts.
func LookupMapElement(fd int, key, value unsafe.Pointer) error {
	attr := mapElemAttr{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
		value: uint64(uintptr(value)),
	}
	_, err := bpf(bpfMapLookupElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// DeleteMapElement deletes the entry for key from the map.
// key must point to a buffer matching the map's key layout.
func DeleteMapElement(fd int, key unsafe.Pointer) error {
	attr := mapElemAttr{
		mapFD: uint32(fd),
		key:   uint64(uintptr(key)),
	}
	_, err := bpf(bpfMapDeleteElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(key)
	return err
}
