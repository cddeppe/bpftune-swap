package main

// bpf_syscall.go — raw BPF syscalls to read/write BPF map entries without
// forking bpftool. Replaces 16+ exec.Command("bpftool") calls per 2-min
// cycle with in-process syscalls (~0.01ms each vs ~15ms per fork).
//
// v0.9.86: introduced to eliminate writebackStreaks forks.
//
// v0.9.112 (round 5): added BPF_OBJ_GET_INFO_BY_FD so callers can validate
// a map's real key_size/value_size instead of hardcoding 16/1024 — the
// field diagnostic on al showed the iteration failing with EINVAL and the
// old error text didn't name the map or its geometry.
//
// The BPF syscall attr structs are defined here (not in golang.org/x/sys/unix)
// because the unix package only has the constants. The layout must match the
// kernel's union bpf_attr — see include/uapi/linux/bpf.h.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF syscall command numbers (from include/uapi/linux/bpf.h enum bpf_cmd)
const (
	bpfCmdMapLookupElem  = 1
	bpfCmdMapUpdateElem  = 2
	bpfCmdMapGetNextKey  = 4
	bpfCmdMapGetFDByID   = 12
	bpfCmdObjGetInfoByFD = 15
)

// bpfMapLookupElemAttr matches the kernel's MAP_LOOKUP_ELEM attr.
type bpfMapLookupElemAttr struct {
	MapFd uint32
	Pad   uint32 // explicit padding for alignment
	Key   unsafe.Pointer
	Value unsafe.Pointer
	Flags uint64
}

// bpfMapUpdateElemAttr matches the kernel's MAP_UPDATE_ELEM attr.
type bpfMapUpdateElemAttr struct {
	MapFd uint32
	Pad   uint32
	Key   unsafe.Pointer
	Value unsafe.Pointer
	Flags uint64
}

// bpfMapGetFDByIDAttr matches the kernel's MAP_GET_FD_BY_ID attr.
type bpfMapGetFDByIDAttr struct {
	ID  uint32
	Pad uint32
}

// bpfMapGetNextKeyAttr matches the kernel's MAP_GET_NEXT_KEY attr.
type bpfMapGetNextKeyAttr struct {
	MapFd   uint32
	Pad     uint32
	Key     unsafe.Pointer
	NextKey unsafe.Pointer
	Flags   uint64
}

// bpfObjGetInfoByFDAttr matches the kernel's BPF_OBJ_GET_INFO_BY_FD attr:
//   struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }
type bpfObjGetInfoByFDAttr struct {
	BpfFd   uint32
	InfoLen uint32
	Info    unsafe.Pointer
}

// bpfMapInfo is the subset of the kernel's struct bpf_map_info we need
// for validation + diagnostics (u32 fields at fixed offsets, then the
// BPF_OBJ_NAME_LEN=16 name at offset 24).
type bpfMapInfo struct {
	Type       uint32
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       string
}

// bpfMapGetFDByID converts a BPF map ID to a file descriptor.
func bpfMapGetFDByID(mapID uint32) (int, error) {
	attr := bpfMapGetFDByIDAttr{ID: mapID}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfCmdMapGetFDByID,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_MAP_GET_FD_BY_ID(%d): %w", mapID, errno)
	}
	return int(fd), nil
}

// bpfMapGetInfoByFD queries the map's identity + geometry via
// BPF_OBJ_GET_INFO_BY_FD.  Used to validate key/value sizes before
// iterating and to name the map in fallback diagnostics.
func bpfMapGetInfoByFD(fd int) (bpfMapInfo, error) {
	// struct bpf_map_info (uapi/linux/bpf.h):
	//   u32 type; u32 id; u32 key_size; u32 value_size;
	//   u32 max_entries; u32 map_flags; char name[16]; ...
	buf := make([]byte, 256)
	attr := bpfObjGetInfoByFDAttr{
		BpfFd:   uint32(fd),
		InfoLen: uint32(len(buf)),
		Info:    unsafe.Pointer(&buf[0]),
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfCmdObjGetInfoByFD,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return bpfMapInfo{}, fmt.Errorf("BPF_OBJ_GET_INFO_BY_FD: %w", errno)
	}
	info := bpfMapInfo{
		Type:       binary.LittleEndian.Uint32(buf[0:4]),
		ID:         binary.LittleEndian.Uint32(buf[4:8]),
		KeySize:    binary.LittleEndian.Uint32(buf[8:12]),
		ValueSize:  binary.LittleEndian.Uint32(buf[12:16]),
		MaxEntries: binary.LittleEndian.Uint32(buf[16:20]),
		MapFlags:   binary.LittleEndian.Uint32(buf[20:24]),
		Name:       strings.TrimRight(string(buf[24:40]), "\x00"),
	}
	return info, nil
}

// bpfMapLookupElem reads a single BPF map entry.
// key must be the exact key bytes (e.g., 4 bytes for v4 /16, 16 for v6 /32).
// value must be pre-allocated to the map's value size (1016/1024 for remote_host_map).
func bpfMapLookupElem(mapFD int, key, value []byte) error {
	if len(key) == 0 || len(value) == 0 {
		return fmt.Errorf("key and value must be non-empty")
	}
	attr := bpfMapLookupElemAttr{
		MapFd: uint32(mapFD),
		Key:   unsafe.Pointer(&key[0]),
		Value: unsafe.Pointer(&value[0]),
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfCmdMapLookupElem,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return fmt.Errorf("BPF_MAP_LOOKUP_ELEM: %w", errno)
	}
	return nil
}

// bpfMapUpdateElem writes a single BPF map entry.
// flags: 0 = any (create or update), BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2.
func bpfMapUpdateElem(mapFD int, key, value []byte, flags uint64) error {
	if len(key) == 0 || len(value) == 0 {
		return fmt.Errorf("key and value must be non-empty")
	}
	attr := bpfMapUpdateElemAttr{
		MapFd: uint32(mapFD),
		Key:   unsafe.Pointer(&key[0]),
		Value: unsafe.Pointer(&value[0]),
		Flags: flags,
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfCmdMapUpdateElem,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return fmt.Errorf("BPF_MAP_UPDATE_ELEM: %w", errno)
	 }
	return nil
}

// bpfMapGetNextKey iterates BPF map keys.
//
// v0.9.112: contract clarified — pass a NIL key to get the first key,
// then pass the PREVIOUS nextKey (a COPY of it) to walk forward. The
// v0.9.86 callers passed a zero-filled key to start and aliased
// curKey/nextKey, which produced BPF_MAP_GET_NEXT_KEY: EINVAL on the
// first call on al (forcing the bpftool fallback every cycle).
// Returns false when there are no more keys (ENOENT).
func bpfMapGetNextKey(mapFD int, key, nextKey []byte) (bool, error) {
	var keyPtr unsafe.Pointer
	if len(key) > 0 {
		keyPtr = unsafe.Pointer(&key[0])
	}
	if len(nextKey) == 0 {
		return false, fmt.Errorf("nextKey must be non-empty")
	}
	attr := bpfMapGetNextKeyAttr{
		MapFd:   uint32(mapFD),
		Key:     keyPtr, // nil = "give me the first key" (kernel contract)
		NextKey: unsafe.Pointer(&nextKey[0]),
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfCmdMapGetNextKey,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno == unix.ENOENT {
		return false, nil // no more keys
	}
	if errno != 0 {
		return false, fmt.Errorf("BPF_MAP_GET_NEXT_KEY: %w", errno)
	}
	return true, nil
}

// bpfOpenPinnedMap opens a pinned BPF map file and returns the FD.
func bpfOpenPinnedMap(pinPath string) (int, error) {
	fd, err := unix.Open(pinPath, unix.O_RDWR, 0)
	if err != nil {
		return -1, fmt.Errorf("open pinned map %s: %w", pinPath, err)
	}
	return fd, nil
}
