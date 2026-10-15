package main

// bpf_syscall.go — raw BPF syscalls to read/write BPF map entries without
// forking bpftool. Replaces 16+ exec.Command("bpftool") calls per 2-min
// cycle with in-process syscalls (~0.01ms each vs ~15ms per fork).
//
// v0.9.86: introduced to eliminate writebackStreaks forks (the biggest
// single source of bpftool subprocess spawns).
//
// The BPF syscall attr structs are defined here (not in golang.org/x/sys/unix)
// because the unix package only has the constants (BPF_MAP_LOOKUP_ELEM etc.)
// but not the attr struct definitions. The layout must match the kernel's
// union bpf_attr — see include/uapi/linux/bpf.h.
//
// All structs use explicit padding to ensure 64-bit alignment matches
// the kernel's expectations. The code uses unsafe.Pointer to pass key/
// value buffer pointers — the caller MUST ensure the buffers stay alive
// for the duration of the syscall (they do — the buffers are local vars).

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF syscall command numbers (from include/uapi/linux/bpf.h enum bpf_cmd)
const (
	bpfCmdMapLookupElem = 1
	bpfCmdMapUpdateElem = 2
	bpfCmdMapGetFDByID  = 12
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

// bpfMapGetFDByID converts a BPF map ID to a file descriptor.
// The caller must close the FD when done (or cache it — the FD stays
// valid until the map is destroyed, which only happens on bpftune reload).
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

// bpfMapLookupElem reads a single BPF map entry.
// key must be the exact key bytes (e.g., 4 bytes for v4 /16, 16 for v6 /32).
// value must be pre-allocated to the map's value size (1016 for remote_host_map).
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
