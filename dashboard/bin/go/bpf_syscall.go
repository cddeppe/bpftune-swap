package main

// bpf_syscall.go — raw BPF syscalls to read/write BPF map entries without
// forking bpftool.
//
// v0.9.86: introduced to eliminate writebackStreaks forks.
// v0.9.112: added BPF_OBJ_GET_INFO_BY_FD (map identity + geometry).
// v0.9.113 (round 5c): VERIFIED FD acquisition.
//
// FIELD EVIDENCE (al, kernel 6.12 x86_64, journal + /proc/<pid>/fd):
//   - BPF_OBJ_GET_INFO_BY_FD returned EINVAL = the fd used was a valid
//     open file that is NOT a BPF object
//   - the process FD table contained NO anon_inode:bpf-map entry at any
//     time (failure at 00:00:12; FDs 5+ were opened at 00:19), so the
//     "map fd" in use was one of the pre-opened non-BPF fds (0-4:
//     /dev/null, journald sockets, buckets.db, eventpoll)
//   - getMapFD() caches one global FD and never invalidates on EINVAL
//     (its EBADF check compares a WRAPPED error to unix.EBADF — always
//     false), so a bad FD was permanent
//
// THE CERTAIN FIX (no guessing): never trust a FD. bpfMapGetFDByIDVerified
// opens the map AND proves the FD via BPF_OBJ_GET_INFO_BY_FD (id + name
// match) before returning it. If the proof fails, the FD is closed and the
// error names exactly what the FD pointed at (readlink /proc/self/fd/N) —
// so the outcome is always either working syscalls or a self-diagnosing
// journal line. Callers own their FD and close it when done; there is no
// shared cache to poison in the read path.

import (
	"encoding/binary"
	"fmt"
	"os"
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
// (u32 fields at fixed offsets, then the BPF_OBJ_NAME_LEN=16 name at 24).
type bpfMapInfo struct {
	Type       uint32
	ID         uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       string
}

// bpfMapGetFDByID converts a BPF map ID to a file descriptor (raw).
// NOTE: the returned FD is UNVERIFIED — prefer bpfMapGetFDByIDVerified.
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
// BPF_OBJ_GET_INFO_BY_FD.  On a non-BPF fd the kernel answers EINVAL.
func bpfMapGetInfoByFD(fd int) (bpfMapInfo, error) {
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

// bpfCloseFD closes an FD owned by the caller (from bpfMapGetFDByIDVerified).
func bpfCloseFD(fd int) {
	if fd >= 0 {
		unix.Close(fd)
	}
}

// bpfMapGetFDByIDVerified — v0.9.113: acquire a map FD and PROVE it before
// handing it out.  The proof is BPF_OBJ_GET_INFO_BY_FD (which the kernel
// answers with EINVAL for any non-BPF fd) plus an id/name match.  On
// failure the FD is closed and the error states exactly what the fd
// pointed at (readlink /proc/self/fd/N) — either the syscalls work or
// the journal names the culprit file.  No shared cache: callers own the
// FD and close it with bpfCloseFD.
func bpfMapGetFDByIDVerified(mapID uint32, wantName string) (int, bpfMapInfo, error) {
	fd, err := bpfMapGetFDByID(mapID)
	if err != nil {
		return -1, bpfMapInfo{}, err
	}
	info, ierr := bpfMapGetInfoByFD(fd)
	if ierr != nil {
		target := fdTarget(fd)
		bpfCloseFD(fd)
		return -1, bpfMapInfo{}, fmt.Errorf(
			"fd %d returned by BPF_MAP_GET_FD_BY_ID(%d) is not a BPF object (points at %q): %w",
			fd, mapID, target, ierr)
	}
	if info.ID != mapID {
		name := info.Name
		bpfCloseFD(fd)
		return -1, bpfMapInfo{}, fmt.Errorf(
			"BPF_MAP_GET_FD_BY_ID(%d) returned wrong map: id=%d name=%q", mapID, info.ID, name)
	}
	if wantName != "" && !strings.Contains(info.Name, wantName) {
		name := info.Name
		bpfCloseFD(fd)
		return -1, bpfMapInfo{}, fmt.Errorf(
			"BPF_MAP_GET_FD_BY_ID(%d) name %q does not contain %q", mapID, name, wantName)
	}
	return fd, info, nil
}

// fdTarget reports what an FD points at (for diagnostics).
func fdTarget(fd int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "<unknown>"
	}
	return target
}

// bpfMapLookupElem reads a single BPF map entry.
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
// flags: 0 = any (create or update), BPF_NOEXIST = 1, BPF_EXIST = 2.
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
// Contract: pass a NIL key to get the first key, then pass a COPY of the
// previous nextKey to walk forward. (v0.9.86 callers passed a zero-filled
// key to start and aliased curKey/nextKey — both wrong.)
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
