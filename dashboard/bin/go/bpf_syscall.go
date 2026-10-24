package main

// bpf_syscall.go — raw BPF syscalls to read/write BPF map entries without
// forking bpftool.
//
// v0.9.86: introduced to eliminate writebackStreaks forks.
// v0.9.112: added BPF_OBJ_GET_INFO_BY_FD (map identity + geometry).
// v0.9.113: VERIFIED FD acquisition (never trust a raw FD).
// v0.9.114 (FINAL): root cause proven by strace on al (kernel 6.12):
//
//   1422703 bpf(BPF_MAP_GET_NEXT_ID, {start_id=141, next_id=0 => 142}, 8) = 0
//   1422703 bpf(BPF_OBJ_GET_INFO_BY_FD, {info={bpf_fd=0, ...}}, 16) = -1 EBADF
//
//   The v0.9.86 constant map for "MAP_GET_FD_BY_ID" sent command 12 —
//   but on this kernel 12 is BPF_MAP_GET_NEXT_ID. That command SUCCEEDS
//   with rc=0 (it writes the next map id into the attr). The code read
//   rc=0 as "fd 0" and every subsequent bpf fd operation ran against
//   fd 0 = /dev/null -> "not a BPF object".  This explains every symptom
//   ever observed (impossible (0,0,0) return, /dev/null target, EINVALs,
//   never once working since v0.9.86).
//
//   Ground truth from the same strace (bpftool's WORKING calls):
//     - the ID-command family attr is 12 bytes {u32 id; u32 next_id;
//       u32 open_flags} (bpftool passes size 12; our 8-byte attr was
//       undersized)
//     - BPF_MAP_GET_FD_BY_ID is 13 or 14 (adjacent to 12; bpftool uses
//       it successfully, strace labels it)
//     - BPF_OBJ_GET_INFO_BY_FD = 15 confirmed by both processes
//
//   THE FIX IS CONSTRUCTION-PROOF: bpfMapGetFDByIDVerified probes BOTH
//   candidate commands and keeps whichever FD VERIFIES as the requested
//   map (BPF_OBJ_GET_INFO_BY_FD id + name match). A wrong command number
//   can never yield a wrong map — it either errors or gets rejected by
//   verification. Whichever candidate survives is correct by definition,
//   and the choice is logged once. There is no residual guesswork.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF syscall command numbers (enum bpf_cmd).
const (
	bpfCmdMapLookupElem  = 1
	bpfCmdMapUpdateElem  = 2
	bpfCmdMapGetNextKey  = 4
	bpfCmdObjGetInfoByFD = 15

	// v0.9.114: strace-proven numbering on kernel 6.12 (al):
	//   12 = BPF_MAP_GET_NEXT_ID (NOT MAP_GET_FD_BY_ID — the old constant
	//   bug that made the syscall path a no-op since v0.9.86)
	bpfCmdMapGetNextID = 12
	// MAP_GET_FD_BY_ID is one of these two; the verifier decides which.
	bpfCmdMapGetFDByIDSysA = 13
	bpfCmdMapGetFDByIDSysB = 14
)

// bpfIDAttr matches the kernel's shared ID-command attr (12 bytes):
//   struct { __u32 start_id/map_id; __u32 next_id; __u32 open_flags; }
// strace shows bpftool passing size 12 for MAP_GET_NEXT_ID /
// MAP_GET_FD_BY_ID. (v0.9.86 used an 8-byte struct — undersized.)
type bpfIDAttr struct {
	ID        uint32
	NextID    uint32
	OpenFlags uint32
}

// bpfMapLookupElemAttr matches the kernel's MAP_LOOKUP_ELEM /
// MAP_UPDATE_ELEM attr (32 bytes with flags).
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

// bpfMapGetNextKeyAttr matches the kernel's MAP_GET_NEXT_KEY attr
// (24 bytes — the kernel attr has NO flags field; the v0.9.86 struct's
// trailing Flags made the struct 32 bytes).
type bpfMapGetNextKeyAttr struct {
	MapFd   uint32
	Pad     uint32
	Key     unsafe.Pointer
	NextKey unsafe.Pointer
}

// bpfObjGetInfoByFDAttr matches the kernel's BPF_OBJ_GET_INFO_BY_FD attr:
//   struct { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }
// (16 bytes — strace-confirmed from both our process and bpftool.)
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

// bpfMapGetFDByIDSyscall issues ONE candidate MAP_GET_FD_BY_ID command.
// Returns the raw result. (If cmd is actually GET_NEXT_ID, success comes
// back as rc=0 — a NON-fd — which verification downstream rejects.)
func bpfMapGetFDByIDSyscall(cmd uintptr, mapID uint32) (int, error) {
	attr := bpfIDAttr{ID: mapID}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		cmd,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("bpf(cmd=%d, map_id=%d): %w", cmd, mapID, errno)
	}
	return int(fd), nil
}

// bpfMapGetInfoByFD queries the map's identity + geometry via
// BPF_OBJ_GET_INFO_BY_FD.  On a non-BPF fd the kernel answers an error.
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

// bpfCloseFD closes an FD owned by the caller.  NEVER closes fd 0-2
// (stdin/stdout/stderr) even if a bogus result hands one back — the
// v0.9.86 bug returned "fd 0" and earlier revisions could have closed
// the process's stdin.
func bpfCloseFD(fd int) {
	if fd > 2 {
		unix.Close(fd)
	}
}

// fdTarget reports what an FD points at (for diagnostics).
func fdTarget(fd int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return "<unknown>"
	}
	return target
}

// mapFDByIDCmdMu guards the one-time "which command worked" log line.
var (
	mapFDByIDCmdMu   sync.Mutex
	mapFDByIDCmdNote string
)

func noteMapFDByIDCmd(cmd uintptr) {
	mapFDByIDCmdMu.Lock()
	defer mapFDByIDCmdMu.Unlock()
	if mapFDByIDCmdNote == "" {
		mapFDByIDCmdNote = fmt.Sprintf("cmd %d", cmd)
		fmt.Fprintf(os.Stderr, "bpf: BPF_MAP_GET_FD_BY_ID resolved as command %d (verified)\n", cmd)
	}
}

// bpfMapGetFDByIDVerified — acquire a map FD and PROVE it before handing
// it out.  Probes the candidate MAP_GET_FD_BY_ID commands; the proof is
// BPF_OBJ_GET_INFO_BY_FD (id AND name must match).  A wrong command
// number can never yield a wrong map — it either errors or is rejected
// by verification.  On total failure the error names every candidate's
// fate (including readlink of any bogus fd).  Caller owns the FD.
func bpfMapGetFDByIDVerified(mapID uint32, wantName string) (int, bpfMapInfo, error) {
	var firstErr error
	for _, cmd := range []uintptr{bpfCmdMapGetFDByIDSysA, bpfCmdMapGetFDByIDSysB} {
		fd, err := bpfMapGetFDByIDSyscall(cmd, mapID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		info, ierr := bpfMapGetInfoByFD(fd)
		if ierr == nil && info.ID == mapID &&
			(wantName == "" || strings.Contains(info.Name, wantName)) {
			noteMapFDByIDCmd(cmd)
			return fd, info, nil
		}
		// Rejected — record why, close the fd (never fd 0-2), try next.
		target := fdTarget(fd)
		bpfCloseFD(fd)
		if firstErr == nil {
			if ierr != nil {
				firstErr = fmt.Errorf("cmd %d: fd %d is not a BPF object (points at %q): %w",
					cmd, fd, target, ierr)
			} else {
				firstErr = fmt.Errorf("cmd %d: fd %d verified as WRONG map (id=%d name=%q, want id=%d name~%q)",
					cmd, fd, info.ID, info.Name, mapID, wantName)
			}
		}
	}
	return -1, bpfMapInfo{}, fmt.Errorf("BPF_MAP_GET_FD_BY_ID(%d): all candidates rejected: %w", mapID, firstErr)
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
// previous nextKey to walk forward.  Returns false when there are no
// more keys (ENOENT).
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
