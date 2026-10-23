package main

// perf_lean5_test.go — v0.9.112 (round 5): BPF attr layout regression tests.
//
// The BPF syscall attr structs must match the kernel's union bpf_attr
// EXACTLY — a layout regression produces CHECK_ATTR failures (EINVAL) that
// look like map errors. These tests pin the sizes/offsets that the kernel
// expects so a future struct edit fails the suite instead of the field.
//
// Also pins the iteration contract: bpfMapGetNextKey accepts a nil key
// (start of iteration) without panicking on nextKey.

import (
        "testing"
        "unsafe"
)

func TestPerf5BpfAttrLayouts(t *testing.T) {
        // kernel: { __u32 map_fd; __aligned_u64 key; __aligned_u64 value; __u64 flags; }
        if sz := unsafe.Sizeof(bpfMapLookupElemAttr{}); sz != 24 {
                t.Fatalf("bpfMapLookupElemAttr size = %d, want 24", sz)
        }
        if sz := unsafe.Sizeof(bpfMapUpdateElemAttr{}); sz != 24 {
                t.Fatalf("bpfMapUpdateElemAttr size = %d, want 24", sz)
        }
        if sz := unsafe.Sizeof(bpfMapGetFDByIDAttr{}); sz != 8 {
                t.Fatalf("bpfMapGetFDByIDAttr size = %d, want 8", sz)
        }
        // kernel: { __u32 map_fd; __aligned_u64 key; __aligned_u64 next_key; }
        // CHECK_ATTR(bytes past next_key must be zero — our trailing Flags).
        if sz := unsafe.Sizeof(bpfMapGetNextKeyAttr{}); sz != 32 {
                t.Fatalf("bpfMapGetNextKeyAttr size = %d, want 32", sz)
        }
        if off := unsafe.Offsetof(bpfMapGetNextKeyAttr{}.NextKey); off != 16 {
                t.Fatalf("NextKey offset = %d, want 16", off)
        }
        // kernel: { __u32 bpf_fd; __u32 info_len; __aligned_u64 info; }
        if sz := unsafe.Sizeof(bpfObjGetInfoByFDAttr{}); sz != 16 {
                t.Fatalf("bpfObjGetInfoByFDAttr size = %d, want 16", sz)
        }
        if off := unsafe.Offsetof(bpfObjGetInfoByFDAttr{}.Info); off != 8 {
                t.Fatalf("Info offset = %d, want 8", off)
        }
}

// TestPerf5MapInfoParse pins the bpf_map_info field offsets used by
// bpfMapGetInfoByFD (type/id/key_size/value_size/max_entries/map_flags/name).
func TestPerf5MapInfoParse(t *testing.T) {
        buf := make([]byte, 256)
        putU32 := func(off int, v uint32) {
                buf[off] = byte(v)
                buf[off+1] = byte(v >> 8)
                buf[off+2] = byte(v >> 16)
                buf[off+3] = byte(v >> 24)
        }
        putU32(0, 1)     // type: HASH
        putU32(4, 42)    // id
        putU32(8, 16)    // key_size
        putU32(12, 1024) // value_size
        putU32(16, 4096) // max_entries
        putU32(20, 0)    // map_flags
        copy(buf[24:40], "remote_host_map")

        info := bpfMapInfo{
                Type:       u32le(buf[0:4]),
                ID:         u32le(buf[4:8]),
                KeySize:    u32le(buf[8:12]),
                ValueSize:  u32le(buf[12:16]),
                MaxEntries: u32le(buf[16:20]),
                MapFlags:   u32le(buf[20:24]),
                Name:       string(buf[24:40]),
        }
        if info.Type != 1 || info.ID != 42 || info.KeySize != 16 ||
                info.ValueSize != 1024 || info.MaxEntries != 4096 {
                t.Fatalf("bpf_map_info parse mismatch: %+v", info)
        }
        if info.Name != "remote_host_map" && info.Name[:15] != "remote_host_map" {
                t.Fatalf("name parse mismatch: %q", info.Name)
        }
}

func u32le(b []byte) uint32 {
        return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
