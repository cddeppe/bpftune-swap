package main

// perf_lean6_test.go — regression test for the FIRST-EVER live run of
// the raw-syscall map read path (v0.9.115).
//
// When the syscall path finally came alive (v0.9.114 fixed the wrong
// BPF command number), it immediately exposed a second latent bug that
// had been hiding behind the first: parseRawKey stored raw key bytes as
// uint8, but toInt() only understands float64/int — every key decoded to
// 0.0.0.0, all hosts merged into one bucket, and the dashboard went
// empty. These tests pin the numeric-type contract between the raw-parse
// path and the merge logic so that class of bug cannot survive the suite.

import (
	"encoding/binary"
	"testing"
)

// TestPerf6RawKeyToInt: every byte of a parsed raw key must round-trip
// through toInt() unchanged (the v0.9.86 bug: uint8 -> toInt -> 0).
func TestPerf6RawKeyToInt(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i + 1) // 1..16 — none of them zero
	}
	km := parseRawKey(key)
	in6u, _ := km["in6_u"].(map[string]interface{})
	arr, _ := in6u["u6_addr8"].([]interface{})
	if len(arr) != 16 {
		t.Fatalf("u6_addr8 length = %d, want 16", len(arr))
	}
	for i, v := range arr {
		if got := toInt(v); got != i+1 {
			t.Fatalf("toInt(u6_addr8[%d]) = %d, want %d — raw key byte lost in type conversion",
				i, got, i+1)
		}
	}
}

// TestPerf6RawEntryMerge: a raw-syscall entry must merge into a real
// host address (v4-mapped key -> dotted quad), NOT "0.0.0.0".
// This is the end-to-end contract with mergeBPFMapEntries.
func TestPerf6RawEntryMerge(t *testing.T) {
	key := make([]byte, 16)
	key[10] = 0xff // v4-mapped marker
	key[11] = 0xff
	key[12], key[13], key[14], key[15] = 1, 2, 3, 4

	val := make([]byte, sizeofRemoteHost)
	// prefixFields[2] = "instances" -> offset 16
	binary.LittleEndian.PutUint64(val[16:], 7)
	// prefixFields[0] = "min_rtt" -> offset 0
	binary.LittleEndian.PutUint64(val[0:], 1234)

	entry := parseRawHostEntry(key, val)
	hosts, err := mergeBPFMapEntries([]map[string]interface{}{entry})
	if err != nil {
		t.Fatalf("mergeBPFMapEntries: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("merged %d hosts, want 1", len(hosts))
	}
	// The v0.9.86 bug collapsed every key to 0.0.0.0 (then dropped).
	if hosts[0].Addr == "" || hosts[0].Addr == "0.0.0.0" {
		t.Fatalf("host addr = %q — raw key decoded as 0.0.0.0 (uint8/toInt regression)", hosts[0].Addr)
	}
	if hosts[0].Inst != 7 {
		t.Fatalf("host Inst = %d, want 7 (instances field decode)", hosts[0].Inst)
	}
	if got := toFloat(hosts[0].V["min_rtt"]); got != 1234 {
		t.Fatalf("min_rtt = %v, want 1234 (value field decode)", got)
	}
}

// TestPerf6ToIntNumericTypes: toInt must understand every numeric type
// the parsers can put into the interface{} maps. (uint8 was the gap that
// made the whole raw path a silent no-op on data.)
func TestPerf6ToIntNumericTypes(t *testing.T) {
	cases := []interface{}{
		float64(42), int(42), int64(42), int32(42), int16(42), int8(42),
		uint(42), uint8(42), uint16(42), uint32(42), uint64(42),
	}
	for _, c := range cases {
		if got := toInt(c); got != 42 {
			t.Fatalf("toInt(%T(%v)) = %d, want 42", c, c, got)
		}
	}
}
