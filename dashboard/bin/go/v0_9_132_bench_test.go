package main

// v0_9_132_bench_test.go — before/after benchmark for the v0.9.132 corpse-tax
// fix. Run with:
//
//      go test -bench=CorpseTax -benchmem -run=XXX ./.
//
// What it measures: the per-30s-cycle MAP WORK of the collector on a host
// with N accumulated remote_host_map generations (tuner reloads), at the
// real fleet geometry (324 hosts/gen, 16-byte key, 1024-byte value):
//
//   BEFORE (v0.9.127-131): every cycle dumps ALL N generations —
//   parseRawHostEntry per entry (~230 Go objects per 1024-byte value) —
//   then mergeBPFMapEntries over the whole N x 324 raw set.
//
//   AFTER  (v0.9.132 steady state): dump ONLY the newest generation
//   (324 parses), merge live-only, then fold the cached corpse
//   contribution back in (struct appends, no parsing). The every-10th-cycle
//   refresh pass costs the same as BEFORE; the amortized figure is
//   0.9*steady + 0.1*refresh.
//
// Scenario: DISJOINT address spaces per generation (each corpse gen holds
// 324 hosts the live map has NOT re-seen), so every corpse-only label
// survives — the WORST case for the new path (fold appends all of them
// every cycle) and therefore a LOWER BOUND on the improvement. With
// overlapping hosts the new path does even less work and the old path
// does the same.
//
// The BPF syscalls themselves (2 per entry + ~3 per map: GET_FD_BY_ID +
// GET_INFO + close) cannot run in a sandbox; they scale with the same
// N -> 1 map reduction and are reported as derived counts, not measured
// time.

import (
        "encoding/binary"
        "testing"
)

const benchHostsPerGen = 324 // the real main host's fleet size

// benchKey builds the IPv4-mapped 16-byte key for a host. Hosts are spread
// across DISTINCT /16 buckets (first two octets carry the global bucket
// index) because the default prefix4 canon is /16 — real fleets are
// internet peers, i.e. naturally distinct /16s. Generations are disjoint:
// gen g owns bucket indices [g*324, (g+1)*324).
func benchKey(gen, i int) []byte {
        key := make([]byte, 16)
        key[10], key[11] = 0xff, 0xff // IPv4-mapped
        h := gen*benchHostsPerGen + i
        key[12] = byte(h / 256)
        key[13] = byte(h % 256)
        key[14] = byte(i%251 + 1)
        key[15] = 7
        return key
}

// benchValue builds a fully populated 1024-byte remote_host value.
func benchValue(gen int) []byte {
        val := make([]byte, sizeofRemoteHost)
        for f := 0; f < 14; f++ { // prefix u64 fields
                binary.LittleEndian.PutUint64(val[f*8:], uint64(1000+f+gen))
        }
        for b := 0; b < rateHistBins; b++ { // rate_hist u32 bins + u64 sum
                binary.LittleEndian.PutUint32(val[offRateHist+b*4:], uint32(b*7+gen))
        }
        binary.LittleEndian.PutUint64(val[offRateHist+rateHistBins*4:], uint64(9000+gen))
        for m := 0; m < numTCPConnMetrics; m++ { // metrics[16], 48 bytes each
                base := offMetricsArray + m*sizeofTCPConnMetric
                binary.LittleEndian.PutUint64(val[base+0:], uint64(m))
                binary.LittleEndian.PutUint64(val[base+8:], uint64(m*3))
                binary.LittleEndian.PutUint64(val[base+16:], uint64(m*5))
                binary.LittleEndian.PutUint64(val[base+24:], uint64(90+m))
                binary.LittleEndian.PutUint16(val[base+32:], uint16(10+m)) // sockets_alive
                binary.LittleEndian.PutUint16(val[base+34:], uint16(8+m))  // sockets_good
                binary.LittleEndian.PutUint16(val[base+36:], uint16(6+m))  // sockets_proved
                binary.LittleEndian.PutUint16(val[base+38:], uint16(80+m)) // rate_ema
                binary.LittleEndian.PutUint16(val[base+40:], uint16(50+m)) // swap_score
                val[base+42] = byte(m % 7)                                 // bad_streak
                val[base+43] = byte(m % 5)                                 // null_streak
        }
        return val
}

type benchKV struct{ key, val []byte }

// benchFixture prebuilds the raw key/value byte pairs per generation so the
// benchmark loops measure ONLY per-cycle work (parse + merge + fold), not
// fixture construction.
func benchFixture(n int) [][]benchKV {
        gens := make([][]benchKV, n)
        for g := 0; g < n; g++ {
                gens[g] = make([]benchKV, benchHostsPerGen)
                for i := 0; i < benchHostsPerGen; i++ {
                        gens[g][i] = benchKV{benchKey(g, i), benchValue(g)}
                }
        }
        return gens
}

// parseGen is what readRemoteHostMapByID does per entry during a dump.
func parseGen(gens []benchKV, gen int) []map[string]interface{} {
        out := make([]map[string]interface{}, 0, len(gens))
        for _, kv := range gens {
                e := parseRawHostEntry(kv.key, kv.val)
                e["map_gen"] = float64(gen)
                out = append(out, e)
        }
        return out
}

// BenchmarkCorpseTaxBeforeN measures ONE v0.9.127-131 cycle at N gens:
// parse every entry of ALL N generations, then the full all-gens merge.
func benchBefore(b *testing.B, n int) {
        gens := benchFixture(n)
        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                var all []map[string]interface{}
                for g := 0; g < n; g++ {
                        all = append(all, parseGen(gens[g], g)...)
                }
                out, err := mergeBPFMapEntries(all)
                if err != nil {
                        b.Fatal(err)
                }
                if len(out) != n*benchHostsPerGen {
                        b.Fatalf("merge output %d, want %d", len(out), n*benchHostsPerGen)
                }
        }
}

// benchAfter measures ONE v0.9.132 STEADY cycle at N gens: parse ONLY the
// live generation (gen 0), merge live-only, fold the cached corpse labels.
// The cache is built once from a full refresh pass — exactly the runtime
// cadence (1 refresh per 10 cycles).
func benchAfter(b *testing.B, n int) {
        gens := benchFixture(n)

        // Refresh pass (setup, NOT per-op): full all-gens dump + merge, rebuild.
        var all []map[string]interface{}
        for g := 0; g < n; g++ {
                all = append(all, parseGen(gens[g], g)...)
        }
        merged, err := mergeBPFMapEntries(all)
        if err != nil {
                b.Fatal(err)
        }
        var cache corpseGenCache
        ids := make([]int, n)
        for i := range ids {
                ids[i] = 500 - i // newest first, like resolveRemoteHostMapIDs
        }
        cache.rebuild(ids, merged, 1)

        b.ReportAllocs()
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
                live, err := mergeBPFMapEntries(parseGen(gens[0], 0))
                if err != nil {
                        b.Fatal(err)
                }
                out := cache.fold(live)
                if len(out) != n*benchHostsPerGen {
                        b.Fatalf("steady output %d, want %d (corpse-only labels lost)", len(out), n*benchHostsPerGen)
                }
        }
}

func BenchmarkCorpseTaxBefore2Gens(b *testing.B)  { benchBefore(b, 2) }
func BenchmarkCorpseTaxBefore8Gens(b *testing.B)  { benchBefore(b, 8) }
func BenchmarkCorpseTaxBefore16Gens(b *testing.B) { benchBefore(b, 16) }

func BenchmarkCorpseTaxAfter2Gens(b *testing.B)  { benchAfter(b, 2) }
func BenchmarkCorpseTaxAfter8Gens(b *testing.B)  { benchAfter(b, 8) }
func BenchmarkCorpseTaxAfter16Gens(b *testing.B) { benchAfter(b, 16) }
