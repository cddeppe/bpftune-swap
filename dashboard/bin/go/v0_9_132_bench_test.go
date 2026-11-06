package main

// v0_9_132_bench_test.go — before/after benchmark for the corpse-tax fix
// line (v0.9.132 steady-state + v0.9.133 flat sweep). Run with:
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
//   AFTER  (v0.9.133 steady state): every cycle is FLAT — dump the live
//   map + at most ONE corpse generation (round-robin sweep), merge both,
//   storeGen, fold the cache. No refresh spike, no startup all-gens dump:
//   the two v0.9.132 residual spikes (every-10th-cycle refresh and the
//   startup/reload full pass, whose single-slice live heap at N > ~30
//   walked into the watchdog's no-grace RSS arm) are gone by construction.
//
// Measured at v0.9.132 (3x50 medians, Before vs the v0.9.132 steady path):
// 2 gens 18.0ms/15.0MB -> 9.3ms/7.7MB (1.9x); 8 gens 75.3ms/60.2MB ->
// 10.3ms/8.2MB (7.3x); 16 gens 164.7ms/120.4MB -> 11.2ms/8.9MB (14.7x);
// amortized with the 1-in-10 refresh: 4.5x/6.2x.
//
// Measured at v0.9.133 (3x50 medians, this benchmark's After = live map +
// ONE corpse map per cycle, every cycle): 2 gens 18.4/15.0 -> 18.7ms/
// 15.2MB (1.0x — with a single corpse, sweeping it costs the same dump it
// always had); 8 gens 78.1/60.2 -> 19.2ms/15.9MB (4.1x); 16 gens 167.9/
// 120.4 -> 22.0ms/16.8MB (7.6x); allocations 1,572,064 -> 195,976 (8.0x).
// The After row is FLAT in N — the same ~2-map cost at 2 gens and at 60 —
// and the worst single cycle IS the steady cycle: no refresh spike, no
// startup all-gens dump, no N-sized live slice against the watchdog RSS
// arm. The per-cycle cost is ~2x the v0.9.132 steady path (a corpse map is
// parsed every cycle instead of never); that buys the flat ceiling.
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

// benchAfter measures ONE v0.9.134 STEADY cycle at N gens (nothing in
// the corpse maps changed): parse + merge the live generation, build the
// live-label set, then selectCorpseCarried — a label pass per corpse key
// (real per-cycle work), one value lookup per corpse-carried label key
// (modeled here as the byte copy the syscall performs) plus the
// byte-compare against the cached signature, and ZERO parses (the
// byte-validated cache). The key-set walk itself is
// BPF_MAP_GET_NEXT_KEY syscalls — not measurable in a sandbox, ~µs per
// key, ~10ms at 16 gens x 324 keys. In THIS geometry (disjoint
// generations — every corpse label is corpse-carried) that is the WORST
// case for lookups and label passes.
func benchAfter(b *testing.B, n int) {
	gens := benchFixture(n)

	// Setup (NOT per-op): per-generation key lists + key->value stores,
	// then one warm cycle to populate the byte-validated cache.
	type genStore struct {
		keys [][]byte
		vals map[string][]byte
	}
	stores := make([]genStore, n)
	for g := 0; g < n; g++ {
		stores[g].keys = make([][]byte, len(gens[g]))
		stores[g].vals = make(map[string][]byte, len(gens[g]))
		for i, kv := range gens[g] {
			stores[g].keys[i] = kv.key
			stores[g].vals[string(kv.key)] = kv.val
		}
	}
	buildFeeds := func() []corpseMapFeed {
		feeds := make([]corpseMapFeed, 0, n-1)
		for g := 1; g < n; g++ {
			st := stores[g]
			feeds = append(feeds, corpseMapFeed{
				rank:  g,
				keys:  st.keys,
				label: func(key []byte) (string, bool) { return rawKeyToFinalLabel(key) },
				lookup: func(key []byte) ([]byte, bool) {
					val, ok := st.vals[string(key)]
					if !ok {
						return nil, false
					}
					out := make([]byte, len(val)) // the syscall's copy
					copy(out, val)
					return out, true
				},
			})
		}
		return feeds
	}
	liveRaw := parseGen(gens[0], 0)
	live, err := mergeBPFMapEntriesCore(liveRaw)
	if err != nil {
		b.Fatal(err)
	}
	liveLabels := make(map[string]bool, len(live))
	for idx := range live {
		liveLabels[live[idx].Addr] = true
	}
	selectCorpseCarried(buildFeeds(), liveLabels) // warm the cache

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		live, err := mergeBPFMapEntriesCore(liveRaw)
		if err != nil {
			b.Fatal(err)
		}
		liveLabels := make(map[string]bool, len(live))
		for idx := range live {
			liveLabels[live[idx].Addr] = true
		}
		out := append([]hostEntry(nil), live...)
		out = append(out, selectCorpseCarried(buildFeeds(), liveLabels)...)
		if len(out) != n*benchHostsPerGen {
			b.Fatalf("steady output %d, want %d (corpse-carried labels lost)", len(out), n*benchHostsPerGen)
		}
	}
}

// benchAfterChurn measures the v0.9.134 WORST window: every corpse value
// changed every cycle (a live zombie program updating the old map — or
// the first cycle after a collector restart, with a cold cache). Every
// corpse-carried label re-parses; the label-level merge keeps the peak
// parsed-entry set at ONE label, never the N-gens slice.
func benchAfterChurn(b *testing.B, n int) {
	gens := benchFixture(n)
	type genStore struct {
		keys [][]byte
		vals map[string][]byte
	}
	stores := make([]genStore, n)
	for g := 0; g < n; g++ {
		stores[g].keys = make([][]byte, len(gens[g]))
		stores[g].vals = make(map[string][]byte, len(gens[g]))
		for i, kv := range gens[g] {
			stores[g].keys[i] = kv.key
			stores[g].vals[string(kv.key)] = kv.val
		}
	}
	buildFeeds := func(cycle int) []corpseMapFeed {
		feeds := make([]corpseMapFeed, 0, n-1)
		for g := 1; g < n; g++ {
			st := stores[g]
			churn := cycle // every value "changes" every cycle
			feeds = append(feeds, corpseMapFeed{
				rank:  g,
				keys:  st.keys,
				label: func(key []byte) (string, bool) { return rawKeyToFinalLabel(key) },
				lookup: func(key []byte) ([]byte, bool) {
					val, ok := st.vals[string(key)]
					if !ok {
						return nil, false
					}
					out := make([]byte, len(val))
					copy(out, val)
					// model a value update: flip a byte so the signature
					// compare misses and the label re-parses
					out[0] = byte(churn)
					return out, true
				},
			})
		}
		return feeds
	}
	liveRaw := parseGen(gens[0], 0)
	live, err := mergeBPFMapEntriesCore(liveRaw)
	if err != nil {
		b.Fatal(err)
	}
	liveLabels := make(map[string]bool, len(live))
	for idx := range live {
		liveLabels[live[idx].Addr] = true
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetCorpseViewForBench()
		live, err := mergeBPFMapEntriesCore(liveRaw)
		if err != nil {
			b.Fatal(err)
		}
		liveLabels := make(map[string]bool, len(live))
		for idx := range live {
			liveLabels[live[idx].Addr] = true
		}
		out := append([]hostEntry(nil), live...)
		out = append(out, selectCorpseCarried(buildFeeds(i+1), liveLabels)...)
		if len(out) != n*benchHostsPerGen {
			b.Fatalf("churn output %d, want %d", len(out), n*benchHostsPerGen)
		}
	}
}

func resetCorpseViewForBench() {
	corpseViewMu.Lock()
	corpseView = map[string]*corpseLabelCache{}
	corpseViewMu.Unlock()
}

// The measured entry points. Before = the v0.9.127-131 full dump every
// cycle; After = the v0.9.134 steady cycle (byte-validated cache, zero
// corpse parses); AfterChurn = the worst window (every corpse value
// changed — cold cache or a live zombie).
func BenchmarkCorpseTaxBefore2Gens(b *testing.B)  { benchBefore(b, 2) }
func BenchmarkCorpseTaxBefore8Gens(b *testing.B)  { benchBefore(b, 8) }
func BenchmarkCorpseTaxBefore16Gens(b *testing.B) { benchBefore(b, 16) }

func BenchmarkCorpseTaxAfter2Gens(b *testing.B)  { benchAfter(b, 2) }
func BenchmarkCorpseTaxAfter8Gens(b *testing.B)  { benchAfter(b, 8) }
func BenchmarkCorpseTaxAfter16Gens(b *testing.B) { benchAfter(b, 16) }

func BenchmarkCorpseTaxChurn2Gens(b *testing.B)  { benchAfterChurn(b, 2) }
func BenchmarkCorpseTaxChurn8Gens(b *testing.B)  { benchAfterChurn(b, 8) }
func BenchmarkCorpseTaxChurn16Gens(b *testing.B) { benchAfterChurn(b, 16) }
