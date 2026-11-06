package main

// v0_9_128_multimap_test.go — regression tests for the frozen-leaderboard
// root cause found on the user's host (2026-11-06, host "al"):
//
// The daemon re-initialized the tcp_conn tuner BPF mid-run (netdev event at
// daemon start +9 min). Two remote_host_map generations coexisted:
//
//	id 223 (gen 1, created at daemon start) — programs DETACHED at the
//	      reload; nothing ever writes it again. Its contents froze at the
//	      reload instant (Cloudflare ema=726 cnt=20).
//	id 282 (gen 2, created at the reload) — attached programs, live data
//	      (instances=5253, metric_count=187, growing every cycle).
//
// The pre-0.9.128 collector resolved "first name match from bpftool map
// show" = LOWEST id = 223 = the corpse, cached it for 5 min, and re-picked
// it forever. The leaderboard froze at map 223's Nov-4 contents. v0.9.127's
// cache fix was correct but pointless: it faithfully re-read a map that
// never changes.
//
// The fix: resolve ALL matching maps, newest first; read every generation;
// let the NEWEST generation win per bucket; older generations only fill
// buckets the newest doesn't have. Writeback patches every generation.

import (
	"testing"
	"time"
)

// ---- pickRemoteHostMapIDs (resolver core) ----

// The exact map inventory of the user's host (ids/types from
// `bpftool map show`, geometry from `bpftool map show id <id>`).
const hostALMapShow = `[
 {"id":219,"type":"array","name":"tuner_config_ma","bytes_key":4,"bytes_value":4},
 {"id":223,"type":"lru_hash","name":"remote_host_map","bytes_key":16,"bytes_value":1024},
 {"id":225,"type":"percpu_array","name":"remote_host_scr","bytes_key":4,"bytes_value":1024},
 {"id":278,"type":"array","name":"tuner_config_ma","bytes_key":4,"bytes_value":4},
 {"id":282,"type":"lru_hash","name":"remote_host_map","bytes_key":16,"bytes_value":1024},
 {"id":284,"type":"percpu_array","name":"remote_host_scr","bytes_key":4,"bytes_value":1024}
]`

func TestPickRemoteHostMapIDsNewestFirstAndScratchExcluded(t *testing.T) {
	ids, err := pickRemoteHostMapIDs([]byte(hostALMapShow))
	if err != nil {
		t.Fatalf("pickRemoteHostMapIDs: %v", err)
	}
	want := []int{282, 223} // newest generation first; scratch maps excluded
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v — pre-0.9.128 picked %d (the corpse) first",
				ids, want, ids[len(ids)-1])
		}
	}
}

// Some bpftool builds (and the sandbox fake) report geometry as
// key_size/value_size instead of bytes_key/bytes_value.
func TestPickRemoteHostMapIDsAlternateGeometryNames(t *testing.T) {
	in := `[
 {"id":223,"type":"lru_hash","name":"remote_host_map","key_size":16,"value_size":1024},
 {"id":225,"type":"percpu_array","name":"remote_host_scr","key_size":4,"value_size":1024},
 {"id":282,"type":"lru_hash","name":"remote_host_map","key_size":16,"value_size":1024}
]`
	ids, err := pickRemoteHostMapIDs([]byte(in))
	if err != nil {
		t.Fatalf("pickRemoteHostMapIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != 282 || ids[1] != 223 {
		t.Fatalf("ids = %v, want [282 223]", ids)
	}
}

// Ancient bpftool without geometry fields: name-only fallback, still
// newest-first. The scratch maps then enter the candidate list, but
// readRemoteHostMapByID's geometry validation rejects them per-read.
func TestPickRemoteHostMapIDsWithoutGeometryFallsBackToName(t *testing.T) {
	in := `[
 {"id":223,"name":"remote_host_map"},
 {"id":225,"name":"remote_host_scr"},
 {"id":282,"name":"remote_host_map"}
]`
	ids, err := pickRemoteHostMapIDs([]byte(in))
	if err != nil {
		t.Fatalf("pickRemoteHostMapIDs: %v", err)
	}
	want := []int{282, 225, 223}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}
}

func TestPickRemoteHostMapIDsNoMatch(t *testing.T) {
	if _, err := pickRemoteHostMapIDs([]byte(`[{"id":9,"name":"netns_map"}]`)); err == nil {
		t.Fatal("expected error when no remote_host map exists")
	}
}

// ---- mergeBPFMapEntries generation rules ----

// genEntry builds one raw entry: v4-mapped key a.b.c.d, cubic slot 0
// carrying rate_ema/count/instances.
func genEntry(a, b, c, d, gen, rateEMA, count, instances int) map[string]interface{} {
	metrics := make([]interface{}, 16)
	metrics[0] = map[string]interface{}{"rate_ema": rateEMA, "metric_count": count}
	val := map[string]interface{}{"instances": instances, "metrics": metrics}
	key := map[string]interface{}{"in6_u": map[string]interface{}{
		"u6_addr8": []interface{}{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, a, b, c, d},
	}}
	return map[string]interface{}{
		"formatted": map[string]interface{}{"key": key, "value": val},
		"map_gen":   float64(gen),
	}
}

func findByAddr(out []hostEntry, addr string) *hostEntry {
	for i := range out {
		if out[i].Addr == addr {
			return &out[i]
		}
	}
	return nil
}

// THE regression: the live generation must win per bucket even when the
// corpse has far more instances (state-restored corpses routinely do). On
// the user's host the corpse's frozen Cloudflare entry (ema=726) otherwise
// kept overriding the live entry forever.
func TestMergeNewestGenerationWinsPerBucket(t *testing.T) {
	corpse := genEntry(1, 2, 3, 4, 1, 726, 20, 5000)  // gen 1: frozen, fat
	live := genEntry(1, 2, 3, 4, 0, 82, 187, 100)     // gen 0: live, young

	// Order must not matter — process corpse first to prove it's the gen
	// tag (not arrival order) doing the work.
	out, err := mergeBPFMapEntries([]map[string]interface{}{corpse, live})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(out))
	}
	if got := firstCubicEMA(out); got != 82 {
		t.Fatalf("v0.9.128 REGRESSION: cubic rate_ema = %d, want 82 — corpse generation (726) won", got)
	}
	if out[0].Inst != 100 {
		t.Fatalf("instances = %d, want 100 (corpse instances must not be summed in)", out[0].Inst)
	}
	if out[0].Gen != 0 {
		t.Fatalf("bucket Gen = %d, want 0 (newest)", out[0].Gen)
	}
}

// Older generations still fill buckets the newest generation doesn't have
// (graceful degradation, matches the documented Python multi-map behavior).
func TestMergeOlderGenerationFillsMissingBuckets(t *testing.T) {
	out, err := mergeBPFMapEntries([]map[string]interface{}{
		genEntry(5, 6, 7, 8, 1, 726, 20, 5000), // corpse-only bucket
		genEntry(1, 2, 3, 4, 0, 82, 187, 100),  // live bucket
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(out))
	}
	if got := firstCubicEMA([]hostEntry{*findByAddr(out, ResolveBucket("5.6.7.8"))}); got != 726 {
		t.Fatalf("corpse-only bucket rate_ema = %d, want 726 (fallback fill)", got)
	}
}

// Same generation, same /16 prefix (dual-stack-style fold): the v0.9.39
// sum-and-merge behavior must be preserved when no generation conflict
// exists.
func TestMergeSameGenerationStillSums(t *testing.T) {
	out, err := mergeBPFMapEntries([]map[string]interface{}{
		genEntry(1, 2, 3, 4, 0, 100, 10, 3),
		genEntry(1, 2, 9, 9, 0, 200, 20, 5),
	})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 folded bucket, got %d", len(out))
	}
	if out[0].Inst != 8 {
		t.Fatalf("same-gen fold: instances = %d, want 8 (3+5)", out[0].Inst)
	}
}

// Untagged entries (legacy single-map dump) behave exactly as pre-0.9.128.
func TestMergeUntaggedEntriesMergeAsBefore(t *testing.T) {
	e1 := genEntry(1, 2, 3, 4, 0, 100, 10, 3)
	delete(e1, "map_gen")
	e2 := genEntry(1, 2, 9, 9, 0, 200, 20, 5)
	delete(e2, "map_gen")
	out, err := mergeBPFMapEntries([]map[string]interface{}{e1, e2})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out) != 1 || out[0].Inst != 8 {
		t.Fatalf("untagged merge changed: out=%v", out)
	}
}

// ---- resolver cache (5-min TTL, list-based) ----

func TestResolveRemoteHostMapIDsCacheRoundTrip(t *testing.T) {
	maskCacheMu.Lock()
	cachedMapIDs = nil
	mapIDCacheAt = time.Time{}
	maskCacheMu.Unlock()
	t.Cleanup(func() {
		maskCacheMu.Lock()
		cachedMapIDs = nil
		mapIDCacheAt = time.Time{}
		maskCacheMu.Unlock()
	})

	maskCacheMu.Lock()
	cachedMapIDs = []int{282, 223}
	mapIDCacheAt = time.Now()
	maskCacheMu.Unlock()

	ids, err := resolveRemoteHostMapIDs() // would fork bpftool if uncached
	if err != nil {
		t.Fatalf("resolveRemoteHostMapIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != 282 || ids[1] != 223 {
		t.Fatalf("cached resolve returned %v, want [282 223]", ids)
	}

	// Expired cache re-resolves (fork fails in unit-test env → error path).
	maskCacheMu.Lock()
	mapIDCacheAt = time.Now().Add(-2 * mapIDCacheTTL)
	maskCacheMu.Unlock()
}
