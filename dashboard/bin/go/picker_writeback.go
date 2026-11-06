package main

// picker_writeback.go — collector-side reanchor substitute (v0.9.129).
//
// ROOT CAUSE this file patches around (proven in source, 2026-11-06):
// rate_best_i / rate_best_v — the swap target the BPF trigger reads
// (tcp_conn_tuner.bpf.c) — has exactly ONE writer: the tuner's reanchor
// worker thread. That thread captures the remote_host_map fd ONCE at
// tuner init (start_reanchor, src/tcp_conn_tuner.c) and the
// reanchor_started guard means a later tuner re-init never refreshes it.
// After the mid-run BPF re-init (the same reload behind the v0.9.128
// corpse/live map pair), the LIVE map generation stopped receiving
// reanchor updates entirely: BPF kept updating metrics (rates / votes /
// scores) around a tracker frozen at its state-restore value. Every
// swap fired at the stale target; the collector, recomputing the pick
// from the same map's fresh metrics, showed the true leader.
//
// This file recomputes the 8 tracker fields (best_i/best_v,
// second_i/second_v, rate_best_i/rate_best_v, rate_second_i/
// rate_second_v) with the EXACT reanchor formula from the deployed
// tuner (reanchor_best(), src/tcp_conn_tuner.c, as of tuner v0.4.106)
// from each bucket's own metrics, and seq-guarded patches EVERY map
// generation, newest first. Hooked from collect() on odd cycles,
// alternating with the streak writeback under the shared writebackMu.
//
// Bit-exact with the C — if the tuner reanchor ever resumes, both
// writers compute identical values; conflict-free:
//
//   - pass 1 (trusted minimum): metric_count >= MIN_LEADER_TRUST (10),
//     metric_value not 0 and not ~0ULL; the leader is the minimum value
//     among trusted candidates.
//   - pass 2 (second-best): metric_count > 0, not the leader,
//     metric_value >= best_v (preserves the best_v <= second_v
//     invariant the BPF vote path maintains); minimum among those.
//   - pass 3 (0.4.45/0.4.56/0.4.60 rate-EMA leader):
//     weighted = rate_ema * swap_score / 256 * 16 / (16 + bad*4 + null*2),
//     gated by metric_count >= MIN_LEADER_TRUST and rate_ema != 0, with
//     the v0.4.99 ZERO-SCORE SKIP: a legitimately-zeroed swap_score
//     stays excluded — no reset-to-neutral (removed in 0.4.89 M1).
//     rate_best_v stores the RAW rate_ema; BPF's trigger math needs a
//     rate. rate_second_* propagates the runner-up (0.4.70 fallback
//     target).
//   - 0.4.63 stale-score init: entries with swap_score == 0 and
//     metric_count > 0 are re-initialized to SWAP_SCORE_NEUTRAL (256)
//     in the same write, so a stale score clears within a cycle.
//   - no trusted leader: the whole tracker is forced to the empty state
//     so the swap path sees "no leader" rather than a stale value.
//
// Deliberately NOT ported: the tuner's rate_hist_decay + p99 refresh of
// max_rate_delivered (0.4.43 reference fix). That field is tuner-owned;
// doing it here too would decay the histogram twice as fast the day the
// tuner-side reanchor fix lands. Not touching it keeps the two writers
// conflict-free by construction.
//
// The proper long-term fix is tuner-side (refresh the reanchor fd on BPF
// re-init) for the next tuner .deb; this patch keeps swaps correct until
// then and coexists with it.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// Prefix field byte offsets in the 1024-byte remote_host value — 14 x u64
// at offsets 0..111, in the exact order of struct remote_host
// (src/tcp_conn_tuner.h) / prefixFields (streak_writeback.go).
const (
	offMinRtt           = 0
	offMaxRateDelivered = 8
	offInstances        = 16
	offSelectionCount   = 24
	offBestI            = 32
	offBestV            = 40
	offSecondI          = 48
	offSecondV          = 56
	offRateBestI        = 64
	offRateBestV        = 72
	offRateSecondI      = 80
	offRateSecondV      = 88
	offRttLowStreak     = 96
	offRttLowMin        = 104
)

// tcp_conn_metric slot sub-offsets (48-byte slots at offMetricsArray).
// offMetricBadStreak (42) / offMetricNullStreak (43) already live in
// streak_writeback.go.
const (
	offMetricStateFlags    = 0
	offMetricGreedyCount   = 8
	offMetricCount         = 16
	offMetricValue         = 24
	offMetricSocketsAlive  = 32
	offMetricSocketsGood   = 34
	offMetricSocketsProved = 36
	offMetricRateEMA       = 38
	offMetricSwapScore     = 40
)

// swapScoreNeutral mirrors SWAP_SCORE_NEUTRAL (src/tcp_conn_tuner.h):
// 256 = neutral per-(bucket,alg) swap outcome score.
const swapScoreNeutral = 256

// metricBase returns the byte offset of metric slot i in the value.
func metricBase(i int) int { return offMetricsArray + i*sizeofTCPConnMetric }

// ============================================================================
// Pure core — bit-exact port of reanchor_best() passes 1/2/3
// ============================================================================

// reanchorOutcome is the recomputed tracker state for one bucket plus
// the 0.4.63 score re-inits to apply in the same write.
type reanchorOutcome struct {
	bestI, bestV             uint64
	secondI, secondV         uint64
	rateBestI, rateBestV     uint64
	rateSecondI, rateSecondV uint64
	scoreInits               []int // metric indices: swap_score 0 -> 256 (0.4.63)
}

// computeReanchor recomputes the 8 tracker fields from one bucket's own
// metrics — a bit-exact port of reanchor_best() passes 1/2/3 from the
// deployed tuner (v0.4.106), including the v0.4.99 zero-score skip and
// the 0.4.63 stale-score init list. buf is the raw 1024-byte
// remote_host_map value. Pure function: no map access, unit-testable.
func computeReanchor(buf []byte) reanchorOutcome {
	var oc reanchorOutcome
	if len(buf) < sizeofRemoteHost {
		return oc
	}

	// ---- Pass 1: trusted minimum. ----
	bestI := ^uint64(0)
	var bestV uint64
	for i := 0; i < numTCPConnMetrics; i++ {
		b := metricBase(i)
		v := binary.LittleEndian.Uint64(buf[b+offMetricValue:])
		cnt := binary.LittleEndian.Uint64(buf[b+offMetricCount:])
		if cnt < minLeaderTrust {
			continue
		}
		if v == 0 || v == ^uint64(0) {
			continue // unset sentinel
		}
		if bestV == 0 || v < bestV {
			bestI = uint64(i)
			bestV = v
		}
	}

	// ---- Pass 2: second-best. ----
	secondI := ^uint64(0)
	var secondV uint64
	if bestV != 0 {
		for i := 0; i < numTCPConnMetrics; i++ {
			b := metricBase(i)
			v := binary.LittleEndian.Uint64(buf[b+offMetricValue:])
			cnt := binary.LittleEndian.Uint64(buf[b+offMetricCount:])
			if uint64(i) == bestI || cnt == 0 {
				continue
			}
			if v == 0 || v == ^uint64(0) {
				continue
			}
			if v < bestV {
				continue // keeps best_v <= second_v
			}
			if secondV == 0 || v < secondV {
				secondI = uint64(i)
				secondV = v
			}
		}
	}

	// ---- Pass 3 (0.4.45/0.4.56/0.4.60/0.4.99): rate-EMA leader. ----
	rateBI, rate2I := ^uint64(0), ^uint64(0)
	var rateBV, rate2V, bestWeighted, secondWeighted uint64
	for j := 0; j < numTCPConnMetrics; j++ {
		b := metricBase(j)
		rv := uint64(binary.LittleEndian.Uint16(buf[b+offMetricRateEMA:]))
		cnt := binary.LittleEndian.Uint64(buf[b+offMetricCount:])
		if cnt < minLeaderTrust {
			continue
		}
		if rv == 0 {
			continue
		}
		ss := uint64(binary.LittleEndian.Uint16(buf[b+offMetricSwapScore:]))
		if ss == 0 {
			// v0.4.99: skip zeroed scores. A legitimately-zeroed score
			// stays excluded (0.4.89 M1 removed reset-to-neutral); the
			// bad_streak penalty still applies to the others, and a
			// recovering algo climbs back via the 0.4.63 init below or
			// the EMA-rise path.
			continue
		}
		weighted := rv * ss / swapScoreNeutral
		{
			// 0.4.60: demote, don't ban — penalty 16/(16 + bad*4 + null*2).
			pen := uint64(16) + uint64(buf[b+offMetricBadStreak])*4 + uint64(buf[b+offMetricNullStreak])*2
			weighted = weighted * 16 / pen
		}
		if rateBV == 0 || weighted > bestWeighted {
			if rateBI != ^uint64(0) {
				rate2I, rate2V, secondWeighted = rateBI, rateBV, bestWeighted
			}
			rateBI, rateBV, bestWeighted = uint64(j), rv, weighted
		} else if weighted > secondWeighted && uint64(j) != rateBI {
			rate2I, rate2V, secondWeighted = uint64(j), rv, weighted
		}
	}
	if rateBV != 0 {
		oc.rateBestI = rateBI
	}
	oc.rateBestV = rateBV
	if rate2V != 0 {
		oc.rateSecondI = rate2I // 0.4.70 second-best rate target
	}
	oc.rateSecondV = rate2V

	// ---- No trusted leader: force the tracker to the empty state. ----
	if bestV == 0 {
		oc.bestI, oc.bestV = 0, 0
		oc.secondI, oc.secondV = 0, 0
	} else {
		oc.bestI, oc.bestV = bestI, bestV
		oc.secondI = 0
		if secondV != 0 {
			oc.secondI = secondI
		}
		oc.secondV = secondV
	}

	// ---- 0.4.63: stale swap_score=0 entries WITH votes re-init to 256.
	// Runs AFTER pass 3, exactly like the C: a zeroed score still loses
	// this cycle's pick, and is re-admitted from the next one on. ----
	for jj := 0; jj < numTCPConnMetrics; jj++ {
		b := metricBase(jj)
		ss := binary.LittleEndian.Uint16(buf[b+offMetricSwapScore:])
		cnt := binary.LittleEndian.Uint64(buf[b+offMetricCount:])
		if ss == 0 && cnt > 0 {
			oc.scoreInits = append(oc.scoreInits, jj)
		}
	}
	return oc
}

// reanchorUnchanged mirrors the C 'unchanged' early-continue: true when
// no 0.4.63 score inits are pending and all 8 tracker fields already
// hold the recomputed values. (The C also compares max_rate_delivered
// around its histogram decay; that field is not touched here — see the
// file header.) When the tuner-side reanchor is alive and already wrote
// the correct values, this keeps the collector's writer silent.
func reanchorUnchanged(buf []byte, oc reanchorOutcome) bool {
	if len(buf) < sizeofRemoteHost {
		return true
	}
	if len(oc.scoreInits) > 0 {
		return false
	}
	return binary.LittleEndian.Uint64(buf[offBestI:]) == oc.bestI &&
		binary.LittleEndian.Uint64(buf[offBestV:]) == oc.bestV &&
		binary.LittleEndian.Uint64(buf[offSecondI:]) == oc.secondI &&
		binary.LittleEndian.Uint64(buf[offSecondV:]) == oc.secondV &&
		binary.LittleEndian.Uint64(buf[offRateBestI:]) == oc.rateBestI &&
		binary.LittleEndian.Uint64(buf[offRateBestV:]) == oc.rateBestV &&
		binary.LittleEndian.Uint64(buf[offRateSecondI:]) == oc.rateSecondI &&
		binary.LittleEndian.Uint64(buf[offRateSecondV:]) == oc.rateSecondV
}

// applyReanchor writes the 8 tracker fields and the 0.4.63 score inits
// into buf. Every other byte is preserved — the same write set as the C
// (minus the tuner-owned rate_hist / max_rate_delivered refresh).
func applyReanchor(buf []byte, oc reanchorOutcome) {
	if len(buf) < sizeofRemoteHost {
		return
	}
	binary.LittleEndian.PutUint64(buf[offBestI:], oc.bestI)
	binary.LittleEndian.PutUint64(buf[offBestV:], oc.bestV)
	binary.LittleEndian.PutUint64(buf[offSecondI:], oc.secondI)
	binary.LittleEndian.PutUint64(buf[offSecondV:], oc.secondV)
	binary.LittleEndian.PutUint64(buf[offRateBestI:], oc.rateBestI)
	binary.LittleEndian.PutUint64(buf[offRateBestV:], oc.rateBestV)
	binary.LittleEndian.PutUint64(buf[offRateSecondI:], oc.rateSecondI)
	binary.LittleEndian.PutUint64(buf[offRateSecondV:], oc.rateSecondV)
	for _, j := range oc.scoreInits {
		binary.LittleEndian.PutUint16(buf[metricBase(j)+offMetricSwapScore:], swapScoreNeutral)
	}
}

// pickerEligible is the display-side mirror of the picker's own pass-3
// eligibility gate: >= MIN_LEADER_TRUST votes, non-zero swap score
// (v0.4.99 skip), non-zero rate. The leaderboard pick highlight and
// row greying (dashboard.js renderMetric) enforce the same rule, with
// the threshold carried via meta.json (min_leader_trust).
func pickerEligible(cnt, swapScore, rateEMA int) bool {
	return cnt >= minLeaderTrust && swapScore != 0 && rateEMA != 0
}

// ============================================================================
// Map access — every generation, newest first
// ============================================================================

// keyArgsFromRaw converts a raw 16-byte map key to bpftool-style hex
// string args, so lookups/updates reuse mapLookupBytes / mapUpdateBytes
// (syscall-first with bpftool fallback + EBADF cache invalidation).
func keyArgsFromRaw(key []byte) []string {
	args := make([]string, len(key))
	for i, b := range key {
		args[i] = fmt.Sprintf("%02x", b)
	}
	return args
}

// remoteHostMapKeys returns every 16-byte key in the map. Primary path:
// BPF_MAP_GET_NEXT_KEY via the cached fd (no bpftool fork). Fallback:
// `bpftool --json map dump` + key extraction (same parsing shape as
// detectMaskUncached).
func remoteHostMapKeys(mapID int) ([][]byte, error) {
	if fd, err := getMapFD(mapID); err == nil {
		var keys [][]byte
		cur := []byte(nil) // nil key = "give me the first key" (syscall contract)
		next := make([]byte, 16)
		for {
			hasMore, err := bpfMapGetNextKey(fd, cur, next)
			if err != nil || !hasMore {
				break
			}
			k := make([]byte, 16)
			copy(k, next)
			keys = append(keys, k)
			cur = k
		}
		return keys, nil
	}

	out, err := exec.Command("bpftool", "--json", "map", "dump", "id", strconv.Itoa(mapID)).Output()
	if err != nil {
		return nil, fmt.Errorf("bpftool map dump id %d: %w", mapID, err)
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("bpftool map dump json: %w", err)
	}
	var keys [][]byte
	for _, entry := range data {
		formatted, _ := entry["formatted"].(map[string]interface{})
		if formatted == nil {
			formatted = entry
		}
		keyData, _ := formatted["key"].(map[string]interface{})
		if keyData == nil {
			continue
		}
		in6u, _ := keyData["in6_u"].(map[string]interface{})
		if in6u == nil {
			continue
		}
		addrBytes, _ := in6u["u6_addr8"].([]interface{})
		if len(addrBytes) != 16 {
			continue
		}
		k := make([]byte, 16)
		for i, v := range addrBytes {
			k[i] = byte(toInt(v))
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ============================================================================
// Entry point — called from collect() on odd cycles
// ============================================================================

// pickerWriteback is the per-cycle entry point (v0.9.129). Called from
// collect() on ODD cycles, alternating with writebackStreaks; both
// share writebackMu so the two writeback types never overlap. The
// TryLock-skip discipline mirrors the streak writeback.
//
// Returns (hostsPatched, fieldsPatched) for logging.
func (c *Collector) pickerWriteback() (hostsPatched, fieldsPatched int) {
	if !writebackMu.TryLock() {
		fmt.Fprintf(os.Stderr, "[picker] skipped (previous writeback still running)\n")
		return 0, 0
	}
	defer writebackMu.Unlock()
	// v0.9.131: close this cycle's map fds before releasing the lock
	// (LIFO: runs before the Unlock) — see closeMapFDs.
	defer closeMapFDs()

	mapIDs, err := resolveRemoteHostMapIDs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[picker] no remote_host_map: %v\n", err)
		return 0, 0
	}

	// v0.9.128 rules: patch EVERY remote_host_map generation, NEWEST
	// FIRST. After a mid-run tuner reload the live map is the newest;
	// userspace cannot prove liveness cheaply, and detached generations
	// are inert — a patch there is harmless. The seq guard below rejects
	// torn/raced buffers on the live map.
	scanned, unchanged, seqBusy := 0, 0, 0
	for _, mapID := range mapIDs {
		keys, err := remoteHostMapKeys(mapID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[picker] map %d: %v\n", mapID, err)
			continue
		}
		for _, key := range keys {
			keyArgs := keyArgsFromRaw(key)

			// Lookup current value (1 BPF map lookup per bucket).
			buf, err := mapLookupBytes(mapID, keyArgs)
			if err != nil || len(buf) != sizeofRemoteHost {
				continue
			}
			scanned++

			// Torn-read guard: an odd seq means the kernel is mid-update
			// on this bucket (seq wraps every multi-field update). Skip
			// this cycle; the next one retries. Mirrors the daemon's own
			// readers ("BPF mid-update") and the C reanchor's retry cap.
			seq := binary.LittleEndian.Uint64(buf[sizeofRemoteHost-sizeofSeqField:])
			if seq&1 == 1 {
				seqBusy++
				continue
			}

			oc := computeReanchor(buf)

			// C 'unchanged' guard: nothing to write. Also keeps this
			// writer silent when the tuner reanchor is alive and already
			// wrote the correct values (conflict-free coexistence).
			if reanchorUnchanged(buf, oc) {
				unchanged++
				continue
			}

			// C1-style seq guard: re-lookup immediately before the write.
			// If the kernel updated the bucket in between (a vote landed),
			// our recomputation is stale — skip rather than clobber, and
			// let the next cycle redo the math on the fresh metrics.
			fresh, err := mapLookupBytes(mapID, keyArgs)
			if err != nil || len(fresh) != sizeofRemoteHost {
				seqBusy++
				continue
			}
			freshSeq := binary.LittleEndian.Uint64(fresh[sizeofRemoteHost-sizeofSeqField:])
			if skip, _ := writebackSeqCheck(seq, freshSeq); skip {
				seqBusy++
				continue
			}

			// Graft ONLY the 8 tracker fields + any 0.4.63 score inits
			// onto the fresh buffer — every other byte stays exactly as
			// the kernel last wrote it.
			applyReanchor(fresh, oc)

			if mapUpdateBytes(mapID, keyArgs, fresh) {
				hostsPatched++
				fieldsPatched += 8 + len(oc.scoreInits)
			}
		}
	}
	if hostsPatched > 0 {
		fmt.Fprintf(os.Stderr, "[picker] done: %d tracker writes (%d fields) across %d map(s); scanned=%d unchanged=%d seq-busy=%d (reanchor substitute)\n",
			hostsPatched, fieldsPatched, len(mapIDs), scanned, unchanged, seqBusy)
	}
	return hostsPatched, fieldsPatched
}
