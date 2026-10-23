package main

// perf_lean4_test.go — v0.9.111-lean4: ring-restriction tests.
//
// The ring buffer now only holds SELECTABLE buckets (top-8 + labeled).
// These tests prove:
//   - selectable buckets are captured into the ring
//   - non-selectable hosts are NOT captured
//   - pre-existing non-selectable entries (e.g. CSV history loaded at
//     startup) are dropped on the next capture cycle
//   - ringSelectable == nil keeps everything (test/legacy default)

import "testing"

func perf4RingSandbox(t *testing.T) {
        t.Helper()
        oldHist := histDir
        oldSel := ringSelectable
        oldRaw := hist.raw
        oldCycle := hist.cycleCount
        histDir = t.TempDir()
        hist.mu.Lock()
        hist.raw = map[string][]bucketSnapshot{}
        hist.mu.Unlock()
        hist.cycleCount = 0
        t.Cleanup(func() {
                histDir = oldHist
                ringSelectable = oldSel
                hist.cycleCount = oldCycle
                hist.mu.Lock()
                hist.raw = oldRaw
                hist.mu.Unlock()
        })
}

func TestPerf4RingSelectableFilter(t *testing.T) {
        perf4RingSandbox(t)

        // Pre-seed a non-selectable bucket (simulates CSV history loaded
        // at startup by loadCSVTailIntoRingBuffer).
        hist.addSnapshot("10.9.9.9", bucketSnapshot{Ts: 1})

        ringSelectable = map[string]bool{"10.0.0.1": true}
        hosts := []hostEntry{
                {Addr: "10.0.0.1", Inst: 3, V: map[string]interface{}{}},
                {Addr: "10.0.0.2", Inst: 3, V: map[string]interface{}{}}, // not selectable
        }
        captureSnapshotsFromBPF(hosts, 1000)

        hist.mu.RLock()
        _, hasSel := hist.raw["10.0.0.1"]
        _, hasOther := hist.raw["10.0.0.2"]
        _, hasOld := hist.raw["10.9.9.9"]
        hist.mu.RUnlock()

        if !hasSel {
                t.Fatal("selectable bucket must be captured into the ring")
        }
        if hasOther {
                t.Fatal("non-selectable host must NOT be captured")
        }
        if hasOld {
                t.Fatal("pre-existing non-selectable ring entries must be dropped")
        }
}

func TestPerf4RingSelectableNil(t *testing.T) {
        perf4RingSandbox(t)

        ringSelectable = nil // legacy/test default: keep all
        hosts := []hostEntry{
                {Addr: "10.0.0.1", Inst: 3, V: map[string]interface{}{}},
                {Addr: "10.0.0.2", Inst: 3, V: map[string]interface{}{}},
        }
        captureSnapshotsFromBPF(hosts, 1000)

        hist.mu.RLock()
        _, hasA := hist.raw["10.0.0.1"]
        _, hasB := hist.raw["10.0.0.2"]
        hist.mu.RUnlock()

        if !hasA || !hasB {
                t.Fatal("ringSelectable=nil must keep all buckets")
        }
}
