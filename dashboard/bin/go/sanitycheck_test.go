package main

import (
	"strings"
	"testing"
)

// TestRxEstabCapturesDest6b verifies the v0.9.0 fix to rxEstab.
// Before: regex was `... dest=(\d+)(?: dest6=(\d+))?` — no dest6b group.
// After:  regex is `... dest=(\d+)(?: dest6=(\d+))?(?: dest6b=(\d+))?`.
func TestRxEstabCapturesDest6b(t *testing.T) {
	line := `1234.5: bpf_trace_printk: estab cookie=4242 alg=0 forced=1 dest=0 dest6=260613440 dest6b=2887722497`
	m := rxEstab.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("rxEstab did not match v6 estab line: %s", line)
	}
	if m[6] == "" {
		t.Fatalf("dest6b group is empty (regex capture broken)")
	}
	if m[6] != "2887722497" {
		t.Fatalf("dest6b value wrong: got %s, want 2887722497", m[6])
	}
	t.Logf("rxEstab captures dest6b=%s ✓", m[6])
}

// TestDestStrV6Full verifies the v0.9.0 destStr() with v6b present.
// 260613440 = 0x0F88A540 → "0f88:a540"
// 2887722497 = 0xAC1F2601 → "ac1f:2601"
// Expected output: "0f88:a540:ac1f:2601::"
func TestDestStrV6Full(t *testing.T) {
	got := destStr("0", "260613440", "2887722497")
	want := "0f88:a540:ac1f:2601::"
	if got != want {
		t.Fatalf("destStr v6b conversion wrong: got %q, want %q", got, want)
	}
	t.Logf("destStr v6b conversion: %q ✓", got)
}

// TestDestStrV6Only verifies backward compat: when v6b is missing,
// destStr still produces the v6:hex form (which foldV6 then handles).
// 260613440 = 0x0F88A540 → "0f88a540"
func TestDestStrV6Only(t *testing.T) {
	got := destStr("0", "260613440", "")
	want := "v6:0f88a540"
	if got != want {
		t.Fatalf("destStr v6-only wrong: got %q, want %q", got, want)
	}
	t.Logf("destStr v6-only (backward compat): %q ✓", got)
}

// TestCookieDestMapStoresV6b verifies the v0.9.0 cookieDestMap merge.
// Before: only stored [2]string{v4, v6} — dropped dest6b entirely.
// After:  stores cdestEntry [3]string{v4, v6, v6b}.
func TestCookieDestMapStoresV6b(t *testing.T) {
	logLines := []string{
		`1234.5: bpf_trace_printk: estab cookie=4242 alg=0 forced=1 dest=0 dest6=260613440 dest6b=2887722497`,
	}
	text := strings.Join(logLines, "\n")
	cdest := cookieDestMap(text)
	entry, ok := cdest["4242"]
	if !ok {
		t.Fatalf("cookie 4242 missing from cdest")
	}
	if entry[2] == "" {
		t.Fatalf("dest6b (entry[2]) is empty — cdest no longer stores v6b")
	}
	if entry[2] != "2887722497" {
		t.Fatalf("dest6b value wrong: got %q, want %q", entry[2], "2887722497")
	}
	t.Logf("cookieDestMap stores v6b=%q ✓", entry[2])
}

// TestCookieDestMapMergeDoesNotOverwriteWithEmpty verifies the merge rule:
// a later event with empty dest6b should NOT blow away a prior dest6b value.
func TestCookieDestMapMergeDoesNotOverwriteWithEmpty(t *testing.T) {
	logLines := []string{
		// First: estab with full v6 + v6b
		`1234.5: bpf_trace_printk: estab cookie=4242 alg=0 forced=1 dest=0 dest6=260613440 dest6b=2887722497`,
		// Then: another estab with only v4 (e.g. a different connection
		// reusing the same cookie — shouldn't happen in practice, but
		// the merge rule should still be safe).
		`1235.5: bpf_trace_printk: estab cookie=4242 alg=0 forced=0 dest=1395917824`,
	}
	text := strings.Join(logLines, "\n")
	cdest := cookieDestMap(text)
	entry, ok := cdest["4242"]
	if !ok {
		t.Fatalf("cookie 4242 missing")
	}
	// v4 should be updated to 1395917824 (latest non-empty)
	if entry[0] != "1395917824" {
		t.Errorf("v4 wrong: got %q, want 1395917824", entry[0])
	}
	// v6 should still be 260613440 (first event's value, not overwritten by empty)
	if entry[1] != "260613440" {
		t.Errorf("v6 lost: got %q, want 260613440", entry[1])
	}
	// v6b should still be 2887722497 (first event's value, not overwritten by empty)
	if entry[2] != "2887722497" {
		t.Errorf("v6b lost: got %q, want 2887722497", entry[2])
	}
	t.Logf("merge preserves v6/v6b across events with empty fields ✓")
}

// TestProofEventsGetDestFromCdest verifies that the proof event (which
// carries no dest field of its own) correctly resolves dest via cdest.
//
// Without labels loaded, destStr produces "0f88:a540:ac1f:2601::" (the
// full /64 form), and canonBucketWithPrefix masks it to /32 → "f88:a540::"
// (Go's net.IP.Mask produces a shortened form for IPv6).
func TestProofEventsGetDestFromCdest(t *testing.T) {
	logLines := []string{
		`1234.5: bpf_trace_printk: estab cookie=4242 alg=0 forced=1 dest=0 dest6=260613440 dest6b=2887722497`,
		`1235.5: bpf_trace_printk: proof cookie=4242 alg=1 rate=100000000 tier=2`,
	}
	text := strings.Join(logLines, "\n")
	cdest := cookieDestMap(text)
	proofs := buildRecentProofRows(text, cdest)
	if len(proofs) != 1 {
		t.Fatalf("expected 1 proof row, got %d", len(proofs))
	}
	row := proofs[0].(map[string]interface{})
	dest, _ := row["dest"].(string)
	// dest should be the labelFor() result.  Since no labels are loaded
	// in this test, labelFor falls back to canonBucketWithPrefix which
	// masks to /prefix6 (default /32).  Go's net.IP.Mask shortens the
	// leading-zero form "0f88:a540::" to "f88:a540::" — both are valid
	// representations of the same IPv6 prefix.
	want := "f88:a540::"
	if dest != want {
		t.Fatalf("proof dest wrong: got %q, want %q", dest, want)
	}
	t.Logf("proof dest resolves correctly via cdest: %q ✓", dest)
}

// TestRxSwapStillMatchesV4Only verifies the rxSwap regex still matches
// swap events that don't have dest6/dest6b (older BPF or v4-only connections).
func TestRxSwapStillMatchesV4Only(t *testing.T) {
	line := `1234.5: bpf_trace_printk: swap cookie=4242 from=0 to=1 bc=10 ac=20 d=2 mt=0 rb=1 dest=1395917824`
	m := rxSwap.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("rxSwap did not match v4-only swap line: %s", line)
	}
	if m[10] != "1395917824" {
		t.Fatalf("dest group wrong: got %s, want 1395917824", m[10])
	}
	if m[11] != "" {
		t.Fatalf("dest6 group should be empty for v4-only: got %s", m[11])
	}
	if m[12] != "" {
		t.Fatalf("dest6b group should be empty for v4-only: got %s", m[12])
	}
	t.Logf("rxSwap still matches v4-only swap events ✓")
}
