package main

// alias_fold_test.go — tests for the bucket fix (writeback alias
// canonicalization on top of v0.9.116).
//
// Mirrors the running C daemon's key derivation:
//   raw alias → mask (v4/16, v6/32) → alias on masked key → masked key
// and verifies that alias targets are used VERBATIM as bucket keys
// (never re-masked) — that is what keyArgsForExact guarantees.

import (
	"os"
	"path/filepath"
	"testing"
)

// writeAliasesFile writes content to a temp file and points the global
// aliasesFile at it. Returns a restore func.
func writeAliasesFile(t *testing.T, content string) func() {
	t.Helper()
	oldPath := aliasesFile
	oldV4, oldV6 := maskBitsV4, maskBitsV6

	dir := t.TempDir()
	p := filepath.Join(dir, "aliases")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write aliases: %v", err)
	}
	aliasesFile = p
	maskBitsV4, maskBitsV6 = 16, 32     // test defaults, mirroring daemon defaults
	aliasCanonicalHolder = mtimeCache{} // force reload

	return func() {
		aliasesFile = oldPath
		maskBitsV4, maskBitsV6 = oldV4, oldV6
		aliasCanonicalHolder = mtimeCache{} // fresh, unlocked
	}
}

func TestCanonicalWritebackHost(t *testing.T) {
	t.Run("raw alias hit uses target verbatim (no re-mask)", func(t *testing.T) {
		restore := writeAliasesFile(t, "# comment\n\n104.18.5.7 = 104.16.9.9 cloudflare\n")
		defer restore()
		host, kind := canonicalWritebackHost("104.18.5.7")
		if host != "104.16.9.9" || kind != "raw" {
			t.Fatalf("got (%q,%q), want (\"104.16.9.9\",\"raw\") — target must not be masked to 104.16.0.0", host, kind)
		}
	})

	t.Run("masked alias hit folds /16 to canonical key", func(t *testing.T) {
		restore := writeAliasesFile(t, "104.18.0.0 = 104.16.9.9 cloudflare\n")
		defer restore()
		host, kind := canonicalWritebackHost("104.18.77.3")
		if host != "104.16.9.9" || kind != "masked" {
			t.Fatalf("got (%q,%q), want (\"104.16.9.9\",\"masked\")", host, kind)
		}
	})

	t.Run("no alias falls back to masked key", func(t *testing.T) {
		restore := writeAliasesFile(t, "104.18.0.0 = 104.16.9.9 cloudflare\n")
		defer restore()
		host, kind := canonicalWritebackHost("8.8.8.8")
		if host != "8.8.0.0" || kind != "" {
			t.Fatalf("got (%q,%q), want (\"8.8.0.0\",\"\")", host, kind)
		}
	})

	t.Run("v6 masked alias fold", func(t *testing.T) {
		restore := writeAliasesFile(t, "2606:1a40:: = 104.16.0.0 cf6\n")
		defer restore()
		host, kind := canonicalWritebackHost("2606:1a40::1234")
		if host != "104.16.0.0" || kind != "masked" {
			t.Fatalf("got (%q,%q), want (\"104.16.0.0\",\"masked\")", host, kind)
		}
	})

	t.Run("malformed lines skipped", func(t *testing.T) {
		restore := writeAliasesFile(t, "not-an-ip = 1.2.3.4\n104.18.0.0 = also-bad\n   \n#x\n104.18.0.0 = 104.16.9.9 ok\n")
		defer restore()
		host, kind := canonicalWritebackHost("104.18.200.1")
		if host != "104.16.9.9" || kind != "masked" {
			t.Fatalf("got (%q,%q), want (\"104.16.9.9\",\"masked\")", host, kind)
		}
	})

	t.Run("missing aliases file preserves v0.9.116 behavior", func(t *testing.T) {
		restore := writeAliasesFile(t, "")
		defer restore()
		if err := os.Remove(aliasesFile); err != nil {
			t.Fatalf("remove: %v", err)
		}
		aliasCanonicalHolder = mtimeCache{} // force re-stat (file now gone)
		host, kind := canonicalWritebackHost("8.8.4.4")
		if host != "8.8.0.0" || kind != "" {
			t.Fatalf("got (%q,%q), want (\"8.8.0.0\",\"\")", host, kind)
		}
	})
}

func TestKeyArgsForExact(t *testing.T) {
	oldV4 := maskBitsV4
	maskBitsV4 = 16
	defer func() { maskBitsV4 = oldV4 }()

	// An UNALIGNED v4 address must come through UNMASKED — this is the
	// whole point of keyArgsForExact (keyArgsFor would zero the last two
	// octets, splitting the alias bucket away from the daemon's key).
	got := keyArgsForExact("104.16.9.9")
	if got == nil {
		t.Fatal("keyArgsForExact returned nil")
	}
	wantTail := []string{"68", "10", "09", "09"} // 104.16.9.9, hex strings
	for i, w := range wantTail {
		if got[12+i] != w {
			t.Fatalf("tail byte %d: got %s, want %s", i, got[12+i], w)
		}
	}
	if got[10] != "ff" || got[11] != "ff" {
		t.Fatalf("v4-mapped prefix wrong: %v %v", got[10], got[11])
	}
	for i := 0; i < 10; i++ {
		if got[i] != "00" {
			t.Fatalf("prefix byte %d = %s, want 00", i, got[i])
		}
	}
}
