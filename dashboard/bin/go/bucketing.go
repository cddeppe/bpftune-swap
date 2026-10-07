package main

// bucketing.go — single source of truth for label resolution + bucketing.
//
// v0.7.0 refactor (per user spec):
//   - All label resolution goes through ONE function: ResolveBucket().
//   - No code path may re-apply labelFor to an already-labeled ID.
//   - CSV writer writes the LABELED form (resolved at write time).
//   - CSV reader does NOT re-apply labelFor — it uses the stored label as-is.
//     (This was the root cause of "custom bucket disappears": a row written
//     as "controld" when label existed, then labelFor("controld") at read
//     time returned "controld" (since not parseable as IP) — but if the
//     label was REMOVED, the row stayed "controld" forever, splitting the
//     bucket away from new BPF reads which produced "2606:1a40::".)
//   - When labels.json mtime changes, all static files in /data/ are
//     invalidated (deleted) so the next renderToDisk cycle regenerates
//     them with the new labels.
//
// Resolution chain (per user spec v0.4.2):
//   1. Apply v6 fold rules (v6:hex → v4 if /etc/bpftune/aliases declares it)
//   2. Convert v6:hex to standard IPv6 form (for label matching)
//   3. Try longest-prefix label match in labels.json + aliases labels
//      (a /32 label wins over a /16 label for the same IP)
//   4. Fall back to canonBucketWithPrefix (with current prefix4/prefix6
//      from /var/lib/bpftune/prefix4 and prefix6)

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// mtime-cached file readers
// ============================================================================

// mtimeCache is a generic mtime-based file cache. Returns the loader's
// output cached until the file's mtime changes. Returns nil (caller
// treats as empty map) if file is missing or loader errors.
type mtimeCache struct {
	mu    sync.Mutex
	val   map[string]string
	mtime time.Time
}

func (c *mtimeCache) get(path string, loader func([]byte) map[string]string) map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(path)
	if err != nil {
		c.val = nil
		c.mtime = time.Time{}
		return map[string]string{}
	}
	if c.val != nil && fi.ModTime().Equal(c.mtime) {
		return c.val
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.val = map[string]string{}
		c.mtime = fi.ModTime()
		return c.val
	}
	loaded := loader(data)
	if loaded == nil {
		loaded = map[string]string{}
	}
	c.val = loaded
	c.mtime = fi.ModTime()
	// Mark labelsMtimeChanged so renderToDisk invalidates static files.
	markLabelsChanged()
	return c.val
}

var (
	labelsHolder        mtimeCache
	foldHolder          mtimeCache
	aliasesLabelsHolder mtimeCache
)

// labelsFileMtime tracks the last-seen mtime of labels.json.  When it
// changes, markLabelsChanged() sets staticFilesDirty=true so the next
// renderToDisk cycle deletes all bucket_*.json + meta.json + fleet.json +
// swaps.json before regenerating them.  This fixes the "custom bucket
// disappears" bug where a stale static file (from before the label was
// added) was served instead of the freshly-labeled dynamic response.
var (
	labelsMtimeMu      sync.Mutex
	labelsLastMtime    time.Time
	staticFilesDirtyMu sync.Mutex
	staticFilesDirty   bool
)

func markLabelsChanged() {
	labelsMtimeMu.Lock()
	defer labelsMtimeMu.Unlock()
	if labelsLastMtime.IsZero() {
		// First load — don't mark dirty (no static files yet).
		fi, _ := os.Stat(labelsFile)
		if fi != nil {
			labelsLastMtime = fi.ModTime()
		}
		return
	}
	fi, err := os.Stat(labelsFile)
	if err != nil {
		return
	}
	if !fi.ModTime().Equal(labelsLastMtime) {
		labelsLastMtime = fi.ModTime()
		staticFilesDirtyMu.Lock()
		staticFilesDirty = true
		staticFilesDirtyMu.Unlock()
	}
}

// StaticFilesAreDirty returns true if labels.json changed since the last
// renderToDisk cycle, indicating static files should be invalidated.
func StaticFilesAreDirty() bool {
	staticFilesDirtyMu.Lock()
	defer staticFilesDirtyMu.Unlock()
	return staticFilesDirty
}

// ClearStaticFilesDirty resets the dirty flag after renderToDisk regenerates.
func ClearStaticFilesDirty() {
	staticFilesDirtyMu.Lock()
	defer staticFilesDirtyMu.Unlock()
	staticFilesDirty = false
}

// loadLabels reads labelsFile (/var/lib/bpftune/aliases.labels.json).
func loadLabels() map[string]string {
	return labelsHolder.get(labelsFile, func(data []byte) map[string]string {
		var m map[string]string
		if err := json.Unmarshal(data, &m); err != nil {
			return map[string]string{}
		}
		return m
	})
}

// loadFoldMap reads /etc/bpftune/aliases and extracts {v6:hex: canonical_v4}.
// Line form: `2603:c020:0:0:0:0:0:0 = 89.168.0.0 [label]`
// Only lines where groups 2..7 are all zero are treated as /32 folds.
func loadFoldMap() map[string]string {
	return foldHolder.get(aliasesFile, func(data []byte) map[string]string {
		out := map[string]string{}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			lhs := strings.TrimSpace(parts[0])
			rhs := strings.Fields(strings.TrimSpace(parts[1]))
			if len(rhs) == 0 {
				continue
			}
			to := rhs[0]
			if !strings.Contains(to, ".") {
				continue
			}
			if !strings.Contains(lhs, ":") {
				continue
			}
			groups := strings.Split(lhs, ":")
			if len(groups) != 8 {
				continue
			}
			allZero := true
			for _, g := range groups[2:] {
				if g != "0" && g != "0000" && g != "" {
					allZero = false
					break
				}
			}
			if !allZero {
				continue
			}
			key := "v6:" + strings.ToLower(padLeft(groups[0], 4)+padLeft(groups[1], 4))
			out[key] = to
		}
		return out
	})
}

// loadAliasesLabelsMap reads /etc/bpftune/aliases and extracts {to_ip: label}.
func loadAliasesLabelsMap() map[string]string {
	return aliasesLabelsHolder.get(aliasesFile, func(data []byte) map[string]string {
		out := map[string]string{}
		for _, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			rest := strings.Fields(strings.TrimSpace(parts[1]))
			if len(rest) < 2 {
				continue
			}
			toIP := rest[0]
			label := rest[1]
			if ip := net.ParseIP(toIP); ip != nil {
				out[ip.String()] = label
			} else {
				out[toIP] = label
			}
		}
		return out
	})
}

// ============================================================================
// Address normalization + label lookup
// ============================================================================

// canonBucketWithPrefix collapses a v4 address to /prefix4, or a v6
// address (in standard form OR v6:hex form) to /prefix6.
func canonBucketWithPrefix(addr string, prefix4, prefix6 int) string {
	if addr == "" {
		return ""
	}
	// Handle v6:hex form (e.g., "v6:2606abcd" — top 32 bits of v6).
	if strings.HasPrefix(addr, "v6:") {
		h := strings.TrimPrefix(addr, "v6:")
		n, err := strconv.ParseUint(h, 16, 64)
		if err != nil {
			return addr
		}
		ip := make([]byte, 16)
		ip[0] = byte(n >> 24)
		ip[1] = byte(n >> 16)
		ip[2] = byte(n >> 8)
		ip[3] = byte(n)
		mask := net.CIDRMask(prefix6, 128)
		masked := net.IP(ip).Mask(mask)
		return masked.String()
	}
	// Standard IP form (v4 dotted or v6 canonical).
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(prefix4, 32)
		masked := v4.Mask(mask)
		return masked.String()
	}
	ip16 := ip.To16()
	mask := net.CIDRMask(prefix6, 128)
	masked := net.IP(ip16).Mask(mask)
	return masked.String()
}

// foldV6 replaces a v6:hex key with its canonical v4 if declared in
// /etc/bpftune/aliases; otherwise converts v6:hex to standard IPv6 /32
// form ("xxxx:xxxx::") so labelFor can normalize + look it up.
func foldV6(addr string) string {
	if addr == "" || !strings.HasPrefix(addr, "v6:") {
		return addr
	}
	if folded, ok := loadFoldMap()[addr]; ok && folded != "" {
		return folded
	}
	// No fold rule — convert v6:hex to standard IPv6 /32
	h := strings.TrimPrefix(addr, "v6:")
	n, err := parseUint64Hex(h)
	if err != nil {
		return addr
	}
	return formatIPv6Slash32(n)
}

// ResolveBucket is the SINGLE entry point for label resolution.
// All code paths that need to convert a raw BPF address (e.g. "v6:26061a40"
// or "1.2.3.4") to a bucket ID MUST call this. Do NOT call labelFor directly
// from outside this file — that was the source of the "bucket disappears"
// bug (labelFor was being re-applied to already-labeled IDs).
//
// Resolution chain:
//  1. Apply v6 fold rules (v6:hex → v4 if /etc/bpftune/aliases declares it)
//  2. Convert v6:hex to standard IPv6 form (for label matching)
//  3. Try longest-prefix label match in labels.json + aliases labels
//  4. Fall back to canonBucketWithPrefix (with current prefix4/prefix6)
func ResolveBucket(addr string) string {
	if addr == "" {
		return ""
	}
	// Step 1+2: fold + v6:hex → standard form.
	addr = foldV6(addr)
	// Step 3: longest-prefix label match.
	if lbl := longestPrefixLabel(addr); lbl != "" {
		return lbl
	}
	// Step 4: canon bucket with current prefix4/prefix6.
	return canonBucketWithPrefix(addr, prefix4Value(), prefix6Value())
}

// labelFor is kept as a thin wrapper for backward compat with log_parsing.go
// and other callers that haven't been updated yet. New code should call
// ResolveBucket directly.
//
// IMPORTANT: If `addr` is already a label (e.g. "controld"), this function
// returns it unchanged (it's not a parseable IP, so canonBucketWithPrefix
// returns it as-is, and longestPrefixLabel returns "" for non-IP input).
// This means calling labelFor on an already-labeled ID is safe but wasteful.
func labelFor(addr string) string {
	return ResolveBucket(addr)
}

// IsLabeledBucketID returns true if s looks like a human-applied label
// (not a parseable IP). Used by CSV reader to skip re-applying labelFor.
func IsLabeledBucketID(s string) bool {
	if s == "" {
		return false
	}
	// v6:hex form is "raw" (not labeled).
	if strings.HasPrefix(s, "v6:") {
		return false
	}
	// If it parses as an IP, it's a raw /masked form (not labeled).
	if ip := net.ParseIP(s); ip != nil {
		return false
	}
	// Otherwise it's a label like "controld" or "vps-us".
	return true
}

// longestPrefixLabel finds the most specific label match for addr.
// Iterates labels.json + aliases labels, computes each key's natural
// prefix length (from trailing zero bytes), and picks the longest
// matching prefix. Returns "" if no match.
func longestPrefixLabel(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	// Fast path: exact string match (covers /32 v4 and /128 v6 labels
	// which is the common case — saves the CIDR construction overhead).
	labels := loadLabels()
	if lbl, ok := labels[addr]; ok && lbl != "" {
		return lbl
	}
	// Slow path: longest-prefix match.
	bestLabel := ""
	bestPrefix := -1
	for k, v := range labels {
		cidr := labelKeyToCIDR(k)
		if cidr == nil {
			continue
		}
		if !cidr.Contains(ip) {
			continue
		}
		ones, _ := cidr.Mask.Size()
		if ones > bestPrefix {
			bestPrefix = ones
			bestLabel = v
		}
	}
	if bestLabel == "" {
		// Try aliases labels as fallback.
		aliasLabels := loadAliasesLabelsMap()
		for k, v := range aliasLabels {
			cidr := labelKeyToCIDR(k)
			if cidr == nil {
				continue
			}
			if !cidr.Contains(ip) {
				continue
			}
			ones, _ := cidr.Mask.Size()
			if ones > bestPrefix {
				bestPrefix = ones
				bestLabel = v
			}
		}
	}
	return bestLabel
}

// labelKeyToCIDR parses a labels.json key as a CIDR.
//   - If the key has "/N" suffix (e.g., "82.43.0.0/16"), parse directly.
//   - Otherwise, infer prefix length from trailing zero bytes.
func labelKeyToCIDR(k string) *net.IPNet {
	if strings.Contains(k, "/") {
		_, ipNet, err := net.ParseCIDR(k)
		if err != nil {
			return nil
		}
		return ipNet
	}
	ip := net.ParseIP(k)
	if ip == nil {
		return nil
	}
	var b []byte
	if v4 := ip.To4(); v4 != nil {
		b = v4
	} else {
		b = ip.To16()
	}
	trailingZeroBytes := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			trailingZeroBytes++
		} else {
			break
		}
	}
	prefixLen := len(b)*8 - trailingZeroBytes*8
	mask := net.CIDRMask(prefixLen, len(b)*8)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}
}

// ============================================================================
// Prefix readers (prefix4 / prefix6 / explore_pct)
// ============================================================================

type mtimeIntCache struct {
	mu    sync.Mutex
	val   int
	set   bool
	mtime time.Time
}

func (c *mtimeIntCache) get(path string, defaultVal int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(path)
	if err != nil {
		c.val = defaultVal
		c.set = true
		c.mtime = time.Time{}
		return defaultVal
	}
	if c.set && fi.ModTime().Equal(c.mtime) {
		return c.val
	}
	data, err := os.ReadFile(path)
	if err != nil {
		c.val = defaultVal
		c.set = true
		c.mtime = fi.ModTime()
		return defaultVal
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		c.val = defaultVal
		c.set = true
		c.mtime = fi.ModTime()
		return defaultVal
	}
	c.val = n
	c.set = true
	c.mtime = fi.ModTime()
	return n
}

var (
	prefix4Holder    mtimeIntCache
	prefix6Holder    mtimeIntCache
	explorePctHolder mtimeIntCache
)

// Prefix file paths.  Vars (not consts) so --data-root can override.
var (
	prefix4Path    = "/var/lib/bpftune/prefix4"
	prefix6Path    = "/var/lib/bpftune/prefix6"
	explorePctPath = "/var/lib/bpftune/explore_pct"
)

func prefix4Value() int {
	n := prefix4Holder.get(prefix4Path, 16)
	if n < 0 || n > 32 {
		return 16
	}
	return n
}

func prefix6Value() int {
	n := prefix6Holder.get(prefix6Path, 32)
	if n < 0 || n > 128 {
		return 32
	}
	return n
}

func explorePctValue() int {
	n := explorePctHolder.get(explorePctPath, 5)  // v0.9.22: match EXPLORE_PCT_DEFAULT in tcp_conn_tuner.h
	if n < 0 || n > 100 {
		return 100
	}
	return n
}

// ============================================================================
// Helpers
// ============================================================================

func padLeft(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

func parseUint64Hex(s string) (uint64, error) {
	var n uint64
	for _, c := range s {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			n |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n |= uint64(c-'A') + 10
		default:
			return 0, errBadHex
		}
	}
	return n, nil
}

var errBadHex = &simpleError{"bad hex digit"}

type simpleError struct{ s string }

func (e *simpleError) Error() string { return e.s }

// formatIPv6Slash32 turns a uint64 (top 32 bits of an IPv6) into "xxxx:xxxx::".
func formatIPv6Slash32(n uint64) string {
	hi := (n >> 16) & 0xFFFF
	lo := n & 0xFFFF
	return formatU16(hi) + ":" + formatU16(lo) + "::"
}

func formatU16(n uint64) string {
	const hex = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{hex[n&0xF]}, b...)
		n >>= 4
	}
	return string(b)
}
