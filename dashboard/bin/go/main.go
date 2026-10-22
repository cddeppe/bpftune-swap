package main

// main.go — HTTP server, SSE, /api/labels, /current.json.
//
// v0.7.0 refactor:
//   - readBPFMap → bpf_reader.go
//   - collect() → collect.go
//   - HTTP /data/* handlers → http_handlers.go
//   - renderToDisk + static file writers → render.go
//   - ring buffer + snapshots → history.go
//   - label resolution → bucketing.go
//   - CSV writer → csv_writer.go
//   - CSV reader + cache → csv_reader.go
//
// This file is now ~280 lines (down from ~1046). Each concern lives in
// its own file, so future patches don't require grepping through a
// monolith to find the right line.

import (
        "compress/gzip"
        "crypto/md5"
        "encoding/json"
        "flag"
        "fmt"
        "net/http"
        _ "net/http/pprof" // v0.9.36: register /debug/pprof/* handlers
        "os"
        "path/filepath"
        "strings"
        "sync"
        "syscall"
        "runtime/debug"
        "time"
)

// ============================================================================
// Configuration
// ============================================================================

var (
        histDir     = "/var/lib/bpftune/history"
        binDir      = "/opt/bpftune-dashboard/bin"
        labelsFile  = "/var/lib/bpftune/aliases.labels.json"
        aliasesFile = "/etc/bpftune/aliases"
)

// ============================================================================
// Global state (protected by mutex)
// ============================================================================

type Collector struct {
        mu         sync.RWMutex
        current    map[string]interface{} // current.json data
        keyHashes  map[string]string      // per-key md5 for SSE delta
        sseClients map[chan []byte]bool
        startedAt  time.Time // for uptime_min field
}

func NewCollector() *Collector {
        c := &Collector{
                current:    make(map[string]interface{}),
                keyHashes:  make(map[string]string),
                sseClients: make(map[chan []byte]bool),
                startedAt:  time.Now(),
        }
        // Load history ring buffer from disk (so charts survive restart)
        hist.loadFromDisk()
        // Load CSV tail (last 24h) into ring buffer so 1h/24h charts
        // work immediately after restart.  Async so HTTP starts fast.
        go loadCSVTailIntoRingBuffer()
        return c
}

// ============================================================================
// current.json writer
// ============================================================================

func (c *Collector) writeCurrentJSON() {
        c.mu.RLock()
        data, _ := json.Marshal(c.current)
        c.mu.RUnlock()

        path := filepath.Join(histDir, "current.json")
        tmp := path + ".tmp"
        if err := os.WriteFile(tmp, data, 0644); err != nil {
                fmt.Fprintf(os.Stderr, "collector: write current.json failed: %v\n", err)
                return
        }
        os.Rename(tmp, path)
}

// v0.9.83: slow-changing keys that don't need to be hashed every 30s cycle.
// These are hashed every 4th cycle (every 2 min) to reduce json.Marshal +
// MD5 overhead. The SSE delta for these keys will be delayed by up to 2 min,
// which is fine since they rarely change.
var slowChangingKeys = map[string]bool{
        "build":       true, // version info — never changes during a session
        "system":      true, // uptime ticks once per minute, 2-min delay is fine
        "hostname":    true, // never changes
        "tunables":    true, // changes only on sysctl writes
        "log_window":  true, // changes only when log range shifts
        "bucket_live": true, // v0.9.84: large object (8 buckets × 16 algs × 120 points),
                             // only needs 2-min freshness for chart updates; the frontend's
                             // _appendLiveMetrics already appends one new point per SSE push
}

func computeKeyHashes(doc map[string]interface{}, fullHash bool) map[string]string {
        hashes := make(map[string]string)
        for k, v := range doc {
                // v0.9.83: skip slow-changing keys on non-full cycles.
                // Their hash from the previous cycle is reused (the caller
                // merges newHashes with prevHashes for slow keys).
                if !fullHash && slowChangingKeys[k] {
                        continue
                }
                data, _ := json.Marshal(v)
                sum := md5.Sum(data)
                hashes[k] = fmt.Sprintf("%x", sum)
        }
        return hashes
}

// ============================================================================
// SSE delta encoding
// ============================================================================

func (c *Collector) notifySSE() {
        c.mu.RLock()
        current := c.current
        prevHashes := c.keyHashes
        c.mu.RUnlock()

        // v0.9.9: SSE delta encoding — only send keys whose MD5 hash changed
        // since the last cycle. Most cycles only generated_ts, bucket_live,
        // and maybe recent_swaps change. Cuts SSE payload by ~80%.
        //
        // The first cycle after startup (prevHashes == nil) sends the full
        // document. Subsequent cycles send only the delta.
        //
        // v0.9.83: hash slow-changing keys only every 4th cycle (every 2 min)
        // to reduce json.Marshal + MD5 overhead. On non-full cycles, reuse
        // the previous hash for slow-changing keys so their delta detection
        // still works (they'll just be delayed by up to 2 min).
        fullHash := (cycleCount % 4) == 0
        newHashes := computeKeyHashes(current, fullHash)

        // v0.9.83: on non-full cycles, carry forward the previous hash for
        // slow-changing keys that weren't recomputed this cycle.
        if !fullHash && len(prevHashes) > 0 {
                for k := range slowChangingKeys {
                        if _, ok := newHashes[k]; !ok {
                                if prev, ok := prevHashes[k]; ok {
                                        newHashes[k] = prev
                                }
                        }
                }
        }

        if len(prevHashes) == 0 {
                // Full document — first push or after reset
                msg := map[string]interface{}{"__t": "f", "v": current}
                data, _ := json.Marshal(msg)
                c.mu.Lock()
                for client := range c.sseClients {
                        select {
                        case client <- data:
                        default:
                        }
                }
                c.keyHashes = newHashes
                c.mu.Unlock()
                return
        }

        // Delta — only changed keys
        // JS protocol: {"__t":"d", "c":{changed keys}, "r":[removed keys]}
        delta := map[string]interface{}{}
        var removed []string
        for k, v := range current {
                hash, ok := newHashes[k]
                if !ok {
                        continue
                }
                prev, existed := prevHashes[k]
                if !existed || prev != hash {
                        delta[k] = v
                }
        }
        // Detect removed keys (in prevHashes but not in current)
        for k := range prevHashes {
                if _, exists := current[k]; !exists {
                        removed = append(removed, k)
                }
        }

        // Store new hashes for next cycle regardless of whether we sent anything
        c.mu.Lock()
        c.keyHashes = newHashes
        c.mu.Unlock()

        if len(delta) == 0 && len(removed) == 0 {
                return // nothing changed
        }

        msg := map[string]interface{}{"__t": "d", "c": delta}
        if len(removed) > 0 {
                msg["r"] = removed
        }
        data, _ := json.Marshal(msg)

        c.mu.Lock()
        for client := range c.sseClients {
                select {
                case client <- data:
                default:
                }
        }
        c.mu.Unlock()
}

// ============================================================================
// HTTP handlers
// ============================================================================

func (c *Collector) handleIndex(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/" || r.URL.Path == "/index.html" {
                c.serveStatic(w, r, filepath.Join(histDir, "index.html"), "text/html; charset=utf-8")
                return
        }
        if r.URL.Path == "/dashboard.js" || r.URL.Path == "/dashboard.css" ||
                r.URL.Path == "/chart.umd.min.js" || r.URL.Path == "/chartjs-adapter-date-fns.bundle.min.js" {
                c.serveStatic(w, r, filepath.Join(binDir, r.URL.Path), "")
                return
        }
        // /data/* — static file first (10 min fresh), then dynamic fallback.
        if strings.HasPrefix(r.URL.Path, "/data/") {
                sub := r.URL.Path[len("/data/"):]
                if sub == "" || strings.HasSuffix(sub, ".csv") || strings.Contains(sub, "..") || strings.HasPrefix(sub, ".") {
                        http.NotFound(w, r)
                        return
                }
                staticPath := filepath.Join(histDir, "data", sub)
                if fi, err := os.Stat(staticPath); err == nil && time.Since(fi.ModTime()) < 10*time.Minute {
                        c.serveStatic(w, r, staticPath, "")
                        return
                }
                // Dynamic fallback
                if strings.HasPrefix(sub, "bucket_") && strings.HasSuffix(sub, ".json") {
                        bucketID := strings.TrimSuffix(strings.TrimPrefix(sub, "bucket_"), ".json")
                        // Un-sanitize: underscores → colons for v6 form
                        if strings.HasPrefix(bucketID, "v6_") {
                                bucketID = "v6:" + strings.TrimPrefix(bucketID, "v6_")
                        }
                        hist.handleBucketJSON(w, r, bucketID)
                        return
                }
                if sub == "meta.json" {
                        c.mu.RLock()
                        buckets := c.current["buckets"]
                        c.mu.RUnlock()
                        hist.handleMetaJSON(w, r, bucketsAsMaps(buckets))
                        return
                }
                if sub == "fleet.json" {
                        c.mu.RLock()
                        buckets := c.current["buckets"]
                        c.mu.RUnlock()
                        hist.handleFleetJSON(w, r, bucketsAsMaps(buckets))
                        return
                }
                if sub == "swaps.json" {
                        c.mu.RLock()
                        so := c.current["swap_outcomes"]
                        c.mu.RUnlock()
                        if m, ok := so.(map[string]interface{}); ok {
                                hist.handleSwapsJSON(w, r, m)
                        } else {
                                // v0.7.0: return empty object instead of 404 when no swaps yet.
                                w.Header().Set("Content-Type", "application/json")
                                w.Header().Set("Cache-Control", "no-cache")
                                w.Write([]byte("{}"))
                        }
                        return
                }
                if sub == "swaps_per_bin.json" {
                        hist.handleSwapsPerBinJSON(w, r)
                        return
                }
                c.serveStatic(w, r, staticPath, "")
                return
        }
        if r.URL.Path == "/current.json" {
                c.handleCurrentJSON(w, r)
                return
        }
        if r.URL.Path == "/sse" {
                c.handleSSE(w, r)
                return
        }
        if strings.HasPrefix(r.URL.Path, "/api/labels") {
                c.handleLabels(w, r)
                return
        }
        if r.URL.Path == "/api/config" {
                c.handleConfig(w, r)
                return
        }
        http.NotFound(w, r)
}

func (c *Collector) serveStatic(w http.ResponseWriter, r *http.Request, path, contentType string) {
        data, err := os.ReadFile(path)
        if err != nil {
                http.NotFound(w, r)
                return
        }
        if contentType == "" {
                contentType = "application/octet-stream"
                switch filepath.Ext(path) {
                case ".html":
                        contentType = "text/html; charset=utf-8"
                case ".js":
                        contentType = "application/javascript; charset=utf-8"
                case ".css":
                        contentType = "text/css; charset=utf-8"
                case ".json":
                        contentType = "application/json; charset=utf-8"
                }
        }
        if acceptsGzip(r) && shouldGzip(path) {
                w.Header().Set("Content-Type", contentType)
                w.Header().Set("Content-Encoding", "gzip")
                w.Header().Set("Vary", "Accept-Encoding")
                w.Header().Set("Cache-Control", "no-cache")
                gz := gzip.NewWriter(w)
                defer gz.Close()
                gz.Write(data)
        } else {
                w.Header().Set("Content-Type", contentType)
                w.Header().Set("Cache-Control", "no-cache")
                w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
                w.Write(data)
        }
}

func (c *Collector) handleCurrentJSON(w http.ResponseWriter, r *http.Request) {
        c.mu.RLock()
        data, _ := json.Marshal(c.current)
        c.mu.RUnlock()

        if acceptsGzip(r) {
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("Content-Encoding", "gzip")
                w.Header().Set("Vary", "Accept-Encoding")
                w.Header().Set("Cache-Control", "no-cache")
                gz := gzip.NewWriter(w)
                defer gz.Close()
                gz.Write(data)
        } else {
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("Cache-Control", "no-cache")
                w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
                w.Write(data)
        }
}

func (c *Collector) handleSSE(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/event-stream")
        w.Header().Set("Cache-Control", "no-cache")
        w.Header().Set("Connection", "keep-alive")

        flusher, ok := w.(http.Flusher)
        if !ok {
                http.Error(w, "streaming not supported", http.StatusInternalServerError)
                return
        }

        // A5-fix: register the channel BEFORE sending the initial snapshot.
        // Previously the initial send happened first, then channel registration
        // — a race window where notifySSE() could fire and the new client would
        // miss the first post-connect update.
        // Also bumped buffer from 10 (5 min) to 60 (30 min) so slow clients
        // don't silently drop updates via the `default:` case in notifySSE.
        ch := make(chan []byte, 60)
        c.mu.Lock()
        c.sseClients[ch] = true
        c.mu.Unlock()
        defer func() {
                c.mu.Lock()
                delete(c.sseClients, ch)
                c.mu.Unlock()
        }()

        c.mu.RLock()
        current := c.current
        c.mu.RUnlock()

        if current != nil {
                msg := map[string]interface{}{"__t": "f", "v": current}
                data, _ := json.Marshal(msg)
                fmt.Fprintf(w, "data: %s\n\n", data)
                flusher.Flush()
        }

        // v0.9.27: added 5-minute heartbeat that sends the full document.
        // Clients that missed deltas (channel full) stay in sync.
        heartbeat := time.NewTicker(5 * time.Minute)
        defer heartbeat.Stop()
        // v0.7.5m: keep a 25s keepalive comment to prevent proxy idle timeout.
        for {
                select {
                case <-r.Context().Done():
                        return
                case data := <-ch:
                        fmt.Fprintf(w, "data: %s\n\n", data)
                        flusher.Flush()
                case <-heartbeat.C:
                        // Send full document as heartbeat
                        c.mu.RLock()
                        fullMsg := map[string]interface{}{"__t": "f", "v": c.current}
                        c.mu.RUnlock()
                        data, _ := json.Marshal(fullMsg)
                        fmt.Fprintf(w, "data: %s\n\n", data)
                        flusher.Flush()
                case <-time.After(25 * time.Second):
                        fmt.Fprintf(w, ": keepalive\n\n")
                        flusher.Flush()
                }
        }
}

// ============================================================================
// /api/labels handler
// ============================================================================

func (c *Collector) handleLabels(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
                labels := loadLabels()
                aliases := readAliases()
                groups := buildGroups(aliases, labels)

                resp := map[string]interface{}{
                        "labels":  labels,
                        "aliases": aliases,
                        "groups":  groups,
                }
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("Access-Control-Allow-Origin", "*")
                w.Header().Set("Cache-Control", "no-cache")
                json.NewEncoder(w).Encode(resp)
                return
        }

        if r.Method == "POST" {
                var req map[string]interface{}
                if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
                        http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
                        return
                }
                ip, _ := req["ip"].(string)
                label, _ := req["label"].(string)
                // Canonicalize IP to current prefix width before storing.
                ip = canonBucketWithPrefix(ip, prefix4Value(), prefix6Value())

                // LABEL-SANDBOX-1: loadLabels returns a private COPY of the
                // cached map, so the mutation below doesn't race with the
                // COLLECT pipeline's longestPrefixLabel iterating the cached
                // map. saveLabels acquires labelsMu internally to serialize
                // the merge+write+cache-update.
                //
                // For deletes (label == ""), we set labels[ip] = "" (rather
                // than delete(labels, ip)) so saveLabels's merge step can
                // detect the delete (the merge iterates the caller's labels
                // map; an entry missing from the caller's map could mean
                // either "delete" or "not in caller's snapshot" — ambiguous.
                // An empty value unambiguously means "delete".)
                labels := loadLabels()
                if label == "" {
                        labels[ip] = "" // mark for delete (saveLabels's merge deletes)
                } else {
                        labels[ip] = label
                }
                saveLabels(labels)

                // v0.7.0: invalidate static files immediately so the new label
                // appears in meta.json + bucket_*.json without waiting 5 min.
                staticFilesDirtyMu.Lock()
                staticFilesDirty = true
                staticFilesDirtyMu.Unlock()

                labels = loadLabels()
                aliases := readAliases()
                groups := buildGroups(aliases, labels)
                resp := map[string]interface{}{
                        "ok":     true,
                        "ip":     ip,
                        "label":  label,
                        "labels": labels,
                        "groups": groups,
                }
                w.Header().Set("Content-Type", "application/json")
                w.Header().Set("Access-Control-Allow-Origin", "*")
                json.NewEncoder(w).Encode(resp)
                return
        }

        if r.Method == "OPTIONS" {
                w.Header().Set("Access-Control-Allow-Origin", "*")
                w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
                w.WriteHeader(200)
                return
        }

        http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
}

// ============================================================================
// Labels helpers
// ============================================================================

func readAliases() []string {
        data, err := os.ReadFile(aliasesFile)
        if err != nil {
                return []string{}
        }
        var lines []string
        for _, line := range strings.Split(string(data), "\n") {
                line = strings.TrimSpace(line)
                if line == "" || strings.HasPrefix(line, "#") {
                        continue
                }
                lines = append(lines, line)
        }
        return lines
}

func buildGroups(aliases []string, labels map[string]string) map[string]interface{} {
        groups := make(map[string]interface{})
        for _, raw := range aliases {
                parts := strings.Fields(raw)
                if len(parts) < 2 {
                        continue
                }
                if !strings.Contains(raw, "=") {
                        continue
                }
                eqParts := strings.SplitN(raw, "=", 2)
                fromIP := strings.TrimSpace(eqParts[0])
                rest := strings.Fields(strings.TrimSpace(eqParts[1]))
                if len(rest) < 1 {
                        continue
                }
                toIP := rest[0]
                label := ""
                if len(rest) > 1 {
                        label = rest[1]
                }
                if label == "" {
                        continue
                }
                g, ok := groups[label].(map[string]interface{})
                if !ok {
                        g = map[string]interface{}{"to_ip": toIP, "from_ips": []string{}}
                        groups[label] = g
                }
                ips, _ := g["from_ips"].([]string)
                ips = append(ips, fromIP)
                g["from_ips"] = ips
                groups[label] = g
        }
        return groups
}

func saveLabels(labels map[string]string) {
        // LABEL-SANDBOX-1: serialize concurrent saves to prevent both:
        //   - Lost updates: 10 concurrent POSTs each overwrite the file
        //     with their own partial view; the last saveLabels to finish
        //     would clobber the others' writes — silent label loss after
        //     restart. The merge below (loadLabels + apply caller's
        //     updates into the cache copy) prevents this.
        //   - Concurrent WriteFile corruption: two os.WriteFile calls
        //     racing on the same file produce interleaved byte writes
        //     yielding invalid JSON on disk (the test logged raw file
        //     content like `{"5.0.0.0":"bucket-4"} "2.0.0.0":"bucket-1",`
        //     — two JSON objects concatenated). Serializing the write
        //     eliminates this.
        labelsMu.Lock()
        defer labelsMu.Unlock()

        // MERGE the caller's labels into the current cache. This is the
        // key fix for lost updates: instead of overwriting the file with
        // the caller's (possibly stale) snapshot, we apply the caller's
        // updates on top of the current cache state. So if goroutine A
        // adds {ip_A: lbl_A} and goroutine B adds {ip_B: lbl_B}
        // concurrently, both entries end up in the merged map.
        //
        // Empty values are treated as deletes: the POST handler uses
        // `labels[ip] = ""` to mark a delete (see handleLabels POST
        // branch). Without this convention, the merge couldn't
        // distinguish "delete" from "not in caller's snapshot".
        merged := loadLabels() // returns copy of current cache
        for k, v := range labels {
                if v == "" {
                        delete(merged, k)
                } else {
                        merged[k] = v
                }
        }

        data, _ := json.MarshalIndent(merged, "", "  ")
        data = append(data, '\n')
        if err := os.WriteFile(labelsFile, data, 0644); err != nil {
                fmt.Fprintf(os.Stderr, "saveLabels: write %s failed: %v\n", labelsFile, err)
                return
        }
        // Update the labelsHolder cache so the new label is visible to
        // subsequent loadLabels() calls within the 30s TTL window
        // (mtimeCache.get short-circuits os.Stat when lastStat < 30s
        // ago). Without this cache update, loadLabels would return the
        // STALE cached val (missing the new label) until the TTL expires
        // — and the POST handler's second loadLabels() call (line 479,
        // which builds the response) would return the OLD labels, hiding
        // the new label from the UI.
        //
        // We set c.val = merged (the freshly-merged map). This is an
        // atomic pointer swap; concurrent loadLabels calls iterating
        // the OLD c.val (via their local copy) are safe (they hold a
        // stable reference to the old map, which we don't mutate).
        labelsHolder.mu.Lock()
        labelsHolder.val = merged
        if fi, err := os.Stat(labelsFile); err == nil {
                labelsHolder.mtime = fi.ModTime()
                labelsHolder.lastStat = time.Now()
        }
        labelsHolder.mu.Unlock()
}

// ============================================================================
// Utility functions
// ============================================================================

func acceptsGzip(r *http.Request) bool {
        return strings.Contains(r.Header.Get("Accept-Encoding"), "gzip")
}

func shouldGzip(path string) bool {
        ext := filepath.Ext(path)
        return ext == ".json" || ext == ".js" || ext == ".css" || ext == ".html"
}

func readProc(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        return strings.TrimSpace(string(data))
}

func toInt(v interface{}) int {
        switch n := v.(type) {
        case float64:
                return int(n)
        case int:
                return n
        default:
                return 0
        }
}

func toFloat(v interface{}) float64 {
        switch n := v.(type) {
        case float64:
                return n
        case int:
                return float64(n)
        default:
                return 0
        }
}

func toString(v interface{}) string {
        if s, ok := v.(string); ok {
                return s
        }
        if n, ok := v.(int); ok {
                return fmt.Sprintf("%d", n)
        }
        return ""
}

// jsonNewEncoder wraps encoding/json.NewEncoder for use by http_handlers.go.
func jsonNewEncoder(w interface{}) *jsonEncoderImpl {
        return &jsonEncoderImpl{w: w.(http.ResponseWriter)}
}

type jsonEncoderImpl struct {
        w http.ResponseWriter
}

func (e *jsonEncoderImpl) Encode(v interface{}) error {
        return json.NewEncoder(e.w).Encode(v)
}

// ============================================================================
// Main
// ============================================================================

func main() {
        port := flag.Int("port", 8082, "HTTP port")
        bind := flag.String("bind", "127.0.0.1", "bind address")
        // v0.7.0: allow overriding data paths for testing / debugging / sandboxes.
        dataRoot := flag.String("data-root", "/var/lib/bpftune", "root for state files (history/, aliases.labels.json, prefix4, etc.)")
        aliasesPath := flag.String("aliases", "/etc/bpftune/aliases", "path to /etc/bpftune/aliases")
        binPath := flag.String("bin-dir", "/opt/bpftune-dashboard/bin", "path to dashboard.js + dashboard.css")
        // v0.7.3: configurable ring buffer cap.  Default 120 = 1h at 30s.
        // For servers with more buckets, use 60 (30min) to save memory.
        ringCapFlag := flag.Int("ring-cap", 120, "ring buffer entries per bucket (120=1h, 60=30min, 240=2h)")
        collectorModeFlag := flag.String("collector-mode", "normal", "collector mode: lean|normal|debug|normal-light")
        flag.Parse()
        collectorMode = parseCollectorMode(*collectorModeFlag)
        // v0.9.81: removed --route-monitor flag + route monitor goroutine +
        // Origin Health panel + ctrld integration. They added complexity
        // without value for the user's use case. Route Health panel (the BPF
        // map per-bucket health view) is unaffected.
        fmt.Fprintf(os.Stderr, "collector: mode=%s interval=%s logTail=%dMB\n", collectorMode.Name, collectorMode.CollectInterval, collectorMode.LogTailBytes/1_000_000)

        // v0.7.3: set ring buffer cap
        ringCap = *ringCapFlag

        // Apply overrides (only if user passed a non-default value).
        if *dataRoot != "/var/lib/bpftune" {
                histDir = *dataRoot + "/history"
                labelsFile = *dataRoot + "/aliases.labels.json"
                // v0.7.0: all path vars are now vars (not consts) so we can override.
                prefix4Path = *dataRoot + "/prefix4"
                prefix6Path = *dataRoot + "/prefix6"
                explorePctPath = *dataRoot + "/explore_pct"
                bucketsCSVPath = *dataRoot + "/history/buckets.v2.csv"
                swapsCSVPath = *dataRoot + "/history/swaps.csv"
                srateCSVPath = *dataRoot + "/history/srate.csv"
                // v0.9.5: proofs.csv path also needs override
                proofsCSVPath = *dataRoot + "/history/proofs.csv"
                // v0.9.7: midsamp.csv path also needs override
                midsampCSVPath = *dataRoot + "/history/midsamp.csv"
                stateJSONPath = *dataRoot + "/history/collector-go-state.json"
                // v0.8.7: truthFilePath was missing from this override block -
                // smoke tests with --data-root /tmp/test-bpftune were writing
                // truth rows to the REAL /var/lib/bpftune/history/swapscore_truth.jsonl,
                // polluting the production ML training file.
                truthFilePath = *dataRoot + "/history/swapscore_truth.jsonl"
                // v0.9.0: cookie_dest persistence file also needs override so
                // sandboxed test runs don't pollute the production cookie map.
                cookieDestPath = *dataRoot + "/history/cookie_dest.json"
        }
        if *aliasesPath != "/etc/bpftune/aliases" {
                aliasesFile = *aliasesPath
        }
        if *binPath != "/opt/bpftune-dashboard/bin" {
                binDir = *binPath
        }

        // COL-002 fix: write sentinel so Python renderer skips data/*.json writes
        _ = os.WriteFile("/var/run/bpftune-collector-go.active", []byte("1\n"), 0644)

        // v0.9.10: initialize SQLite backend (migrates CSV on first run)
        initSQLite()

        // v0.9.34: set CPU priority and GC tuning from inside the binary.
        // This ensures it works on all hosts without service file changes.
        // Nice=10: lower CPU priority so xray/ctrld/SSH always preempt us.
        // GOGC=50: more frequent, smaller GC runs (prevents 91% spikes).
        syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
        os.Setenv("GOGC", "50")
	startWatchdog() // v0.9.102: self-kill safety switch
        debug.SetGCPercent(50)
        fmt.Fprintf(os.Stderr, "collector: CPU priority=nice(10) GOGC=50\n")

        // v0.9.45: Auto-fix trace_pipe ring buffer + sync BPF config on startup.
        // These are system-level settings that should "just work" without
        // manual intervention. The collector is the right place to enforce them
        // because it's always running and knows the tuner's needs.
        ensureSystemHealth()

        // v0.9.89: clear stale log content from a previous boot.
        // This is the permanent fix for the recurring "BPF events not
        // showing" issue after a reboot. The log file persists across
        // reboots (not in /tmp), so after a reboot it contains events
        // from the previous boot (ktime > current uptime). The
        // previous-boot filter drops these, but the health check was
        // fooled by the file's mtime (always fresh because the trace
        // service touches the file). clearStaleLog checks the CONTENT's
        // ktime and truncates if stale.
        clearStaleLog("/var/log/bpftune-met-live.log")

        collector := NewCollector()

        // v0.9.81: route monitor goroutine removed (was --route-monitor flag).
        // The Origin Health panel + automatic v4/v6 route switching + ctrld
        // DNS cache integration were all removed as unnecessary complexity.

        // Synchronous first collect — current.json populated before HTTP starts.
        collector.collect()
        // COL-002: refresh sentinel after first collect
        _ = os.WriteFile("/var/run/bpftune-collector-go.active", []byte("1\n"), 0644)

        // v0.7.3: synchronous first renderToDisk — static files ready before
        // HTTP starts.  This adds ~5-15s to startup but ensures all chart
        // requests are served from fast static files (not slow CSV reads).
        // fast=true: only 1h+24h (7d+all generated by renderSlowToDisk below).
        collector.renderToDisk()
        // Also generate 7d+all on startup (synchronous, ~10-30s for large CSV)
        go collector.renderSlowToDisk() // v0.7.5n: async

        // Collection loop (every 30s)
        // v0.9.73: add recover() — without it, ANY panic in collect() (nil map
        // deref, type assertion failure, out-of-bounds metric slot) silently
        // kills this goroutine. The HTTP server keeps serving the last
        // c.current snapshot forever; SSE deltas stop entirely; the dashboard
        // freezes at last-known state with no log entry explaining why.
        // Mirrors the recover() pattern already used in
        // loadCSVTailIntoRingBuffer (csv_reader.go).
        go func() {
                ticker := time.NewTicker(collectorMode.CollectInterval)
                defer ticker.Stop()
                for range ticker.C {
                        func() {
                                defer func() {
                                        if r := recover(); r != nil {
                                                fmt.Fprintf(os.Stderr, "collector: collect() PANICKED: %v\n%s\n", r, debug.Stack())
                                        }
                                }()
                                collector.collect()
                                // COL-002: refresh sentinel so Python renderer knows we're alive
                                _ = os.WriteFile("/var/run/bpftune-collector-go.active", []byte("1\n"), 0644)
                        }()
                }
        }()

        // v0.9.45: Periodic system health re-sync (every 5 min).
        // If bpftune restarts or the BPF map is reset, this re-applies
        // the saved explore_pct and ensures the trace buffer stays large.
        // v0.9.46: Also restarts the trace capture service if it dies.
        go func() {
                ticker := time.NewTicker(5 * time.Minute)
                defer ticker.Stop()
                for range ticker.C {
                        ensureTraceBufferSize()
                        syncExplorePctToBPF()
                        ensureTraceCaptureService()
                }
        }()

        // renderToDisk loop: 1h + 24h + meta + swaps + fleet
        // v0.9.35: every 2 min (was 5 min) so 24h charts show fresh accumulated data
        // v0.9.33: skip when no new swaps (SkipRenderWhenIdle mode)
        go func() {
                ticker := time.NewTicker(5 * time.Minute)
                defer ticker.Stop()
                lastSwapCount := 0
                for range ticker.C {
                        if collectorMode.SkipRenderWhenIdle {
                                collector.mu.RLock()
                                so := collector.current["swap_outcomes"]
                                collector.mu.RUnlock()
                                if m, ok := so.(map[string]interface{}); ok {
                                        sl, _ := m["swaps_list"].([]interface{})
                                        if len(sl) == lastSwapCount {
                                                continue // no new swaps, skip render
                                        }
                                        lastSwapCount = len(sl)
                                }
                        }
                        collector.renderToDisk()
                }
        }()

        // renderSlowToDisk loop: 7d + all charts
        // v0.9.83: changed from daily (4am) to every 30 min so 7d/all charts
        // stay fresh without manual restart. The cost is ~10-30s of CPU every
        // 30 min (reads full CSV history), which is acceptable.
        // Also prunes SQLite rows older than 30 days on each run.
        go func() {
                // First run: wait 5 min after startup so the first collect +
                // renderToDisk cycles complete, then generate 7d+all.
                time.Sleep(5 * time.Minute)
                collector.renderSlowToDisk()
                pruneSQLiteOld(30)
                // v0.9.83: every 30 min (was every 24h)
                ticker := time.NewTicker(30 * time.Minute)
                defer ticker.Stop()
                for range ticker.C {
                        collector.renderSlowToDisk()
                        pruneSQLiteOld(30)
                }
        }()

        // ============================================================================
        // HTTP server
        // v0.9.36: use http.DefaultServeMux so net/http/pprof handlers
        // (auto-registered via blank import) are available at /debug/pprof/*.
        // Access: curl http://localhost:PORT/debug/pprof/heap > heap.pb.gz
        //         go tool pprof heap.pb.gz
        mux := http.DefaultServeMux
        mux.HandleFunc("/", collector.handleIndex)

        addr := fmt.Sprintf("%s:%d", *bind, *port)
        fmt.Fprintf(os.Stderr, "collector: HTTP server on %s (serves /, /sse, /current.json, /api/labels, /data/*, /debug/pprof/*)\n", addr)

        srv := &http.Server{
                Addr:    addr,
                Handler: mux,
        }

        if err := srv.ListenAndServe(); err != nil {
                fmt.Fprintf(os.Stderr, "collector: HTTP server failed: %v\n", err)
                os.Exit(1)
        }
}
