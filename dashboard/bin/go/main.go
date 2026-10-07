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
        "os"
        "path/filepath"
        "strings"
        "sync"
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

func computeKeyHashes(doc map[string]interface{}) map[string]string {
        hashes := make(map[string]string)
        for k, v := range doc {
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
        c.mu.RUnlock()

        // v0.7.5m: marshal ONCE, send to all clients
        msg := map[string]interface{}{"__t": "f", "v": current}
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

        // v0.7.5m: removed per-second hash polling (was the 9% CPU sink).
        // notifySSE() pushes to the channel every 30s after collect().
        // Keep a 25s keepalive comment to prevent proxy idle timeout.
        for {
                select {
                case <-r.Context().Done():
                        return
                case data := <-ch:
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

                labels := loadLabels()
                if label == "" {
                        delete(labels, ip)
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
        data, _ := json.MarshalIndent(labels, "", "  ")
        data = append(data, '\n')
        os.WriteFile(labelsFile, data, 0644)
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
	collectorModeFlag := flag.String("collector-mode", "lean", "collector mode: lean|normal|debug")
        flag.Parse()
	collectorMode = parseCollectorMode(*collectorModeFlag)
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

        collector := NewCollector()

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
        go func() {
                ticker := time.NewTicker(collectorMode.CollectInterval)
                defer ticker.Stop()
                for range ticker.C {
                        collector.collect()
                        // COL-002: refresh sentinel so Python renderer knows we're alive
                        _ = os.WriteFile("/var/run/bpftune-collector-go.active", []byte("1\n"), 0644)
                }
        }()

        // renderToDisk loop (every 5 min): 1h + 24h + meta + swaps + fleet
        go func() {
                ticker := time.NewTicker(5 * time.Minute)
                defer ticker.Stop()
                for range ticker.C {
                        collector.renderToDisk()
                }
        }()

        // renderSlowToDisk loop (once a day at 4am, or every 24h): 7d + all
        go func() {
                // Calculate time until next 4am
                now := time.Now()
                next := time.Date(now.Year(), now.Month(), now.Day()+1, 4, 0, 0, 0, now.Location())
                time.Sleep(next.Sub(now))
                collector.renderSlowToDisk()
                ticker := time.NewTicker(24 * time.Hour)
                defer ticker.Stop()
                for range ticker.C {
                        collector.renderSlowToDisk()
                }
        }()

        // ============================================================================
        // HTTP server
        mux := http.NewServeMux()
        mux.HandleFunc("/", collector.handleIndex)

        addr := fmt.Sprintf("%s:%d", *bind, *port)
        fmt.Fprintf(os.Stderr, "collector: HTTP server on %s (serves /, /sse, /current.json, /api/labels, /data/*)\n", addr)

        srv := &http.Server{
                Addr:    addr,
                Handler: mux,
        }

        if err := srv.ListenAndServe(); err != nil {
                fmt.Fprintf(os.Stderr, "collector: HTTP server failed: %v\n", err)
                os.Exit(1)
        }
}
