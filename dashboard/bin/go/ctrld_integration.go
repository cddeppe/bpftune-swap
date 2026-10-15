package main

// ctrld_integration.go — fetches DNS cache from ctrld's /cache endpoint
// and builds an IP→domain map for the dashboard to display.
//
// v0.9.68: Dashboard-only feature. Zero BPF changes.
// The collector fetches http://127.0.0.1:9101/cache?active=true every 60s,
// builds a reverse map (IP → domain), and includes it in current.json.
// The frontend uses it to show "google.com (142.250.0.0)" instead of
// raw IPs in the buckets table and Origin Health panel.
//
// If ctrld is not running or the endpoint is not reachable, the feature
// is silently disabled — the dashboard falls back to raw IPs.

import (
        "encoding/json"
        "fmt"
        "net/http"
        "os"
        "strings"
        "sync"
        "time"
)

// ctrldCacheResponse is the JSON returned by ctrld's /cache endpoint.
type ctrldCacheResponse struct {
        SnapshotTime string           `json:"snapshot_time"`
        Count        int              `json:"count"`
        Entries      []ctrldCacheEntry `json:"entries"`
}

type ctrldCacheEntry struct {
        Name            string   `json:"name"`
        Qtype           string   `json:"qtype"`
        IPs             []string `json:"ips"`
        TTLRemainingSec int64    `json:"ttl_remaining_sec"`
}

// ctrldState holds the DNS cache integration state.
var ctrldState struct {
        mu         sync.RWMutex
        ipToDomain map[string]string // IP → domain (without trailing dot)
        available  bool              // is ctrld reachable?
        entryCount int                // how many cache entries
        lastFetch  time.Time
}

var ctrldStarted bool

// startCtrldPoller starts a background goroutine that fetches the ctrld
// DNS cache every 60 seconds. Called once on collector startup.
func startCtrldPoller() {
        if ctrldStarted {
                return
        }
        ctrldStarted = true

        // Initialize state
        ctrldState.ipToDomain = map[string]string{}

        // Do an immediate fetch on startup
        fetchCtrldCache()

        // Then poll every 60 seconds
        go func() {
                ticker := time.NewTicker(60 * time.Second)
                defer ticker.Stop()
                for range ticker.C {
                        fetchCtrldCache()
                }
        }()
}

// fetchCtrldCache fetches the DNS cache from ctrld and updates the
// IP→domain map. Silent on failure — ctrld is optional.
func fetchCtrldCache() {
        client := &http.Client{Timeout: 3 * time.Second}
        resp, err := client.Get("http://127.0.0.1:9101/cache?active=true")
        if err != nil {
                ctrldState.mu.Lock()
                ctrldState.available = false
                ctrldState.mu.Unlock()
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                ctrldState.mu.Lock()
                ctrldState.available = false
                ctrldState.mu.Unlock()
                return
        }

        var data ctrldCacheResponse
        if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
                ctrldState.mu.Lock()
                ctrldState.available = false
                ctrldState.mu.Unlock()
                return
        }

        // Build fresh map — replace, don't merge, so evicted entries don't linger
        fresh := make(map[string]string, data.Count)
        for _, e := range data.Entries {
                if len(e.IPs) == 0 {
                        continue // skip NODATA/NXDOMAIN entries
                }
                // Strip trailing dot (FQDN form → simple domain)
                name := strings.TrimSuffix(e.Name, ".")
                for _, ip := range e.IPs {
                        // If multiple domains map to the same IP, keep the first
                        // (most common case is one domain per IP)
                        if _, exists := fresh[ip]; !exists {
                                fresh[ip] = name
                        }
                }
        }

        ctrldState.mu.Lock()
        ctrldState.ipToDomain = fresh
        ctrldState.available = true
        ctrldState.entryCount = len(fresh)
        ctrldState.lastFetch = time.Now()
        ctrldState.mu.Unlock()

        fmt.Fprintf(os.Stderr, "ctrld: cache fetched %d entries (%d IP→domain mappings)\n",
                data.Count, len(fresh))
}

// getDomainForIP returns the domain name for an IP address from the ctrld
// DNS cache, or "" if not found / ctrld not running.
func getDomainForIP(ip string) string {
        ctrldState.mu.RLock()
        defer ctrldState.mu.RUnlock()
        if !ctrldState.available {
                return ""
        }
        return ctrldState.ipToDomain[ip]
}

// getDomainForBucket returns the domain name for a bucket IP prefix.
// The bucket is a /16 masked IPv4 (e.g. "142.250.0.0") or an IPv6 prefix
// of the form "v6:<hex-prefix>" (e.g. "v6:26061a40"). We check if any
// IP in the DNS cache falls within the prefix and return the domain.
//
// v0.9.73: port the IPv6 prefix logic from the JS-side
// getDomainForBucketDisplay (dashboard.js:122-134) — without this, the
// v0.9.72 v6->v4 linking branch in route_monitor.go:194-206 was
// unreachable for v6-only labels, leaving them stranded with no
// domain enrichment.
func getDomainForBucket(bucketAddr string) string {
        ctrldState.mu.RLock()
        defer ctrldState.mu.RUnlock()
        if !ctrldState.available {
                return ""
        }

        // Try exact match first (for labeled buckets like "home-sco")
        if domain, ok := ctrldState.ipToDomain[bucketAddr]; ok {
                return domain
        }

        // IPv4 /16 path
        if strings.Count(bucketAddr, ".") == 3 && !strings.HasPrefix(bucketAddr, "v6:") {
                parts := strings.Split(bucketAddr, ".")
                if len(parts) == 4 {
                        prefix := parts[0] + "." + parts[1] + "."
                        for ip, domain := range ctrldState.ipToDomain {
                                if strings.HasPrefix(ip, prefix) {
                                        return domain
                                }
                        }
                }
                return ""
        }

        // IPv6 prefix path: bucket labels are of the form "v6:<hex>" where
        // <hex> is the leading hex digits of the IPv6 address (no colons,
        // lowercase). The cached IPv6 strings are the full canonical form
        // (e.g. "2606:1a40:..."). To compare, strip colons from the cached
        // IP and match the hex prefix.
        if strings.HasPrefix(bucketAddr, "v6:") {
                hexPrefix := strings.TrimPrefix(bucketAddr, "v6:")
                hexPrefix = strings.ToLower(hexPrefix)
                for ip, domain := range ctrldState.ipToDomain {
                        if !strings.Contains(ip, ":") {
                                continue // skip v4 entries
                        }
                        compact := strings.ToLower(strings.ReplaceAll(ip, ":", ""))
                        if strings.HasPrefix(compact, hexPrefix) {
                                return domain
                        }
                }
                return ""
        }

        return ""
}

// getCtrldStatus returns the integration status for the Service Health panel.
func getCtrldStatus() map[string]interface{} {
        ctrldState.mu.RLock()
        defer ctrldState.mu.RUnlock()

        status := map[string]interface{}{
                "available": ctrldState.available,
        }

        if ctrldState.available {
                status["entry_count"] = ctrldState.entryCount
                status["last_fetch"] = time.Since(ctrldState.lastFetch).Round(time.Second).String()
        } else {
                status["entry_count"] = 0
                status["last_fetch"] = ""
        }

        return status
}

// getCtrldDomainMap returns a copy of the IP→domain map for inclusion
// in current.json. The frontend uses this to display domain names
// alongside bucket IPs in the dashboard.
func getCtrldDomainMap() map[string]string {
        ctrldState.mu.RLock()
        defer ctrldState.mu.RUnlock()
        if !ctrldState.available || ctrldState.ipToDomain == nil {
                return nil
        }
        // Return a copy to avoid race with the poller goroutine
        out := make(map[string]string, len(ctrldState.ipToDomain))
        for k, v := range ctrldState.ipToDomain {
                out[k] = v
        }
        return out
}
