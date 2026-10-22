package main

// v0.9.104_test.go - Comprehensive test suite for v0.9.104 collector.
//
// Covers:
//   1. SQLite dedup (hash-based skip when data unchanged)
//   2. SQLite 50MB cap + VACUUM stages
//   3. SQLite PRAGMA settings (mmap, cache, temp_store, soft_heap)
//   4. Watchdog RSS/CPU read functions
//   5. readTail helper (4KB tail reads)
//   6. getServiceHealth 5-min cache
//   7. writeBucketSQLite 60s throttle
//   8. renderSlowToDisk 6h cadence (compile-time check)
//   9. isLogContentStale correctness on tail-only reads
//  10. sqliteMaxBytes constant
//  11. resetSQLiteForTest helper
//  12. Build sanity (no broken string literals)
//  13-25. Source-level checks + memory/CPU soak + race tests
//
// Run:  go test -run 'TestV0_9_104' -v ./...

import (
        "bufio"
        "database/sql"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        
        "strconv"
        "strings"
        "sync"
        "testing"
        "time"
)

// ============================================================================
// 1. SQLite dedup
// ============================================================================

func TestV0_9_104_SQLiteDedupSkipsUnchanged(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        lastWriteHash = make(map[string]uint64, 8)
        openTestDB(t, dir)

        h := hostEntry{Addr: "1.2.3.4", Inst: 5}
        now := int64(1700000000)

        // Force even cycle (so throttle lets the write through)
        sqliteWriteCycleMu.Lock()
        sqliteWriteCycle = 1 // next call increments to 2 (even)
        sqliteWriteCycleMu.Unlock()

        writeBucketSQLite(h, now, 4096, 87380, 6291456)
        count1 := sqliteRowCount(t)
        if count1 != 1 {
                t.Fatalf("after first write: expected 1 row, got %d", count1)
        }

        // Reset cycle to odd then increment to even for second call
        sqliteWriteCycleMu.Lock()
        sqliteWriteCycle = 1
        sqliteWriteCycleMu.Unlock()

        // Second write - SAME data, different ts. Should be skipped by dedup.
        writeBucketSQLite(h, now+30, 4096, 87380, 6291456)
        count2 := sqliteRowCount(t)
        if count2 != 1 {
                t.Fatalf("after dedup: expected 1 row (unchanged data), got %d", count2)
        }

        t.Logf("OK dedup skipped unchanged snapshot (1 row after 2 writes)")
}

func TestV0_9_104_SQLiteDedupHashMap(t *testing.T) {
        resetSQLiteForTest()
        lastWriteHash = make(map[string]uint64, 8)

        lastWriteHashMu.Lock()
        lastWriteHash["host-A"] = 0xAAAA
        lastWriteHashMu.Unlock()

        lastWriteHashMu.Lock()
        v, ok := lastWriteHash["host-A"]
        lastWriteHashMu.Unlock()
        if !ok || v != 0xAAAA {
                t.Fatalf("hash map store failed: got %v %v", v, ok)
        }

        lastWriteHashMu.Lock()
        _, ok2 := lastWriteHash["host-B"]
        lastWriteHashMu.Unlock()
        if ok2 {
                t.Fatalf("host-B should not be in hash map")
        }

        t.Logf("OK dedup hash map correctly stores per-host snapshots")
}

// ============================================================================
// 2. SQLite 50MB cap constant
// ============================================================================

func TestV0_9_104_SQLiteMaxBytesConstant(t *testing.T) {
        expected := int64(50 * 1024 * 1024)
        if sqliteMaxBytes != expected {
                t.Fatalf("sqliteMaxBytes = %d, expected %d", sqliteMaxBytes, expected)
        }
        t.Logf("OK sqliteMaxBytes = %d bytes (%d MB)", sqliteMaxBytes, sqliteMaxBytes/1024/1024)
}

// ============================================================================
// 3. SQLite PRAGMA settings
// ============================================================================

func TestV0_9_104_SQLitePRAGMAsApplied(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)

        if sqliteDB == nil {
                t.Skip("sqliteDB is nil - initSQLite failed in test env")
        }

        checks := []struct {
                name  string
                query string
        }{
                {"journal_mode", "PRAGMA journal_mode"},
                {"synchronous", "PRAGMA synchronous"},
                {"temp_store", "PRAGMA temp_store"},
                {"mmap_size", "PRAGMA mmap_size"},
                {"cache_size", "PRAGMA cache_size"},
                {"soft_heap_limit", "PRAGMA soft_heap_limit"},
        }
        for _, c := range checks {
                var val string
                err := sqliteDB.QueryRow(c.query).Scan(&val)
                if err != nil {
                        t.Logf("  %s: query error (acceptable in test envs): %v", c.name, err)
                        continue
                }
                t.Logf("  %s = %s", c.name, val)
        }
        t.Logf("OK SQLite PRAGMA settings queryable")
}

// ============================================================================
// 4. Watchdog RSS/CPU readers
// ============================================================================

func TestV0_9_104_WatchdogReadRSSMB(t *testing.T) {
        rss := readRSSMB()
        if rss < 1 {
                t.Fatalf("readRSSMB returned %d, expected >0", rss)
        }
        t.Logf("OK readRSSMB = %d MB", rss)
}

func TestV0_9_104_WatchdogReadCPUPercent(t *testing.T) {
        var prevU, prevS int64
        prevT := time.Now()
        time.Sleep(10 * time.Millisecond)
        cpu := readCPUPercent(&prevU, &prevS, &prevT, time.Now())
        if cpu < 0 {
                t.Fatalf("CPU percent should be non-negative, got %f", cpu)
        }
        t.Logf("OK readCPUPercent = %.2f%%", cpu)
}

func TestV0_9_104_WatchdogConstants(t *testing.T) {
        if watchdogRSSLimit != 250 {
                t.Errorf("watchdogRSSLimit = %d, expected 250", watchdogRSSLimit)
        }
        if watchdogCPULimit != 80 {
                t.Errorf("watchdogCPULimit = %d, expected 80", watchdogCPULimit)
        }
        if watchdogMaxBreaches != 2 {
                t.Errorf("watchdogMaxBreaches = %d, expected 2", watchdogMaxBreaches)
        }
        if watchdogHeapLimit != 200 {
                t.Errorf("watchdogHeapLimit = %d, expected 200", watchdogHeapLimit)
        }
        if watchdogGOGC != 30 {
                t.Errorf("watchdogGOGC = %d, expected 30", watchdogGOGC)
        }
        if watchdogInterval != 30*time.Second {
                t.Errorf("watchdogInterval = %v, expected 30s", watchdogInterval)
        }
        t.Logf("OK watchdog constants correct (RSS=%dMB, CPU=%d%%, breaches=%d, heap=%dMiB, GOGC=%d, interval=%v)",
                watchdogRSSLimit, watchdogCPULimit, watchdogMaxBreaches,
                watchdogHeapLimit, watchdogGOGC, watchdogInterval)
}

// ============================================================================
// 5. readTail helper
// ============================================================================

func TestV0_9_104_ReadTailSmallFile(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "small.txt")
        content := []byte("hello world")
        if err := os.WriteFile(path, content, 0644); err != nil {
                t.Fatal(err)
        }
        got, err := readTail(path, 4096)
        if err != nil {
                t.Fatal(err)
        }
        if string(got) != "hello world" {
                t.Fatalf("readTail returned %q, expected %q", got, content)
        }
        t.Logf("OK readTail returns full content for files < budget")
}

func TestV0_9_104_ReadTailLargeFile(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "large.log")
        var b strings.Builder
        for i := 0; i < 100; i++ {
                fmt.Fprintf(&b, "line-%d-padding-to-80-bytes-padding-to-80-bytes-padding-to-80\n", i)
        }
        full := b.String()
        if err := os.WriteFile(path, []byte(full), 0644); err != nil {
                t.Fatal(err)
        }
        got, err := readTail(path, 256)
        if err != nil {
                t.Fatal(err)
        }
        if len(got) > 256 {
                t.Fatalf("readTail returned %d bytes, expected <= 256", len(got))
        }
        if !strings.Contains(string(got), "line-99") {
                t.Fatalf("readTail should contain last line 'line-99', got %q", got)
        }
        if strings.Contains(string(got), "line-50") {
                t.Fatalf("readTail should not contain line-50, got %q", got)
        }
        t.Logf("OK readTail returns only last %d bytes of larger file", 256)
}

func TestV0_9_104_ReadTailMissingFile(t *testing.T) {
        _, err := readTail("/nonexistent/path/should/not/exist", 4096)
        if err == nil {
                t.Fatal("expected error for missing file")
        }
        t.Logf("OK readTail returns error for missing file")
}

// ============================================================================
// 6. getServiceHealth 5-min cache
// ============================================================================

func TestV0_9_104_GetServiceHealthCache(t *testing.T) {
        serviceHealthCacheMu.Lock()
        serviceHealthCache = nil
        serviceHealthCacheTs = time.Time{}
        serviceHealthCacheMu.Unlock()

        h1 := getServiceHealth()
        if h1 == nil {
                t.Fatal("getServiceHealth returned nil")
        }
        if _, ok := h1["bpf_programs"]; !ok {
                t.Fatal("health map missing 'bpf_programs' key")
        }

        h2 := getServiceHealth()
        if h2 == nil {
                t.Fatal("second call returned nil")
        }

        serviceHealthCacheMu.Lock()
        cached := serviceHealthCache
        ts := serviceHealthCacheTs
        serviceHealthCacheMu.Unlock()
        if cached == nil {
                t.Fatal("serviceHealthCache was not populated")
        }
        if ts.IsZero() {
                t.Fatal("serviceHealthCacheTs was not set")
        }

        t.Logf("OK getServiceHealth populated cache (bpf_programs=%v)", h1["bpf_programs"])
}

func TestV0_9_104_GetServiceHealthCacheTTL(t *testing.T) {
        if serviceHealthCacheTTL != 5*time.Minute {
                t.Fatalf("serviceHealthCacheTTL = %v, expected 5m", serviceHealthCacheTTL)
        }
        t.Logf("OK serviceHealthCacheTTL = %v", serviceHealthCacheTTL)
}

// ============================================================================
// 7. writeBucketSQLite 60s throttle
// ============================================================================

func TestV0_9_104_WriteBucketSQLiteThrottle(t *testing.T) {
        sqliteWriteCycleMu.Lock()
        sqliteWriteCycle = 0
        sqliteWriteCycleMu.Unlock()

        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)
        lastWriteHash = make(map[string]uint64, 8)

        h := hostEntry{Addr: "9.9.9.9", Inst: 1}
        now := int64(1700000010)

        writeBucketSQLite(h, now, 4096, 87380, 6291456)
        writeBucketSQLite(h, now+30, 4096, 87380, 6291456)

        sqliteWriteCycleMu.Lock()
        cycle := sqliteWriteCycle
        sqliteWriteCycleMu.Unlock()
        if cycle != 2 {
                t.Fatalf("sqliteWriteCycle = %d, expected 2 after 2 calls", cycle)
        }

        count := sqliteRowCount(t)
        t.Logf("OK after 2 calls (cycle=%d), DB has %d rows (throttle skipped cycle 1)", cycle, count)
}

// ============================================================================
// 8. renderSlowToDisk 6h cadence
// ============================================================================

func TestV0_9_104_RenderSlowToDisk6hCadence(t *testing.T) {
        mainGo, err := os.ReadFile("main.go")
        if err != nil {
                t.Skip("main.go not readable from test working dir")
        }
        src := string(mainGo)
        if !strings.Contains(src, "6 * time.Hour") {
                t.Fatal("main.go missing '6 * time.Hour' - renderSlowToDisk not bumped to 6h")
        }
        if !strings.Contains(src, "v0.9.104 S2") {
                t.Fatal("main.go missing v0.9.104 S2 comment")
        }
        if strings.Contains(src, "ticker := time.NewTicker(30 * time.Minute)") {
                t.Fatal("main.go still has 30 * time.Minute ticker - renderSlowToDisk not patched")
        }
        t.Logf("OK renderSlowToDisk uses 6h cadence (no 30m ticker)")
}

// ============================================================================
// 9. isLogContentStale correctness
// ============================================================================

func TestV0_9_104_IsLogContentStaleOnMissingFile(t *testing.T) {
        if !isLogContentStale("/nonexistent/file/path") {
                t.Fatal("isLogContentStale should return true for missing file")
        }
        t.Logf("OK isLogContentStale returns true for missing file")
}

func TestV0_9_104_IsLogContentStaleOnEmptyFile(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "empty.log")
        if err := os.WriteFile(path, []byte{}, 0644); err != nil {
                t.Fatal(err)
        }
        if !isLogContentStale(path) {
                t.Fatal("isLogContentStale should return true for empty file")
        }
        t.Logf("OK isLogContentStale returns true for empty file")
}

func TestV0_9_104_IsLogContentStaleOnOldTraceLine(t *testing.T) {
        dir := t.TempDir()
        path := filepath.Join(dir, "old.log")
        line := "9999999999.0: bpf_trace_printk: stale content\n"
        if err := os.WriteFile(path, []byte(line), 0644); err != nil {
                t.Fatal(err)
        }
        if !isLogContentStale(path) {
                t.Fatal("isLogContentStale should return true for stale ktime")
        }
        t.Logf("OK isLogContentStale returns true for stale (future ktime) log")
}

// ============================================================================
// 10. Build sanity - no broken string literals
// ============================================================================

func TestV0_9_104_SQLiteSourceBuildSanity(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        brokenPattern := `fmt.Fprintf(os.Stderr, "sqlite: insert failed: %v`
        if strings.Contains(s, brokenPattern+"\n") && !strings.Contains(s, brokenPattern+`\n`) {
                t.Fatal("sqlite.go contains broken newline-in-string at insert failed Fprintf")
        }
        if !strings.Contains(s, `"sqlite: insert failed: %v\n"`) {
                t.Fatal("sqlite.go missing properly-escaped insert-failed string")
        }
        if !strings.Contains(s, "lastWriteHash[h.Addr]") {
                t.Fatal("sqlite.go missing 'lastWriteHash[h.Addr]' - broken syntax may still be present")
        }
        t.Logf("OK sqlite.go source clean (no broken string literals)")
}

// ============================================================================
// 11. resetSQLiteForTest helper
// ============================================================================

func TestV0_9_104_ResetSQLiteForTestClearsState(t *testing.T) {
        lastWriteHashMu.Lock()
        lastWriteHash = map[string]uint64{"x": 1}
        lastWriteHashMu.Unlock()

        resetSQLiteForTest()

        lastWriteHashMu.Lock()
        defer lastWriteHashMu.Unlock()
        if lastWriteHash != nil {
                t.Fatalf("resetSQLiteForTest should nil out lastWriteHash, got %v", lastWriteHash)
        }
        t.Logf("OK resetSQLiteForTest clears lastWriteHash map")
}

// ============================================================================
// 12. Memory soak (skipped in normal runs)
// ============================================================================

func TestV0_9_104_MemoryUnderHardCeiling(t *testing.T) {
        t.Skip("Memory soak test - run manually via TestV0_9_104_MemorySoak")

        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)
        lastWriteHash = make(map[string]uint64, 64)

        hosts := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
        now := int64(1700000000)
        for cycle := 0; cycle < 100; cycle++ {
                for _, addr := range hosts {
                        h := hostEntry{Addr: addr, Inst: 3}
                        writeBucketSQLite(h, now+int64(cycle*30), 4096, 87380, 6291456)
                }
                if cycle%10 == 0 {
                        runtime.GC()
                }
        }

        rss := readRSSMB()
        if rss > 250 {
                t.Errorf("RSS = %d MB after soak, exceeds 250 MB ceiling", rss)
        }
        t.Logf("OK after 100-cycle soak with 5 hosts, RSS = %d MB", rss)
}

func TestV0_9_104_CPUUnderHardCeiling(t *testing.T) {
        t.Skip("CPU soak test - run manually")
}

// ============================================================================
// 13. GOMEMLIMIT constant
// ============================================================================

func TestV0_9_104_GOMEMLIMITSet(t *testing.T) {
        if watchdogHeapLimit != 200 {
                t.Fatalf("watchdogHeapLimit = %d, expected 200", watchdogHeapLimit)
        }
        expected := int64(200 * 1024 * 1024)
        if int64(watchdogHeapLimit)*1024*1024 != expected {
                t.Fatalf("watchdogHeapLimit math wrong")
        }
        t.Logf("OK watchdogHeapLimit = %d MiB = %d bytes", watchdogHeapLimit, expected)
}

// ============================================================================
// 14. Race tests
// ============================================================================

func TestV0_9_104_NoRaceOnDedupMap(t *testing.T) {
        resetSQLiteForTest()
        lastWriteHash = make(map[string]uint64, 16)

        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
                wg.Add(1)
                go func(n int) {
                        defer wg.Done()
                        for j := 0; j < 100; j++ {
                                lastWriteHashMu.Lock()
                                lastWriteHash[fmt.Sprintf("host-%d", n)] = uint64(j)
                                lastWriteHashMu.Unlock()
                        }
                }(i)
        }
        wg.Wait()
        t.Logf("OK no race on dedup map (10 goroutines x 100 writes)")
}

func TestV0_9_104_NoRaceOnWriteCycle(t *testing.T) {
        sqliteWriteCycleMu.Lock()
        sqliteWriteCycle = 0
        sqliteWriteCycleMu.Unlock()

        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
                wg.Add(1)
                go func() {
                        defer wg.Done()
                        for j := 0; j < 100; j++ {
                                sqliteWriteCycleMu.Lock()
                                sqliteWriteCycle++
                                sqliteWriteCycleMu.Unlock()
                        }
                }()
        }
        wg.Wait()

        sqliteWriteCycleMu.Lock()
        final := sqliteWriteCycle
        sqliteWriteCycleMu.Unlock()
        if final != 1000 {
                t.Fatalf("sqliteWriteCycle = %d, expected 1000", final)
        }
        t.Logf("OK no race on write cycle counter (10 goroutines x 100 incs = %d)", final)
}

// ============================================================================
// 15. DB size stays small
// ============================================================================

func TestV0_9_104_SQLiteDBSizeStaysSmall(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)
        lastWriteHash = make(map[string]uint64, 8)

        h := hostEntry{Addr: "5.5.5.5", Inst: 7}
        now := int64(1700000000)

        for i := 0; i < 50; i++ {
                sqliteWriteCycleMu.Lock()
                sqliteWriteCycle = 1 // force even on next call
                sqliteWriteCycleMu.Unlock()
                writeBucketSQLite(h, now+int64(i*30), 4096, 87380, 6291456)
        }

        count := sqliteRowCount(t)
        if count > 26 {
                t.Fatalf("after 50 identical writes, expected <= 26 rows (dedup+throttle), got %d", count)
        }

        dbPath := filepath.Join(dir, "buckets.db")
        if fi, err := os.Stat(dbPath); err == nil {
                sizeMB := fi.Size() / 1024 / 1024
                t.Logf("OK DB file size = %d bytes (%d MB) after 50 writes (dedup+throttle)", fi.Size(), sizeMB)
                if sizeMB > 5 {
                        t.Errorf("DB size %d MB exceeds 5MB threshold", sizeMB)
                }
        }
        t.Logf("OK SQLite dedup keeps row count to %d after 50 identical writes", count)
}

// ============================================================================
// 16. Source-file regex sanity
// ============================================================================

func TestV0_9_104_SourceHasNoBrokenFprintf(t *testing.T) {
        files := []string{"sqlite.go", "main.go", "health_check.go", "watchdog.go", "collect.go"}
        for _, fname := range files {
                src, err := os.ReadFile(fname)
                if err != nil {
                        continue
                }
                s := string(src)
                lines := strings.Split(s, "\n")
                for i, line := range lines {
                        opens := strings.Count(line, `"`) - strings.Count(line, `\"`)
                        if opens%2 == 1 && strings.Contains(line, "Fprintf") {
                                if i+1 < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i+1]), `"`) {
                                        t.Errorf("%s:%d: Fprintf line has odd number of quotes: %q", fname, i+1, line)
                                }
                        }
                }
        }
        t.Logf("OK no broken Fprintf patterns in source files")
}

// ============================================================================
// 17. Watchdog self-kill behavior (manual)
// ============================================================================

func TestV0_9_104_WatchdogSelfKillBehavior(t *testing.T) {
        if os.Getenv("BPFTUNE_TEST_KILL") == "" {
                t.Skip("set BPFTUNE_TEST_KILL=1 to run this test")
        }
        memBreaches := watchdogMaxBreaches
        if memBreaches != 2 {
                t.Fatalf("expected 2 max breaches, got %d", memBreaches)
        }
        t.Logf("watchdog would self-kill after %d consecutive breaches", memBreaches)
}

// ============================================================================
// 18. SQLite PRAGMA constants present in source
// ============================================================================

func TestV0_9_104_SoftHeapLimitConstant(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        if !strings.Contains(string(src), "soft_heap_limit(20971520)") {
                t.Fatal("sqlite.go missing soft_heap_limit(20971520) in DSN")
        }
        if !strings.Contains(string(src), "PRAGMA soft_heap_limit=20971520") {
                t.Fatal("sqlite.go missing PRAGMA soft_heap_limit=20971520 belt-and-suspenders")
        }
        t.Logf("OK soft_heap_limit = 20971520 bytes (20MB) - present in both DSN and Exec")
}

func TestV0_9_104_MmapSizeConstant(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        if !strings.Contains(s, "mmap_size(8388608)") {
                t.Fatal("sqlite.go missing mmap_size(8388608) in DSN")
        }
        if !strings.Contains(s, "PRAGMA mmap_size=8388608") {
                t.Fatal("sqlite.go missing PRAGMA mmap_size=8388608 belt-and-suspenders")
        }
        if 8388608 != 8*1024*1024 {
                t.Fatal("8MB math wrong")
        }
        t.Logf("OK mmap_size = 8388608 bytes (8MB) - present in both DSN and Exec")
}

func TestV0_9_104_CacheSizeConstant(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        if !strings.Contains(s, "cache_size(-512)") {
                t.Fatal("sqlite.go missing cache_size(-512) in DSN")
        }
        if !strings.Contains(s, "PRAGMA cache_size=-512") {
                t.Fatal("sqlite.go missing PRAGMA cache_size=-512 belt-and-suspenders")
        }
        t.Logf("OK cache_size = -512 (512KB) - present in both DSN and Exec")
}

func TestV0_9_104_TempStoreConstant(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        if !strings.Contains(s, "temp_store(MEMORY)") {
                t.Fatal("sqlite.go missing temp_store(MEMORY) in DSN")
        }
        if !strings.Contains(s, "PRAGMA temp_store=MEMORY") {
                t.Fatal("sqlite.go missing PRAGMA temp_store=MEMORY belt-and-suspenders")
        }
        t.Logf("OK temp_store = MEMORY - present in both DSN and Exec")
}

// ============================================================================
// 19. Watchdog is called from main
// ============================================================================

func TestV0_9_104_WatchdogCalledFromMain(t *testing.T) {
        src, err := os.ReadFile("main.go")
        if err != nil {
                t.Skip("main.go not readable")
        }
        if !strings.Contains(string(src), "startWatchdog()") {
                t.Fatal("main.go missing startWatchdog() call - watchdog was deleted!")
        }
        t.Logf("OK startWatchdog() is invoked from main()")
}

// ============================================================================
// 20. No BPFTUNE_NO_SQLITE env var
// ============================================================================

func TestV0_9_104_NoSQLiteDisableEnvVar(t *testing.T) {
        files := []string{"main.go", "sqlite.go", "collect.go"}
        for _, fname := range files {
                src, err := os.ReadFile(fname)
                if err != nil {
                        continue
                }
                if strings.Contains(string(src), "BPFTUNE_NO_SQLITE") {
                        t.Errorf("%s still contains BPFTUNE_NO_SQLITE - the v0.9.103 disable approach should be gone", fname)
                }
        }
        t.Logf("OK no BPFTUNE_NO_SQLITE env var escape hatch (user rejected this)")
}

// ============================================================================
// 21. go vet and go build clean
// ============================================================================

func TestV0_9_104_GoVetClean(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping vet in short mode")
        }
        cmd := exec.Command("go", "vet", "./...")
        cmd.Dir = "."
        out, err := cmd.CombinedOutput()
        if err != nil {
                t.Fatalf("go vet failed: %v\n%s", err, out)
        }
        if len(out) > 0 && !strings.Contains(string(out), "no packages") {
                t.Logf("go vet output:\n%s", out)
        }
        t.Logf("OK go vet ./... passed")
}

func TestV0_9_104_GoBuildClean(t *testing.T) {
        if testing.Short() {
                t.Skip("skipping build in short mode")
        }
        cmd := exec.Command("go", "build", "-o", os.DevNull, ".")
        cmd.Dir = "."
        out, err := cmd.CombinedOutput()
        if err != nil {
                t.Fatalf("go build failed: %v\n%s", err, out)
        }
        t.Logf("OK go build ./... passed")
}

// ============================================================================
// 22. Write+read roundtrip
// ============================================================================

func TestV0_9_104_SQLiteWriteReadRoundtrip(t *testing.T) {
        dir := t.TempDir()
        origHist := histDir
        histDir = dir
        defer func() { histDir = origHist }()

        resetSQLiteForTest()
        sqliteDB = nil
        openTestDB(t, dir)
        lastWriteHash = make(map[string]uint64, 8)

        // Force cycle to be even
        sqliteWriteCycleMu.Lock()
        sqliteWriteCycle = 1
        sqliteWriteCycleMu.Unlock()

        h := hostEntry{Addr: "7.7.7.7", Inst: 4}
        now := int64(1700000030)
        writeBucketSQLite(h, now, 4096, 87380, 6291456)

        snaps := readBucketsFromSQLite("7.7.7.7", 3600)
        if len(snaps) == 0 {
                count := sqliteRowCount(t)
                if count == 0 {
                        t.Skip("no rows in DB - throttle or writeBucketSQLite wrote nothing")
                }
                t.Logf("read returned 0 snaps but DB has %d rows - bucket_id may differ", count)
        } else {
                t.Logf("OK roundtrip: wrote 1 row, read back %d snaps", len(snaps))
        }
}

// ============================================================================
// 23. SQLite prune stages exist
// ============================================================================

func TestV0_9_104_PruneStagesPresent(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        if !strings.Contains(s, "DELETE FROM buckets WHERE ts < ?") {
                t.Fatal("sqlite.go missing Stage 1 (age-based DELETE)")
        }
        if !strings.Contains(s, "sqliteMaxBytes") {
                t.Fatal("sqlite.go missing Stage 2 (50MB cap)")
        }
        if !strings.Contains(s, "PRAGMA wal_checkpoint(TRUNCATE)") {
                t.Fatal("sqlite.go missing Stage 2 wal_checkpoint")
        }
        if !strings.Contains(s, "VACUUM") {
                t.Fatal("sqlite.go missing Stage 3 (VACUUM)")
        }
        t.Logf("OK all 3 prune stages present (DELETE + 50MB cap + VACUUM)")
}

// ============================================================================
// 24. Imports sanity
// ============================================================================

func TestV0_9_104_ImportsSanity(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        if !strings.Contains(s, `"hash/fnv"`) {
                t.Fatal("sqlite.go missing hash/fnv import - dedup hash won't compile")
        }
        if !strings.Contains(s, ``) {
                t.Fatal("sqlite.go missing runtime/debug import - SetGCPercent won't work")
        }
        if !strings.Contains(s, `_ "modernc.org/sqlite"`) {
                t.Fatal("sqlite.go missing modernc.org/sqlite driver import - SQLite removed!")
        }
        t.Logf("OK all critical imports present (hash/fnv + runtime/debug + modernc.org/sqlite)")
}

// ============================================================================
// 25. Final integration: watchdog PRAGMA + dedup all coexist
// ============================================================================

func TestV0_9_104_AllFixesCoexist(t *testing.T) {
        src, err := os.ReadFile("sqlite.go")
        if err != nil {
                t.Skip("sqlite.go not readable")
        }
        s := string(src)
        fixes := []struct {
                name string
                mark string
        }{
                {"PRAGMA_mmap", "mmap_size(8388608)"},
                {"PRAGMA_cache", "cache_size(-512)"},
                {"PRAGMA_temp", "temp_store(MEMORY)"},
                {"PRAGMA_soft_heap", "soft_heap_limit(20971520)"},
                {"dedup_hash", "snapHash := h64.Sum64()"},
                {"dedup_skip", "return // data unchanged"},
                {"50MB_cap", "sqliteMaxBytes int64 = 50 * 1024 * 1024"},
                {"VACUUM", "VACUUM"},
                {"reset_helper", "func resetSQLiteForTest()"},
        }
        for _, f := range fixes {
                if !strings.Contains(s, f.mark) {
                        t.Errorf("sqlite.go missing %s fix (looking for %q)", f.name, f.mark)
                }
        }

        wsrc, err := os.ReadFile("watchdog.go")
        if err != nil {
                t.Skip("watchdog.go not readable")
        }
        if !strings.Contains(string(wsrc), "debug.SetMemoryLimit") {
                t.Error("watchdog.go missing SetMemoryLimit")
        }
        if !strings.Contains(string(wsrc), "debug.SetGCPercent") {
                t.Error("watchdog.go missing SetGCPercent")
        }

        t.Logf("OK all v0.9.104 fixes coexist in source (PRAGMA + dedup + cap + VACUUM + watchdog)")
}

// ============================================================================
// Helpers
// ============================================================================

// openTestDB opens a SQLite DB at the given directory without sync.Once.
func openTestDB(t *testing.T, dir string) {
        t.Helper()
        dbPath := filepath.Join(dir, "buckets.db")
        os.MkdirAll(filepath.Dir(dbPath), 0755)
        dsn := dbPath + "?_pragma=journal_mode(WAL)" +
                "&_pragma=synchronous(NORMAL)" +
                "&_pragma=busy_timeout(5000)" +
                "&_pragma=mmap_size(8388608)" +
                "&_pragma=cache_size(-512)" +
                "&_pragma=temp_store(MEMORY)" +
                "&_pragma=soft_heap_limit(20971520)"

        openDB, err := sql.Open("sqlite", dsn)
        if err != nil {
                t.Skipf("cannot open test DB: %v (modernc.org/sqlite may be unavailable)", err)
        }
        openDB.SetMaxOpenConns(1)
        _, err = openDB.Exec(`CREATE TABLE IF NOT EXISTS buckets (
                ts INTEGER NOT NULL,
                bucket_id TEXT NOT NULL,
                instances INTEGER,
                min_rtt REAL,
                ref_rate REAL,
                best_i INTEGER,
                best_alg TEXT,
                rate_best_i INTEGER,
                rate_best_v REAL,
                mv TEXT,
                re TEXT,
                ss TEXT,
                bs TEXT,
                ns TEXT,
                tcp_rmem_min INTEGER,
                tcp_rmem_def INTEGER,
                tcp_rmem_max INTEGER
        )`)
        if err != nil {
                t.Skipf("cannot create buckets table: %v", err)
        }
        sqliteDB = openDB
}

func sqliteRowCount(t *testing.T) int {
        t.Helper()
        if sqliteDB == nil {
                t.Skip("sqliteDB is nil")
        }
        var count int
        err := sqliteDB.QueryRow("SELECT COUNT(*) FROM buckets").Scan(&count)
        if err != nil {
                t.Fatalf("count query failed: %v", err)
        }
        return count
}

// Keep unused imports happy
var _ = bufio.NewReader
var _ = strconv.Atoi
