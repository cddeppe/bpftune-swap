package main

// sqlite.go — SQLite storage backend for bucket snapshots.
//
// Replaces buckets.v2.csv for historical queries. The CSV file is still
// written for backward compatibility during the transition period, but
// renderToDisk and readCSVTail prefer SQLite when available.
//
// Migration: on first startup, if buckets.db doesn't exist but buckets.v2.csv
// does, the CSV is imported into SQLite. This preserves all history.
//
// Schema:
//   CREATE TABLE buckets (
//     ts INTEGER NOT NULL,           -- collected timestamp (unix seconds)
//     bucket_id TEXT NOT NULL,       -- labeled bucket addr
//     instances INTEGER,
//     min_rtt REAL,
//     ref_rate REAL,                 -- Mbps
//     best_i INTEGER,
//     best_alg TEXT,
//     rate_best_i INTEGER,
//     rate_best_v REAL,
//     mv TEXT,                       -- JSON array of 16 metric_value floats
//     re TEXT,                       -- JSON array of 16 rate_ema floats
//     ss TEXT,                       -- JSON array of 16 swap_score ints
//     bs TEXT,                       -- JSON array of 16 bad_streak ints
//     ns TEXT,                       -- JSON array of 16 null_streak ints
//     tcp_rmem_min INTEGER,
//     tcp_rmem_def INTEGER,
//     tcp_rmem_max INTEGER
//   );
//   CREATE INDEX idx_buckets_ts_bucket ON buckets(ts, bucket_id);
//   CREATE INDEX idx_buckets_bucket ON buckets(bucket_id);

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	sqliteDB   *sql.DB
	sqliteOnce sync.Once
	sqliteMu  sync.Mutex
)

// sqlitePath returns the path to the SQLite database file.
func sqlitePath() string {
	return filepath.Join(histDir, "buckets.db")
}

// initSQLite opens (or creates) the SQLite database and creates tables.
// Called once at startup via sync.Once.
func initSQLite() {
	sqliteOnce.Do(func() {
		dbPath := sqlitePath()
		// Ensure parent directory exists
		os.MkdirAll(filepath.Dir(dbPath), 0755)

		db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
		if err != nil {
			fmt.Fprintf(os.Stderr, "sqlite: open failed: %v\n", err)
			return
		}
		// Optimize for write throughput
		db.SetMaxOpenConns(1) // SQLite single-writer
		db.Exec("PRAGMA synchronous=NORMAL")
		db.Exec("PRAGMA cache_size=-8000") // 8MB cache

		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS buckets (
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
			fmt.Fprintf(os.Stderr, "sqlite: create table failed: %v\n", err)
			return
		}

		db.Exec("CREATE INDEX IF NOT EXISTS idx_buckets_ts_bucket ON buckets(ts, bucket_id)")
		db.Exec("CREATE INDEX IF NOT EXISTS idx_buckets_bucket ON buckets(bucket_id)")

		sqliteDB = db

		// Check if we need to migrate from CSV
		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM buckets").Scan(&count)
		if err == nil && count == 0 {
			csvPath := bucketsCSVPath
			if _, err := os.Stat(csvPath); err == nil {
				fmt.Fprintf(os.Stderr, "sqlite: migrating %s to %s...\n", csvPath, dbPath)
				migrateCSVToSQLite(csvPath)
			}
		}
	})
}

// migrateCSVToSQLite reads a buckets CSV file and imports all rows into
// the SQLite database. Called once on first startup when the DB is empty.
func migrateCSVToSQLite(csvPath string) {
	f, err := os.Open(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: migration: cannot open CSV: %v\n", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20) // 8MB max line

	// Read header to determine column layout
	if !scanner.Scan() {
		fmt.Fprintf(os.Stderr, "sqlite: migration: empty CSV\n")
		return
	}
	header := strings.Split(scanner.Text(), ",")

	// Build column index map
	colIdx := make(map[string]int)
	for i, col := range header {
		colIdx[col] = i
	}

	tx, err := sqliteDB.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: migration: begin tx failed: %v\n", err)
		return
	}
	stmt, err := tx.Prepare(`INSERT INTO buckets
		(ts, bucket_id, instances, min_rtt, ref_rate, best_i, best_alg,
		 rate_best_i, rate_best_v, mv, re, ss, bs, ns,
		 tcp_rmem_min, tcp_rmem_def, tcp_rmem_max)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: migration: prepare failed: %v\n", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	rowCount := 0
	batchStart := time.Now()

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) < len(header) {
			continue
		}

		// Extract core fields
		tsStr := getField(fields, colIdx, "collected_ts")
		ts, _ := strconv.ParseInt(tsStr, 10, 64)
		if ts == 0 {
			continue
		}
		bucketID := getField(fields, colIdx, "addr")
		if bucketID == "" {
			continue
		}
		instances, _ := strconv.Atoi(getField(fields, colIdx, "instances"))
		minRtt, _ := strconv.ParseFloat(getField(fields, colIdx, "min_rtt"), 64)
		refRate, _ := strconv.ParseFloat(getField(fields, colIdx, "ref_rate"), 64)
		bestI, _ := strconv.Atoi(getField(fields, colIdx, "best_i"))
		bestAlg := getField(fields, colIdx, "best_alg")
		rateBestI, _ := strconv.Atoi(getField(fields, colIdx, "rate_best_i"))
		rateBestV, _ := strconv.ParseFloat(getField(fields, colIdx, "rate_best_v"), 64)
		rmemMin, _ := strconv.Atoi(getField(fields, colIdx, "tcp_rmem_min"))
		rmemDef, _ := strconv.Atoi(getField(fields, colIdx, "tcp_rmem_def"))
		rmemMax, _ := strconv.Atoi(getField(fields, colIdx, "tcp_rmem_max"))

		// Build JSON arrays for per-algorithm metrics
		mv := extractAlgArray(fields, colIdx, "mv_")
		re := extractAlgArray(fields, colIdx, "re_")
		ss := extractAlgArray(fields, colIdx, "ss_")
		bs := extractAlgArray(fields, colIdx, "bs_")
		ns := extractAlgArray(fields, colIdx, "ns_")

		_, err := stmt.Exec(ts, bucketID, instances, minRtt, refRate, bestI, bestAlg,
			rateBestI, rateBestV, mv, re, ss, bs, ns,
			rmemMin, rmemDef, rmemMax)
		if err != nil {
			// Log but continue — a few bad rows shouldn't abort the migration
			fmt.Fprintf(os.Stderr, "sqlite: migration: row %d failed: %v\n", rowCount, err)
			continue
		}
		rowCount++

		// Commit in batches of 10000 to avoid holding the transaction too long
		if rowCount%10000 == 0 {
			stmt.Close()
			tx.Commit()
			tx, _ = sqliteDB.Begin()
			stmt, _ = tx.Prepare(`INSERT INTO buckets
				(ts, bucket_id, instances, min_rtt, ref_rate, best_i, best_alg,
				 rate_best_i, rate_best_v, mv, re, ss, bs, ns,
				 tcp_rmem_min, tcp_rmem_def, tcp_rmem_max)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: migration: scanner error: %v\n", err)
	}

	stmt.Close()
	if err := tx.Commit(); err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: migration: commit failed: %v\n", err)
		return
	}

	elapsed := time.Since(batchStart)
	fmt.Fprintf(os.Stderr, "sqlite: migration complete — %d rows in %s\n", rowCount, elapsed)
}

// getField safely gets a field by column name from the CSV row.
func getField(fields []string, colIdx map[string]int, col string) string {
	if i, ok := colIdx[col]; ok && i < len(fields) {
		return fields[i]
	}
	return ""
}

// extractAlgArray builds a JSON array string from per-algorithm CSV columns.
// e.g. prefix="mv_" → collects mv_cubic, mv_bbr, mv_htcp, ... into [v1,v2,...]
func extractAlgArray(fields []string, colIdx map[string]int, prefix string) string {
	arr := make([]interface{}, 16)
	for i, alg := range CONGS {
		col := prefix + alg
		val := getField(fields, colIdx, col)
		if val == "" {
			arr[i] = nil
		} else {
			if prefix == "mv_" || prefix == "re_" {
				f, _ := strconv.ParseFloat(val, 64)
				arr[i] = f
			} else {
				n, _ := strconv.Atoi(val)
				arr[i] = n
			}
		}
	}
	data, _ := json.Marshal(arr)
	return string(data)
}

// writeBucketSQLite inserts a bucket snapshot into the SQLite database.
// Called from writeBucketsCSV (dual-write during transition).
func writeBucketSQLite(h hostEntry, now int64, rmemMin, rmemDef, rmemMax int) {
	if sqliteDB == nil {
		return
	}
	v := h.V
	metrics, _ := v["metrics"].([]interface{})

	mv := make([]interface{}, 16)
	re := make([]interface{}, 16)
	ss := make([]interface{}, 16)
	bs := make([]interface{}, 16)
	ns := make([]interface{}, 16)
	for i := 0; i < 16; i++ {
		var mi map[string]interface{}
		if i < len(metrics) {
			mi, _ = metrics[i].(map[string]interface{})
		}
		if mi == nil {
			mv[i] = nil
			re[i] = nil
			ss[i] = nil
			bs[i] = nil
			ns[i] = nil
		} else {
			mv[i] = toFloat(mi["metric_value"])
			re[i] = toFloat(mi["rate_ema"])
			mc := toInt(mi["metric_count"])
			if mc > 0 || toInt(mi["sockets_alive"]) > 0 || toFloat(mi["rate_ema"]) > 0 {
				ss[i] = toInt(mi["swap_score"])
				bs[i] = toInt(mi["bad_streak"])
				ns[i] = toInt(mi["null_streak"])
			} else {
				ss[i] = nil
				bs[i] = nil
				ns[i] = nil
			}
		}
	}

	bestI := toInt(v["best_i"])
	bestAlg := ""
	if bestI >= 0 && bestI < len(CONGS) {
		bestAlg = CONGS[bestI]
	}
	rateBestI := bestI
	rateBestV := 0.0
	if bestI >= 0 && bestI < len(metrics) {
		mi, _ := metrics[bestI].(map[string]interface{})
		if mi != nil {
			rateBestV = toFloat(mi["rate_ema"])
		}
	}

	mvJSON, _ := json.Marshal(mv)
	reJSON, _ := json.Marshal(re)
	ssJSON, _ := json.Marshal(ss)
	bsJSON, _ := json.Marshal(bs)
	nsJSON, _ := json.Marshal(ns)

	sqliteMu.Lock()
	defer sqliteMu.Unlock()
	_, err := sqliteDB.Exec(
		`INSERT INTO buckets
		(ts, bucket_id, instances, min_rtt, ref_rate, best_i, best_alg,
		 rate_best_i, rate_best_v, mv, re, ss, bs, ns,
		 tcp_rmem_min, tcp_rmem_def, tcp_rmem_max)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		now, h.Addr, h.Inst, toFloat(v["min_rtt"]),
		toFloat(v["max_rate_delivered"])/bpsToMbps, bestI, bestAlg,
		rateBestI, rateBestV, string(mvJSON), string(reJSON),
		string(ssJSON), string(bsJSON), string(nsJSON),
		rmemMin, rmemDef, rmemMax,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: insert failed: %v\n", err)
	}
}

// readBucketsFromSQLite queries bucket snapshots for a given bucket_id and
// time range (span seconds). Returns a slice of bucketSnapshot.
// Falls back to CSV if SQLite is not available.
func readBucketsFromSQLite(bucketID string, span int64) []bucketSnapshot {
	if sqliteDB == nil {
		return readBucketCSV(bucketID, span)
	}
	cutoff := time.Now().Unix() - span
	rows, err := sqliteDB.Query(
		`SELECT ts, instances, min_rtt, ref_rate, best_i, best_alg,
		        mv, re, ss, bs, ns
		 FROM buckets
		 WHERE bucket_id = ? AND ts >= ?
		 ORDER BY ts ASC`,
		bucketID, cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: query failed: %v — falling back to CSV\n", err)
		return readBucketCSV(bucketID, span)
	}
	defer rows.Close()

	var snaps []bucketSnapshot
	for rows.Next() {
		var snap bucketSnapshot
		var minRtt, refRate float64
		var bestI int
		var bestAlg, mvJSON, reJSON, ssJSON, bsJSON, nsJSON string
		var instances int
		var ts int64
		if err := rows.Scan(&ts, &instances, &minRtt, &refRate, &bestI, &bestAlg,
			&mvJSON, &reJSON, &ssJSON, &bsJSON, &nsJSON); err != nil {
			continue
		}
		snap.Ts = ts
		snap.Instances = instances
		snap.MinRtt = minRtt
		snap.RefRate = refRate
		snap.BestI = bestI
		snap.BestAlg = bestAlg
		// Parse JSON arrays back into snap arrays
		json.Unmarshal([]byte(mvJSON), &snap.Mv)
		json.Unmarshal([]byte(reJSON), &snap.Re)
		json.Unmarshal([]byte(ssJSON), &snap.Ss)
		json.Unmarshal([]byte(bsJSON), &snap.Bs)
		json.Unmarshal([]byte(nsJSON), &snap.Ns)
		snaps = append(snaps, snap)
	}
	return snaps
}

// readBucketsAllFromSQLite queries all bucket IDs' snapshots within a time span.
// Returns a map keyed by bucket_id → []bucketSnapshot (like readCSVTail).
func readBucketsAllFromSQLite(span int64) map[string][]bucketSnapshot {
	out := map[string][]bucketSnapshot{}
	if sqliteDB == nil {
		return out
	}
	cutoff := time.Now().Unix() - span
	rows, err := sqliteDB.Query(
		`SELECT ts, bucket_id, instances, min_rtt, ref_rate, best_i, best_alg,
		        mv, re, ss, bs, ns
		 FROM buckets
		 WHERE ts >= ?
		 ORDER BY ts ASC`,
		cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: query all failed: %v\n", err)
		return out
	}
	defer rows.Close()

	for rows.Next() {
		var snap bucketSnapshot
		var minRtt, refRate float64
		var bestI int
		var bestAlg, mvJSON, reJSON, ssJSON, bsJSON, nsJSON, bucketID string
		var instances int
		var ts int64
		if err := rows.Scan(&ts, &bucketID, &instances, &minRtt, &refRate,
			&bestI, &bestAlg, &mvJSON, &reJSON, &ssJSON, &bsJSON, &nsJSON); err != nil {
			continue
		}
		snap.Ts = ts
		snap.Instances = instances
		snap.MinRtt = minRtt
		snap.RefRate = refRate
		snap.BestI = bestI
		snap.BestAlg = bestAlg
		json.Unmarshal([]byte(mvJSON), &snap.Mv)
		json.Unmarshal([]byte(reJSON), &snap.Re)
		json.Unmarshal([]byte(ssJSON), &snap.Ss)
		json.Unmarshal([]byte(bsJSON), &snap.Bs)
		json.Unmarshal([]byte(nsJSON), &snap.Ns)
		out[bucketID] = append(out[bucketID], snap)
	}
	return out
}

// pruneSQLiteOld removes rows older than `days` days. Called periodically
// to prevent the database from growing unboundedly.
func pruneSQLiteOld(days int) {
	if sqliteDB == nil {
		return
	}
	cutoff := time.Now().Unix() - int64(days*86400)
	sqliteMu.Lock()
	defer sqliteMu.Unlock()
	result, err := sqliteDB.Exec("DELETE FROM buckets WHERE ts < ?", cutoff)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sqlite: prune failed: %v\n", err)
		return
	}
	if n, _ := result.RowsAffected(); n > 0 {
		fmt.Fprintf(os.Stderr, "sqlite: pruned %d rows older than %d days\n", n, days)
	}
}
