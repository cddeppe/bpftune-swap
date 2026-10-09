cd /root/bpftune/dashboard/bin/go

python3 << 'PYEOF'
import re

# === 1. Patch render.go ===
with open("render.go") as f:
    src = f.read()

# Change buildSeriesFromSnaps signature to return tsArr
src = src.replace(
    "func buildSeriesFromSnaps(snaps []bucketSnapshot, width int) map[string]interface{} {",
    "func buildSeriesFromSnaps(snaps []bucketSnapshot, width int) (map[string]interface{}, []int64) {"
)

# Change return statement
src = src.replace(
    "	return series\n}",
    "	return series, tsArr\n}",
    1  # only first occurrence (buildSeriesFromSnaps)
)

# Change the caller in renderBucketToDisk to use returned tsArr
# Replace: series := buildSeriesFromSnaps(snaps, width)
# With:    series, tsArr := buildSeriesFromSnaps(snaps, width)
src = src.replace(
    "series := buildSeriesFromSnaps(snaps, width)",
    "series, tsArr := buildSeriesFromSnaps(snaps, width)"
)

# Replace the inlined swaps code to use tsArr directly (no type assertion)
old_block = """\t\ttsArr, _ := series["ts"].([]int64)
\t\tswapsArr := make([]interface{}, len(tsArr))
\t\tif len(tsArr) > 0 {
\t\t\tbinCounts := map[int64]int{}
\t\t\tif sf, err := os.Open(swapsCSVPath); err == nil {
\t\t\t\tsc := bufio.NewScanner(sf)
\t\t\t\tsc.Buffer(make([]byte, 1024*1024), 1024*1024)
\t\t\t\tsc.Scan()
\t\t\t\tfor sc.Scan() {
\t\t\t\t\tc := strings.Split(sc.Text(), ",")
\t\t\t\t\tif len(c) < 13 { continue }
\t\t\t\t\tif ResolveBucket(c[11]) != bucketID { continue }
\t\t\t\t\tst, _ := strconv.ParseInt(c[0], 10, 64)
\t\t\t\t\tbinCounts[st/int64(width)]++
\t\t\t\t}
\t\t\t\tsf.Close()
\t\t\t}
\t\t\tfor i, ts := range tsArr {
\t\t\t\tswapsArr[i] = binCounts[ts/int64(width)]
\t\t\t}
\t\t}
\t\tseries["swaps"] = swapsArr"""

new_block = """\t\t// v0.7.5e: use tsArr returned by buildSeriesFromSnaps (no type assertion)
\t\tswapsArr := make([]interface{}, len(tsArr))
\t\tif len(tsArr) > 0 {
\t\t\tbinCounts := map[int64]int{}
\t\t\tif sf, err := os.Open(swapsCSVPath); err == nil {
\t\t\t\tsc := bufio.NewScanner(sf)
\t\t\t\tsc.Buffer(make([]byte, 1024*1024), 1024*1024)
\t\t\t\tsc.Scan()
\t\t\t\tfor sc.Scan() {
\t\t\t\t\tc := strings.Split(sc.Text(), ",")
\t\t\t\t\tif len(c) < 13 { continue }
\t\t\t\t\tif ResolveBucket(c[11]) != bucketID { continue }
\t\t\t\t\tst, _ := strconv.ParseInt(c[0], 10, 64)
\t\t\t\t\tbinCounts[st/int64(width)]++
\t\t\t\t}
\t\t\t\tsf.Close()
\t\t\t}
\t\t\tfor i, ts := range tsArr {
\t\t\t\tswapsArr[i] = binCounts[ts/int64(width)]
\t\t\t}
\t\t}
\t\tseries["swaps"] = swapsArr"""

src = src.replace(old_block, new_block)

with open("render.go", "w") as f:
    f.write(src)
print("Patched render.go")

# === 2. Patch http_handlers.go ===
with open("http_handlers.go") as f:
    src2 = f.read()

src2 = src2.replace(
    "series := buildSeriesFromSnaps(snaps, width)",
    "series, _ := buildSeriesFromSnaps(snaps, width)"
)

with open("http_handlers.go", "w") as f:
    f.write(src2)
print("Patched http_handlers.go")
PYEOF

# Verify
grep "func buildSeriesFromSnaps" render.go
grep "series, tsArr := buildSeriesFromSnaps" render.go | head -2
grep "series, _ := buildSeriesFromSnaps" http_handlers.go

# Rebuild + deploy
go build -o bpftune-collector-go . || { echo "BUILD FAILED"; exit 1; }
echo "Build OK"
systemctl stop bpftune-collector-go
cp bpftune-collector-go /opt/bpftune-dashboard/bin/bpftune-collector-go
rm -f /var/lib/bpftune/history/data/*.json
systemctl start bpftune-collector-go
sleep 30

# Verify swaps now match ts length
curl -s http://127.0.0.1:8080/data/bucket_home-sco.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
s=d.get('series',{})
for rng in ['1h','24h','7d','30d','all']:
    r=s.get(rng,{})
    ts_len = len(r.get('ts',[]))
    swaps_len = len(r.get('swaps',[]))
    swaps_sum = sum(r.get('swaps',[0]))
    print(f'{rng}: ts={ts_len} swaps={swaps_len} match={ts_len==swaps_len} total_swaps={swaps_sum}')
"
