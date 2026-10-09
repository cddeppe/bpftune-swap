(function () {
  var PALETTE = [
    "#4e79a7", "#f28e2c", "#e15759", "#76b7b2",
    "#59a14f", "#edc949", "#af7aa1", "#ff9da7",
    "#9c755f", "#bab0ab", "#1b9e77", "#d95f02",
    "#7570b3", "#e7298a", "#66a61e", "#e6ab02"
  ];

  var gen = document.getElementById("gen");
  var footgen = document.getElementById("footgen");

  function status(msg, isErr) {
    if (gen) {
      gen.textContent = msg;
      gen.style.color = isErr ? "#e5484d" : "";
      if (!isErr) {
        gen.classList.add("flash");
        setTimeout(function () { gen.classList.remove("flash"); }, 300);
      }
    }
  }
  function err(msg, e) { status(msg, true); if (e) console.error(msg, e); }

  function loadScript(url) {
    return new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = url;
      s.onload = resolve;
      s.onerror = function () { reject(new Error("failed to load " + url)); };
      document.head.appendChild(s);
    });
  }

  function applyChartDefaults() {
    var dark = window.matchMedia &&
               window.matchMedia("(prefers-color-scheme: dark)").matches;
    var grid = dark ? "rgba(255,255,255,.06)" : "rgba(20,30,50,.06)";
    var tick = dark ? "#8b929b" : "#6b7280";
    Chart.defaults.font.family =
      "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.color = tick;
    Chart.defaults.borderColor = grid;
    Chart.defaults.elements.line.borderWidth = 1.5;
    Chart.defaults.elements.point.radius = 0;
    Chart.defaults.elements.point.hoverRadius = 3;
    Chart.defaults.animation = false;
    Chart.defaults.plugins.legend.labels.boxWidth = 10;
    Chart.defaults.plugins.legend.labels.boxHeight = 10;
    Chart.defaults.plugins.legend.labels.padding = 8;
    Chart.defaults.plugins.tooltip.backgroundColor = dark ? "#1c2028" : "#fff";
    Chart.defaults.plugins.tooltip.borderColor = dark ? "#2a2f39" : "#e5e7eb";
    Chart.defaults.plugins.tooltip.borderWidth = 1;
    Chart.defaults.plugins.tooltip.titleColor = dark ? "#e6e8eb" : "#131720";
    Chart.defaults.plugins.tooltip.bodyColor  = dark ? "#e6e8eb" : "#131720";
    Chart.defaults.plugins.tooltip.padding = 8;
    Chart.defaults.plugins.tooltip.cornerRadius = 6;
  }

  function $(id) { return document.getElementById(id); }
  function setHTML(id, s) { var e = $(id); if (e) e.innerHTML = s; }
  /* 0.4.79: monotonic-age label for recent swaps / proofs. */
  var SERVER_NOW_MONO = 0;
  // v0.9.20: ageLabel accepts optional epoch_ts (wall-clock).
  // When boot_ts is from a PREVIOUS boot (age < 0), fall back to
  // epoch_ts so ages display correctly after a reboot.
  // Backward compat: if epoch_ts is missing, returns '' (same as before).
  function ageLabel(boot_ts, epoch_ts) {
    if (!boot_ts) return '';
    if (SERVER_NOW_MONO) {
      var age = SERVER_NOW_MONO - boot_ts;
      if (age >= 0) {
        if (age < 60)    return Math.round(age) + 's';
        if (age < 3600)  return Math.round(age/60) + 'm';
        if (age < 86400) return Math.round(age/3600) + 'h';
        return Math.round(age/86400) + 'd';
      }
    }
    // boot_ts is from a different boot (age < 0) — use epoch_ts
    if (epoch_ts) {
      var nowSec = Math.floor(Date.now() / 1000);
      var eAge = nowSec - epoch_ts;
      if (eAge < 0) return '';
      if (eAge < 60)    return Math.round(eAge) + 's';
      if (eAge < 3600)  return Math.round(eAge/60) + 'm';
      if (eAge < 86400) return Math.round(eAge/3600) + 'h';
      return Math.round(eAge/86400) + 'd';
    }
    return '';
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return ({ "&": "&amp;", "<": "&lt;", ">": "&gt;",
                '"': "&quot;", "'": "&#39;" })[c];
    });
  }
  function fmtN(v) {
    return (v == null) ? "-" : Math.round(v).toLocaleString();
  }
  function fmtMbps(v) {
    return (v == null) ? "-" : (v / 125000).toFixed(1);
  }
  function fmtRe(v) {
    return (v == null) ? "-" : (v * 0.8).toFixed(1);
  }
  function scaleRe(v) {
    return v == null ? null : v * 0.8;
  }
  function fmtRTT(v) {
    return (v == null) ? "-" : (v / 1000).toFixed(1) + " ms";
  }
  function fmtBytes(b) {
    if (b == null) return "-";
    if (b >= 1e9) return (b / 1e9).toFixed(2) + " GB";
    if (b >= 1e6) return (b / 1e6).toFixed(1) + " MB";
    return Math.round(b) + " B";
  }
  function fmtUptime(s) {
    if (s == null) return "-";
    var d = Math.floor(s / 86400);
    var h = Math.floor((s % 86400) / 3600);
    var m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + h + "h " + m + "m";
  }
  function relTime(epochSec) {
    if (!epochSec) return "";
    var dt = Math.max(0, Math.floor(Date.now() / 1000) - epochSec);
    if (dt < 60) return dt + "s ago";
    if (dt < 3600) return Math.floor(dt / 60) + "m ago";
    if (dt < 86400) return Math.floor(dt / 3600) + "h ago";
    return Math.floor(dt / 86400) + "d ago";
  }

  function renderBuild(b) {
    // v0.9.10 fix: check focus BEFORE setHTML destroys the inputs.
    // The old E2-fix checked focus AFTER setHTML, by which point the
    // inputs were already gone and document.activeElement was <body>.
    // Now we skip the entire rebuild if any config input has focus.
    var _cfgIds = ['cfg-p4', 'cfg-p6', 'cfg-ep', 'cfg-pg', 'cfg-pp'];
    var _activeEl = document.activeElement;
    for (var _ci = 0; _ci < _cfgIds.length; _ci++) {
      var _el = document.getElementById(_cfgIds[_ci]);
      if (_el && _el === _activeEl) {
        // User is editing — skip the rebuild entirely.
        return;
      }
    }
    var rows = [
      ["tuner",     b.version, "hi"],
      ["dashboard", b.dash_version || "?", "hi"],
      ["service",   b.service, b.service === "active" ? "hi" : ""],
    ];
    if (b.uptime_min != null) {
      var h = Math.floor(b.uptime_min / 60);
      var m = b.uptime_min % 60;
      rows.push(["uptime", h + "h " + m + "m"]);
    }
    if (b.started_utc) rows.push(["started", b.started_utc + " UTC"]);
    if (b.prefix4 != null) rows.push(["prefix4 (v4)", "/" + b.prefix4]);
    if (b.prefix6 != null) rows.push(["prefix6 (v6)", "/" + b.prefix6]);
    if (b.explore_pct != null) rows.push(["exploration", b.explore_pct + "%"]);
    if (b.proof_good_bps != null) rows.push(["proof good", (b.proof_good_bps * 8 / 1000000).toFixed(0) + " Mbps"]);
    if (b.proof_proved_bps != null) rows.push(["proof proved", (b.proof_proved_bps * 8 / 1000000).toFixed(0) + " Mbps"]);
    setHTML("lv-build", rows.map(function (r) {
      return '<div class="row"><span class="k">' + esc(r[0]) + '</span>' +
             '<span class="v ' + (r[2] || "") + '">' + esc(r[1]) + '</span></div>';
    }).join(""));

  // v0.7.5p: inline editable prefix4/prefix6/explore_pct + Save button
  (function() {
    var _be = document.getElementById('lv-build');
    if (!_be || !b.prefix4) return;
    // E2-fix: skip rebuilding config inputs if any of them currently has
    // focus. The old code rebuilt the entire #lv-build block on every
    // SSE push (every 30s), destroying the inputs mid-typing and losing
    // the user's focus + partial input. Now we leave the inputs alone
    // while the user is interacting with them.
    var _activeEl = document.activeElement;
    var _cfgIds = ['cfg-p4', 'cfg-p6', 'cfg-ep', 'cfg-pg', 'cfg-pp'];
    for (var _ci = 0; _ci < _cfgIds.length; _ci++) {
      var _el = document.getElementById(_cfgIds[_ci]);
      if (_el && _el === _activeEl) {
        // User is editing — skip the rebuild entirely. The Save button
        // is already attached from the previous render.
        return;
      }
    }
    // Also skip if the Save button was already attached (avoid duplicate
    // buttons on re-renders where no input has focus but inputs exist).
    var _existingSave = _be.querySelector('button');
    if (_existingSave) {
      // Inputs exist and aren't focused — just update their values from
      // the new b without rebuilding. This keeps the inputs stable
      // across SSE pushes while still reflecting server-side changes
      // (e.g. another tab edited the config).
      var _p4 = document.getElementById('cfg-p4');
      var _p6 = document.getElementById('cfg-p6');
      var _ep = document.getElementById('cfg-ep');
      var _pg = document.getElementById('cfg-pg');
      var _pp = document.getElementById('cfg-pp');
      if (_p4) _p4.value = b.prefix4;
      if (_p6) _p6.value = b.prefix6;
      if (_ep) _ep.value = b.explore_pct;
      if (_pg) _pg.value = (b.proof_good_bps * 8 / 1000000).toFixed(0);
      if (_pp) _pp.value = (b.proof_proved_bps * 8 / 1000000).toFixed(0);
      return;
    }
    var _rows = _be.querySelectorAll('.row');
    _rows.forEach(function(row) {
      var _k = row.querySelector('.k');
      var _v = row.querySelector('.v');
      if (!_k || !_v) return;
      var _kt = _k.textContent;
      if (_kt.indexOf('prefix4') >= 0) {
        _v.innerHTML = '/<input type="text" id="cfg-p4" value="' + b.prefix4 + '" min="1" max="32" style="width:40px;font-size:13px;font-family:var(--mono);background:transparent;border:1px solid var(--border);border-radius:3px;color:inherit;padding:1px 3px;text-align:right">';
      } else if (_kt.indexOf('prefix6') >= 0) {
        _v.innerHTML = '/<input type="text" id="cfg-p6" value="' + b.prefix6 + '" min="1" max="128" style="width:40px;font-size:13px;font-family:var(--mono);background:transparent;border:1px solid var(--border);border-radius:3px;color:inherit;padding:1px 3px;text-align:right">';
      } else if (_kt.indexOf('exploration') >= 0) {
        _v.innerHTML = '<input type="text" id="cfg-ep" value="' + b.explore_pct + '" min="0" max="100" style="width:40px;font-size:13px;font-family:var(--mono);background:transparent;border:1px solid var(--border);border-radius:3px;color:inherit;padding:1px 3px;text-align:right">%';
      } else if (_kt.indexOf('proof good') >= 0) {
        _v.innerHTML = '<input type="text" id="cfg-pg" value="' + (b.proof_good_bps * 8 / 1000000).toFixed(0) + '" min="1" style="width:50px;font-size:13px;font-family:var(--mono);background:transparent;border:1px solid var(--border);border-radius:3px;color:inherit;padding:1px 3px;text-align:right"> Mbps';
      } else if (_kt.indexOf('proof proved') >= 0) {
        _v.innerHTML = '<input type="text" id="cfg-pp" value="' + (b.proof_proved_bps * 8 / 1000000).toFixed(0) + '" min="1" style="width:50px;font-size:13px;font-family:var(--mono);background:transparent;border:1px solid var(--border);border-radius:3px;color:inherit;padding:1px 3px;text-align:right"> Mbps';
      }
    });
    var _sb = document.createElement('button');
    _sb.textContent = 'Save';
    _sb.style.cssText = 'font-size:10px;padding:2px 12px;cursor:pointer;border:1px solid var(--good);border-radius:3px;background:var(--good);color:#fff;margin-top:8px;display:block';
    _sb.onclick = function() {
      var ch = {};
      var p4 = document.getElementById('cfg-p4');
      var p6 = document.getElementById('cfg-p6');
      var ep = document.getElementById('cfg-ep');
      if (p4) ch.prefix4 = parseInt(p4.value);
      if (p6) ch.prefix6 = parseInt(p6.value);
      if (ep) ch.explore_pct = parseInt(ep.value);
      var pg = document.getElementById('cfg-pg');
      var pp = document.getElementById('cfg-pp');
      if (pg) ch.proof_good_bps = Math.round(parseFloat(pg.value) * 1000000 / 8);
      if (pp) ch.proof_proved_bps = Math.round(parseFloat(pp.value) * 1000000 / 8);
      fetch('/api/config', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(ch)})
        .then(function(r) { return r.json(); })
        .then(function(d) { if (d.ok) { status('Config saved — live on next bpftune restart'); if (d.prefix4 != null) { var _i = document.getElementById('cfg-p4'); if (_i) _i.value = d.prefix4; } if (d.prefix6 != null) { var _i2 = document.getElementById('cfg-p6'); if (_i2) _i2.value = d.prefix6; } if (d.explore_pct != null) { var _i3 = document.getElementById('cfg-ep'); if (_i3) _i3.value = d.explore_pct; }
          if (d.proof_good_bps != null) { var _i4 = document.getElementById('cfg-pg'); if (_i4) _i4.value = (d.proof_good_bps * 8 / 1000000).toFixed(0); }
          if (d.proof_proved_bps != null) { var _i5 = document.getElementById('cfg-pp'); if (_i5) _i5.value = (d.proof_proved_bps * 8 / 1000000).toFixed(0); } } })
        .catch(function(e) { err('config: ' + e.message); });
    };
    _be.appendChild(_sb);
  })();;
  }

  function renderSystem(s) {
    var rows = [];
    if (s.kernel)     rows.push(["kernel", s.kernel, "hi"]);
    if (s.default_cc) rows.push(["default cc", s.default_cc, "hi"]);
    if (s.cpu_count != null) rows.push(["cpu", s.cpu_count + " cores"]);
    if (s.load_1 != null) {
      rows.push(["load",
        s.load_1.toFixed(2) + " / " + s.load_5.toFixed(2) +
        " / " + s.load_15.toFixed(2)]);
    }
    if (s.procs_total != null) {
      rows.push(["processes",
        (s.procs_running == null ? "?" : s.procs_running) +
        " running / " + s.procs_total + " total"]);
    }
    if (s.host_uptime_s != null) {
      rows.push(["host uptime", fmtUptime(s.host_uptime_s)]);
    }
    if (s.mem_total_bytes != null && s.mem_total_bytes > 0) {
      var used = (s.mem_used_bytes != null)
                 ? s.mem_used_bytes
                 : (s.mem_total_bytes - (s.mem_avail_bytes || 0));
      var pct = (s.mem_used_pct != null)
                ? s.mem_used_pct.toFixed(0) + "%"
                : "";
      rows.push(["memory",
        fmtBytes(used) + " / " + fmtBytes(s.mem_total_bytes) +
        (pct ? "  " + pct : "")]);
    }
    setHTML("lv-system", rows.map(function (r) {
      return '<div class="row"><span class="k">' + esc(r[0]) + '</span>' +
             '<span class="v ' + (r[2] || "") + '">' + esc(r[1]) + '</span></div>';
    }).join(""));
  }

  function renderTunables(groups) {
    var cnt = $("lv-tun-cnt");
    if (!groups || !groups.length) {
      if (cnt) cnt.textContent = "";
      setHTML("lv-tunables",
              '<div class="placeholder">(none seen in journal this boot)</div>');
      return;
    }
    var total = 0;
    groups.forEach(function (g) { total += g.items.length; });
    if (cnt) cnt.textContent = total + " keys · " + groups.length + " groups";
    setHTML("lv-tunables", groups.map(function (g) {
      var rows = g.items.map(function (it) {
        return '<div class="grow"><span class="k">' + esc(it.key) +
               '</span><span class="v">' + esc(it.value) + '</span></div>';
      }).join("");
      return '<div class="tun-group"><div class="gname">' +
             esc(g.group) + '</div>' + rows + '</div>';
    }).join(""));
  }

  function renderBuckets(rows) {
    state.lastBucketRows = rows || [];
    if (!rows.length) {
      setHTML("lv-buckets", '<div class="placeholder">(no buckets)</div>');
      return;
    }
    var cov = {};
    var f = state.fleet || {};
    var fb = f.buckets || [];
    var fc = f.coverage_24h || [];
    for (var i = 0; i < fb.length; i++) cov[fb[i]] = fc[i];

    var html = '<table class="tbl"><thead><tr>' +
      '<th>dest</th><th>instances</th><th>min rtt</th>' +
      '<th>ref rate</th><th>best alg</th><th>algs</th>' +
      '<th style="width:24%">coverage · 24h</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      var v = cov[r.dest];
      var cell;
      if (v == null) {
        cell = '<td class="mono dim">&ndash;</td>';
      } else {
        var pct = Math.max(0, Math.min(100, v));
        cell = '<td class="mono"><span class="covbar"><i style="width:' +
               pct.toFixed(0) + '%"></i></span>' + pct.toFixed(0) + '%</td>';
      }
      html += '<tr>' +
        '<td class="mono name">' + esc(shortAddr(r.dest)) + '</td>' +
        '<td class="mono">' + fmtN(r.inst) + '</td>' +
        '<td class="mono dim">' + (r.rtt_us / 1000).toFixed(1) + ' ms</td>' +
        '<td class="mono">' + r.ref_mbps.toFixed(1) + '</td>' +
        '<td>' + esc(r.best_alg) + '</td>' +
        '<td class="mono dim">' + r.n_alg + '</td>' +
        cell +
        '</tr>';
    });
    setHTML("lv-buckets", html + '</tbody></table>');
  }

  function renderRecentSwapsForBucket() {
    var bk = _currentBucketLabel();
    var swaps = state.lastLiveSwaps || [];
    if (bk.bid !== 'all') {
      swaps = swaps.filter(function(s) { return _destMatches(s.dest, bk.bid, bk.label); });
    }
    renderRecentSwaps(swaps.slice(0, 18));
  }

  function renderMetricForBucket() {
    var bs = $("bucket");
    var addr = (bs && bs.value) ? bs.value : null;
    if (!addr && state.meta && state.meta.default_bucket) {
      addr = state.meta.default_bucket;
    }
    if (addr === 'all') {
      var hb = _heaviestBucketWithCoverage();
      if (hb) addr = hb.bid;
    }
    var byB = state.metricByBucket || {};
    var keys = Object.keys(byB);
    // 0.4.87: try the raw addr first (the dropdown value), then the
    // label form (metric_by_bucket is keyed by _label_for(addr) on
    // the python side via read_map, so for labeled buckets only the
    // label form matches).
    var rows = (addr && byB[addr]) ? byB[addr] : [];
    if (!rows.length) {
      var lbl = _labelForBucketAddr(addr);
      if (lbl && lbl !== addr && byB[lbl]) rows = byB[lbl];
    }
    // 0.4.87: do NOT silently fall back to keys[0] (the first bucket).
    // The previous behaviour showed whichever bucket happened to sort
    // first, which looked correct but was for the wrong destination.
    if (!rows.length) {
      // v0.9.3: no live metric_by_bucket data for this bucket.
      // Instead of showing "(no metrics yet)", show the last row of
      // the 24h series from bucketDoc (which has re_/ss_/bs_/ns_ per
      // alg). This keeps the Swap Target Pick table populated on all
      // ranges instead of going empty on 7d/30d/all.
      var doc = state.bucketDoc;
      if (doc && doc.last && doc.last.re) {
        var re = doc.last.re;
        var ss = doc.last.ss || {};
        var bs_arr = doc.last.bs || {};
        var ns = doc.last.ns || {};
        var _algs = (state.meta && state.meta.algs) || Object.keys(re);
        rows = _algs.map(function (alg) {
          var _re = re[alg] != null ? re[alg] : null;
          var _ss = ss[alg] != null ? ss[alg] : 256;
          var _bs = bs_arr[alg] != null ? bs_arr[alg] : 0;
          var _ns = ns[alg] != null ? ns[alg] : 0;
          // Compute penalty + score (same formula as the Go collector):
          //   penalty = 16 / (16 + bad*4 + null*2)
          //   score = rate_ema * (swap_score/256) * penalty
          var pen = 16.0 / (16.0 + _bs * 4.0 + _ns * 2.0);
          var sc = _re != null ? (_re * (_ss / 256.0) * pen) : null;
          return {
            alg: alg,
            rate_ema: _re,
            swap_score: _ss,
            bad_streak: _bs,
            null_streak: _ns,
            penalty: pen,
            score: sc,
            metric: null,  // metric value not available in bucketDoc.last
            active: _re != null && _re > 0,
          };
        }).filter(function (r) { return r.rate_ema != null; })
         .sort(function (a, b) {
           // v0.9.22: sort by active desc, then score desc (matches Go backend)
           if (a.active !== b.active) return a.active ? -1 : 1;
           return (b.score || 0) - (a.score || 0);
         });
      }
    }
    renderMetric(rows);
  }

  function renderMetric(rows) {
    if (!rows.length) {
      setHTML("lv-metric", '<div class="placeholder">(no metrics yet)</div>');
      return;
    }
    function colorSwapScore(v) {
      if (v == null) return "cell-dim";
      if (v > 256) return "cell-good";
      if (v < 256) return "cell-bad";
      return "cell-dim";
    }
    function colorPenalty(v) {
      if (v == null) return "cell-dim";
      if (v >= 0.99) return "cell-dim";
      if (v >= 0.8)  return "";
      if (v >= 0.5)  return "cell-bad";
      return "cell-bad";
    }
    function colorStreak(v) {
      if (v == null) return "cell-dim";
      if (v === 0) return "cell-good";
      return "cell-bad";
    }
    // Top row is the picker's choice: sorted by score in the CLI, so
    // the first non-inactive row wins.
    var picked = null;
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].active) { picked = i; break; }
    }
    var html = '<table class="tbl"><thead><tr>' +
      '<th>alg</th><th>Rate EMA<br>'
        + '<span style="font-weight:400;text-transform:none;letter-spacing:0">Mb/s</span></th>'
        + '<th>Swap Score</th>' +
      '<th>penalty</th><th>score</th><th>metric</th>' +
      '<th>bad</th><th>null</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r, i) {
      var cls = [];
      if (!r.active) cls.push("inactive");
      if (i === picked) cls.push("pick");
      var trClass = cls.length ? ' class="' + cls.join(" ") + '"' : "";
      var pen = (r.penalty == null) ? "-" : r.penalty.toFixed(3);
      html += '<tr' + trClass + '>' +
        '<td class="name">' + esc(r.alg) + '</td>' +
        '<td class="mono">' +
          (r.rate_ema == null ? "-"
           : fmtRe(r.rate_ema)
             + '<span class="dim" style="font-weight:400"> ('
             + r.rate_ema + ')</span>') +
        '</td>' +
        '<td class="mono ' + colorSwapScore(r.swap_score) + '">' +
          (r.swap_score == null ? "-" : r.swap_score) + '</td>' +
        '<td class="mono ' + colorPenalty(r.penalty) + '">' + pen + '</td>' +
        '<td class="mono cell-good">' +
          (r.score == null ? "-" : r.score.toFixed(1)) + '</td>' +
        '<td class="mono dim">' +
          (r.metric == null ? "-" : r.metric.toFixed(1)) +
        '</td>' +
        '<td class="mono ' + colorStreak(r.bad_streak) + '">' +
          (r.bad_streak == null ? "-" : r.bad_streak) + '</td>' +
        '<td class="mono ' + colorStreak(r.null_streak) + '">' +
          (r.null_streak == null ? "-" : r.null_streak) + '</td>' +
        '</tr>';
    });
    setHTML("lv-metric", html + '</tbody></table>' +
      '<div class="note" style="margin-top:8px">' +
      'Rate EMA is <b>Mb/s</b> in this table, matching the chart and NOW. ' +
      'The raw 100&nbsp;KB/s value the picker uses is shown in parenthesis.' +
      '</div>');
  }

  function renderProof(rows) {
    if (!rows.length) {
      setHTML("lv-proof", '<div class="placeholder">(none in tail)</div>');
      return;
    }
    var peak = 1;
    rows.forEach(function (r) {
      [r.proven_max, r.sampled_avg, r.sampled_max].forEach(function (v) {
        if (v != null && v > peak) peak = v;
      });
    });
    function bar(v, cls) {
      // 0.4.78.2: covbar + fixed-width number in a single flex row
      // so the bar's left edge aligns across all rows.
      if (v == null) {
        return '<span class="proof-cell">' +
               '<span class="mono dim">-</span></span>';
      }
      var w = Math.max(2, Math.round(100 * v / peak));
      return '<span class="proof-cell">' +
             '<span class="mono">' + v.toFixed(1) + '</span>' +
             '<span class="covbar ' + cls + '">' +
             '<i style="width:' + w + '%"></i></span>' +
             '</span>';
    }
    var html = '<table class="tbl proof-tbl"><thead><tr>' +
      '<th>alg</th>' +
      '<th>good</th><th>proved</th>' +
      '<th>proven max</th>' +
      '<th>sustained avg</th>' +
      '<th>sustained max</th>' +
      '<th>n</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      html += '<tr>' +
        '<td class="name">' + esc(r.alg) + '</td>' +
        '<td class="mono dim">' + r.good + '</td>' +
        '<td class="mono dim">' + r.proved + '</td>' +
        '<td>' + bar(r.proven_max,  'v-proven' ) + '</td>' +
        '<td>' + bar(r.sampled_avg, 'v-avg'    ) + '</td>' +
        '<td>' + bar(r.sampled_max, 'v-sampled') + '</td>' +
        '<td class="mono dim">' +
          (r.samples == null ? "-" : r.samples) + '</td>' +
        '</tr>';
    });
    setHTML("lv-proof", html + '</tbody></table>');
  }

  function renderRate(rows) {
    if (!rows.length) {
      setHTML("lv-rate", '<div class="placeholder">(no midsamp lines)</div>');
      return;
    }
    var html = '<table class="tbl"><thead><tr>' +
      '<th>thr</th><th>n</th><th>mean</th><th>min</th><th>max</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      html += '<tr>' +
        '<td class="mono">' + fmtN(r.thr) + '</td>' +
        '<td class="mono dim">' + r.n + '</td>' +
        '<td class="mono">'   + r.mean.toFixed(1) + '</td>' +
        '<td class="mono dim">' + r.min.toFixed(1) + '</td>' +
        '<td class="mono">'   + r.max.toFixed(1) + '</td>' +
        '</tr>';
    });
    setHTML("lv-rate", html + '</tbody></table>');
  }

  function bigTriple(so) {
    return '<div class="bigstats">' +
      '<div class="big win"><div class="k">win</div>' +
        '<div class="v">' + so.win + '</div>' +
        '<div class="p">' + so.win_pct.toFixed(0) + '%</div></div>' +
      '<div class="big null"><div class="k">null</div>' +
        '<div class="v">' + so.null + '</div>' +
        '<div class="p">' + so.null_pct.toFixed(0) + '%</div></div>' +
      '<div class="big loss"><div class="k">loss</div>' +
        '<div class="v">' + so.loss + '</div>' +
        '<div class="p">' + so.loss_pct.toFixed(0) + '%</div></div>' +
      '</div>';
  }

  function renderSwapOutcomes(payload, churn) {
    var so = (payload && payload.sustained) ? payload.sustained
              : (payload || {win:0,win_pct:0,null:0,null_pct:0,
                             loss:0,loss_pct:0,measurable:0,unmeasurable:0,
                             rescued:0, full_loss:0, open:0});
    var ch = churn || {cookies:0, one:0, mid:0, many:0, max:0};
    var rescued = so.rescued || 0;
    var fullLoss = so.full_loss || 0;
    var openLoss = so.open || 0;
    var totalLoss = so.loss || 0;
    function pct(n, d) { return d > 0 ? Math.round(n / d * 100) : 0; }
    function cell(cls, val, p, k) {
      return '<div class="lr-cell ' + cls + '">' +
               '<div class="lr-v">' + val + '</div>' +
               '<div class="lr-pct">' + p + '%</div>' +
               '<div class="lr-k">' + k + '</div>' +
             '</div>';
    }
    function frow(k, v, dim) {
      return '<div class="row' + (dim ? ' dim' : '') + '"><span class="k">' + k + '</span>' +
             '<span class="v' + (dim ? ' dim' : '') + '">' + v + '</span></div>';
    }
    var hasLossData = (rescued || fullLoss || openLoss) > 0;
    var html = bigTriple(so);
    if (hasLossData) {
      html +=
        '<div class="loss-recovery">' +
          '<div class="lr-header">loss recovery \u2014 what happened to the ' + totalLoss + ' losses</div>' +
          '<div class="lr-cells">' +
            cell('rescued', rescued, pct(rescued, totalLoss), 'rescued') +
            cell('full',   fullLoss, pct(fullLoss, totalLoss), 'full loss') +
            cell('open',   openLoss, pct(openLoss, totalLoss), 'open') +
          '</div>' +
          '<div class="lr-cap">a later win on the same cookie closes a loss</div>' +
        '</div>';
    } else {
      html +=
        '<div class="loss-recovery placeholder">' +
          '<div class="lr-header">loss recovery \u2014 awaiting server-side data</div>' +
          '<div class="lr-cells">' +
            cell('rescued ph', '\u2014', 0, 'rescued') +
            cell('full   ph', '\u2014', 0, 'full loss') +
            cell('open   ph', '\u2014', 0, 'open') +
          '</div>' +
          '<div class="lr-cap">apply bpftune-cli.py patch to populate</div>' +
        '</div>';
    }
    html +=
      '<div class="lr-footer">' +
        frow('measurable', so.measurable || 0) +
        frow('cookies swapped', ch.cookies || 0) +
        frow('unmeasurable', so.unmeasurable || 0, true) +
        frow('one-off', ch.one || 0) +
        '<div class="row empty"></div>' +
        frow('2-4x', ch.mid || 0) +
        '<div class="row empty"></div>' +
        frow('5x+', ch.many || 0) +
        '<div class="row empty"></div>' +
        frow('max per cookie', ch.max || 0) +
      '</div>';
    setHTML("lv-swapout", html);
  }


  function renderDivergence(rows) {
    if (!rows.length) {
      setHTML("lv-div", '<div class="placeholder">(no swaps)</div>');
      return;
    }
    var html = '<table class="tbl"><thead><tr>' +
      '<th>category</th><th style="width:32%">composite</th>' +
      '<th style="width:32%">sustained</th>' +
      '<th>n</th>' +
      '</tr></thead><tbody>';
    rows.forEach(function (r) {
      function bar(w, n, l) {
        var out = '<div class="cellbar">';
        if ((w + n + l) > 0) {
          if (w > 0) out += '<span class="w" style="width:' + w + '%">' +
            (w >= 8 ? w.toFixed(0) + '%' : '') + '</span>';
          if (n > 0) out += '<span class="n" style="width:' + n + '%">' +
            (n >= 8 ? n.toFixed(0) + '%' : '') + '</span>';
          if (l > 0) out += '<span class="l" style="width:' + l + '%">' +
            (l >= 8 ? l.toFixed(0) + '%' : '') + '</span>';
        } else {
          out += '<span class="n" style="width:100%">no data</span>';
        }
        out += '</div>';
        return out;
      }
      html += '<tr>' +
        '<td class="name">' + esc(r.category) + '</td>' +
        '<td>' + bar(r.win_pct, r.null_pct, r.loss_pct) + '</td>' +
        '<td>' + bar(r.win_pct_sustained, r.null_pct_sustained,
                     r.loss_pct_sustained) + '</td>' +
        '<td class="mono dim">' + r.measured + ' / ' +
          r.measured_sustained + '</td>' +
        '</tr>';
    });
    setHTML("lv-div", html + '</tbody></table>');
  }

  function renderRecentProofs(rows) {
    rows = (rows || []).slice(0, 18);
    if (!rows.length) {
      setHTML("lv-proofs", '<div class="placeholder">(none)</div>');
      return;
    }
    var html = '<div class="list">';
    // 0.4.90: data_recent_proofs now returns newest-first, so render
    // forward (was .slice().reverse() which assumed oldest-first input).
    rows.forEach(function (r) {
      // v0.9.0: show "(unknown)" instead of a bare middot when dest is
      // genuinely empty (passive connection, pre-estab sample, or — most
      // commonly — a cookie that's not in cdest yet).  The previous bare
      // middot (" · 174.7 Mb/s · 2m ago") was the user-reported "dash".
      var destLabel = r.dest ? esc(shortAddr(r.dest)) : '<span class="dim">(unknown)</span>';
      html += '<div class="item">' +
        '<span class="flow">' + esc(r.alg) + '</span>' +
        '<span class="meta">' + destLabel +
          ' &middot; ' + r.mbps.toFixed(1) + ' Mb/s' +
          (r.boot_ts ? ' &middot; ' + ageLabel(r.boot_ts, r.epoch_ts) : '') +
          '</span>' +
        '<span class="sp ' + r.tier + '">' + r.tier + '</span>' +
        '</div>';
    });
    setHTML("lv-proofs", html + '</div>');
  }

  function shortAddr(a) {
    // 0.4.124: added /16 scan so '89.168.0.0' (a /16 in meta.json)
    // resolves to 'vps-de' when labels has '89.168.90.153' -> 'vps-de'.
    // v0.9.0: also handle full /64 IPv6 form "xxxx:xxxx:yyyy:yyyy::"
    //         returned by the Go destStr() when both dest6 and dest6b
    //         were present in the log.  Previously only "v6:XXXXXXXX"
    //         (the 32-bit-truncated form) was handled.
    a = a || "";
    var L = window.__labels || {};
    if (L[a]) return L[a];
    if (a.indexOf("v6:") === 0) {
      var hex = a.substring(3);
      if (hex.length >= 8) {
        var ip6 = hex.substring(0,4) + ":" + hex.substring(4,8) + "::";
        if (L[ip6]) return L[ip6];
      }
      return a;
    }
    // v0.9.0: standard IPv6 form ("xxxx:xxxx:yyyy:yyyy::" or "xxxx:xxxx::")
    // from the Go destStr() when dest6b is present.
    if (a.indexOf(":") >= 0) {
      // Try exact match first (already done above via L[a]).
      // Try the /32 form ("xxxx:xxxx::") — strip the /64 part.
      var slash32 = a.replace(/^([0-9a-f]{1,4}:[0-9a-f]{1,4}):.*/, '$1::');
      if (slash32 !== a && L[slash32]) return L[slash32];
      // Try the /48 form ("xxxx:xxxx:yyyy::") — strip the last group.
      var slash48 = a.replace(/^([0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{1,4}):.*/, '$1::');
      if (slash48 !== a && slash48 !== slash32 && L[slash48]) return L[slash48];
      return a;
    }
    var p = a.split(".");
    if (p.length === 4) {
      var slash16 = p[0] + "." + p[1] + ".0.0";
      if (L[slash16]) return L[slash16];
      var prefix = p[0] + "." + p[1] + ".";
      for (var ip in L) {
        if (ip.indexOf(prefix) === 0 && ip !== slash16) {
          return L[ip];
        }
      }
      return slash16;
    }
    return a;
  }

  function renderRecentSwaps(rows) {
    if (!rows.length) {
      setHTML("lv-swaps", '<div class="placeholder">(none in tail)</div>');
      return;
    }
    var html = '<div class="list">';
    /* 0.4.79: rows arrive newest-first from the CLI.  Do NOT
     * reverse here -- that was flipping to oldest-first, so the
     * top of the panel showed hours-old swaps and looked
     * current.  Fixed 2026-09-26. */
    rows.forEach(function (r) {
      /* 0.4.79: only outcome_sustained is final.  The composite
       * outcome is provisional -- it may read null while the
       * sustained window is still open.  Show "pending" until the
       * collector has classified the swap on the sustained ruler
       * (T+60..T+300 after the swap). */
      var o = r.outcome_sustained || "";
      // v0.9.28: display no_post as "nopost" with faded style
      var pillLabel = o === 'no_post' ? 'no post' : o;
      var pillClass = o === 'no_post' ? 'null' : o;  // reuse null pill style
      var pill = o
        ? '<span class="sp ' + pillClass + '">' + pillLabel + '</span>'
        : (function() {
            var age = (r.boot_ts && SERVER_NOW_MONO) ? (SERVER_NOW_MONO - r.boot_ts) : 0;
            if (age < 60) return '<span class="sp wait">wait</span>';
            return '<span class="sp void">void</span>';
          })();
      // v0.9.0: show "(unknown)" instead of a bare middot when dest is empty.
      var destLabel = r.dest ? esc(shortAddr(r.dest)) : '<span class="dim">(unknown)</span>';
      html += '<div class="item">' +
        '<span class="flow">' + esc(r.from_alg) +
          '<span class="arrow">&rarr;</span>' + esc(r.to_alg) + '</span>' +
        '<span class="meta">' + destLabel +
          ' &middot; d' + r.d +
          (r.boot_ts ? ' &middot; ' + ageLabel(r.boot_ts, r.epoch_ts) : '') +
          '</span>' +
        pill +
        '</div>';
    });
    setHTML("lv-swaps", html + '</div>');
  }

  function renderLogWindow(doc) {
    var lw = doc.log_window || {};
    if (!lw.span_min) return;
    var text = 'rolling ' + lw.span_min + ' min \u00b7 ' + lw.swap_count + ' swaps \u00b7 newest ' + lw.age_min + 'm ago';
    ['time-window-outcomes', 'time-window-recent-swaps'].forEach(function(id) {
      var el = document.getElementById(id);
      if (el) el.textContent = text;
    });
  }

  // FE-001/FE-009 fix: try all three forms (label, raw addr, /16 form)
  function _destMatches(dest, bid, label) {
    if (!dest) return false;
    if (dest === label) return true;
    if (dest === bid) return true;
    if (bid && bid.indexOf('.') > 0) {
      var parts = bid.split('.');
      if (parts.length === 4) {
        var slash16 = parts[0] + '.' + parts[1] + '.0.0';
        if (dest === slash16) return true;
      }
    }
    return false;
  }

  function _filterByBucket(doc, bucketLabel, bucketBid) {
    if (!bucketBid) bucketBid = bucketLabel;
    if (bucketLabel === 'all' || !bucketLabel) return doc;
    var f = JSON.parse(JSON.stringify(doc));
    // Filter swap outcomes from swaps_list
    if (f.swap_outcomes && f.swap_outcomes.swaps_list) {
      var swaps = f.swap_outcomes.swaps_list.filter(function(s) {
        return _destMatches(s.dest, bucketBid, bucketLabel);
      });
      var c = {win: 0, null: 0, loss: 0, skip: 0};
      swaps.forEach(function(s) {
        var o = s.outcome_sustained;
        if (o === null || o === undefined) c.skip++;
        else c[o] = (c[o] || 0) + 1;
      });
      var total = c.win + c.null + c.loss;
      // Compute loss recovery from filtered swaps
      var losses = swaps.filter(function(s) { return s.outcome_sustained === 'loss'; });
      losses.sort(function(a, b) { return (a.ts || 0) - (b.ts || 0); });
      var lastTs = swaps.length ? Math.max.apply(null, swaps.map(function(s) { return s.ts || 0; })) : 0;
      var rescued = 0, fullLoss = 0, openLoss = 0;
      var WINDOW = 3600;
      losses.forEach(function(loss) {
        var lossTs = loss.ts || 0;
        var found = false;
        for (var i = 0; i < swaps.length; i++) {
          var s = swaps[i];
          if (s === loss) continue;
          var sTs = s.ts || 0;
          if (sTs <= lossTs) continue;
          if (sTs - lossTs > WINDOW) break;
          if (s.cookie === loss.cookie && s.outcome_sustained === 'win') { found = true; break; }
        }
        if (found) rescued++;
        else if ((lastTs - lossTs) > WINDOW) fullLoss++;
        else openLoss++;
      });
      var totalLoss = c.loss;
      f.swap_outcomes.sustained = {
        win: c.win, null: c.null, loss: c.loss,
        measurable: total, unmeasurable: c.skip,
        win_pct: total ? Math.round(c.win/total*100) : 0,
        null_pct: total ? Math.round(c.null/total*100) : 0,
        loss_pct: total ? Math.round(c.loss/total*100) : 0,
        rescued: rescued, full_loss: fullLoss, open: openLoss,
        rescued_pct: totalLoss ? Math.round(rescued/totalLoss*100) : 0,
        full_loss_pct: totalLoss ? Math.round(fullLoss/totalLoss*100) : 0,
        open_pct: totalLoss ? Math.round(openLoss/totalLoss*100) : 0,
      };
    }
    // Filter recent proofs
    if (f.recent_proofs) {
      f.recent_proofs = f.recent_proofs.filter(function(p) {
        return _destMatches(p.dest, bucketBid, bucketLabel);
      });
    }
    // Re-aggregate proof leaderboard from proofs_raw
    if (f.proofs_raw) {
      var fp = f.proofs_raw.filter(function(p) { return _destMatches(p.dest, bucketBid, bucketLabel); });
      var byAlg = {};
      fp.forEach(function(p) {
        if (!byAlg[p.alg]) byAlg[p.alg] = {good:0, proved:0, pmax:0, sum:0, n:0, smax:0};
        if (p.tier === 'good') byAlg[p.alg].good++;
        if (p.tier === 'proved') byAlg[p.alg].proved++;
        if (p.tier === 'proved' && p.rate > byAlg[p.alg].pmax) byAlg[p.alg].pmax = p.rate;
        byAlg[p.alg].sum += p.rate;
        byAlg[p.alg].n++;
        if (p.rate > byAlg[p.alg].smax) byAlg[p.alg].smax = p.rate;
      });
      f.proof = Object.keys(byAlg).map(function(alg) {
        var a = byAlg[alg];
        return {alg:alg, good:a.good, proved:a.proved,
          proven_max: a.pmax || null,
          sampled_avg: a.n ? Math.round(a.sum/a.n*10)/10 : null,
          sampled_max: a.smax || null,
          samples: a.n || null};
      }).sort(function(a,b) { return (b.proven_max||0) - (a.proven_max||0); });
    }
    // Re-aggregate rate progression from rate_raw
    if (f.rate_raw) {
      var fr = f.rate_raw.filter(function(r) { return _destMatches(r.dest, bucketBid, bucketLabel); });
      var byThr = {};
      fr.forEach(function(r) {
        if (!byThr[r.thr]) byThr[r.thr] = [];
        byThr[r.thr].push(r.srate);
      });
      f.rate = Object.keys(byThr).map(function(thr) {
        var vs = byThr[thr];
        var BPS = 125000;
        return {thr: parseInt(thr), n: vs.length,
          mean: Math.round(vs.reduce(function(a,b){return a+b},0)/vs.length/BPS*10)/10,
          min: Math.round(Math.min.apply(null,vs)/BPS*10)/10,
          max: Math.round(Math.max.apply(null,vs)/BPS*10)/10};
      }).sort(function(a,b) { return a.thr - b.thr; });
    }
    return f;
  }


  function _reFilterPanels() {
    var doc = window.__current_doc;
    if (!doc) return;
    _updateBucketTags();   // 0.4.87: keep panel headers in sync on dropdown change
    var bk = _currentBucketLabel();
    var bid = bk.bid;
    var blabel = bk.label;
    var fdoc = bid === 'all' ? doc : _filterByBucket(doc, blabel, bid);
    var soDoc = fdoc;
    if (bid === 'all') {
      var hb1 = _heaviestBucketWithCoverage();
      // show aggregate not heaviest
    }
    _safeRender('proof',       function() { renderProof(fdoc.proof || []); });
    _safeRender('rate',        function() { renderRate(fdoc.rate || []); });
    _safeRender('swap_outcomes', function() { renderSwapOutcomes(soDoc.swap_outcomes || null, soDoc.churn || {}); });
    _safeRender('recent_proofs', function() { renderRecentProofs(fdoc.recent_proofs || []); });
    window.__filtered_doc = fdoc;
    // 0.4.122: wrap renderSwaps in _safeRender — if Chart.js hasn't
    // finished loading yet (liveRefresh fires before boot's _loadCharts
    // resolves), mk() throws "Chart is not defined" and propagates out
    // of _reFilterPanels, aborting _populateBucketSelect mid-flight.
    _safeRender('swaps', function() { renderSwaps(); });
  }

  function _safeRender(label, fn) {
    try {
      fn();
    } catch (e) {
      console.error('[render] ' + label + ':', e);
    }
  }

  // v0.7.5e: rebuild the bucket dropdown options from live data.
  // Previously the dropdown only refreshed every 5 min from meta.json
  // (refreshAll) while the table refreshed every 30s from current.json
  // (SSE) — so they showed different buckets in different orders. Now
  // both views read from current.json's buckets[] (server-side sorted
  // to match meta.json's order, server-side labeled). Custom labels
  // from window.__labels that aren't currently active are appended at
  // the end so the user can still pick them.
  function _rebuildDropdownFromLive(liveBuckets) {
    var bs = $('bucket');
    if (!bs) return;
    var prev = bs.value;
    var seen = {};
    var html = '';
    for (var k = 0; k < liveBuckets.length; k++) {
      var id = liveBuckets[k].dest;
      if (!id || seen[id]) continue;
      seen[id] = true;
      html += '<option value="' + id + '">' + id + '</option>';
    }
    if (window.__labels) {
      Object.keys(window.__labels).forEach(function(ip) {
        var lbl = window.__labels[ip];
        if (lbl && lbl !== ip && !seen[ip] && !seen[lbl]) {
          seen[lbl] = true;
          html += '<option value="' + lbl + '">' + lbl + '</option>';
        }
      });
    }
    bs.innerHTML = html;
    bs.add(new Option('All Buckets', 'all'), 0);
    // Restore selection if still present; else "All Buckets".
    var stillThere = false;
    for (var i = 0; i < bs.options.length; i++) {
      if (bs.options[i].value === prev) { stillThere = true; break; }
    }
    bs.value = stillThere ? prev : 'all';
  }

  function _syncBucketDropdown(doc) {
    var _bs = $('bucket');
    var _prevVal = _bs ? _bs.value : null;
    // E3-fix: skip the dropdown rebuild if the bucket set hasn't changed
    // since last push. The old code rebuilt <option>s on every 30s SSE
    // push, which closed the dropdown mid-selection if the user was
    // picking a bucket when a push arrived. We hash the bucket IDs and
    // only rebuild when the set actually differs.
    var _newHash = '';
    if (doc.buckets && doc.buckets.length) {
      var _ids = doc.buckets.map(function(b) { return b ? b.dest : ''; }).sort();
      _newHash = _ids.join('|');
    }
    if (_bs && _bs._lastBucketHash === _newHash && _newHash !== '') {
      // Bucket set unchanged — preserve the dropdown as-is. Still
      // restore _prevVal in case something else changed it.
      if (_bs && _prevVal) {
        var _stillThere = false;
        for (var si = 0; si < _bs.options.length; si++) {
          if (_bs.options[si].value === _prevVal) { _stillThere = true; break; }
        }
        _bs.value = _stillThere ? _prevVal : 'all';
      }
      return;
    }
    if (_bs) _bs._lastBucketHash = _newHash;
    _safeRender('buckets', function() { renderBuckets(doc.buckets || []); });
    // v0.7.5e: also rebuild the dropdown options from live buckets —
    // previously the dropdown stayed stale for 5 min until refreshAll
    // ran, diverging from the table on every 30s SSE push.
    _safeRender('dropdown', function() { _rebuildDropdownFromLive(doc.buckets || []); });
    _bs = $('bucket');
    if (_bs && _bs.options.length > 0 && _bs.options[0].value !== 'all') {
      _bs.add(new Option('All Buckets', 'all'), 0);
    }
    // API-009 fix: merge in any buckets present in doc.buckets that
    // renderBuckets() didn't add (e.g. buckets whose addr didn't make
    // the meta.json top-N but are alive right now).  These show up as
    // "<shortAddr> (live)" so the user can still pick them.
    if (_bs && doc.buckets && doc.buckets.length) {
      var existingIds = {};
      var existingTexts = {};
      for (var ei = 0; ei < _bs.options.length; ei++) {
        existingIds[_bs.options[ei].value] = true;
        existingTexts[_bs.options[ei].text] = true;
      }
      // Find the insertion point: after the static 'All Buckets' (and
      // any other meta-derived entries) but BEFORE the first custom-
      // labeled "(live)" entry from a prior cycle, so live entries
      // cluster at the bottom of the dropdown.
      var insertAt = _bs.options.length;
      for (var ii = 0; ii < _bs.options.length; ii++) {
        if (/\(live\)$/.test(_bs.options[ii].text)) {
          insertAt = ii;
          break;
        }
      }
      for (var bi = 0; bi < doc.buckets.length; bi++) {
        var b = doc.buckets[bi];
        if (!b || !b.dest) continue;
        if (existingIds[b.dest]) continue;
        var liveText = shortAddr(b.dest) + ' (live)';
        if (existingTexts[liveText]) continue;
        try {
          _bs.add(new Option(liveText, b.dest), insertAt);
          existingIds[b.dest] = true;
          existingTexts[liveText] = true;
          insertAt++;
        } catch (e) { /* IE quirk: ignore */ }
      }
    }
    // API-009 fix: only restore _prevVal if it still exists in the
    // dropdown — otherwise the select silently ends up with no value
    // selected and the bucket panels render empty.  Fall back to 'all'.
    if (_bs && _prevVal) {
      var _stillThere = false;
      for (var si = 0; si < _bs.options.length; si++) {
        if (_bs.options[si].value === _prevVal) { _stillThere = true; break; }
      }
      _bs.value = _stillThere ? _prevVal : 'all';
    }
    else if (_bs) { _bs.value = 'all'; }
    if (_bs && !_bs._refilterHooked) {
      _bs.addEventListener('change', _reFilterPanels);
      _bs._refilterHooked = true;
    }
  }

  function _heaviestBucketWithCoverage() {
    if (!state.meta || !state.meta.buckets || !state.meta.buckets.length) return null;
    var f = state.fleet || {};
    var fb = f.buckets || [];
    var fc = f.coverage_24h || [];
    var cov = {};
    for (var ci = 0; ci < fb.length; ci++) cov[fb[ci]] = fc[ci];
    var bs = $('bucket');
    var inDropdown = {};
    if (bs && bs.options) {
      for (var di = 0; di < bs.options.length; di++) {
        inDropdown[bs.options[di].value] = true;
      }
    }
    for (var bi = 0; bi < state.meta.buckets.length; bi++) {
      var b = state.meta.buckets[bi];
      if (cov[b.id] != null && cov[b.id] > 0 && inDropdown[b.id]) {
        return {bid: b.id, label: b.label || b.id};
      }
    }
    for (var bi2 = 0; bi2 < state.meta.buckets.length; bi2++) {
      var b2 = state.meta.buckets[bi2];
      if (inDropdown[b2.id]) {
        return {bid: b2.id, label: b2.label || b2.id};
      }
    }
    var top = state.meta.buckets[0];
    return {bid: top.id, label: top.label || top.id};
  }

  function _currentBucketLabel() {
    var _bid = $('bucket') ? $('bucket').value : 'all';
    if (_bid === 'all') return {bid: 'all', label: 'all'};
    // FE-001 fix: server data is keyed by _label_for(addr) which returns
    // the LABEL if labeled, or the RAW ADDR if unlabeled. Never use shortAddr's
    // /16 form as the label — it won't match any server-side key.
    var _blabel;
    if (window.__labels && window.__labels[_bid] && window.__labels[_bid] !== _bid) {
      _blabel = window.__labels[_bid];
    } else {
      _blabel = _bid;  // raw addr — matches server-side _label_for(unlabeled)
    }
    return {bid: _bid, label: _blabel};
  }

  // 0.4.87: lookup the human-readable label for any raw bucket addr.
  // Used by renderMetricForBucket / renderBucket to find the right
  // entry in dicts that the python side keys by _label_for(addr)
  // (i.e. label if labeled, raw addr otherwise).  Returns null if no
  // label is known for the addr.
  function _labelForBucketAddr(addr) {
    if (!addr || addr === 'all') return addr;
    if (window.__labels && window.__labels[addr]) {
      return window.__labels[addr];
    }
    // v6:hex form may be labeled under the canonical "xxxx:xxxx::" form.
    if (addr.indexOf('v6:') === 0) {
      var hex = addr.substring(3);
      if (hex.length >= 8) {
        var ip6 = hex.substring(0,4) + ':' + hex.substring(4,8) + '::';
        if (window.__labels && window.__labels[ip6]) return window.__labels[ip6];
      }
    }
    // The dropdown option text may already carry the label (set by
    // _fetchAndApplyLabels after the /api/labels fetch).  Strip the
    // trailing " (NN)" point count.
    var bs = $('bucket');
    if (bs && bs.options) {
      for (var i = 0; i < bs.options.length; i++) {
        if (bs.options[i].value === addr) {
          return bs.options[i].text.replace(/ \(\d+\)$/, '');
        }
      }
    }
    return null;
  }

  // 0.4.87: update every .bucket-tag span with the current bucket's
  // label so the user can see at a glance which bucket's data each
  // panel is showing.  Called on every renderLiveState / bucket change.
  var _TOP_BUCKET_TAG_IDS = [
    'bucket-tag-metric', 'bucket-tag-swapout',
    'bucket-tag-ratechart', 'bucket-tag-sscore',
    'bucket-tag-streaks', 'bucket-tag-swapschart'
  ];
  var _ALL_BUCKET_TAG_IDS = [
    'bucket-tag-swaps', 'bucket-tag-proof',
    'bucket-tag-proofs', 'bucket-tag-rate'
  ];
  function _updateBucketTags() {
    var bk = _currentBucketLabel();
    if (bk.bid === 'all') {
      var hb = _heaviestBucketWithCoverage();
      // 0.4.124: resolve hb.label via shortAddr
      var topText = hb ? ('— ' + shortAddr(hb.bid) + ' (top)') : '— all';
      for (var i = 0; i < _TOP_BUCKET_TAG_IDS.length; i++) {
        var el = document.getElementById(_TOP_BUCKET_TAG_IDS[i]);
        if (el) el.textContent = topText;
      }
      for (var j = 0; j < _ALL_BUCKET_TAG_IDS.length; j++) {
        var el2 = document.getElementById(_ALL_BUCKET_TAG_IDS[j]);
        if (el2) el2.textContent = '— all';
      }
    } else {
      var text = '— ' + bk.label;
      var allIds = _TOP_BUCKET_TAG_IDS.concat(_ALL_BUCKET_TAG_IDS);
      for (var k = 0; k < allIds.length; k++) {
        var el3 = document.getElementById(allIds[k]);
        if (el3) el3.textContent = text;
      }
    }
  }

  function _renderFilteredPanels(doc) {
    var bk = _currentBucketLabel();
    var _fdoc = bk.bid === 'all' ? doc : _filterByBucket(doc, bk.label, bk.bid);
    var _soDoc = _fdoc;
    if (bk.bid === 'all') {
      var hb2 = _heaviestBucketWithCoverage();
      // show aggregate not heaviest
    }
    _safeRender('proof', function() { renderProof(_fdoc.proof || []); });
    _safeRender('rate', function() { renderRate(_fdoc.rate || []); });
    _safeRender('swap_outcomes', function() { renderSwapOutcomes(_soDoc.swap_outcomes || null, _soDoc.churn || {}); });
    _safeRender('recent_proofs', function() { renderRecentProofs(_fdoc.recent_proofs || []); });
  }

  var _lastLabelsFetch = 0;
  function _fetchAndApplyLabels(force) {
    // v0.9.10 fix: debounce — only fetch labels at most once per 5 minutes
    // from SSE pushes. Labels rarely change, and fetching on every 30s
    // push was wasteful. Use force=true after a label edit to bypass.
    if (!force && Date.now() - _lastLabelsFetch < 300000) return;
    _lastLabelsFetch = Date.now();
    fetch('/api/labels', {cache: 'no-store'}).then(function(r) { return r.json(); }).then(function(ld) {
      window.__labels = ld.labels || {};
      // 0.4.123: build a /16 -> label index so a bucket id like
      // '89.168.0.0' can find '89.168.90.153' -> 'vps-de' in labels.
      var _slash16 = {};
      Object.keys(window.__labels).forEach(function(ip) {
        var parts = ip.split('.');
        if (parts.length === 4) {
          var p = parts[0] + '.' + parts[1] + '.0.0';
          if (!_slash16[p]) _slash16[p] = window.__labels[ip];
        }
      });
      var bs = $('bucket');
      if (bs && bs.options) {
        for (var i = 0; i < bs.options.length; i++) {
          var ip = bs.options[i].value;
          var label = window.__labels[ip];
          if (!label && _slash16[ip]) label = _slash16[ip];
          if (!label && ip.indexOf("v6:") === 0) {
            var hex = ip.substring(3);
            if (hex.length >= 8) {
              var ip6 = hex.substring(0,4) + ":" + hex.substring(4,8) + "::";
              label = window.__labels[ip6];
            }
          }
          if (label) {
            var pts = bs.options[i].text.match(/\((\d+)\)/);
            bs.options[i].text = label + ' (' + (pts ? pts[1] : '') + ')';
          }
        }
      }
      // 0.4.87: labels just landed — refresh the bucket-tag chips so
      // panel headers reflect the new label, and re-render the panels
      // that look up by label (metric / bucket_live chart).
      _updateBucketTags();
      _safeRender('metric_for_bucket', function() { renderMetricForBucket(); });
      if ($("range") && state.bucketDoc) {
        _safeRender('bucket_chart', function() { renderBucket(); });
      }
    }).catch(function() {});
  }

  function renderLiveState(doc) {
    // A7-fix: prevent stale HTTP poll (liveRefresh) from overwriting
    // newer SSE state. Track the highest generated_ts seen; if the
    // incoming doc is older, skip the render. SSE pushes and HTTP
    // polls can resolve out of order on network jitter, causing
    // "data goes backward" flicker.
    if (doc && doc.generated_ts) {
      var _ts = doc.generated_ts;
      if (window.__latest_doc_ts && _ts < window.__latest_doc_ts) {
        return;
      }
      window.__latest_doc_ts = _ts;
    }
    window.__current_doc = doc;
    _safeRender('log_window', function() { renderLogWindow(doc); });
    if (doc.now_mono) SERVER_NOW_MONO = doc.now_mono;
    _safeRender('build', function() { renderBuild(doc.build || {}); });
    _safeRender('system', function() { renderSystem(doc.system || {}); });
    _safeRender('tunables', function() { renderTunables(doc.tunables || []); });
    _syncBucketDropdown(doc);
    _updateBucketTags();
    state.metricByBucket = doc.metric_by_bucket || {};
    // A2-fix: MERGE per-bucket instead of wholesale-replacing. The old
    // `state.bucketLive = doc.bucket_live || {}` wiped any accumulated
    // points from _appendLiveMetrics on every SSE push, causing 1h live
    // charts to show stale/single-point data.
    if (!state.bucketLive) state.bucketLive = {};
    var _newBL = doc.bucket_live || {};
    for (var _bk in _newBL) {
      if (_newBL.hasOwnProperty(_bk)) state.bucketLive[_bk] = _newBL[_bk];
    }
    _appendLiveMetrics(doc);
    state.recentSwapsByBucket = doc.recent_swaps_by_bucket || null;
    _safeRender('metric_for_bucket', function() { renderMetricForBucket(); });
    _safeRender('recent_swaps_for_bucket', function() { renderRecentSwapsForBucket(); });
    // 0.4.87: always call renderBucket on every SSE push — even when
    // "All Buckets" is selected (state.bucketDoc === null).  The new
    // All-Buckets path aggregates state.bucketLive so the rate/sscore/
    // streaks charts refresh on every 30s tick instead of every 5 min.
    if ($("range")) {
      _safeRender('bucket_chart', function() { renderBucket(); });
    }
    _renderFilteredPanels(doc);
    // Ensure swaps-per-bin also refreshes on every SSE push, regardless of
    // whether _renderFilteredPanels happened to call it.  Harmless no-op if
    // already called (Chart.js mk() destroys + re-creates the chart).
    // 0.4.122: wrap in _safeRender — Chart may not be loaded yet on the
    // very first liveRefresh call (fires before boot's _loadCharts resolves).
    _safeRender('swaps', function() { renderSwaps(); });
    _safeRender('score-now', function() { renderScoreNow(); });
    _safeRender('div', function() { renderDivChart("div", ""); });
    _safeRender('div_sustained', function() { renderDivChart("div_sustained", "_sustained"); });
    state.lastLiveSwaps = doc.recent_swaps || [];
    _safeRender('recent_swaps_for_bucket', function() { renderRecentSwapsForBucket(); });
    _fetchAndApplyLabels();
  }

  function liveRefresh() {
    fetch("current.json", {cache: "no-store"}).then(function (r) {
      if (!r.ok) throw new Error("current.json: " + r.status);
      return r.json();
    }).then(function (doc) {
      renderLiveState(doc);
    }).catch(function (e) {
      setHTML("lv-build",
              '<div class="placeholder">current.json unavailable: ' +
              esc(e.message) + '</div>');
    });
  }

  // SSE real-time updates with polling fallback.
  // SSE pushes data within 1s of collection; polling fallback (30s)
  // ensures the dashboard still works if SSE crashes.
  var _sseSource = null;
  var _pollFallback = null;

  function startLiveUpdates() {
    // 0.4.122: expose liveRefresh as window.__liveFetch so the label
    // editor / IP-move flows can trigger a live refresh after edits.
    // Before this, every `if (window.__liveFetch) window.__liveFetch()`
    // call silently no-op'd because __liveFetch was never assigned —
    // meaning renamed/moved/deleted IPs didn't refresh the live panels
    // until the next 30s polling tick.
    window.__liveFetch = liveRefresh;
    if (typeof EventSource !== "undefined") {
      _sseSource = new EventSource("/sse");
      _sseSource.onmessage = function (e) {
        try {
          var msg = JSON.parse(e.data);
          // Phase 3: handle full vs delta messages
          if (msg.__t === "f") {
            window.__current_doc = msg.v;
          } else if (msg.__t === "d") {
            if (!window.__current_doc) window.__current_doc = {};
            for (var k in msg.c) {
              if (msg.c.hasOwnProperty(k)) window.__current_doc[k] = msg.c[k];
            }
            for (var i = 0; i < (msg.r || []).length; i++) {
              delete window.__current_doc[msg.r[i]];
            }
          } else {
            window.__current_doc = msg;
          }
          renderLiveState(window.__current_doc);
          refreshNowCardAndChart();
        } catch (err) {
          console.error("SSE parse error:", err);
        }
      };
      _sseSource.onerror = function () {
        // A1-fix: do NOT call _sseSource.close(). The browser's
        // EventSource already auto-reconnects with built-in backoff
        // (default ~3s, scaling up). The old code closed the stream
        // permanently on any transient error (proxy timeout, network
        // blip, server restart), killing real-time updates forever
        // and falling back to 30s polling. We only log; the browser
        // will reconnect on its own.
        console.log("SSE error — browser will auto-reconnect");
      };
      console.log("SSE connected — real-time updates enabled");
      // Also do an immediate fetch so the page loads fast (don't
      // wait for the next SSE push)
      liveRefresh();
    } else {
      startPollingFallback();
    }
  }

  function startPollingFallback() {
    if (_pollFallback) return;
    console.log("Polling fallback active (30s interval)");
    liveRefresh();
    refreshNowCardAndChart();
    _pollFallback = setInterval(function () {
      liveRefresh();
      refreshNowCardAndChart();
    }, 30000);
  }

  function renderNow() {
    var bid = $("bucket").value;
    if (bid === 'all') {
      var hb = _heaviestBucketWithCoverage();
      if (hb) bid = hb.bid;
      else if (state.meta && state.meta.buckets && state.meta.buckets.length) bid = state.meta.buckets[0].id;
    }
    var _live = window.__current_doc || {};
    if (!_live.buckets) return;
    var doc = state.bucketDoc;  // may be null for 'all' — used for doc.last below
    var sub = $("nowbucket");
    var _nowLabel;
    if ($("bucket").value === 'all') {
      var hbLabel = _heaviestBucketWithCoverage();
      _nowLabel = hbLabel ? (hbLabel.label + ' (top)') : 'all';
    } else {
      _nowLabel = (window.__labels && window.__labels[bid] !== bid && window.__labels[bid]) ||
        ($("bucket") && $("bucket").selectedIndex >= 0 ? $("bucket").options[$("bucket").selectedIndex].text.replace(/ \(\d+\)$/, "") : bid);
    }
    if (sub) sub.textContent = _nowLabel;
    // Build label from the dropdown text (already updated by renderLiveState)
    var _dropdownLabel = bid;
    var _bs2 = $("bucket");
    if (_bs2 && _bs2.options) {
      for (var _j = 0; _j < _bs2.options.length; _j++) {
        if (_bs2.options[_j].value === bid) {
          _dropdownLabel = _bs2.options[_j].text.replace(/ \(\d+\)$/, '');
          break;
        }
      }
    }
    var _bidLabel = (window.__labels && window.__labels[bid] !== bid && window.__labels[bid]) || _dropdownLabel || bid;
    // Find this bucket in doc.buckets (for instances, ref_rate, min_rtt, best_alg)
    var _bkt = null;
    var _bidDisplay = shortAddr(bid);
    (_live.buckets || []).forEach(function(b) {
      if (b.dest === bid || b.dest === _bidDisplay || b.dest === _bidLabel) _bkt = b;
    });
    var L = {
      instances: _bkt ? _bkt.inst : null,
      ref_rate: _bkt ? _bkt.ref_mbps : null,
      min_rtt: _bkt ? _bkt.rtt_us : null,
      best_alg: _bkt ? _bkt.best_alg : null,
      collected_ts: _live.generated_ts,
      tcp_rmem_max: ((doc || {}).last || {}).tcp_rmem_max || null,
      re: {}
    };
    // Build rate_ema dict from metric_by_bucket (live, 100KB/s units)
    var _mb = _live.metric_by_bucket || {};
    var _mbRows = _mb[bid] || _mb[_bidLabel] || [];
    _mbRows.forEach(function(r) {
      if (r.alg && r.rate_ema != null) L.re[r.alg] = r.rate_ema;
    });
    var setT = function (id, s) { var e = $(id); if (e) e.textContent = s; };
    setT("n_inst", fmtN(L.instances));
    setT("n_ref",  (L.ref_rate != null ? L.ref_rate.toFixed(1) : "0.0") + " Mb/s");
    setT("n_rtt",  fmtRTT(L.min_rtt));
    // Use doc.live_leaders (same source as the swap target leaderboard)
    var _ll = (window.__current_doc && window.__current_doc.live_leaders) || [];
    var _top = null;
    for (var _i = 0; _i < _ll.length; _i++) {
      if (_ll[_i].dest === bid || (_ll[_i].dest === ((window.__labels||{})[bid]))) {
        _top = (_ll[_i].top || [])[0] || null; break;
      }
    }
    // Fallback: use metricByBucket if live_leaders doesn't have this bucket
    if (!_top) {
      var _byB = state.metricByBucket || {};
      var _rows2 = (bid && _byB[bid]) ? _byB[bid] : [];
      _top = _rows2[0] || null;
    }
    // Show picker's choice as best algorithm
    setT("n_best", _top ? _top.alg : (L.best_alg || "-"));
    // Streak/penalty (from live_leaders — has correct bad/null fields)
    if (_top) {
      var _bad = _top.bad || 0;
      var _nul = _top.null || 0;
      var _pen = 16 + _bad * 4 + _nul * 2;
      var _st = (16/_pen).toFixed(3);
      if (_bad > 0) _st += " b=" + _bad;
      if (_nul > 0) _st += " n=" + _nul;
      setT("n_streak", _st);
      setT("n_swaps", _top.count ? fmtN(_top.count) : "-");
      setT("n_algs2", ((state.metricByBucket||{})[bid]||[]).length + "/16");
    } else {
      setT("n_streak", "-");
      setT("n_swaps", "-");
      setT("n_algs2", "-");
    }
    setT("nowupdated",
         L.collected_ts ? "updated " + relTime(L.collected_ts) : "");

    // 0.4.122: guard state.meta — renderNow can fire from SSE / polling
    // before boot() finishes loading data/meta.json. The downstream
    // _heaviestBucketWithCoverage() already handles a null meta, so
    // just bail early here too.
    if (!state.meta) return;
    var algs = state.meta.algs;
    var rates = [];
    for (var i = 0; i < algs.length; i++) {
      var a = algs[i];
      var v = (L.re && L.re[a] != null) ? L.re[a] : null;
      if (v != null && v > 0) rates.push({a: a, v: v});
    }
    rates.sort(function (x, y) { return y.v - x.v; });

    if (rates.length) {
      setT("n_rbest", rates[0].a + "  " + fmtRe(rates[0].v) + " Mb/s");
      var line = rates.slice(0, 8).map(function (x) {
        return x.a + " " + fmtRe(x.v);
      }).join("  ·  ");
      setT("n_rates", line);
    } else {
      setT("n_rbest", "-");
      setT("n_rates", "(no live rates for this bucket)");
    }
  }

  var state  = { meta: null, bucketDoc: null, swaps: null, fleet: null, metricByBucket: null, bucketLive: {}, recentSwapsByBucket: null };
  var charts = {};
  // v0.9.32: cache for /data/swaps_per_bin.json responses
  var swapsPerBinCache = {};
  var swapsPerBinInflight = {};

  function mk(id, cfg) {
    var cv = $(id);
    if (!cv) return;
    // 0.4.122: guard against Chart not being loaded yet — the very
    // first liveRefresh fires before boot's _loadCharts() resolves,
    // so mk() would throw "Chart is not defined". _safeRender catches
    // it but the noise fills the console. Bail out silently instead.
    if (typeof Chart === "undefined") return;
    // E1-fix: update an existing chart in place instead of destroy +
    // recreate. The old code destroyed and re-created the chart on
    // every 30s SSE push, causing flicker, loss of tooltips/hover
    // state, and GC churn across 7 charts per push.
    //
    // We try to update the existing chart's data + options in place.
    // Only destroy + recreate if the chart type changed (rare) or the
    // dataset count changed (e.g. switching bucket ranges).
    var existing = charts[id];
    if (existing) {
      try {
        var sameType = !existing.config || !cfg.type ||
                       existing.config.type === cfg.type;
        var sameDSCount = existing.data &&
                          existing.data.datasets &&
                          cfg.data &&
                          cfg.data.datasets &&
                          existing.data.datasets.length === cfg.data.datasets.length;
        if (sameType && sameDSCount) {
          // In-place update: replace data + scales, keep the chart
          // instance alive so hover state + animations are preserved.
          existing.data = cfg.data;
          if (cfg.options) {
            existing.options = cfg.options;
          }
          existing.update('none'); // 'none' = no animation, instant
          return;
        }
      } catch (e) {
        // fall through to destroy + recreate
      }
      try { existing.destroy(); } catch(e) {}
    } else {
      // No existing chart in our map, but Chart.js may still have one
      // registered for this canvas (e.g. after a tab restore). Clear it.
      var stale = Chart.getChart(cv);
      if (stale) { try { stale.destroy(); } catch(e) {} }
    }
    charts[id] = new Chart(cv, cfg);
  }

  function j(url) {
    return fetch(url, {cache: "no-store"}).then(function (r) {
      if (!r.ok) { throw new Error(url + ": " + r.status); }
      return r.json();
    });
  }

  // v0.9.32: fetch swaps-per-bin data from the dynamic endpoint.
  // Returns cached data immediately if fresh (<30s), kicks off async refresh.
  function fetchSwapsPerBin(rng, bucket, cb) {
    var key = rng + "|" + (bucket || "all");
    var now = Date.now();
    var cached = swapsPerBinCache[key];
    var fresh = cached && (now - cached.fetchedAt) < 30000;
    if (swapsPerBinInflight[key]) {
      if (cached) cb(cached, false);
      swapsPerBinInflight[key].push(cb);
      return;
    }
    if (fresh) { cb(cached, true); return; }
    if (cached) cb(cached, false);
    swapsPerBinInflight[key] = [cb];
    fetch("/data/swaps_per_bin.json?range=" + encodeURIComponent(rng) +
          "&bucket=" + encodeURIComponent(bucket || "all"),
          {cache: "no-store"})
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(doc) {
        if (!doc || !doc.ts) return;
        doc.fetchedAt = Date.now();
        swapsPerBinCache[key] = doc;
        var waiters = swapsPerBinInflight[key] || [];
        delete swapsPerBinInflight[key];
        waiters.forEach(function(w) { w(doc, true); });
      })
      .catch(function() {
        var waiters = swapsPerBinInflight[key] || [];
        delete swapsPerBinInflight[key];
      });
  }

  function lineData(cols, series, ts, colors, scale, pointRadius) {
    scale = scale || function (v) { return v; };
    var pr = (pointRadius == null) ? 0 : pointRadius;
    return cols.map(function (c, i) {
      return {
        label: c,
        data: (series[c] || []).map(function (y, k) {
          return {x: ts[k] * 1000, y: y == null ? null : scale(y)};
        }),
        borderColor: colors[i % colors.length],
        backgroundColor: colors[i % colors.length],
        pointRadius: pr,
        pointHoverRadius: Math.max(3, pr + 1),
        borderWidth: 1.5,
        tension: 0.15,
        spanGaps: true,
      };
    });
  }

  function timeOpts(extra) {
    var base = {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      interaction: {mode: "nearest", intersect: false},
      layout: {padding: {top: 4, right: 8, bottom: 0, left: 0}},
      scales: {
        x: {
          type: "time",
          time: {tooltipFormat: "MMM d, HH:mm"},
          grid: {display: false},
          ticks: {maxRotation: 0, autoSkipPadding: 24, padding: 4},
          // Force the x-axis to span the fixed window [now-rSec, now] even
          // when actual data only covers part of it.  Set by renderBucket
          // and renderSwaps after buildFixedAxis(); undefined for "all".
          min: window.__chart_axis_min || undefined,
          max: window.__chart_axis_max || undefined,
        },
        y: {
          beginAtZero: false,
          grid: {drawTicks: false},
          ticks: {maxTicksLimit: 5, padding: 6},
        },
      },
      plugins: {
        legend: {display: false},
        tooltip: {displayColors: true, boxPadding: 4},
      },
    };
    if (!extra) return base;
    // Shallow-merge top-level keys, but deep-merge scales so charts that pass
    // extra.scales = {x:..., y:...} (overriding base.scales) still inherit
    // base.scales.x.min/max and other base props not in their extra.
    var result = Object.assign({}, base);
    for (var k in extra) {
      if (k === 'scales' && extra.scales) {
        result.scales = {};
        result.scales.x = Object.assign({}, base.scales.x || {}, extra.scales.x || {});
        result.scales.y = Object.assign({}, base.scales.y || {}, extra.scales.y || {});
      } else {
        result[k] = extra[k];
      }
    }
    return result;
  }

  // ---- Fixed-axis helpers ----
  // Build a continuous ts axis anchored to NOW: [floor(now - rSec), floor(now)]
  // snapped to interval boundaries. 1h = 60s bins, 24h = 30min bins, 7d = 2h bins.
  // Returns {ts, interval, rSec} or null for "all" (caller falls back to data's own ts).
  function buildFixedAxis(rng, now) {
    if (typeof now === 'undefined') now = Date.now() / 1000;
    var cfg = {
      "1h":  {rSec: 3600,    interval: 60},
      "24h": {rSec: 86400,   interval: 1800},
      "7d":  {rSec: 604800,  interval: 7200},
      "30d": {rSec: 2592000, interval: 21600},
    };
    var c = cfg[rng];
    if (!c) return null;
    var endBin   = Math.floor(now / c.interval) * c.interval;
    var startBin = endBin - c.rSec;
    var ts = [];
    for (var t = startBin; t <= endBin; t += c.interval) {
      ts.push(t);
    }
    return {ts: ts, interval: c.interval, rSec: c.rSec};
  }

  // For a single targetT, find the closest origTs value within +/-maxDist.
  // Returns the value or null if no sample is close enough.
  function rebinValue(origTs, origVals, targetT, maxDist) {
    if (!origTs.length) return null;
    if (targetT <= origTs[0]) {
      return (origTs[0] - targetT <= maxDist) ? origVals[0] : null;
    }
    if (targetT >= origTs[origTs.length - 1]) {
      var lastIdx = origTs.length - 1;
      return (targetT - origTs[lastIdx] <= maxDist) ? origVals[lastIdx] : null;
    }
    var lo = 0, hi = origTs.length - 1;
    while (lo < hi - 1) {
      var mid = (lo + hi) >> 1;
      if (origTs[mid] <= targetT) lo = mid; else hi = mid;
    }
    var diffLo = Math.abs(targetT - origTs[lo]);
    var diffHi = Math.abs(targetT - origTs[hi]);
    var bestIdx = (diffLo <= diffHi) ? lo : hi;
    var bestDiff = Math.min(diffLo, diffHi);
    return (bestDiff <= maxDist) ? origVals[bestIdx] : null;
  }

  // Rebin a sparse {col: [values]} dict onto a new fixed-axis ts.
  // Skips the 'ts' key. Values are aligned by nearest original sample;
  // null where no sample within +/-1.5*interval.
  function rebinOntoAxis(origTs, origSeriesByCol, newTs, interval) {
    var maxDist = interval * 1.5;
    var result = {};
    for (var col in origSeriesByCol) {
      if (col === 'ts') continue;
      var origVals = origSeriesByCol[col];
      if (!Array.isArray(origVals)) { result[col] = origVals; continue; }
      result[col] = newTs.map(function(t) {
        return rebinValue(origTs, origVals, t, maxDist);
      });
    }
    return result;
  }

  // 0.4.87: aggregate all state.bucketLive entries into one combined
  // {ts, cols} for the "All Buckets" 1h view.  Without this, the rate /
  // swap-score / streaks charts only refreshed every 5 min via refreshAll
  // when "All Buckets" was selected (because state.bucketDoc is null in
  // that case and renderBucket was gated on it).  Now the charts refresh
  // on every SSE push (~30s) using the same source as the per-bucket view.
  //
  // Per-bin aggregation: SUM across buckets for re_/ss_ (the picker's
  // totals across the whole fleet); MAX across buckets for bs_/ns_
  // (worst streak anywhere, since a single bad streak is the
  // operator's signal).  Empty bins stay null.
  function _aggregateAllBucketsLive() {
    var keys = Object.keys(state.bucketLive || {});
    if (!keys.length) return null;
    var tsSet = {};
    for (var i = 0; i < keys.length; i++) {
      var lb = state.bucketLive[keys[i]];
      if (lb && lb.ts) {
        for (var j = 0; j < lb.ts.length; j++) tsSet[lb.ts[j]] = true;
      }
    }
    var ts = Object.keys(tsSet).map(Number).sort(function(a, b) { return a - b; });
    if (!ts.length) return null;
    var tsIdx = {};
    for (var k = 0; k < ts.length; k++) tsIdx[ts[k]] = k;
    var cols = {};
    var sumPrefixes = { re_: true, ss_: true };
    var maxPrefixes = { bs_: true, ns_: true };
    for (var b = 0; b < keys.length; b++) {
      var lb2 = state.bucketLive[keys[b]];
      if (!lb2 || !lb2.cols) continue;
      var lbTs = lb2.ts || [];
      for (var col in lb2.cols) {
        if (!cols[col]) cols[col] = new Array(ts.length).fill(null);
        var vals = lb2.cols[col];
        var isMax = !!maxPrefixes[col.substring(0, 3)];
        for (var v = 0; v < vals.length; v++) {
          var idx = tsIdx[lbTs[v]];
          if (idx == null) continue;
          var cur = cols[col][idx];
          var val = vals[v];
          if (val == null) continue;
          if (cur == null) {
            cols[col][idx] = val;
          } else if (isMax) {
            if (val > cur) cols[col][idx] = val;
          } else {
            cols[col][idx] = cur + val;
          }
        }
      }
    }
    return {ts: ts, cols: cols};
  }

  function _appendLiveMetrics(doc) {
    if (!doc.metric_by_bucket || !state.bucketLive) return;
    var ts = doc.generated_ts; if (!ts) return;
    var bk = _currentBucketLabel();
    var bid = bk.bid;
    if (!bid || bid === 'all') {
      var hb3 = _heaviestBucketWithCoverage();
      if (hb3) bid = hb3.bid; else return;
    }
    var lb = state.bucketLive[bid];
    if (!lb) { var lbl = _labelForBucketAddr(bid); if (lbl && lbl !== bid) lb = state.bucketLive[lbl]; }
    if (!lb || !lb.ts || !lb.cols) return;
    if (lb.ts.length > 0 && lb.ts[lb.ts.length - 1] >= ts) return;
    var mbRows = doc.metric_by_bucket[bid];
    if (!mbRows) { var lbl2 = _labelForBucketAddr(bid); if (lbl2 && lbl2 !== bid) mbRows = doc.metric_by_bucket[lbl2]; }
    if (!mbRows || !mbRows.length) return;
    lb.ts.push(ts);
    for (var i = 0; i < mbRows.length; i++) {
      var r = mbRows[i]; if (!r.alg) continue;
      var prefixes = [['re_', 'rate_ema'], ['ss_', 'swap_score'], ['bs_', 'bad_streak'], ['ns_', 'null_streak']];
      for (var p = 0; p < prefixes.length; p++) {
        var key = prefixes[p][0] + r.alg;
        if (!lb.cols[key]) lb.cols[key] = [];
        lb.cols[key].push(r[prefixes[p][1]] != null ? r[prefixes[p][1]] : null);
      }
    }
    var MAX = 240;
    if (lb.ts.length > MAX) {
      lb.ts = lb.ts.slice(-MAX);
      for (var k in lb.cols) { if (Array.isArray(lb.cols[k])) lb.cols[k] = lb.cols[k].slice(-MAX); }
    }
  }

  function renderBucket() {
    // 0.4.122: guard state.meta — renderLiveState can fire (via SSE /
    // polling) before boot() has finished loading data/meta.json.
    // Without this guard, state.meta.algs throws "Cannot read
    // properties of null (reading 'algs')".
    var doc = state.bucketDoc;
    if (!state.meta) return;
    var algs = state.meta.algs;
    if (!algs) return;   // 0.4.87: meta not loaded yet — boot() still running
    // v0.8.7: guard $("range") — SSE can fire before boot populates
    // the <select>.  Treat as "1h" (matches boot's default).
    var rng = $("range") ? $("range").value : "1h";
    var bid = $("bucket") ? $("bucket").value : null;
    if (!bid || bid === 'all') {
      var hb2 = _heaviestBucketWithCoverage();
      if (hb2) bid = hb2.bid;
    }
    var s, ts;
    if (s == null && rng === "1h" && bid && state.bucketLive && state.bucketLive[bid]) {
      var lb = state.bucketLive[bid];
      if (lb.ts && lb.ts.length) {
        s = {};
        for (var k in (lb.cols || {})) s[k] = lb.cols[k];
        ts = lb.ts;
      }
    } else if (s == null && rng === "1h" && bid && state.bucketLive) {
      // 0.4.87: bucket_live is keyed by _label_for(addr) on the python
      // side (bpftune_data.py:385), so for labeled buckets the dropdown's
      // raw addr (b.id from meta.json) doesn't match.  Try the label
      // form before falling back to the 15-min renderer output.
      var _lbl = _labelForBucketAddr(bid);
      if (_lbl && _lbl !== bid && state.bucketLive[_lbl]) {
        var _lb = state.bucketLive[_lbl];
        if (_lb.ts && _lb.ts.length) {
          s = {};
          for (var _k in (_lb.cols || {})) s[_k] = _lb.cols[_k];
          ts = _lb.ts;
        }
      }
    }
    // Fall back to the renderer's 15-min bucket_<id>.json output for
    // longer ranges, or for 1h if bucket_live didn't have the entry.
    if (s == null) {
      if (!doc) return;   // "All Buckets" + range > 1h: no historical aggregate
      var sDoc = doc.series[rng];
      if (!sDoc) return;
      s = sDoc;
      ts = sDoc.ts;
    }
    // Build a fixed-axis ts anchored to NOW so all four charts (rate, score,
    // streak, swaps-per-bin) share the exact same x-axis: [now-rSec, now] at
    // fixed intervals.  Rebin original series onto this axis (null where no
    // sample within +/-1.5*interval).  "all" range keeps the original ts.
    // 0.4.88: use __current_doc.generated_ts (always fresh on every SSE
    // push) instead of __filtered_doc.generated_ts (which was stale —
    // _renderFilteredPanels doesn't set __filtered_doc, so it held the
    // value from the last bucket change).  This is why the rate/sscore/
    // streaks charts used a slightly older "now" than the swaps-per-bin
    // chart, making the timelines visibly different at the right edge.
    var __now = (window.__current_doc && window.__current_doc.generated_ts) || (Date.now() / 1000);
    var __fixedAxis = buildFixedAxis(rng, __now);
    if (__fixedAxis) {
      s = rebinOntoAxis(ts, s, __fixedAxis.ts, __fixedAxis.interval);
      ts = __fixedAxis.ts;
      // Expose min/max so timeOpts() can force x-axis to span the full
      // [now-rSec, now] window even where data is null.
      window.__chart_axis_min = ts[0] * 1000;
      window.__chart_axis_max = ts[ts.length - 1] * 1000;
    } else {
      // "all" range — let Chart.js auto-scale to data extent
      window.__chart_axis_min = undefined;
      window.__chart_axis_max = undefined;
    }

    function makeSeries(prefix, source) {
      source = source || s;
      return algs.map(function (a) {
        return prefix + a;
      }).filter(function (c) { return c in source; });
    }

    var rateCols = makeSeries("re_", s);
    mk("rate", {
      type: "line",
      data: {datasets: lineData(rateCols, s, ts, PALETTE, scaleRe, 0)},
      options: timeOpts({
        plugins: {
          legend: {
            display: true, position: "bottom", align: "start",
            labels: {boxWidth: 8, boxHeight: 8, padding: 8,
                     font: {size: 10.5}},
          },
        },
      }),
    });

    var ssCols = makeSeries("ss_");
    mk("sscore", {
      type: "line",
      data: {datasets: lineData(ssCols, s, ts, PALETTE, null, 0)},
      options: timeOpts({
        scales: {
          x: {type: "time", time: {tooltipFormat: "MMM d, HH:mm"},
              grid: {display: false},
              ticks: {maxRotation: 0, autoSkipPadding: 24, padding: 4}},
          y: {beginAtZero: false, grid: {drawTicks: false},
              ticks: {maxTicksLimit: 6, padding: 6}},
        },
        plugins: {
          legend: {
            display: true, position: "bottom", align: "start",
            labels: {boxWidth: 8, boxHeight: 8, padding: 8,
                     font: {size: 10.5}},
          },
        },
      }),
    });

    var bsCols = makeSeries("bs_");
    var nsCols = makeSeries("ns_");
    var streakSets = [];
    streakSets = streakSets.concat(
      lineData(bsCols, s, ts, PALETTE, null, 0).map(function (ds) {
        ds.borderDash = [4, 3];
        ds.label = ds.label.replace(/^bs_/, "") + " bad";
        return ds;
      }));
    streakSets = streakSets.concat(
      lineData(nsCols, s, ts, PALETTE, null, 0).map(function (ds) {
        ds.label = ds.label.replace(/^ns_/, "") + " null";
        return ds;
      }));
    mk("streaks", {
      type: "line",
      data: {datasets: streakSets},
      options: timeOpts({
        scales: {
          x: {type: "time", time: {tooltipFormat: "MMM d, HH:mm"},
              grid: {display: false},
              ticks: {maxRotation: 0, autoSkipPadding: 24, padding: 4}},
          y: {beginAtZero: true, grid: {drawTicks: false},
              ticks: {maxTicksLimit: 6, padding: 6, precision: 0}},
        },
        plugins: {
          legend: {
            display: true, position: "bottom", align: "start",
            labels: {boxWidth: 8, boxHeight: 8, padding: 8,
                     font: {size: 10.5}},
          },
        },
      }),
    });
  }

  function renderDivChart(canvasId, suffix) {
    // v0.8.7: guard state.swaps — SSE can fire renderDivergenceCharts
    // before boot()'s data/swaps.json fetch resolves, so state.swaps is
    // still null.  Without this guard, `doc[rng]` throws
    // "Cannot read properties of null (reading '')" and aborts the
    // whole renderDivergenceCharts call (both div + div_sustained).
    var doc = state.swaps, rng = $("range") ? $("range").value : "1h";
    if (!doc) return;
    var d = doc[rng];
    if (!d) return;
    var ts = d.ts;
    var sfx = suffix || "";

    function mkLine(key, label, color, dash) {
      return {
        label: label,
        data: (d[key] || []).map(function (y, k) {
          return {x: ts[k] * 1000, y: y};
        }),
        borderColor: color,
        backgroundColor: color,
        borderDash: dash || [],
        pointRadius: 2,
        pointHoverRadius: 4,
        borderWidth: 1.5,
        spanGaps: true,
      };
    }

    mk(canvasId, {
      type: "line",
      data: {datasets: [
        mkLine("d1_rate" + sfx, "diverges=1", "#59a14f"),
        mkLine("d1_lo"   + sfx, "d1 95% lo", "#59a14f", [4, 3]),
        mkLine("d1_hi"   + sfx, "d1 95% hi", "#59a14f", [4, 3]),
        mkLine("d0_rate" + sfx, "diverges=0", "#e15759"),
        mkLine("d0_lo"   + sfx, "d0 95% lo", "#e15759", [4, 3]),
        mkLine("d0_hi"   + sfx, "d0 95% hi", "#e15759", [4, 3]),
      ]},
      options: timeOpts({
        scales: {
          x: {type: "time", grid: {display: false},
              ticks: {maxRotation: 0, autoSkipPadding: 24}},
          y: {min: 0, max: 1, grid: {drawTicks: false},
              ticks: {maxTicksLimit: 5, padding: 6,
                      callback: function (v) {
                        return Math.round(v * 100) + "%";
                      }}},
        },
        plugins: {
          legend: {
            display: true, position: "bottom", align: "start",
            labels: {boxWidth: 8, boxHeight: 8, padding: 8,
                     font: {size: 10.5},
                     filter: function (item) {
                       return !/_lo|_hi/.test(item.text);
                     }},
          },
        },
      }),
    });
  }

  function sustainedHasData() {
    var doc = state.swaps;
    if (!doc) return false;
    var d = doc["24h"] || doc["7d"] || doc["all"];
    if (!d) return false;
    var arr = d.d1_n_sustained || [];
    for (var i = 0; i < arr.length; i++) {
      if ((arr[i] || 0) > 0) return true;
    }
    return false;
  }

  function renderScoreNow() {
    if (!state.meta) return;
    var _rs = $("range");
    if (!_rs) return;
    var rng = _rs.value;
    var bid = $("bucket") ? $("bucket").value : null;
    if (!bid || bid === "all") { var hb = _heaviestBucketWithCoverage(); if (hb) bid = hb.bid; }
    var s = null, ts = null;
    // v0.8.4: for 1h range, use live bucket data (30s SSE) and compute
    // score_ from re_/ss_/bs_/ns_. Formula: score = re*ss/(256+bs*64+ns*32)
    if (rng === "1h" && bid && state.bucketLive && state.bucketLive[bid]) {
      var lb = state.bucketLive[bid];
      if (lb.ts && lb.ts.length && lb.cols) {
        s = {}; ts = lb.ts;
        for (var k in lb.cols) {
          if (k.indexOf("re_") === 0) {
            var alg = k.substring(3);
            var reA = lb.cols["re_"+alg]||[], ssA = lb.cols["ss_"+alg]||[];
            var bsA = lb.cols["bs_"+alg]||[], nsA = lb.cols["ns_"+alg]||[];
            s["score_"+alg] = reA.map(function(re,i){
              var ss=ssA[i]||0, bs=bsA[i]||0, ns=nsA[i]||0;
              return (re && ss) ? re*ss/(256+bs*64+ns*32) : null;
            });
          }
        }
      }
    }
    // Try labeled bucket if raw addr didn't match
    if (!s && rng === "1h" && bid) {
      var _lbl = _labelForBucketAddr(bid);
      if (_lbl && _lbl !== bid && state.bucketLive && state.bucketLive[_lbl]) {
        var _lb = state.bucketLive[_lbl];
        if (_lb.ts && _lb.ts.length && _lb.cols) {
          s = {}; ts = _lb.ts;
          for (var _k in _lb.cols) {
            if (_k.indexOf("re_") === 0) {
              var _a = _k.substring(3);
              var rA=_lb.cols["re_"+_a]||[], sA=_lb.cols["ss_"+_a]||[];
              var bA=_lb.cols["bs_"+_a]||[], nA=_lb.cols["ns_"+_a]||[];
              s["score_"+_a] = rA.map(function(re,i){
                var ss=sA[i]||0, bs=bA[i]||0, ns=nA[i]||0;
                return (re && ss) ? re*ss/(256+bs*64+ns*32) : null;
              });
            }
          }
        }
      }
    }
    // Fall back to static bucketDoc for longer ranges (5 min refresh)
    if (!s) {
      if (!state.bucketDoc || !state.bucketDoc.series) return;
      var doc = state.bucketDoc;
      if (!doc.series || !doc.series[rng]) return;
      s = doc.series[rng]; ts = s.ts;
      if (!ts || !ts.length) return;
    }
    var scoreCols = Object.keys(s).filter(function(k) { return k.indexOf("score_") === 0; });
    mk("score-now", {
      type: "line",
      data: {datasets: lineData(scoreCols, s, ts, PALETTE, null, 0)},
      options: timeOpts({
        plugins: {
          legend: {
            display: true, position: "bottom", align: "start",
            labels: {boxWidth: 8, boxHeight: 8, padding: 8, font: {size: 10.5}},
          },
        },
        scales: {
          y: {beginAtZero: true, grid: {drawTicks: false},
              ticks: {maxTicksLimit: 5, padding: 6}},
        },
      }),
    });
  }

  function renderSwaps() {
    // v0.8.7: guard $("range") — SSE can fire before boot populates
    // the <select>, so $("range") is null briefly.  Treat as "1h".
    var rng = $("range") ? $("range").value : "1h";
    var d = null;
    // v0.9.12: check SSE swaps_list FIRST for 1h range (freshest data).
    // The old code checked static bucketDoc first, which meant stale
    // CSV-derived data took priority over live SSE data. For 1h, the
    // SSE swaps_list is always more current than the 5-min static file.
    if (rng === "1h" && window.__current_doc && window.__current_doc.swap_outcomes && window.__current_doc.swap_outcomes.swaps_list && window.__current_doc.swap_outcomes.swaps_list.length > 0) {
      var sse = window.__current_doc;
      var sw = sse.swap_outcomes.swaps_list;
      var now = (sse.generated_ts) || (Date.now()/1000);
      var fixedAxis = buildFixedAxis(rng, now);
      var monoOffset = (sse.now_mono && sse.now_mono > 0) ? (now - sse.now_mono) : 0;
      if (fixedAxis) {
        window.__chart_axis_min = fixedAxis.ts[0] * 1000;
        window.__chart_axis_max = fixedAxis.ts[fixedAxis.ts.length - 1] * 1000;
        var swapCounts = fixedAxis.ts.map(function(){return 0;});
        sw.forEach(function(s) {
          var t = (s.ts || 0) + monoOffset;
          var fa = fixedAxis.ts;
          if (t < fa[0] || t > fa[fa.length - 1]) return;
          if (t <= fa[0]) { swapCounts[0]++; return; }
          var hi = fa.length - 1;
          if (t >= fa[hi]) { swapCounts[hi]++; return; }
          var lo = 0;
          while (lo < hi - 1) {
            var mid = (lo + hi) >> 1;
            if (fa[mid] <= t) lo = mid; else hi = mid;
          }
          if (Math.abs(t - fa[lo]) <= Math.abs(t - fa[hi])) {
            swapCounts[lo]++;
          } else {
            swapCounts[hi]++;
          }
        });
        d = {ts: fixedAxis.ts, swaps: swapCounts};
      }
    }
    // v0.9.32: fetch from dynamic /data/swaps_per_bin.json endpoint for 24h+
    // This reads swaps.csv directly, always fresh, handles labeled buckets.
    if (!d && rng !== "1h") {
      var bk = _currentBucketLabel();
      var bucketForFetch = (bk.bid === "all") ? "all" : (bk.label || bk.bid);
      var key = rng + "|" + bucketForFetch;
      var cached = swapsPerBinCache[key];
      if (cached && cached.ts && cached.swaps) {
        var __now = (window.__current_doc && window.__current_doc.generated_ts) || (Date.now() / 1000);
        var __fa = buildFixedAxis(rng, __now);
        if (__fa) {
          var rebinned = __fa.ts.map(function(){return 0;});
          var maxDist = __fa.interval * 1.5;
          for (var si = 0; si < cached.ts.length; si++) {
            var t = cached.ts[si];
            if (t < __fa.ts[0] - maxDist || t > __fa.ts[__fa.ts.length - 1] + maxDist) continue;
            if (t <= __fa.ts[0]) { rebinned[0] += (cached.swaps[si] || 0); continue; }
            var hi = __fa.ts.length - 1;
            if (t >= __fa.ts[hi]) { rebinned[hi] += (cached.swaps[si] || 0); continue; }
            var lo = 0;
            while (lo < hi - 1) {
              var mid = (lo + hi) >> 1;
              if (__fa.ts[mid] <= t) lo = mid; else hi = mid;
            }
            if (Math.abs(t - __fa.ts[lo]) <= Math.abs(t - __fa.ts[hi])) {
              rebinned[lo] += (cached.swaps[si] || 0);
            } else {
              rebinned[hi] += (cached.swaps[si] || 0);
            }
          }
          d = {ts: __fa.ts, swaps: rebinned};
          window.__chart_axis_min = __fa.ts[0] * 1000;
          window.__chart_axis_max = __fa.ts[__fa.ts.length - 1] * 1000;
        } else {
          d = {ts: cached.ts, swaps: cached.swaps};
          window.__chart_axis_min = undefined;
          window.__chart_axis_max = undefined;
        }
      }
      // Kick off async refresh; re-render when fresh data arrives
      fetchSwapsPerBin(rng, bucketForFetch, function(doc, fresh) {
        if (fresh) _safeRender('swaps', function() { renderSwaps(); });
      });
    }
    if (!d && state.bucketDoc && state.bucketDoc.series && state.bucketDoc.series[rng] && state.bucketDoc.series[rng].swaps) {
      var s2 = state.bucketDoc.series[rng];
      // 0.8.5: rebin onto the SAME fixed axis as renderBucket() so all
      // four charts share an identical x-axis. Was using raw s2.ts which
      // was offset from the bucket charts by up to 1 interval.
      var __now = (window.__current_doc && window.__current_doc.generated_ts) || (Date.now() / 1000);
      var __fa = buildFixedAxis(rng, __now);
      if (__fa) {
        var rebinned = __fa.ts.map(function(){return 0;});
        var maxDist = __fa.interval * 1.5;
        for (var si = 0; si < s2.ts.length; si++) {
          var t = s2.ts[si];
          if (t < __fa.ts[0] - maxDist || t > __fa.ts[__fa.ts.length - 1] + maxDist) continue;
          if (t <= __fa.ts[0]) { rebinned[0] += (s2.swaps[si] || 0); continue; }
          var hi = __fa.ts.length - 1;
          if (t >= __fa.ts[hi]) { rebinned[hi] += (s2.swaps[si] || 0); continue; }
          var lo = 0;
          while (lo < hi - 1) {
            var mid = (lo + hi) >> 1;
            if (__fa.ts[mid] <= t) lo = mid; else hi = mid;
          }
          if (Math.abs(t - __fa.ts[lo]) <= Math.abs(t - __fa.ts[hi])) {
            rebinned[lo] += (s2.swaps[si] || 0);
          } else {
            rebinned[hi] += (s2.swaps[si] || 0);
          }
        }
        d = {ts: __fa.ts, swaps: rebinned};
        window.__chart_axis_min = __fa.ts[0] * 1000;
        window.__chart_axis_max = __fa.ts[__fa.ts.length - 1] * 1000;
      } else {
        // "all" range — no fixed axis, keep original ts
        d = {ts: s2.ts, swaps: s2.swaps};
        window.__chart_axis_min = undefined;
        window.__chart_axis_max = undefined;
      }
    }
    if (!d) {
    // B5-fix: always read from __current_doc (fresh on every SSE push),
    // never from __filtered_doc (set only on bucket change — stale by
    // up to 5 min). The old `window.__filtered_doc || window.__current_doc`
    // meant that after a bucket change, the swaps-per-bin chart used a
    // stale now_mono for the monotonic→epoch offset, plotting bars at
    // the wrong time relative to the line charts.
    var sse = window.__current_doc;
    if (sse && sse.swap_outcomes && sse.swap_outcomes.swaps_list) {
      var sw = sse.swap_outcomes.swaps_list;
      var now = (window.__current_doc && window.__current_doc.generated_ts) || (Date.now()/1000);
      var fixedAxis = buildFixedAxis(rng, now);
      // Swap timestamps are in CLOCK_MONOTONIC (seconds since boot), NOT Unix
      // epoch.  Convert to epoch using sse.now_mono: epoch = mono + offset
      // where offset = generated_ts - now_mono.  Without this, all swaps fall
      // outside the [now-rSec, now] window (since swap.ts ~= 887000 but
      // generated_ts ~= 1790700000) and no bars appear.
      var monoOffset = (sse.now_mono && sse.now_mono > 0) ? (now - sse.now_mono) : 0;
      // Set min/max globals (same as renderBucket) so this chart's x-axis
      // also spans the full fixed window even where bins are 0.
      if (fixedAxis) {
        window.__chart_axis_min = fixedAxis.ts[0] * 1000;
        window.__chart_axis_max = fixedAxis.ts[fixedAxis.ts.length - 1] * 1000;
      } else {
        window.__chart_axis_min = undefined;
        window.__chart_axis_max = undefined;
      }
      if (fixedAxis) {
        // Use the SAME fixed-axis ts as Rate EMA / Swap Score / Bad Streak so
        // all four charts share an identical x-axis.  Each swap is assigned
        // to its nearest bin via binary search.  Empty bins -> 0 bars.
        var swapCounts = fixedAxis.ts.map(function(){return 0;});
        sw.forEach(function(s) {
          var t = (s.ts || 0) + monoOffset;   // monotonic -> epoch
          var fa = fixedAxis.ts;
          if (t < fa[0] || t > fa[fa.length - 1]) return;
          if (t <= fa[0]) { swapCounts[0]++; return; }
          var hi = fa.length - 1;
          if (t >= fa[hi]) { swapCounts[hi]++; return; }
          var lo = 0;
          while (lo < hi - 1) {
            var mid = (lo + hi) >> 1;
            if (fa[mid] <= t) lo = mid; else hi = mid;
          }
          if (Math.abs(t - fa[lo]) <= Math.abs(t - fa[hi])) {
            swapCounts[lo]++;
          } else {
            swapCounts[hi]++;
          }
        });
        d = {ts: fixedAxis.ts, swaps: swapCounts};
      } else {
        // "all" range: keep only-populated bins (avoid millions of empties)
        var bSec = 86400;
        var bins = {};
        sw.forEach(function(s) {
          var t = (s.ts || 0) + monoOffset;   // monotonic -> epoch
          var b = Math.floor(t/bSec)*bSec;
          bins[b] = (bins[b]||0)+1;
        });
        var sk = Object.keys(bins).map(Number).sort(function(a,b){return a-b;});
        if (sk.length) d = {ts: sk, swaps: sk.map(function(t){return bins[t];})};
      }
    }
    }
    if (!d) { var doc = state.swaps; d = doc ? doc[rng] : null; }
    if (!d) return;
    // v0.9.10 fix: set axis globals for this path too — renderScoreNow and
    // renderDivChart read them via timeOpts(). Without this, they'd use
    // stale axis values from a previous renderBucket/renderSwaps call.
    var _fa = buildFixedAxis(rng);
    if (_fa && d.ts && d.ts.length) {
      window.__chart_axis_min = _fa.ts[0] * 1000;
      window.__chart_axis_max = _fa.ts[_fa.ts.length - 1] * 1000;
    } else {
      window.__chart_axis_min = undefined;
      window.__chart_axis_max = undefined;
    }
    var ts = d.ts;

    mk("swaps", {
      type: "bar",
      data: {
        datasets: [{
          label: "swaps",
          data: d.swaps.map(function(v, k) { return {x: ts[k] * 1000, y: v}; }),
          backgroundColor: "#4e79a7",
          borderColor: "#4e79a7",
          borderRadius: 2,
          maxBarThickness: 14,
        }],
      },
      options: timeOpts({
        scales: {
          x: {type: "time", grid: {display: false}, ticks: {maxRotation: 0, autoSkipPadding: 24, padding: 4}},
          y: {beginAtZero: true, grid: {drawTicks: false},
              ticks: {maxTicksLimit: 4, padding: 6}},
        },
      }),
    });
  }

  function renderDivergenceCharts() {
    renderDivChart("div", "");
    renderDivChart("div_sustained", "_sustained");
    var note = document.getElementById("div_sustained_note");
    if (note) {
      if (sustainedHasData()) {
        note.textContent = "sustained = median srate in [t+60, t+300], " +
          "compared to last srate before the swap. Excludes the cwnd-reset " +
          "dip. This is the accurate throughput measure.";
        note.style.color = "";
      } else {
        note.textContent = "no sustained data yet. Requires 0.4.53+ emitting " +
          "`srate` lines AND the collector writing srate.csv AND a swap " +
          "landing with 60+ s of post-swap votes. Will populate on its own.";
        note.style.color = "#9aa0a6";
      }
    }
  }

  function renderFleet() {
    /* 0.4.78.2: fleet.json no longer drives a separate chart.  Its
     * coverage_24h feeds the new coverage column on the top-
     * destination-buckets table.  refreshAll calls this right
     * after assigning state.fleet, so re-render the buckets tail
     * here and the column will fill in. */
    if (state.lastBucketRows) renderBuckets(state.lastBucketRows);
  }

  function loadBucket(id) {
    if (id === "all") {
      var hb = _heaviestBucketWithCoverage();
      if (hb) {
        id = hb.bid;
      } else {
        state.bucketDoc = null;
        renderNow();
_safeRender("score-now", function() { renderScoreNow(); });
        renderRecentSwapsForBucket();
        renderMetricForBucket();
        return Promise.resolve();
      }
    }
    var safe = (id || "").replace(/[^A-Za-z0-9._-]/g, "_");
    return j("data/bucket_" + safe.replace(/:/g, "_") + ".json").then(function (doc) {
      state.bucketDoc = doc;
      // v0.9.13: only re-render from static file for ranges > 1h.
      // For 1h, the live SSE data (state.bucketLive) is always fresher
      // — re-rendering from the static file causes chart flicker.
      var _rng = $("range") ? $("range").value : "1h";
      if (_rng !== "1h" || !state.bucketLive || Object.keys(state.bucketLive).length === 0) {
        renderBucket();
      }
      renderNow();
      renderRecentSwapsForBucket();
      renderMetricForBucket();
      _safeRender("score-now", function() { renderScoreNow(); });
    }).catch(function (e) {
      state.bucketDoc = null;
      renderNow();
      renderRecentSwapsForBucket();
      renderMetricForBucket();
    });
  }

  function refreshNowCardAndChart() {
    var id = $("bucket").value;
    if (id) loadBucket(id);
  }

function _populateBucketSelect(desiredBucket) {
  var bs = $("bucket");
  var stillThere = false;
  var metaIds = {};
  var usedLabels = {};  // 0.4.124: track labels already shown
  var slash16Label = {};
  var L0 = window.__labels || {};
  Object.keys(L0).forEach(function(ip) {
    var parts = ip.split('.');
    if (parts.length === 4) {
      var p = parts[0] + '.' + parts[1] + '.0.0';
      if (!slash16Label[p]) slash16Label[p] = L0[ip];
    }
  });
  var metaHtml = "";
  for (var k = 0; k < state.meta.buckets.length; k++) {
    var b = state.meta.buckets[k];
    metaIds[b.id] = true;
    var disp = shortAddr(b.id);
    if (disp === b.id && b.label && b.label !== b.id) disp = b.label;
    if (disp && disp !== b.id) usedLabels[disp] = true;
    metaHtml += '<option value="' + b.id + '">' + disp +
            '</option>';
    if (b.id === desiredBucket) stillThere = true;
  }
  var customHtml = "";
  if (window.__labels) {
    var customLabels = {};
    Object.keys(window.__labels).forEach(function(ip) {
      var lbl = window.__labels[ip];
      if (lbl && lbl !== ip && !metaIds[ip] && !metaIds[lbl] && !customLabels[lbl]) {
        if (usedLabels[lbl]) return;
        var parts = ip.split('.');
        if (parts.length === 4) {
          var s16 = parts[0] + '.' + parts[1] + '.0.0';
          if (metaIds[s16]) return;
        }
        customLabels[lbl] = true;
        customHtml += '<option value="' + lbl + '">' + lbl + '</option>';
        if (lbl === desiredBucket) stillThere = true;
      }
    });
  }
  bs.innerHTML = customHtml + metaHtml;
  bs.add(new Option('All Buckets', 'all'), 0);
  bs.value = stillThere ? desiredBucket : 'all';
  if (window.__current_doc) _reFilterPanels();
  return bs.value;
}

  function refreshAll() {
    var keep = $("bucket").value;
    Promise.all([
      j("data/meta.json"),
      j("data/swaps.json"),
      j("data/fleet.json"),
    ]).then(function (results) {
      state.meta  = results[0];
      state.swaps = results[1];
      state.fleet = results[2];

      var finalBucket = _populateBucketSelect(keep);

      var stamp = new Date(state.meta.generated_ts * 1000).toISOString()
                      .replace("T", " ").slice(0, 19) + "Z";
      if (footgen) footgen.textContent = "rendered " + stamp;
      status("updated " + relTime(state.meta.generated_ts));

      return loadBucket(finalBucket);
    }).then(function () {
      renderSwaps();
      _safeRender("div", function() { renderDivChart("div", ""); });
      _safeRender("div_sustained", function() { renderDivChart("div_sustained", "_sustained"); });
      _safeRender("score-now", function() { renderScoreNow(); });
      renderFleet();
    }).catch(function (e) {
      err("refresh: " + (e && e.message ? e.message : e), e);
    });
  }

  function boot() {
    // v0.7.5h: startLiveUpdates() moved below
    setInterval(refreshAll, 300000);

    status("loading charts\u2026");
    // 0.4.122: separate the Chart.js load from the data load. The
    // previous chain did loadScript(chart.js).then(load data) — if
    // the CDN was unreachable (air-gapped, ad-blocker, network outage),
    // the entire boot aborted at chart.js and state.meta was never
    // set, so the bucket dropdown stayed empty and every render that
    // needed state.meta bailed. Now the chart.js failure is logged
    // but the data load still runs; the live panels (NOW, recent
    // swaps, tunables, system, build) all work without charts.
    // v0.9.5: Chart.js is now loaded via <script> tags in index.html
    // (not dynamic loadScript). Just apply defaults and continue.
    function _loadCharts() {
      try {
        if (typeof Chart !== 'undefined') {
          applyChartDefaults();
        } else {
          err("Chart.js not loaded — check <script> tags in index.html");
        }
      } catch (e) {
        err("chart defaults: " + (e && e.message), e);
      }
      return Promise.resolve();
    }

    function _loadData() {
      status("loading data\u2026");
      return Promise.all([
        j("data/meta.json"),
        j("data/swaps.json"),
        j("data/fleet.json"),
      ]);
    }

    _loadCharts().then(function() { startLiveUpdates(); return _loadData(); }).then(function (results) {
        state.meta  = results[0];
        state.swaps = results[1];
        state.fleet = results[2];

        var saved_bucket = null;
        try { saved_bucket = localStorage.getItem("bpftune.bucket"); } catch (e) {}
        _populateBucketSelect(saved_bucket);
        // 0.4.123: fetch /api/labels NOW so the dropdown options
        // get human-readable text on first paint.
        _fetchAndApplyLabels();

        var rs = $("range");
        var rhtml = "";
        for (var m = 0; m < state.meta.ranges.length; m++) {
          rhtml += '<option value="' + state.meta.ranges[m] + '">' +
                   state.meta.ranges[m] + '</option>';
        }
        rs.innerHTML = rhtml;
        /* 0.4.79: default to 1h so the first paint reads the
         * live ring (current.json, 60s) instead of loading a
         * 260 KB bucket_*.json just to show the page.  Restore
         * the user's last choice if there is one; historical
         * ranges load on demand. */
        var saved_range = null;
        try { saved_range = localStorage.getItem("bpftune.range"); } catch (e) {}
        rs.value = (saved_range && state.meta.ranges.indexOf(saved_range) >= 0)
                   ? saved_range : "1h";
        rs.onchange = function () {
          try { localStorage.setItem("bpftune.range", rs.value); } catch (e) {}
          renderBucket();
        };

        var stamp = new Date(state.meta.generated_ts * 1000).toISOString()
                        .replace("T", " ").slice(0, 19) + "Z";
        status("updated " + relTime(state.meta.generated_ts));
        if (footgen) footgen.textContent = "rendered " + stamp;

        var bs = $("bucket");
        bs.onchange = function () {
          try { localStorage.setItem("bpftune.bucket", bs.value); } catch (e) {}
          loadBucket(bs.value);
          renderMetricForBucket();
          renderRecentSwapsForBucket();
          _updateBucketTags();   // 0.4.87: panel headers follow the dropdown
        };
        try { localStorage.setItem("bpftune.bucket", bs.value); } catch (e) {}
        // 0.4.87: merge the two rs.onchange assignments — the previous
        // code overwrote the first (which persisted to localStorage)
        // with the second (which didn't), so the user's range choice
        // was lost on reload.
        rs.onchange = function () {
          try { localStorage.setItem("bpftune.range", rs.value); } catch (e) {}
          renderBucket();
          renderSwaps();
          _safeRender("div", function() { renderDivChart("div", ""); });
          _safeRender("div_sustained", function() { renderDivChart("div_sustained", "_sustained"); });
          _safeRender("score-now", function() { renderScoreNow(); });
          // v0.9.1: re-render the Swap Target Pick table on range change
          // too — it reads from live metric_by_bucket data (not historical),
          // so it should always show regardless of selected range.
          _safeRender('metric_for_bucket', function() { renderMetricForBucket(); });
          _updateBucketTags();
        };

        /* 0.4.79 fix: load the bucket the dropdown actually shows
         * (bs.value), not meta's default.  Boot was setting bs.value
         * to the saved bucket and then loading a different one, so
         * the chart showed one bucket's data under another's name
         * until the user re-selected. */
        if (bs.value === 'all') {
          // 0.4.122: even when "All Buckets" is selected, still kick
          // off loadBucket so _heaviestBucketWithCoverage resolves
          // the top bucket, fetches bucket_<id>.json, and calls
          // renderNow(). The previous `return Promise.resolve()`
          // path skipped loadBucket entirely, leaving the NOW card
          // at "-" (initial) until the next 30s polling tick fired
          // refreshNowCardAndChart.
          return loadBucket('all');
        }
        return loadBucket(bs.value);
      })
      .then(function () {
        renderSwaps();
        renderFleet();
      })
      .catch(function (e) {
        err("FAIL: " + (e && e.message ? e.message : e), e);
      });
  }  boot();

  // A3-fix: refresh immediately when the tab becomes visible again.
  // Browsers throttle setInterval / setTimeout to ~1/min in background
  // tabs, so on return the dashboard shows minutes-old data. Without
  // this, the user perceives "not updating" for 30+ seconds after
  // switching back.
  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "visible") {
      // Reset the stale-detection watermark so an immediate liveRefresh
      // isn't rejected by the A7-fix check (the visible-tab refresh is
      // intentional, even if generated_ts hasn't advanced).
      window.__latest_doc_ts = null;
      if (typeof liveRefresh === "function") liveRefresh();
      if (typeof refreshNowCardAndChart === "function") refreshNowCardAndChart();
    }
  });

  // 0.4.78.2: dark/light toggle.  Persists per-browser in
  // localStorage; falls back to prefers-color-scheme.
  (function () {
    var saved = null;
    try { saved = localStorage.getItem("bpftune.theme"); } catch (e) {}
    if (saved === "dark" || saved === "light") {
      document.documentElement.setAttribute("data-theme", saved);
    }
    var b = document.getElementById("theme-toggle");
    if (!b) return;
    b.addEventListener("click", function () {
      var cur = document.documentElement.getAttribute("data-theme");
      if (!cur) {
        cur = window.matchMedia(
          "(prefers-color-scheme: dark)").matches ? "dark" : "light";
      }
      var next = cur === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("bpftune.theme", next); } catch (e) {}
    });
  })();
})();

  /* ---- Label Editor Modal (reads /etc/bpftune/aliases groups) ---- */
  function _le_esc(s) { return String(s==null?'':s).replace(/[&<>"']/g, function(c) { return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }
  function openLabelEditor() {
    fetch('/api/labels').then(function(r) { return r.json(); }).then(function(d) {
      _le_render(d.labels || {}, d.groups || {});
      document.getElementById('label-modal').style.display = 'flex';
      loadBucketIps();
    }).catch(function(err) { alert('Error: ' + err); });
  }
  function closeLabelEditor() { document.getElementById('label-modal').style.display = 'none'; }

  var _le_label_ips = {};
  function _le_render(labels, groups) {
    var allLabels = {};
    Object.keys(labels || {}).forEach(function(ip) {
      var label = labels[ip];
      if (!allLabels[label]) allLabels[label] = { ips: [], canonical: ip };
      if (allLabels[label].ips.indexOf(ip) < 0) allLabels[label].ips.push(ip);
    });
    if (groups) {
      Object.keys(groups).forEach(function(label) {
        var g = groups[label];
        if (!allLabels[label]) allLabels[label] = { ips: [], canonical: g.to_ip || '' };
        if (g.from_ips) {
          g.from_ips.forEach(function(ip) {
            if (allLabels[label].ips.indexOf(ip) < 0) allLabels[label].ips.push(ip);
          });
        }
      });
    }
    var html = '';
    Object.keys(allLabels).sort().forEach(function(label) {
      var g = allLabels[label];
      _le_label_ips[label] = g.ips;
      var count = g.ips.length;
      var ipText = count > 1 ? (count + ' IPs') : g.ips[0];
      html += '<tr><td><input type="text" value="' + _le_esc(label) + '" data-old-label="' + _le_esc(label) + '" class="label-edit-input" data-ips=' + encodeURIComponent(JSON.stringify(g.ips)) + ' style="font-size:11px;border:1px solid var(--muted);padding:2px 6px;border-radius:3px;width:100%;box-sizing:border-box"></td>' +
        '<td><span style="color:var(--muted)">' + _le_esc(ipText) + '</span>' +
        (count > 1 ? ' <button id="le-btn-' + _le_esc(label) + '" onclick="_le_toggle(\'' + _le_esc(label) + '\')" style="font-size:10px;padding:0 4px;cursor:pointer">show</button>' : '') +
        '</td><td><button onclick="_le_del_group(\'' + _le_esc(label) + '\')" style="font-size:10px;padding:2px 6px;border:1px solid var(--bad);border-radius:3px;cursor:pointer;color:var(--bad)">Delete</button></td></tr>';
      g.ips.forEach(function(ip, idx) {
        var style = count > 1 ? ' style="display:none"' : '';
        html += '<tr class="le-ips-' + _le_esc(label) + '"' + style + '><td colspan="2" style="padding-left:24px;font-size:11px">' +
          '<span>' + _le_esc(ip) + '</span>' +
          ' <button onclick="_le_del_ip(\'' + _le_esc(ip) + '\')" style="font-size:10px;padding:0 4px;border:1px solid var(--bad);border-radius:3px;cursor:pointer;color:var(--bad);margin-left:6px">x</button>' +
          '</td><td></td></tr>';
      });
    });
    document.getElementById('label-rows').innerHTML = html;
  }
  function addLabel() {
    var raw = document.getElementById('new-ip').value.trim();
    var label = document.getElementById('new-label').value.trim();
    if (!raw || !label) return;
    var ips = raw.split(/[\s,]+/).filter(function(x) { return x.length > 0; });
    ips = ips.map(function(ip) { return ip.split('/')[0]; });
    if (ips.length === 0) return;
    if (ips.length === 1) {
      saveLabel(ips[0], label);
    } else {
      fetch('/api/labels', {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ips: ips, label: label})})
        .then(function(r) { return r.json(); })
        .then(function(d) {
          if (d.ok) {
            _le_render(d.labels || {}, d.groups || {});
            if (window.__liveFetch) window.__liveFetch();
          } else {
            alert('Error: ' + JSON.stringify(d));
          }
        })
        .catch(function(err) { alert('Fetch error: ' + err); });
    }
    document.getElementById('new-ip').value = '';
    document.getElementById('new-label').value = '';
  }

  function _le_toggle(label) {
    var rows = document.querySelectorAll('.le-ips-' + label);
    if (rows.length === 0) return;
    var isHidden = rows[0].style.display === 'none';
    for (var i = 0; i < rows.length; i++) {
      rows[i].style.display = isHidden ? '' : 'none';
    }
    var btn = document.getElementById('le-btn-' + label);
    if (btn) btn.textContent = isHidden ? 'hide' : 'show';
  }
  function _le_del_ip(ip) {
    if (!confirm('Remove ' + ip + '?')) return;
    fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip: ip, label: ''})})
      .then(function(r) { return r.json(); })
      .then(function(d) { _le_render(d.labels || {}, d.groups || {}); if (window.__liveFetch) window.__liveFetch(); }).catch(function(e) { console.error('delete failed:', e); alert('Delete failed: ' + e.message); });
  }

  function _le_del_group(label) {
    if (!confirm('Delete entire group "' + label + '" and all its IPs?')) return;
    var ips = _le_label_ips[label] || [];
    if (!ips.length) {
      var input = document.querySelector('input[data-old-label="' + label + '"]');
      if (input) {
        try { ips = JSON.parse(decodeURIComponent(input.getAttribute('data-ips') || '[]')); } catch(e) { ips = []; }
      }
    }
    if (!ips.length) return;
    fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ips: ips, label: ''})})
      .then(function(r) { return r.json(); })
      .then(function(d) {
        _le_render(d.labels || {}, d.groups || {});
        if (window.__liveFetch) window.__liveFetch();
      });
  }

  function _le_save_all() {
    var btn = document.getElementById('le-save-btn');
    if (btn) { btn.textContent = 'Saving...'; btn.style.opacity = '0.6'; }
    var count = 0;
    // 0.4.127: don't rely on input.blur() to trigger the rename via the
    // document-level blur listener — that only fires if the input had
    // focus, which it often doesn't. Instead, directly invoke the
    // rename for each changed input.
    document.querySelectorAll('.label-edit-input').forEach(function(input) {
      var newLabel = input.value.trim();
      var oldLabel = input.getAttribute('data-old-label');
      if (newLabel && newLabel !== oldLabel) {
        count++;
        _le_do_rename(input, newLabel, oldLabel);
      }
    });
    if (btn) setTimeout(function() {
      btn.textContent = count > 0 ? 'Saved ' + count : 'No changes';
      btn.style.opacity = '1';
      setTimeout(function() { btn.textContent = 'Save'; }, 1500);
    }, 500);
  }
  // 0.4.127: extracted rename logic so both _le_save_all (Save button)
  // and the blur listener (per-input blur) can call it. Eliminates
  // the silent-failure mode where input.blur() was a no-op because
  // the input didn't have focus.
  // v0.9.10 fix: use async/await with Promise.all to guarantee ordering.
  // The old fire-and-forget approach could execute set-before-clear on a
  // slow server, leaving labels cleared instead of renamed.
  async function _le_do_rename(input, newLabel, oldLabel) {
    var ips;
    try { ips = JSON.parse(decodeURIComponent(input.getAttribute('data-ips') || '[]')); }
    catch (e) { ips = []; }
    if (!ips.length) return;
    try {
      // Phase 1: clear all labels (wait for ALL to complete)
      await Promise.all(ips.map(function(ip) {
        return fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ip: ip, label: ''})});
      }));
      // Phase 2: set new label on all IPs (wait for ALL to complete)
      await Promise.all(ips.map(function(ip) {
        return fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ip: ip, label: newLabel})});
      }));
      // Phase 3: refresh labels from server
      var r = await fetch('/api/labels');
      var d = await r.json();
      _le_render(d.labels || {}, d.groups || {});
      if (window.__liveFetch) window.__liveFetch();
    } catch (e) {
      console.error('rename failed:', e);
    }
  }
  function saveLabel(ip, label) {
    fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip: ip, label: label})})
      .then(function(r) { return r.json(); })
      .then(function(d) { _le_render(d.labels || {}, d.groups || {}); if (window.__liveFetch) window.__liveFetch(); });
  }

  document.addEventListener('blur', function(e) {
    if (e.target && e.target.classList && e.target.classList.contains('label-edit-input')) {
      var newLabel = e.target.value.trim();
      var oldLabel = e.target.getAttribute('data-old-label');
      if (newLabel && newLabel !== oldLabel) {
        _le_do_rename(e.target, newLabel, oldLabel);
      }
    }
  }, true);
  document.addEventListener('click', function(e) {
    if (e.target && e.target.id === 'label-modal') closeLabelEditor();
  });

  /* ---- Bucket IPs (individual IPs inside masked buckets) ---- */
  var _bucketIps = null;
  var _allLabels = [];


  function _bi_toggle(masked) {
    var el = document.getElementById('bi-' + masked);
    if (el) el.style.display = (el.style.display === 'none') ? 'block' : 'none';
  }
  function _bi_move(ip, fromBucket, target) {
    if (!target) return;
    if (target === '__new__') {
      target = prompt('New label for ' + ip + ':');
      if (!target) return;
    }
    if (!confirm('Move ' + ip + ' from ' + fromBucket + ' to ' + target + '?')) return;
    // Add the IP to the target group (writes to /etc/bpftune/aliases)
    fetch('/api/labels', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip: ip, label: target})})
      .then(function(r) { return r.json(); })
      .then(function(d) {
        // Reload everything
        loadBucketIps();
        _le_render(d.labels || {}, d.groups || {});
        if (window.__liveFetch) window.__liveFetch();
      });
  }

