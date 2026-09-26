import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "output")
os.makedirs(OUT_DIR, exist_ok=True)

alerts = json.load(open(os.path.join(DATA_DIR, "alerts.json")))
metrics = json.load(open(os.path.join(DATA_DIR, "metrics.json")))
gts = json.load(open(os.path.join(DATA_DIR, "ground_truth.json")))

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Signal Deck — Mini SIEM Console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0e1116; --panel:#141821; --panel-2:#181d28; --line:#262c3a;
  --ink:#e7ebf3; --ink-dim:#8891a4; --ink-faint:#5b6377;
  --accent:#5b8cff; --accent-dim:#2c3f6e;
  --crit:#ff5470; --high:#ff9f43; --med:#e8c547; --low:#4fd1c5;
  font-family:'IBM Plex Sans',sans-serif;
  box-sizing:border-box;
  padding-top:env(safe-area-inset-top,0px);
  padding-bottom:env(safe-area-inset-bottom,0px);
}
@media (prefers-color-scheme:light){
  :root:not([data-theme="dark"]){
    --bg:#f4f5f8; --panel:#ffffff; --panel-2:#eef0f5; --line:#dde1ea;
    --ink:#161a24; --ink-dim:#565f74; --ink-faint:#8891a4;
    --accent-dim:#dde6ff;
  }
}
*{box-sizing:border-box;}
html{scroll-padding-top:env(safe-area-inset-top,0px);}
body{margin:0;background:var(--bg);color:var(--ink);min-height:100%;}
code,.mono{font-family:'IBM Plex Mono',monospace;}

header{
  position:sticky;top:0;z-index:5;
  padding:18px 28px calc(18px);
  padding-top:calc(18px + env(safe-area-inset-top,0px));
  background:linear-gradient(180deg,var(--bg) 70%,rgba(14,17,22,0));
  border-bottom:1px solid var(--line);
  display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px 24px;
}
header h1{font-size:20px;margin:0;font-weight:600;letter-spacing:-0.01em;}
header .sub{color:var(--ink-dim);font-size:13px;font-family:'IBM Plex Mono',monospace;}

main{max-width:1180px;margin:0 auto;padding:24px 28px 64px;}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;
  background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:28px;}
.stat{background:var(--panel);padding:16px 18px;}
.stat .n{font-family:'IBM Plex Mono',monospace;font-size:26px;font-weight:600;line-height:1;}
.stat .l{color:var(--ink-dim);font-size:12.5px;margin-top:6px;}
.stat.accent .n{color:var(--accent);}
.stat.crit .n{color:var(--crit);}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:24px;}
.panel h2{font-size:14px;font-weight:600;margin:0;padding:14px 18px;border-bottom:1px solid var(--line);color:var(--ink);}
.panel h2 span{color:var(--ink-faint);font-weight:400;font-family:'IBM Plex Mono',monospace;font-size:12px;margin-left:8px;}

table.score{width:100%;border-collapse:collapse;font-size:13px;}
table.score th{text-align:left;color:var(--ink-dim);font-weight:500;padding:8px 18px;font-size:12px;border-bottom:1px solid var(--line);}
table.score td{padding:8px 18px;border-bottom:1px solid var(--line);font-family:'IBM Plex Mono',monospace;}
table.score tr:last-child td{border-bottom:none;}
table.score td.fp{color:var(--crit);}
table.score td.fp.zero{color:var(--ink-faint);}

.filters{display:flex;gap:8px;padding:12px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap;align-items:center;}
.filters select, .filters input{
  background:var(--panel-2);color:var(--ink);border:1px solid var(--line);border-radius:6px;
  padding:7px 10px;font-family:'IBM Plex Sans',sans-serif;font-size:13px;
}
.filters input{flex:1;min-width:160px;}
.filters .count{color:var(--ink-faint);font-size:12.5px;margin-left:auto;font-family:'IBM Plex Mono',monospace;}

.alert-row{border-bottom:1px solid var(--line);padding:14px 18px;cursor:pointer;display:grid;
  grid-template-columns:86px 150px 1fr auto;gap:14px;align-items:start;}
.alert-row:hover{background:var(--panel-2);}
.alert-row:last-child{border-bottom:none;}
.sev{font-size:11px;font-weight:600;padding:3px 8px;border-radius:4px;white-space:nowrap;height:fit-content;
  font-family:'IBM Plex Mono',monospace;letter-spacing:0.02em;}
.sev.Critical{background:rgba(255,84,112,.15);color:var(--crit);}
.sev.High{background:rgba(255,159,67,.15);color:var(--high);}
.sev.Medium{background:rgba(232,197,71,.15);color:var(--med);}
.sev.Low{background:rgba(79,209,197,.15);color:var(--low);}
.meta{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--ink-dim);line-height:1.6;}
.meta b{color:var(--ink);font-weight:500;}
.body-col .type{font-weight:600;font-size:14px;margin-bottom:3px;}
.body-col .evidence{color:var(--ink-dim);font-size:13px;line-height:1.5;}
.mitre{font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--accent);white-space:nowrap;
  background:var(--accent-dim);padding:3px 8px;border-radius:4px;height:fit-content;}
.detail{display:none;grid-column:1/-1;background:var(--panel-2);border-radius:8px;padding:12px 14px;margin-top:4px;font-size:13px;}
.detail.open{display:block;}
.detail .row{margin-bottom:8px;}
.detail .row:last-child{margin-bottom:0;}
.detail .k{color:var(--ink-faint);font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:2px;}

footer{color:var(--ink-faint);font-size:12px;text-align:center;padding:20px;font-family:'IBM Plex Mono',monospace;}
</style>
</head>
<body>
<header>
  <h1>Signal Deck</h1>
  <div class="sub">mini SIEM · __LOOKBACK__ · 3 collectors → 8 detectors</div>
</header>
<main>

  <div class="stats">
    <div class="stat accent"><div class="n">__TOTAL_ALERTS__</div><div class="l">alerts fired</div></div>
    <div class="stat crit"><div class="n">__CRIT_COUNT__</div><div class="l">critical</div></div>
    <div class="stat"><div class="n">__DETECTED__/__TOTAL_CAMPAIGNS__</div><div class="l">campaigns detected</div></div>
    <div class="stat"><div class="n">__PRECISION__</div><div class="l">precision (TP/alerts)</div></div>
    <div class="stat"><div class="n">__RECALL__</div><div class="l">recall (campaigns)</div></div>
    <div class="stat"><div class="n">__F1__</div><div class="l">F1 score</div></div>
  </div>

  <div class="panel">
    <h2>Detection scorecard <span>synthetic red-team campaigns vs. detector output</span></h2>
    <table class="score">
      <tr><th>Attack type</th><th>Campaigns</th><th>Detected</th><th>Alerts fired</th><th>False positives</th></tr>
      __SCORE_ROWS__
    </table>
  </div>

  <div class="panel">
    <h2>Alerts <span id="alertCount"></span></h2>
    <div class="filters">
      <select id="fSev"><option value="">All severities</option></select>
      <select id="fType"><option value="">All attack types</option></select>
      <input id="fSearch" placeholder="Search IP, host, evidence…">
    </div>
    <div id="alertList"></div>
  </div>

  <footer>Generated locally from synthetic logs · no real hosts, users, or IPs · click a row for evidence + response</footer>
</main>

<script>
const ALERTS = __ALERTS_JSON__;
const SEV_ORDER = {Critical:0, High:1, Medium:2, Low:3};

function el(tag, cls, html){ const e=document.createElement(tag); if(cls) e.className=cls; if(html!=null) e.innerHTML=html; return e; }

function populateFilters(){
  const sevs = [...new Set(ALERTS.map(a=>a.severity))].sort((a,b)=>SEV_ORDER[a]-SEV_ORDER[b]);
  const types = [...new Set(ALERTS.map(a=>a.attack_type))].sort();
  const fSev = document.getElementById('fSev'), fType = document.getElementById('fType');
  sevs.forEach(s=>fSev.appendChild(el('option','',s)).value=s);
  types.forEach(t=>fType.appendChild(el('option','',t.replace(/_/g,' '))).value=t);
}

function render(){
  const sev = document.getElementById('fSev').value;
  const type = document.getElementById('fType').value;
  const q = document.getElementById('fSearch').value.toLowerCase();
  const list = document.getElementById('alertList');
  list.innerHTML = '';
  const filtered = ALERTS.filter(a=>{
    if(sev && a.severity!==sev) return false;
    if(type && a.attack_type!==type) return false;
    if(q && !(a.evidence+a.src_ip+a.target_host).toLowerCase().includes(q)) return false;
    return true;
  }).sort((a,b)=> SEV_ORDER[a.severity]-SEV_ORDER[b.severity] || (a.ts<b.ts?1:-1));
  document.getElementById('alertCount').textContent = `${filtered.length} of ${ALERTS.length}`;

  filtered.forEach(a=>{
    const row = el('div','alert-row');
    row.appendChild(el('div', 'sev '+a.severity, a.severity));
    row.appendChild(el('div','meta', `${a.ts.replace(' ','<br>')}`));
    row.appendChild(el('div','body-col', `<div class="type">${a.attack_type.replace(/_/g,' ')}</div><div class="evidence">${a.src_ip} → ${a.target_host}</div>`));
    row.appendChild(el('div','mitre', a.mitre_technique));
    const detail = el('div','detail', `
      <div class="row"><div class="k">Evidence</div>${a.evidence}</div>
      <div class="row"><div class="k">MITRE ATT&amp;CK</div>${a.mitre_technique} — ${a.mitre_tactic}</div>
      <div class="row"><div class="k">Recommended response</div>${a.recommended_response}</div>
      <div class="row"><div class="k">Detector / confidence</div>${a.detector} · ${(a.confidence*100).toFixed(0)}%</div>
    `);
    row.addEventListener('click', ()=> detail.classList.toggle('open'));
    const wrap = el('div');
    wrap.appendChild(row);
    wrap.appendChild(detail);
    list.appendChild(wrap);
  });
}

populateFilters();
render();
['fSev','fType'].forEach(id=>document.getElementById(id).addEventListener('change', render));
document.getElementById('fSearch').addEventListener('input', render);
</script>
</body>
</html>
"""

sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
crit_count = sum(1 for a in alerts if a["severity"] == "Critical")

by_type = metrics["by_type"]
fp_by_type = metrics["false_positives_by_type"]
score_rows = ""
for atype in sorted(by_type):
    s = by_type[atype]
    fp = fp_by_type.get(atype, 0)
    fp_cls = "fp" if fp else "fp zero"
    score_rows += (f"<tr><td style='font-family:\"IBM Plex Sans\"'>{atype.replace('_',' ')}</td>"
                   f"<td>{s['campaigns']}</td><td>{s['detected']}/{s['campaigns']}</td>"
                   f"<td>{s['alerts']}</td><td class='{fp_cls}'>{fp}</td></tr>")

html = (HTML
        .replace("__TOTAL_ALERTS__", str(metrics["total_alerts"]))
        .replace("__CRIT_COUNT__", str(crit_count))
        .replace("__DETECTED__", str(metrics["detected_campaigns"]))
        .replace("__TOTAL_CAMPAIGNS__", str(metrics["total_campaigns"]))
        .replace("__PRECISION__", f"{metrics['precision']:.2f}")
        .replace("__RECALL__", f"{metrics['recall']:.2f}")
        .replace("__F1__", f"{metrics['f1']:.2f}")
        .replace("__SCORE_ROWS__", score_rows)
        .replace("__LOOKBACK__", "Sep 22–24, 2026")
        .replace("__ALERTS_JSON__", json.dumps(alerts)))

out_path = os.path.join(OUT_DIR, "dashboard.html")
with open(out_path, "w") as f:
    f.write(html)
print("wrote", out_path, len(html), "bytes")
