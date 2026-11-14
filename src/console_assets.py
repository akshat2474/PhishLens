"""
Static stylesheet and client script for the PhishLens web console.
Calm charcoal document layout: content sits on the page, color is reserved for small marks.
"""

PAGE_CSS = """
:root {
    --bg: #181818;
    --surface: #1F1F1F;
    --raised: #272727;
    --line: #272727;
    --line-strong: #3A3A3A;
    --text: #FFFFFF;
    --muted: #D4D4D4;
    --faint: #A1A1A1;
    --risk: #E5484D;
    --safe: #30A46C;
    --warn: #E2A336;
    --sans: "Geist", ui-sans-serif, system-ui, sans-serif;
    --mono: "Geist Mono", ui-monospace, SFMono-Regular, monospace;
    --ease: cubic-bezier(0.2, 0.8, 0.2, 1);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
[hidden] { display: none !important; }
html { background: var(--bg); color-scheme: dark; }
body {
    font-family: var(--sans);
    font-size: 14px;
    line-height: 20px;
    color: var(--text);
    font-style: normal;
    -webkit-font-smoothing: antialiased;
}
button, input, select { font: inherit; color: inherit; font-style: normal; }
button { cursor: pointer; }
::selection { background: #313131; }

.page { max-width: 1440px; margin: 0 auto; padding: 0 32px 64px; }
.rule { height: 1px; background: var(--line); }

/* Navigation */
.nav { display: flex; align-items: center; justify-content: space-between; height: 64px; gap: 16px; }
.brand { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 14px; }
.nav-tabs { display: flex; gap: 4px; }
.nav-tab {
    background: none; border: 0; padding: 8px 12px; border-radius: 6px;
    color: var(--muted); transition: color 150ms, background-color 150ms;
}
.nav-tab:hover { color: var(--text); }
.nav-tab.active { color: var(--text); background: var(--surface); }
.nav-meta { font-size: 12px; line-height: 16px; color: var(--faint); font-family: var(--mono); }

/* Panels */
.panel { display: none; }
.panel.active { display: block; animation: rise 320ms var(--ease) both; }
.intro { padding: 32px 0 24px; }
.intro h1 {
    font-size: 30px; line-height: 36px; font-weight: 600; letter-spacing: -0.02em;
    max-width: 680px; text-wrap: balance;
    color: #FFFFFF;
}
.intro p { margin-top: 8px; max-width: 680px; font-size: 16px; line-height: 24px; color: var(--text); text-wrap: pretty; }

/* Query bar */
.query { display: flex; flex-direction: column; gap: 12px; }
.seg {
    display: inline-flex; gap: 2px; padding: 2px; width: max-content;
    background: var(--surface); border: 1px solid var(--line); border-radius: 8px;
}
.seg-btn {
    background: none; border: 0; padding: 4px 12px; border-radius: 6px; white-space: nowrap;
    color: var(--muted); transition: color 150ms, background-color 150ms;
}
.seg-btn:hover { color: var(--text); }
.seg-btn.active { background: var(--raised); color: var(--text); }
.bar {
    display: flex; align-items: center; gap: 4px; padding: 4px;
    background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
    transition: border-color 150ms;
}
.bar:focus-within { border-color: var(--line-strong); }
.bar-field {
    flex: 1; min-width: 0; padding: 8px 12px; background: none; border: 0; outline: none;
    font-family: var(--mono); font-size: 14px; color: var(--text);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.bar-field::placeholder { color: var(--faint); }
.counter { padding: 0 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); white-space: nowrap; }
.btn {
    display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; border-radius: 8px;
    border: 1px solid transparent; background: none; color: var(--muted); white-space: nowrap;
    transition: color 150ms, background-color 150ms, border-color 150ms;
}
.btn:hover { color: var(--text); background: var(--raised); }
.btn-primary { background: #FFFFFF; color: #181818; font-weight: 500; }
.btn-primary:hover { background: #FFFFFF; color: #000000; }
.btn-icon { padding: 8px; }
.presets { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.presets-label { font-size: 12px; line-height: 16px; color: var(--faint); margin-right: 4px; }
.preset {
    padding: 4px 12px; border-radius: 9999px; border: 1px solid var(--line); background: none;
    font-size: 12px; line-height: 16px; color: var(--muted); transition: color 150ms, border-color 150ms;
}
.preset:hover { color: var(--text); border-color: var(--line-strong); }

/* Results */
#inspect-results { transition: opacity 200ms; }
#inspect-results.loading { opacity: 0.5; }
.results { margin-top: 32px; animation: rise 360ms var(--ease) both; }
.verdict { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 32px; align-items: end; }
.tag { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-weight: 500; }
.tag-note { color: var(--muted); font-weight: 400; }
.dot { width: 8px; height: 8px; border-radius: 9999px; flex: none; }
.url {
    margin-top: 12px; font-family: var(--mono); font-size: 18px; line-height: 28px;
    color: var(--text); word-break: break-all;
}
.url-risk { text-decoration: underline; text-decoration-color: var(--risk); text-decoration-thickness: 2px; text-underline-offset: 6px; }
.url-hint { margin-top: 12px; font-size: 12px; line-height: 16px; color: var(--faint); }
.score { text-align: right; }
.score-num { font-size: 48px; line-height: 1; font-weight: 600; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
.score-cap { margin-top: 8px; font-size: 12px; line-height: 16px; color: var(--faint); }
.gauge { position: relative; height: 4px; margin-top: 32px; border-radius: 9999px; background: var(--raised); }
.gauge-fill { position: absolute; top: 0; bottom: 0; left: 0; border-radius: 9999px; transform-origin: left center; animation: grow 700ms var(--ease) both; }
.gauge-mid { position: absolute; left: 50%; transform: translateX(-50%); }
.gauge-tick { position: absolute; left: 50%; top: -4px; width: 1px; height: 12px; background: var(--faint); }
.gauge-scale { position: relative; display: flex; justify-content: space-between; margin-top: 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }

.models { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 32px; padding: 32px 0; }
.model-name { font-size: 12px; line-height: 16px; color: var(--faint); }
.model-val { margin-top: 4px; font-size: 16px; line-height: 24px; font-weight: 500; font-variant-numeric: tabular-nums; }
.model-track { height: 2px; margin-top: 8px; border-radius: 9999px; background: var(--raised); overflow: hidden; }
.model-fill { height: 2px; border-radius: 9999px; transform-origin: left center; animation: grow 700ms var(--ease) both; }

.section { padding: 32px 0 0; }
.section-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
.section-title { font-size: 16px; line-height: 24px; font-weight: 600; }
.section-sub { margin-top: 4px; color: var(--muted); max-width: 680px; text-wrap: pretty; }

/* Drivers */
.drivers { --cols: minmax(0, 1.5fr) minmax(0, 1fr) 72px; }
.drivers.live { --cols: minmax(0, 1.5fr) 112px minmax(0, 1fr) 72px; }
.axis, .driver { display: grid; grid-template-columns: var(--cols); gap: 24px; align-items: center; }
.axis { padding: 0 0 8px; font-size: 12px; line-height: 16px; color: var(--faint); }
.axis-labels { display: flex; justify-content: space-between; }
.axis-spacer { min-width: 0; }
.driver { padding: 12px; margin: 0 -12px; border-radius: 8px; transition: background-color 150ms; }
.driver:hover { background: var(--surface); }
.driver-extra { display: none; }
.show-all .driver-extra { display: grid; animation: rise 240ms var(--ease) both; }
.driver-name { display: flex; align-items: baseline; gap: 8px; font-weight: 500; }
.driver-key { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); font-weight: 400; }
.driver-text {
    margin-top: 2px; color: var(--muted); text-wrap: pretty;
    display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;
}
.driver:hover .driver-text { -webkit-line-clamp: 3; }
.track { position: relative; height: 16px; }
.track::before { content: ""; position: absolute; left: 50%; top: 0; width: 1px; height: 16px; background: var(--line-strong); }
.fill { position: absolute; top: 5px; height: 6px; border-radius: 9999px; animation: grow 600ms var(--ease) both; }
.fill-up { left: 50%; background: var(--risk); transform-origin: left center; }
.fill-down { right: 50%; background: var(--safe); transform-origin: right center; }
.driver-val { font-family: var(--mono); text-align: right; color: var(--muted); }

.pick {
    display: inline-flex; gap: 2px; padding: 2px;
    background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
}
.pick-btn {
    background: none; border: 0; min-width: 32px; padding: 2px 8px; border-radius: 4px;
    font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint);
    transition: color 150ms, background-color 150ms;
}
.pick-btn:hover { color: var(--text); }
.pick-btn.on { background: var(--raised); color: var(--text); }

/* Fixes */
.fix { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: baseline; padding: 12px; margin: 0 -12px; border-radius: 8px; transition: background-color 150ms; }
.fix:hover { background: var(--surface); }
.fix-text { color: var(--muted); margin-top: 2px; text-wrap: pretty; }
.fix-gain { font-family: var(--mono); color: var(--safe); white-space: nowrap; }

/* Evaluation */
.stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 32px; }
.stat-label { font-size: 12px; line-height: 16px; color: var(--faint); }
.stat-val { margin-top: 4px; font-size: 24px; line-height: 32px; font-weight: 600; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.table-wrap { overflow-x: auto; }
.table { width: 100%; border-collapse: collapse; }
.table th { padding: 8px 12px; font-size: 12px; line-height: 16px; font-weight: 400; color: var(--faint); text-align: right; white-space: nowrap; }
.table td { padding: 12px; font-family: var(--mono); text-align: right; white-space: nowrap; }
.table th:first-child, .table td:first-child { text-align: left; font-family: var(--sans); }
.table td:first-child { font-weight: 500; }
.table tbody tr:nth-child(odd) td { background: var(--surface); }
.table tbody tr td:first-child { border-radius: 8px 0 0 8px; }
.table tbody tr td:last-child { border-radius: 0 8px 8px 0; }
.table .sub { display: block; font-size: 12px; line-height: 16px; color: var(--faint); font-weight: 400; }
.card { background: var(--surface); border: 1px solid var(--line); border-radius: 12px; padding: 24px; }
.card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; margin-bottom: 16px; }
.card-title { font-weight: 500; }
.card-meta { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }
.split { display: grid; grid-template-columns: minmax(0, 1.25fr) minmax(0, 1fr); gap: 16px; margin-top: 16px; }
.slider-row { display: flex; align-items: center; gap: 16px; }
.slider-val { font-size: 24px; line-height: 32px; font-weight: 600; font-variant-numeric: tabular-nums; min-width: 64px; text-align: right; }
.range { flex: 1; appearance: none; -webkit-appearance: none; height: 4px; border-radius: 9999px; background: var(--raised); outline: none; }
.range::-webkit-slider-thumb { -webkit-appearance: none; width: 16px; height: 16px; border-radius: 9999px; background: #FFFFFF; transition: transform 150ms; }
.range::-webkit-slider-thumb:hover { transform: scale(1.15); }
.range::-moz-range-thumb { width: 16px; height: 16px; border: 0; border-radius: 9999px; background: #FFFFFF; }
.thresh-stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 24px; margin-top: 24px; }
.roc { display: block; width: 100%; height: auto; }
.roc-dot { transition: cx 200ms var(--ease), cy 200ms var(--ease); }
.legend { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 12px; font-size: 12px; line-height: 16px; color: var(--faint); }
.legend-item { display: inline-flex; align-items: center; gap: 8px; }
.legend-line { width: 16px; height: 2px; border-radius: 9999px; }
.cm { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.cm-cell { display: flex; flex-direction: column; gap: 8px; padding: 16px; border-radius: 8px; background: var(--raised); }
.cm-label { display: flex; align-items: center; gap: 8px; font-size: 12px; line-height: 16px; color: var(--muted); }
.cm-count { font-size: 24px; line-height: 32px; font-weight: 600; font-variant-numeric: tabular-nums; }
.cm-pct { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }
.cm-track { height: 2px; border-radius: 9999px; background: var(--bg); overflow: hidden; }
.cm-fill { height: 2px; border-radius: 9999px; transition: width 300ms var(--ease); }
.imp { display: grid; grid-template-columns: 200px minmax(0, 1fr) 56px; gap: 16px; align-items: center; padding: 8px 0; }
.imp-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.imp-track { height: 6px; border-radius: 9999px; background: var(--raised); overflow: hidden; }
.imp-fill { height: 6px; border-radius: 9999px; transform-origin: left center; animation: grow 700ms var(--ease) both; }
.imp-val { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--muted); text-align: right; }

/* Catalog */
.filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.field {
    padding: 8px 12px; border-radius: 8px; border: 1px solid var(--line); background: var(--surface);
    outline: none; transition: border-color 150ms;
}
.field:focus { border-color: var(--line-strong); }
.field-grow { flex: 1; min-width: 220px; }
.field::placeholder { color: var(--faint); }
.match { margin-left: auto; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }
.cat-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; margin-top: 24px; }
.cat {
    display: flex; flex-direction: column; gap: 12px; padding: 24px;
    background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
    transition: border-color 150ms;
}
.cat:hover { border-color: var(--line-strong); }
.cat-head { display: flex; justify-content: space-between; align-items: baseline; gap: 16px; }
.cat-name { font-weight: 500; }
.cat-key { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }
.cat-group { font-size: 12px; line-height: 16px; color: var(--faint); white-space: nowrap; }
.cat-desc { color: var(--muted); text-wrap: pretty; }
.cat-rule { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); text-wrap: pretty; }
.prev { margin-top: auto; }
.prev-track { display: flex; gap: 2px; height: 4px; border-radius: 9999px; overflow: hidden; }
.prev-legend { display: flex; justify-content: space-between; margin-top: 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }

.footer { margin-top: 96px; font-size: 12px; line-height: 16px; color: var(--faint); }

@keyframes rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation: none !important; transition: none !important; }
}
@media (max-width: 1100px) {
    .cat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
    .page { padding: 0 16px 48px; }
    .nav-meta { display: none; }
    .verdict { grid-template-columns: 1fr; gap: 24px; }
    .score { text-align: left; }
    .models, .stats, .thresh-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 24px; }
    .split, .cat-grid { grid-template-columns: 1fr; }
    .drivers { --cols: minmax(0, 1fr) 64px; }
    .drivers.live { --cols: minmax(0, 1fr) auto 64px; }
    .counter, .driver-key { display: none; }
    .nav-tab { padding: 8px; }
    .drivers .track, .axis { display: none; }
    .imp { grid-template-columns: 120px minmax(0, 1fr) 48px; }
}
"""

CONSOLE_JS = """
const $ = (id) => document.getElementById(id);
window.__overrides = {};

function tween(el, target, decimals, suffix) {
    const start = parseFloat(el.dataset.val);
    el.dataset.val = String(target);
    if (Number.isNaN(start) || Math.abs(target - start) < 0.05) {
        el.textContent = target.toFixed(decimals) + suffix;
        return;
    }
    const t0 = performance.now();
    function step(now) {
        const p = Math.min(1, (now - t0) / 420);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = (start + (target - start) * eased).toFixed(decimals) + suffix;
        if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function switchTab(name) {
    document.querySelectorAll('.nav-tab').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + name));
    if (name === 'eval') drawEvalCharts();
}

function totalRecords() {
    return window.__evalData ? window.__evalData.y_true.length : 1659;
}

function syncControls(data) {
    if (data.mode === 'uci') {
        $('uci-url-text').textContent = data.url;
        $('uci-idx-input').value = String(data.idx);
        $('uci-record-counter').textContent = (data.idx + 1).toLocaleString() + ' / ' + totalRecords().toLocaleString();
        return;
    }
    $('reset-overrides-btn').hidden = !data.has_overrides;
}

async function loadDiagnosis(params) {
    const box = $('inspect-results');
    const prevEl = $('verdict-score-num');
    const prev = prevEl ? prevEl.dataset.val : null;
    const showAll = !!document.querySelector('.drivers.show-all');
    box.classList.add('loading');
    try {
        const res = await fetch('/api/diagnose?' + new URLSearchParams(params).toString());
        if (!res.ok) return;
        const data = await res.json();
        box.innerHTML = data.html;
        syncControls(data);
        if (showAll) toggleDrivers(true);
        const el = $('verdict-score-num');
        if (el && prev !== null) { el.dataset.val = prev; tween(el, data.risk_pct, 1, '%'); }
    } finally {
        box.classList.remove('loading');
    }
}

function setInspectMode(mode) {
    $('mode-btn-uci').classList.toggle('active', mode === 'uci');
    $('mode-btn-live').classList.toggle('active', mode === 'live');
    $('controls-uci').hidden = mode !== 'uci';
    $('controls-live').hidden = mode !== 'live';
    window.__overrides = {};
    if (mode === 'uci') loadDiagnosis({ mode: 'uci', idx: $('uci-idx-input').value || '835' });
    else loadDiagnosis({ mode: 'live', url: $('live-url-input').value.trim() });
}

function liveUrl() { return $('live-url-input').value.trim(); }

function scanPreset(url) {
    window.__overrides = {};
    $('live-url-input').value = url;
    loadDiagnosis({ mode: 'live', url });
}

function submitLiveScan(ev) {
    ev.preventDefault();
    window.__overrides = {};
    if (liveUrl()) loadDiagnosis({ mode: 'live', url: liveUrl() });
}

function setFeatureOverride(idx, val) {
    window.__overrides['f_' + idx] = val;
    loadDiagnosis(Object.assign({ mode: 'live', url: liveUrl() }, window.__overrides));
}

function resetLiveOverrides() {
    window.__overrides = {};
    loadDiagnosis({ mode: 'live', url: liveUrl() });
}

function pickRandomUci() {
    loadDiagnosis({ mode: 'uci', idx: Math.floor(Math.random() * totalRecords()) });
}

function stepUci(delta) {
    const total = totalRecords();
    const cur = parseInt($('uci-idx-input').value || '835', 10);
    loadDiagnosis({ mode: 'uci', idx: (cur + delta + total) % total });
}

function toggleDrivers(showAll) {
    const wrap = document.querySelector('.drivers');
    if (!wrap) return;
    wrap.classList.toggle('show-all', showAll);
    const top = $('drivers-top-btn'), all = $('drivers-all-btn');
    if (top) top.classList.toggle('active', !showAll);
    if (all) all.classList.toggle('active', showAll);
}

function thresholdStats(thresh) {
    const yt = window.__evalData.y_true, yp = window.__evalData.y_probs;
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (let i = 0; i < yt.length; i++) {
        const pred = yp[i] >= thresh ? 1 : 0;
        if (yt[i] === 1 && pred === 1) tp++;
        else if (yt[i] === 0 && pred === 1) fp++;
        else if (yt[i] === 0) tn++;
        else fn++;
    }
    const precision = tp / Math.max(1, tp + fp);
    const recall = tp / Math.max(1, tp + fn);
    const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
    return { precision, recall, f1, tp, fp, tn, fn, fpr: fp / Math.max(1, tn + fp), total: yt.length };
}

function drawEvalCharts() {
    if (!window.__evalData || !$('threshold-slider')) return;
    const t = parseFloat($('threshold-slider').value);
    const s = thresholdStats(t);
    $('thresh-readout').textContent = t.toFixed(2);
    $('kpi-prec-val').textContent = (s.precision * 100).toFixed(1) + '%';
    $('kpi-rec-val').textContent = (s.recall * 100).toFixed(1) + '%';
    $('kpi-f1-val').textContent = s.f1.toFixed(3);
    $('kpi-fpfn-val').textContent = s.fp + ' / ' + s.fn;
    const cx = (56 + s.fpr * 440).toFixed(1), cy = (256 - s.recall * 236).toFixed(1);
    $('roc-active-dot').setAttribute('cx', cx);
    $('roc-active-dot').setAttribute('cy', cy);
    $('roc-coords-label').textContent = 'FPR ' + (s.fpr * 100).toFixed(1) + '%  TPR ' + (s.recall * 100).toFixed(1) + '%';
    [['tn', s.tn], ['fp', s.fp], ['fn', s.fn], ['tp', s.tp]].forEach(([k, v]) => {
        const pct = (v * 100 / Math.max(1, s.total)).toFixed(1);
        $('cm-' + k + '-cnt').textContent = v.toLocaleString();
        $('cm-' + k + '-pct').textContent = pct + '% of test set';
        $('cm-' + k + '-bar').style.width = pct + '%';
    });
}

function filterCatalog() {
    const q = ($('cat-search-input').value || '').toLowerCase().trim();
    const domain = $('cat-domain-select').value;
    const mode = $('cat-mode-select').value;
    let visible = 0, total = 0;
    document.querySelectorAll('.cat').forEach(card => {
        total++;
        const show = (domain === 'All domains' || card.dataset.domain === domain)
            && (mode === 'All features' || card.dataset.mode === mode)
            && (!q || (card.dataset.search || '').includes(q));
        card.hidden = !show;
        if (show) visible++;
    });
    $('cat-match-count').textContent = visible + ' of ' + total;
}
"""
