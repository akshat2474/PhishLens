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

/* Results & 4-Stage Telemetry */
#inspect-results { transition: opacity 200ms; }
#inspect-results.loading { opacity: 0.5; }
.results { margin-top: 32px; animation: rise 360ms var(--ease) both; }
.verdict { display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(0, 1fr); gap: 32px; align-items: end; }
.verdict-right { display: flex; align-items: flex-end; justify-content: flex-end; gap: 24px; }
.tag { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-size: 16px; line-height: 24px; font-weight: 600; }
.tag-note { font-size: 12px; line-height: 16px; color: var(--muted); font-weight: 400; }
.dot { width: 8px; height: 8px; border-radius: 9999px; flex: none; transition: background-color 240ms; }
.url {
    margin-top: 12px; font-family: var(--mono); font-size: 18px; line-height: 28px;
    color: var(--text); word-break: break-all;
}
.url-seg { transition: text-decoration-color 240ms; }
.url-risk { text-decoration: underline; text-decoration-color: var(--risk); text-decoration-thickness: 2px; text-underline-offset: 6px; }
.url-risk.healed { text-decoration-color: transparent; }
.morph-token {
    display: inline-block; max-width: 320px; overflow: hidden; vertical-align: bottom;
    transition: max-width 320ms cubic-bezier(0.22, 1, 0.36, 1), opacity 240ms ease, background-color 200ms ease, color 200ms ease;
    border-radius: 2px;
}
.morph-token.erased { max-width: 0px !important; opacity: 0 !important; }
.morph-token.preview-erase { background: #313131; color: #E57373; }
.url-hint { margin-top: 12px; font-size: 12px; line-height: 16px; color: var(--faint); }
.score { text-align: right; flex: none; }
.score-num { font-size: 48px; line-height: 1; font-weight: 600; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; }
.score-cap { margin-top: 8px; font-size: 12px; line-height: 16px; color: var(--faint); }

/* Stage 2: 576-Node (64x9) Matrix Collapse */
.matrix-box {
    flex: 1; min-width: 280px; max-width: 440px; padding: 12px;
    background: var(--surface); border: 1px solid var(--line); border-radius: 12px;
}
.matrix-head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
.matrix-title { font-size: 12px; line-height: 16px; color: var(--muted); font-weight: 500; }
.matrix-meta { font-family: var(--mono); font-size: 12px; line-height: 16px; color: #FFFFFF; }
.matrix-svg { display: block; width: 100%; height: auto; background: #181818; border: 1px solid var(--line); border-radius: 8px; }
.m-dot { fill: #272727; transition: fill 260ms ease, opacity 260ms ease; }
.m-dot.sieve-lit { fill: #7A7A7A; }
.m-dot.collapsed { fill: #1F1F1F; opacity: 0.45; }
.m-dot.active { fill: #FFFFFF !important; opacity: 1 !important; }
.matrix-route-path {
    stroke: #FFFFFF; stroke-width: 1; stroke-dasharray: 520; stroke-dashoffset: 0;
    transition: d 320ms var(--ease); animation: drawRoute 420ms var(--ease) both;
}
.matrix-ghost-path { stroke: var(--safe); stroke-width: 1; stroke-dasharray: 3 3; }

/* Gauge & Mechanical Needle */
.gauge { position: relative; height: 4px; margin-top: 24px; border-radius: 9999px; background: var(--raised); }
.gauge-fill {
    position: absolute; top: 0; bottom: 0; left: 0; border-radius: 9999px;
    transform-origin: left center; transition: width 360ms cubic-bezier(0.22, 1, 0.36, 1), background-color 280ms ease;
}
.gauge-needle {
    position: absolute; top: -6px; width: 2px; height: 16px; background: #FFFFFF; border-radius: 2px;
    transform: translateX(-50%); transition: left 360ms cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.gauge-ghost {
    position: absolute; top: -6px; width: 2px; height: 16px; background: var(--safe); border-radius: 2px;
    transform: translateX(-50%); pointer-events: none;
}
.gauge-mid { position: absolute; left: 50%; transform: translateX(-50%); }
.gauge-tick { position: absolute; left: 50%; top: -4px; width: 1px; height: 12px; background: var(--faint); }
.gauge-scale { position: relative; display: flex; justify-content: space-between; margin-top: 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }

/* Stage 1: The Lexical Shredder & Span Calipers */
.shredder {
    margin-top: 24px; padding: 16px; background: var(--surface);
    border: 1px solid var(--line); border-radius: 12px;
}
.shredder-top { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
.shredder-title { display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
.shredder-sub { font-size: 12px; line-height: 16px; font-weight: 400; color: var(--faint); }
.shred-rail {
    position: relative; display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
    gap: 8px; overflow: hidden; padding: 2px 0;
}
.scan-laser {
    position: absolute; top: 0; bottom: 0; left: 0; width: 1px; background: #FFFFFF;
    pointer-events: none; opacity: 0; z-index: 4;
}
.scan-laser.sweeping { animation: laserSweep 300ms linear forwards; }
.shred-block {
    padding: 8px 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
    transition: border-color 180ms ease, transform 180ms cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.shred-block.risk-lock { border-color: #E57373; }
.shred-block.healed { border-color: var(--line) !important; }
.shred-Head { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; }
.shred-lbl { font-size: 12px; line-height: 16px; color: var(--faint); }
.shred-delta { font-family: var(--mono); font-size: 12px; line-height: 16px; font-weight: 600; }
.shred-val {
    margin-top: 4px; font-family: var(--mono); font-size: 14px; line-height: 20px; color: #FFFFFF;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.shred-feat { margin-top: 4px; font-size: 12px; line-height: 16px; color: var(--muted); }
.caliper-row {
    display: flex; align-items: center; gap: 12px; margin-top: 12px;
    font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint);
}
.caliper-lbl { white-space: nowrap; }
.caliper-lbl strong { color: #FFFFFF; font-weight: 600; }
.caliper-bar { position: relative; flex: 1; height: 4px; background: var(--raised); border-radius: 9999px; overflow: hidden; }
.caliper-fill { height: 4px; background: #FFFFFF; border-radius: 9999px; transition: width 300ms var(--ease); }
.caliper-tick { position: absolute; top: 0; bottom: 0; width: 1px; background: #E57373; }
.vec-grid { display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)); gap: 8px; margin-top: 12px; }
.vec-slot {
    display: flex; flex-direction: column; align-items: center; gap: 4px; padding: 8px;
    background: var(--bg); border: 1px solid var(--line); border-radius: 8px;
    transition: border-color 180ms ease, transform 200ms cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.vec-slot.risk-lock { border-color: #E57373; }
.vec-slot.snap-pop { transform: scale(1.04); }
.vec-lbl { font-size: 12px; line-height: 16px; color: var(--faint); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }
.vec-digit { font-family: var(--mono); font-size: 18px; line-height: 28px; font-weight: 600; color: #FFFFFF; font-variant-numeric: tabular-nums; }
.vec-slot.risk-lock .vec-digit { color: #E57373; }
.vec-cal { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--muted); white-space: nowrap; }

.models { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 32px; padding: 32px 0; }
.model-name { font-size: 12px; line-height: 16px; color: var(--faint); }
.model-val { margin-top: 4px; font-size: 18px; line-height: 28px; font-weight: 600; font-variant-numeric: tabular-nums; color: #FFFFFF; }
.model-track { height: 2px; margin-top: 8px; border-radius: 9999px; background: var(--raised); overflow: hidden; }
.model-fill { height: 2px; border-radius: 9999px; transform-origin: left center; transition: width 360ms var(--ease), background-color 240ms ease; }

.section { padding: 32px 0 0; }
.section-head { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 16px; }
.section-title { font-size: 20px; line-height: 28px; font-weight: 600; color: #FFFFFF; }
.section-sub { margin-top: 4px; font-size: 14px; line-height: 20px; color: var(--muted); max-width: 680px; text-wrap: pretty; }

/* Stage 3: The Shapley Spring-Stack */
.spring-card {
    margin-bottom: 24px; padding: 16px; background: var(--surface);
    border: 1px solid var(--line); border-radius: 12px;
}
.spring-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }
.spring-title { display: block; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
.spring-sub { display: block; margin-top: 2px; font-size: 12px; line-height: 16px; color: var(--faint); }
.spring-meta { font-family: var(--mono); font-size: 12px; line-height: 16px; color: #FFFFFF; background: var(--bg); border: 1px solid var(--line); border-radius: 6px; padding: 4px 8px; }
.sig-scale, .logit-scale {
    display: flex; justify-content: space-between; font-family: var(--mono);
    font-size: 12px; line-height: 16px; color: var(--faint);
}
.spring-stage {
    position: relative; height: 64px; margin: 8px 0; background: var(--bg);
    border: 1px solid var(--line); border-radius: 8px; overflow: hidden;
}
.zero-line { position: absolute; top: 0; bottom: 0; width: 1px; background: var(--line-strong); }
.prior-line {
    position: absolute; top: 0; bottom: 0; width: 1px; background: #A1A1A1; z-index: 2;
    animation: priorDrop 260ms var(--ease) both;
}
.prior-tag {
    position: absolute; top: 4px; left: 4px; font-family: var(--mono);
    font-size: 12px; line-height: 16px; color: var(--muted); white-space: nowrap;
}
.tug-lanes {
    position: absolute; top: 24px; left: 12px; right: 12px; height: 24px;
    display: grid; grid-template-columns: 1fr 1fr; gap: 2px; align-items: center;
}
.tug-lane { display: flex; align-items: center; gap: 2px; height: 20px; overflow: hidden; }
.tug-neg { justify-content: flex-end; }
.tug-pos { justify-content: flex-start; }
.sblk {
    height: 18px; border-radius: 4px; display: inline-flex; align-items: center; justify-content: center;
    padding: 0 4px; overflow: hidden; white-space: nowrap;
    animation: springDrop 480ms cubic-bezier(0.175, 0.885, 0.32, 1.275) both;
    transition: width 360ms cubic-bezier(0.175, 0.885, 0.32, 1.275), background-color 240ms ease, opacity 240ms ease;
}
.sblk-risk { background: var(--risk); color: #FFFFFF; }
.sblk-safe { background: var(--safe); color: #FFFFFF; }
.sblk-txt { font-family: var(--mono); font-size: 12px; line-height: 16px; font-weight: 500; }
.net-axis {
    position: absolute; top: 0; bottom: 0; width: 2px; background: #FFFFFF; z-index: 3;
    transition: left 420ms cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
.net-tag {
    position: absolute; bottom: 4px; right: 4px; padding: 0 4px; border-radius: 4px;
    background: #FFFFFF; color: #181818; font-family: var(--mono);
    font-size: 12px; line-height: 16px; font-weight: 600; white-space: nowrap;
}

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
.driver-name { display: flex; align-items: baseline; gap: 8px; font-size: 16px; line-height: 24px; font-weight: 600; color: #FFFFFF; flex-wrap: wrap; }
.driver-key { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); font-weight: 400; }
.driver-text {
    margin-top: 2px; font-size: 12px; line-height: 16px; color: var(--muted); text-wrap: pretty;
    display: -webkit-box; -webkit-line-clamp: 1; -webkit-box-orient: vertical; overflow: hidden;
}
.driver:hover .driver-text { -webkit-line-clamp: 3; }
.track { position: relative; height: 16px; }
.track::before { content: ""; position: absolute; left: 50%; top: 0; width: 1px; height: 16px; background: var(--line-strong); }
.fill {
    position: absolute; top: 5px; height: 6px; border-radius: 9999px;
    animation: grow 600ms var(--ease) both;
    transition: width 360ms cubic-bezier(0.175, 0.885, 0.32, 1.275), background-color 240ms ease;
}
.fill-up { left: 50%; background: var(--risk); transform-origin: left center; }
.fill-down { right: 50%; background: var(--safe); transform-origin: right center; }
.driver-val { font-family: var(--mono); font-size: 16px; line-height: 24px; font-weight: 600; text-align: right; font-variant-numeric: tabular-nums; transition: color 240ms ease; }

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

/* Stage 4: Counterfactual Fixes */
.fix {
    display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 24px; align-items: center;
    padding: 12px 16px; margin-bottom: 8px; border-radius: 8px;
    background: var(--surface); border: 1px solid var(--line); cursor: pointer;
    transition: background-color 150ms, border-color 150ms, transform 150ms;
}
.fix:hover { background: var(--raised); border-color: var(--safe); }
.fix-badge {
    font-family: var(--mono); font-size: 12px; line-height: 16px; font-weight: 400;
    color: var(--safe); padding: 2px 8px; border-radius: 9999px; border: 1px solid var(--line-strong);
}
.fix-text { margin-top: 4px; font-size: 12px; line-height: 16px; color: var(--muted); text-wrap: pretty; }
.fix-gain { font-family: var(--mono); font-size: 18px; line-height: 28px; font-weight: 600; color: var(--safe); white-space: nowrap; font-variant-numeric: tabular-nums; }

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
.cat-name { font-size: 16px; line-height: 24px; font-weight: 600; color: #FFFFFF; }
.cat-key { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }
.cat-group { font-size: 12px; line-height: 16px; color: var(--faint); white-space: nowrap; }
.cat-desc { font-size: 12px; line-height: 16px; color: var(--muted); text-wrap: pretty; }
.cat-rule { font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); text-wrap: pretty; }
.prev { margin-top: auto; }
.prev-track { display: flex; gap: 2px; height: 4px; border-radius: 9999px; overflow: hidden; }
.prev-legend { display: flex; justify-content: space-between; margin-top: 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: var(--faint); }

.footer { margin-top: 96px; font-size: 12px; line-height: 16px; color: var(--faint); }

@keyframes rise { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
@keyframes grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@keyframes laserSweep {
    0% { left: 0%; opacity: 1; }
    92% { left: 100%; opacity: 1; }
    100% { left: 100%; opacity: 0; }
}
@keyframes drawRoute {
    from { stroke-dashoffset: 520; }
    to { stroke-dashoffset: 0; }
}
@keyframes priorDrop {
    from { transform: translateY(-100%); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}
@keyframes springDrop {
    0% { transform: translateY(-28px) scaleX(0.4); opacity: 0; }
    70% { transform: translateY(2px) scaleX(1.03); opacity: 1; }
    100% { transform: translateY(0) scaleX(1); opacity: 1; }
}
@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation: none !important; transition: none !important; }
}
@media (max-width: 1100px) {
    .cat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .verdict { grid-template-columns: 1fr; }
    .verdict-right { justify-content: space-between; }
    .shred-rail { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .vec-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
    .page { padding: 0 16px 48px; }
    .nav-meta { display: none; }
    .verdict { grid-template-columns: 1fr; gap: 24px; }
    .verdict-right { flex-direction: column; align-items: stretch; }
    .score { text-align: left; }
    .shred-rail { grid-template-columns: 1fr; }
    .vec-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
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
const LIVE_FEATS = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'HTTPS_token'
];
const BIN_IDX = [0, 2, 3, 4, 5, 7];
const PROBE_CYCLES = ['\u22121', '+1', '0', '\u22121', '+1'];
window.__overrides = {};

function fmtState(v) { return v < 0 ? '\u22121' : (v > 0 ? '+1' : '0'); }
function fmtDelta(v, d = 3) { return (v >= 0 ? '+' : '\u2212') + Math.abs(v).toFixed(d); }
function logitToPct(z) { return 6.0 + (Math.max(-4.5, Math.min(4.5, z)) + 4.5) / 9.0 * 88.0; }
function toneColor(pct) { return pct >= 70 ? '#E5484D' : (pct >= 50 ? '#E2A336' : '#30A46C'); }
function toneLabel(pct) { return pct >= 70 ? 'Likely phishing' : (pct >= 50 ? 'Suspicious' : 'Looks legitimate'); }

function vecToCoord(vec) {
    let col = 0;
    for (let i = 0; i < BIN_IDX.length; i++) col = (col << 1) | (vec[BIN_IDX[i]] > 0 ? 1 : 0);
    const row = Math.max(0, Math.min(8, (vec[1] + 1) * 3 + (vec[6] + 1)));
    return [col, row];
}

function getLiveVec() {
    const root = $('results-root');
    if (!root) return [1, 1, 1, 1, 1, 1, 1, 1];
    return JSON.parse(root.dataset.liveVec || '[1,1,1,1,1,1,1,1]');
}

function getBaseVec() {
    const root = $('results-root');
    if (!root) return [1, 1, 1, 1, 1, 1, 1, 1];
    return JSON.parse(root.dataset.baseVec || '[1,1,1,1,1,1,1,1]');
}

function tween(el, target, decimals, suffix) {
    if (!el) return;
    const start = parseFloat(el.dataset.val);
    el.dataset.val = String(target);
    if (Number.isNaN(start) || Math.abs(target - start) < 0.05) {
        el.textContent = target.toFixed(decimals) + suffix;
        return;
    }
    const t0 = performance.now();
    function step(now) {
        const p = Math.min(1, (now - t0) / 360);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = (start + (target - start) * eased).toFixed(decimals) + suffix;
        if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

/* Stage 1 & 2: 300ms Lexical Shredder Sweep + 576-Node Matrix Collapse */
function replayScan() {
    const laser = $('scan-laser');
    if (!laser) return;
    laser.classList.remove('sweeping');
    void laser.offsetWidth;
    laser.classList.add('sweeping');

    const vec = getLiveVec();
    const [targetCol, targetRow] = vecToCoord(vec);
    const dots = document.querySelectorAll('.m-dot');
    dots.forEach(d => { d.classList.remove('collapsed', 'active'); d.classList.add('sieve-lit'); });

    const route = $('matrix-route-path');
    if (route) { route.style.animation = 'none'; void route.offsetWidth; route.style.animation = 'drawRoute 420ms var(--ease) both'; }

    const t0 = performance.now();
    function tick(now) {
        const p = Math.min(1, (now - t0) / 300);
        const lockedCount = Math.floor(p * 8);
        for (let i = 0; i < 8; i++) {
            const dig = $('vec-digit-' + i), slot = $('vec-slot-' + i);
            if (!dig || !slot) continue;
            if (i < lockedCount || p >= 1) {
                dig.textContent = dig.dataset.final;
                slot.classList.toggle('risk-lock', vec[i] < 0);
            } else {
                dig.textContent = PROBE_CYCLES[(Math.floor(now / 32) + i) % PROBE_CYCLES.length];
            }
        }
        if (p < 1) {
            requestAnimationFrame(tick);
        } else {
            dots.forEach(d => {
                const c = parseInt(d.dataset.c, 10), r = parseInt(d.dataset.r, 10);
                d.classList.remove('sieve-lit');
                if (c === targetCol && r === targetRow) d.classList.add('active');
                else d.classList.add('collapsed');
            });
        }
    }
    requestAnimationFrame(tick);
}

function initTelemetry() {
    replayScan();
}

/* Stage 2: Update 576-Node Matrix Crosshair & 90-Degree Orthogonal Routing Path */
function updateMatrixCoord(col, row) {
    const dx = 13 + col * 6, dy = 15 + row * 6;
    const nodeNum = row * 64 + col + 1;
    const tag = $('matrix-coord-tag');
    if (tag) tag.textContent = `Node [${col}, ${row}] (#${nodeNum} of 576) \u00b7 O(1) hash fetch`;
    const cv = $('matrix-cross-v'), ch = $('matrix-cross-h'), rp = $('matrix-route-path');
    if (cv) { cv.setAttribute('x1', dx); cv.setAttribute('x2', dx); }
    if (ch) { ch.setAttribute('y1', dy); ch.setAttribute('y2', dy); }
    if (rp) rp.setAttribute('d', `M ${dx} ${dy} L ${dx} 74 L 412 74 L 412 24`);
    document.querySelectorAll('.m-dot').forEach(d => {
        const isAct = parseInt(d.dataset.c, 10) === col && parseInt(d.dataset.r, 10) === row;
        d.classList.toggle('active', isAct);
        d.classList.toggle('collapsed', !isAct);
        d.setAttribute('width', isAct ? '4' : '2');
        d.setAttribute('height', isAct ? '4' : '2');
        d.setAttribute('x', 12 + parseInt(d.dataset.c, 10) * 6 + (isAct ? -1 : 0));
        d.setAttribute('y', 14 + parseInt(d.dataset.r, 10) * 6 + (isAct ? -1 : 0));
    });
}

/* Stage 4: Hover Ghost Preview on Gauge and 576-Node Matrix */
function previewOverride(idx, val) {
    if (!window.__liveLattice || idx < 0) return;
    const vec = getLiveVec().slice();
    vec[idx] = val;
    const entry = window.__liveLattice.states[vec.join(',')];
    if (!entry) return;
    const targetPct = Math.min(100, Math.max(0, entry[0] * 100));
    const ghost = $('gauge-ghost');
    if (ghost) { ghost.hidden = false; ghost.style.left = targetPct.toFixed(1) + '%'; }
    const [curC, curR] = vecToCoord(getLiveVec());
    const [nxtC, nxtR] = vecToCoord(vec);
    const gp = $('matrix-ghost-path');
    if (gp) {
        const x1 = 13 + curC * 6, y1 = 15 + curR * 6, x2 = 13 + nxtC * 6, y2 = 15 + nxtR * 6;
        gp.setAttribute('d', `M ${x1} ${y1} L ${x2} ${y1} L ${x2} ${y2}`);
    }
    const feat = LIVE_FEATS[idx];
    document.querySelectorAll(`.morph-token[data-feat="${feat}"]`).forEach(el => {
        el.classList.toggle('preview-erase', val > 0);
    });
}

function clearPreview() {
    const ghost = $('gauge-ghost'), gp = $('matrix-ghost-path');
    if (ghost) ghost.hidden = true;
    if (gp) gp.setAttribute('d', '');
    document.querySelectorAll('.morph-token.preview-erase').forEach(el => el.classList.remove('preview-erase'));
}

/* Stage 4: Physical URL Token Erasure */
function morphUrlTokenOnly(feat, erase = true) {
    document.querySelectorAll(`.morph-token[data-feat="${feat}"]`).forEach(el => {
        el.classList.remove('preview-erase');
        el.classList.toggle('erased', erase);
    });
}

/* Stage 3 & 4: Synchronized 0ms Client-Side Domino Reconciliation */
function updateSpringStackAndDrivers(vec, shaps, prob) {
    const baseVal = window.__liveLattice.base;
    let netShap = 0, maxAbs = 0.1;
    for (let i = 0; i < 8; i++) {
        netShap += shaps[i];
        if (Math.abs(shaps[i]) > maxAbs) maxAbs = Math.abs(shaps[i]);
    }
    const netLogit = baseVal + netShap;
    const riskPct = prob * 100;
    const netAxis = $('stack-net-axis'), netTag = $('stack-net-tag'), mathTag = $('spring-math-tag');
    if (netAxis) netAxis.style.left = logitToPct(netLogit).toFixed(1) + '%';
    if (netTag) netTag.textContent = 'Posterior ' + fmtDelta(netLogit, 2);
    if (mathTag) mathTag.textContent = `Prior ${fmtDelta(baseVal, 2)} \u2192 Net ${fmtDelta(netLogit, 2)} log odds (${riskPct.toFixed(1)}%)`;

    const negLane = $('tug-lane-neg'), posLane = $('tug-lane-pos');
    for (let i = 0; i < 8; i++) {
        const feat = LIVE_FEATS[i], sVal = shaps[i], vVal = vec[i];
        const meta = (window.__featMeta && window.__featMeta[feat]) || { label: feat, risk: '', safe: '' };
        const fill = $('drv-fill-' + feat), valEl = $('drv-val-' + feat), keyEl = $('drv-key-' + feat), txtEl = $('drv-txt-' + feat);
        if (fill) {
            fill.style.width = Math.min(50, Math.abs(sVal) / maxAbs * 50).toFixed(1) + '%';
            fill.classList.toggle('fill-up', sVal > 0);
            fill.classList.toggle('fill-down', sVal <= 0);
        }
        if (valEl) {
            valEl.textContent = fmtDelta(sVal, 3);
            valEl.style.color = Math.abs(sVal) < 0.005 ? '#7A7A7A' : (sVal > 0 ? '#E5484D' : '#30A46C');
        }
        if (keyEl) keyEl.textContent = feat + ' ' + fmtState(vVal);
        if (txtEl) txtEl.textContent = sVal > 0 ? meta.risk : meta.safe;

        const blk = $('sblk-' + feat);
        if (blk && negLane && posLane) {
            const wPct = Math.max(2.2, Math.min(22.0, Math.abs(sVal) / 4.5 * 88.0));
            blk.style.width = wPct.toFixed(1) + '%';
            blk.classList.toggle('sblk-risk', sVal >= 0);
            blk.classList.toggle('sblk-safe', sVal < 0);
            const shortLbl = meta.label.split(' ')[0];
            blk.querySelector('.sblk-txt').textContent = shortLbl + ' ' + fmtDelta(sVal, 2);
            if (sVal >= 0 && blk.parentElement !== posLane) posLane.appendChild(blk);
            else if (sVal < 0 && blk.parentElement !== negLane) negLane.appendChild(blk);
        }
    }
}

function updateLiveRecourseList(vec, currentProb) {
    const sec = $('fixes-section'), list = $('fixes-list');
    if (!sec || !list || !window.__liveLattice) return;
    const candidates = [];
    for (let i = 0; i < 8; i++) {
        if (vec[i] === 1) continue;
        const testVec = vec.slice();
        testVec[i] = 1;
        const entry = window.__liveLattice.states[testVec.join(',')];
        if (!entry) continue;
        const dropPct = (currentProb - entry[0]) * 100;
        if (dropPct > 1.0) candidates.push({ idx: i, feat: LIVE_FEATS[i], drop: dropPct });
    }
    candidates.sort((a, b) => b.drop - a.drop);
    if (!candidates.length) { sec.hidden = true; return; }
    sec.hidden = false;
    list.innerHTML = candidates.slice(0, 3).map(c => {
        const lbl = (window.__featMeta && window.__featMeta[c.feat]) ? window.__featMeta[c.feat].label : c.feat;
        return `<div class="fix" data-fix-feat="${c.feat}" role="button" tabindex="0" `
            + `onclick="applyCounterfactual(${c.idx}, 1, '${c.feat}')" `
            + `onmouseenter="previewOverride(${c.idx}, 1)" onmouseleave="clearPreview()">`
            + `<div><div class="driver-name">${lbl}<span class="fix-badge">Click to erase token &amp; morph score</span></div>`
            + `<div class="fix-text">If ${c.feat} met legitimate criteria, phishing probability would drop by ${c.drop.toFixed(1)}%.</div></div>`
            + `<div class="fix-gain">\u2212${c.drop.toFixed(1)}%</div></div>`;
    }).join('');
}

function reconcileLiveClient(vec) {
    const root = $('results-root');
    if (!root || !window.__liveLattice) return false;
    const entry = window.__liveLattice.states[vec.join(',')];
    if (!entry) return false;
    root.dataset.liveVec = JSON.stringify(vec);
    const [prob, shaps] = entry;
    const riskPct = prob * 100;
    const col = toneColor(riskPct);

    /* 1. Update Verdict & Gauge Needle */
    tween($('verdict-score-num'), riskPct, 1, '%');
    if ($('verdict-dot')) $('verdict-dot').style.background = col;
    if ($('verdict-label-txt')) $('verdict-label-txt').textContent = toneLabel(riskPct);
    if ($('gauge-fill')) { $('gauge-fill').style.width = riskPct.toFixed(1) + '%'; $('gauge-fill').style.background = col; }
    if ($('gauge-needle')) $('gauge-needle').style.left = riskPct.toFixed(1) + '%';

    /* 2. Update 8-Slot Vector Register & Picker Pills */
    for (let i = 0; i < 8; i++) {
        const dig = $('vec-digit-' + i), slot = $('vec-slot-' + i);
        if (dig) { dig.textContent = fmtState(vec[i]); dig.dataset.final = fmtState(vec[i]); }
        if (slot) {
            slot.classList.toggle('risk-lock', vec[i] < 0);
            slot.classList.add('snap-pop');
            setTimeout(() => slot.classList.remove('snap-pop'), 200);
        }
        document.querySelectorAll(`.pick[data-picker-idx="${i}"] .pick-btn`).forEach(btn => {
            btn.classList.toggle('on', parseInt(btn.dataset.opt, 10) === vec[i]);
        });
        morphUrlTokenOnly(LIVE_FEATS[i], vec[i] > 0);
    }

    /* 3. Update 576-Node Matrix & 3-Model Consensus */
    const [c, r] = vecToCoord(vec);
    updateMatrixCoord(c, r);
    const badCnt = vec.filter(v => v < 1).length;
    const rulePct = badCnt / 8 * 100;
    [[0, riskPct], [1, riskPct], [2, rulePct]].forEach(([idx, val]) => {
        if ($('model-val-' + idx)) $('model-val-' + idx).textContent = val.toFixed(1) + '%';
        if ($('model-fill-' + idx)) {
            $('model-fill-' + idx).style.width = val.toFixed(1) + '%';
            $('model-fill-' + idx).style.background = val >= 50 ? '#E5484D' : '#30A46C';
        }
    });

    /* 4. Update Shapley Spring-Stack, Driver Bars, and Recourse Cards */
    updateSpringStackAndDrivers(vec, shaps, prob);
    updateLiveRecourseList(vec, prob);
    const baseVec = getBaseVec();
    const hasOverrides = vec.some((v, i) => v !== baseVec[i]);
    if ($('reset-overrides-btn')) $('reset-overrides-btn').hidden = !hasOverrides;
    clearPreview();
    return true;
}

function applyCounterfactual(idx, val, feat) {
    morphUrlTokenOnly(feat, val > 0);
    setFeatureOverride(idx, val);
}

function setFeatureOverride(idx, val) {
    window.__overrides['f_' + idx] = val;
    const root = $('results-root');
    if (root && root.dataset.mode === 'live' && window.__liveLattice) {
        const vec = getLiveVec().slice();
        vec[idx] = val;
        if (reconcileLiveClient(vec)) return;
    }
    loadDiagnosis(Object.assign({ mode: 'live', url: liveUrl() }, window.__overrides));
}

function resetLiveOverrides() {
    window.__overrides = {};
    const root = $('results-root');
    if (root && root.dataset.mode === 'live' && window.__liveLattice) {
        if (reconcileLiveClient(getBaseVec().slice())) return;
    }
    loadDiagnosis({ mode: 'live', url: liveUrl() });
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
    if ($('reset-overrides-btn')) $('reset-overrides-btn').hidden = !data.has_overrides;
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
        replayScan();
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
