"""
Walkthrough stage for the PhishLens console.

A timeline driven demo: the address is read, split into 8 checks, each check is
inspected one at a time, and its risk or safety nudges the final phishing probability.
Python builds the data and static markup; the client engine renders every frame from time.
"""

import html
import json
import re
import urllib.parse

PART_LABELS = (
    "IP address",
    "URL length",
    "Link shortener",
    "At symbol",
    "Hidden redirect",
    "Dash in domain",
    "Subdomains",
    "Fake https",
)
CHIP_LIMIT = 26
SCHEME_GAP = 3
LENGTH_PART = 1


# Address geometry: where each of the 8 checks looks inside the URL string


def _netloc_span(url):
    """Returns the character span of the network location inside the URL."""
    start = url.find("://") + SCHEME_GAP if "://" in url else 0
    return start, start + len(urllib.parse.urlsplit(url).netloc)


def _host_span(url):
    """Returns the span of the host, without user info or port."""
    start, end = _netloc_span(url)
    at = url.rfind("@", start, end)
    start = at + 1 if at >= 0 else start
    port = re.search(r":\d+$", url[start:end])
    return start, end - (len(port.group()) if port else 0)


def _subdomain_span(url):
    """Returns the span of subdomain labels, or the whole host when there are none."""
    start, end = _host_span(url)
    host = url[start:end]
    labels = host.split(".")
    if len(labels) <= 2 or host.replace(".", "").isdigit():
        return start, end
    return start, start + len(".".join(labels[:-2]))


def _redirect_span(url):
    """Returns the span of an embedded double slash, or the normal scheme separator."""
    pos = url.rfind("//")
    if pos > 7:
        return pos, pos + 2
    start, _ = _netloc_span(url)
    return max(0, start - SCHEME_GAP), start


def part_ranges(url):
    """Returns the inspected character span for each of the 8 checks."""
    host = _host_span(url)
    at = url.find("@")
    at_span = (at, at + 1) if at >= 0 else _netloc_span(url)
    return [host, (0, len(url)), host, at_span, _redirect_span(url), host, _subdomain_span(url), host]


def _find_all(url, token, span):
    """Returns every span where the token appears inside the given span."""
    start, end = span
    return [[m.start() + start, m.end() + start] for m in re.finditer(re.escape(token), url[start:end])]


def part_marks(url, ranges):
    """Returns the exact characters to underline when a check fails."""
    host = list(ranges[0])
    return [
        [host],
        [],
        [host],
        _find_all(url, "@", (0, len(url))),
        [list(ranges[4])],
        _find_all(url, "-", ranges[5]),
        [list(ranges[6])],
        _find_all(url, "https", ranges[7]),
    ]


def _chip_text(url, span):
    """Returns the short text that travels from the address into its card."""
    text = url[span[0]:span[1]]
    return text if len(text) <= CHIP_LIMIT else text[:CHIP_LIMIT - 1] + "\u2026"


def part_chips(url, ranges):
    """Returns the traveling chip text for each check."""
    chips = [_chip_text(url, span) for span in ranges]
    chips[LENGTH_PART] = f"{len(url)} characters"
    return chips


def _phrase(risky, safe, middle=None):
    """Builds the plain finding for each state of one check."""
    return {"-1": risky, "0": middle or safe, "1": safe}


def part_phrases(url):
    """Returns the plain language finding for every state of every check."""
    size = len(url)
    return [
        _phrase("The host is a raw IP address", "The host is a normal domain name"),
        {
            "-1": f"{size} characters, longer than 75",
            "0": f"{size} characters, between 54 and 75",
            "1": f"{size} characters, shorter than 54",
        },
        _phrase("The host is a known link shortener", "The host is not a link shortener"),
        _phrase("An at symbol hides the real destination", "No at symbol in the address"),
        _phrase("A second double slash redirects elsewhere", "No hidden redirect in the address"),
        _phrase("The domain name contains a dash", "No dash in the domain name"),
        _phrase("A long chain of subdomains", "A plain domain with no extra levels", "One extra subdomain level"),
        _phrase("The word https is faked inside the domain", "No fake https word in the domain"),
    ]


def build_demo_data(url, result):
    """Assembles everything the client engine needs to play the walkthrough."""
    ranges = part_ranges(url)
    live_shaps = result["live_shaps"]
    all_shap = sum(item["shap_value"] for item in result["all_features"])
    return {
        "url": url,
        "ranges": [list(span) for span in ranges],
        "marks": part_marks(url, ranges),
        "chips": part_chips(url, ranges),
        "labels": list(PART_LABELS),
        "phrases": part_phrases(url),
        "vec": result["live_vector"],
        "base_vec": result["base_vector"],
        "shaps": live_shaps,
        "prior": float(result["base_value"]),
        "rest": round(all_shap - sum(live_shaps), 4),
    }


# Markup

ICON_PLAY = (
    '<svg class="ic-play" width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">'
    '<path d="M5 3.5L12 8L5 12.5V3.5Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg>'
)
ICON_PAUSE = (
    '<svg class="ic-pause" width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">'
    '<path d="M5.5 3.5V12.5M10.5 3.5V12.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
)
ICON_REPLAY = (
    '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true">'
    '<path d="M3 8a5 5 0 1 0 1.6-3.7M3 2.5V5H5.5" stroke="currentColor" stroke-width="1.5" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def _char_spans(url):
    """Renders one inline span per character so the engine can focus, mark, and erase text."""
    return "".join(f'<span class="ch">{html.escape(ch)}</span>' for ch in url)


def _card(index):
    """Renders one check card that fills in as the walkthrough plays."""
    return (
        f'<div id="dcard-{index}" class="dcard" onclick="Demo.focusPart({index})">'
        f'<div class="dcard-top"><span class="dcard-lbl">{html.escape(PART_LABELS[index])}</span>'
        f'<span class="dcard-num">Part 0{index + 1}</span></div>'
        f'<div id="dslice-{index}" class="dcard-slice empty"></div>'
        f'<div id="dverd-{index}" class="dcard-verdict"><span class="dcard-dot"></span><span class="dcard-word"></span>'
        f'<span id="dshare-{index}" class="dcard-share"></span></div>'
        f'<div id="dfind-{index}" class="dcard-find"></div>'
        f'<div class="dcard-push"><div class="dcard-bar"><i id="dbar-{index}"></i></div>'
        f'<div id="dpush-{index}" class="dcard-pushtxt"></div></div></div>'
    )


def _result_row():
    """Renders the running probability readout and gauge."""
    return (
        '<div id="demo-result" class="demo-result">'
        '<div class="demo-scorebox"><div id="demo-score" class="demo-score">0.0%</div>'
        '<div class="demo-score-cap">Phishing probability</div>'
        '<div id="demo-verdict" class="demo-verdict"><span id="demo-verdict-dot" class="dcard-dot"></span>'
        '<span id="demo-verdict-txt"></span></div></div>'
        '<div class="demo-gaugebox"><div class="demo-gauge">'
        '<div id="demo-gauge-fill" class="demo-gauge-fill"></div>'
        '<div id="demo-gauge-prior" class="demo-gauge-prior"><span>Starting point</span></div>'
        '<div class="demo-gauge-tick"></div>'
        '<div id="demo-gauge-mark" class="demo-gauge-mark"></div>'
        '<div id="demo-ghost" class="demo-gauge-ghost" hidden><span id="demo-ghost-tag"></span></div></div>'
        '<div class="demo-gauge-scale"><span>0% safe</span><span>50% threshold</span><span>100% phishing</span></div>'
        '</div></div>'
    )


def _controls():
    """Renders play, pause, scrubber, and clock."""
    return (
        '<div class="demo-foot">'
        f'<button id="demo-play" type="button" class="btn btn-icon" onclick="Demo.toggle()" aria-label="Play or pause">{ICON_PLAY}{ICON_PAUSE}</button>'
        f'<button type="button" class="btn btn-icon" onclick="Demo.replay()" aria-label="Replay">{ICON_REPLAY}</button>'
        '<input id="demo-scrub" class="demo-scrub" type="range" min="0" max="10600" step="1" value="0" '
        'oninput="Demo.scrub(this.value)" aria-label="Walkthrough position">'
        '<span id="demo-clock" class="demo-clock">0:00 / 0:11</span></div>'
    )


def render_demo_stage(url, result, note, has_overrides=False, mode="live"):
    """Renders the walkthrough stage for one diagnosed address."""
    data = html.escape(json.dumps(build_demo_data(url, result), separators=(",", ":")), quote=True)
    cards = "".join(_card(i) for i in range(len(PART_LABELS)))
    reset = (
        '<button id="reset-overrides-btn" type="button" class="btn" onclick="resetLiveOverrides()"'
        f'{"" if has_overrides else " hidden"}>Reset</button>'
        if mode == "live"
        else ""
    )
    return (
        f'<section id="demo-stage" class="demo" data-demo="{data}" data-mode="{mode}">'
        f'<div class="demo-head"><div class="demo-cap"><div class="demo-eyebrow">{html.escape(note)}</div>'
        '<div id="demo-cap-main" class="demo-cap-main"></div><div id="demo-cap-sub" class="demo-cap-sub"></div></div>'
        f'<div class="demo-head-actions">{reset}</div></div>'
        f'<div id="demo-urlwrap" class="demo-urlwrap"><div id="demo-url" class="demo-url">{_char_spans(url)}</div>'
        '<div id="demo-bracket" class="demo-bracket"></div></div>'
        f'<div class="demo-cards">{cards}</div>{_result_row()}{_controls()}'
        '<div id="demo-chip" class="demo-chip"></div></section>'
    )


# Styles

DEMO_CSS = """
/* Walkthrough stage */
.demo { position: relative; margin-top: 32px; padding: 32px; background: #000000; border: 1px solid #272727; border-radius: 16px; overflow: hidden; }
.demo-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; min-height: 72px; }
.demo-eyebrow { font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; }
.demo-cap-main { margin-top: 8px; font-size: 20px; line-height: 28px; font-weight: 600; color: #FFFFFF; }
.demo-cap-sub { margin-top: 2px; font-size: 14px; line-height: 20px; color: #A1A1A1; min-height: 20px; }
.demo-head-actions { display: flex; gap: 8px; }

.demo-urlwrap { position: relative; margin-top: 16px; padding: 16px 0 24px; overflow-x: auto; scrollbar-width: none; }
.demo-urlwrap::-webkit-scrollbar { display: none; }
.demo-url { width: max-content; font-family: var(--mono); font-size: 20px; line-height: 28px; color: #FFFFFF; white-space: nowrap; opacity: 0; }
.ch { display: inline-block; max-width: 1ch; overflow: hidden; vertical-align: bottom; }
.ch.erased { max-width: 0; opacity: 0 !important; }
.demo-bracket { position: absolute; bottom: 12px; left: 0; width: 0; height: 2px; border-radius: 2px; background: #FFFFFF; opacity: 0; }
.demo-bracket::before, .demo-bracket::after { content: ""; position: absolute; bottom: 0; width: 2px; height: 8px; border-radius: 2px; background: inherit; }
.demo-bracket::before { left: 0; }
.demo-bracket::after { right: 0; }

.demo-cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; margin-top: 8px; }
.dcard { display: flex; flex-direction: column; gap: 12px; padding: 16px; background: #181818; border: 1px solid #272727; border-radius: 12px; opacity: 0; cursor: pointer; transition: border-color 200ms var(--ease); }
.dcard:hover { border-color: #3A3A3A; }
.dcard.active { border-color: #FFFFFF; }
.dcard-top { display: flex; align-items: baseline; justify-content: space-between; gap: 8px; }
.dcard-lbl { font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
.dcard-num { font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; }
.dcard-slice { min-height: 36px; padding: 8px; font-family: var(--mono); font-size: 12px; line-height: 20px; color: #FFFFFF; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; background: #000000; border: 1px solid #272727; border-radius: 6px; }
.dcard-slice.empty { border-style: dashed; }
.dcard-verdict { display: flex; align-items: center; gap: 8px; font-size: 14px; line-height: 20px; font-weight: 600; opacity: 0; }
.dcard-share { margin-left: auto; font-family: var(--mono); font-size: 12px; line-height: 16px; font-weight: 500; color: #FFFFFF; }
.dcard-dot { width: 8px; height: 8px; border-radius: 9999px; flex: none; background: #7A7A7A; }
.dcard-find { font-size: 12px; line-height: 16px; color: #A1A1A1; text-wrap: pretty; opacity: 0; }
.dcard-push { margin-top: auto; }
.dcard-bar { height: 4px; border-radius: 9999px; background: #272727; overflow: hidden; }
.dcard-bar i { display: block; width: 0; height: 4px; border-radius: 9999px; background: #7A7A7A; }
.dcard-pushtxt { margin-top: 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; min-height: 16px; }

.demo-chip { position: absolute; top: 0; left: 0; z-index: 4; padding: 4px 8px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: #000000; background: #FFFFFF; border-radius: 6px; white-space: nowrap; pointer-events: none; opacity: 0; will-change: transform; }

.demo-result { display: grid; grid-template-columns: 240px minmax(0, 1fr); gap: 32px; align-items: center; margin-top: 24px; padding: 24px; background: #181818; border: 1px solid #272727; border-radius: 12px; opacity: 0; }
.demo-score { font-size: 48px; line-height: 1; font-weight: 600; letter-spacing: -0.04em; font-variant-numeric: tabular-nums; color: #FFFFFF; }
.demo-score-cap { margin-top: 8px; font-size: 12px; line-height: 16px; color: #A1A1A1; }
.demo-verdict { display: flex; align-items: center; gap: 8px; margin-top: 12px; font-size: 16px; line-height: 24px; font-weight: 600; opacity: 0; }
.demo-gaugebox { padding-top: 24px; }
.demo-gauge { position: relative; height: 8px; border-radius: 9999px; background: #272727; }
.demo-gauge-fill { position: absolute; top: 0; left: 0; height: 8px; width: 0; border-radius: 9999px; background: #7A7A7A; }
.demo-gauge-mark { position: absolute; top: -4px; left: 0; width: 2px; height: 16px; transform: translateX(-50%); border-radius: 2px; background: #FFFFFF; }
.demo-gauge-prior { position: absolute; top: -4px; left: 0; width: 1px; height: 16px; background: #7A7A7A; opacity: 0; }
.demo-gauge-prior span { position: absolute; bottom: 20px; left: 0; transform: translateX(-50%); font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; white-space: nowrap; }
.demo-gauge-tick { position: absolute; top: -4px; left: 50%; width: 1px; height: 16px; background: #313131; }
.demo-gauge-ghost { position: absolute; top: -4px; left: 0; width: 2px; height: 16px; transform: translateX(-50%); border-radius: 2px; background: #30A46C; }
.demo-gauge-ghost span { position: absolute; top: 20px; left: 0; transform: translateX(-50%); font-family: var(--mono); font-size: 12px; line-height: 16px; color: #30A46C; white-space: nowrap; }
.demo-gauge-scale { display: flex; justify-content: space-between; margin-top: 12px; font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; }

.demo-foot { display: flex; align-items: center; gap: 8px; margin-top: 24px; }
.demo-scrub { flex: 1; min-width: 0; height: 16px; margin: 0 8px; appearance: none; -webkit-appearance: none; background: transparent; cursor: pointer; }
.demo-scrub::-webkit-slider-runnable-track { height: 4px; border-radius: 9999px; background: #272727; }
.demo-scrub::-moz-range-track { height: 4px; border-radius: 9999px; background: #272727; }
.demo-scrub::-webkit-slider-thumb { appearance: none; -webkit-appearance: none; width: 12px; height: 12px; margin-top: -4px; border: 0; border-radius: 9999px; background: #FFFFFF; }
.demo-scrub::-moz-range-thumb { width: 12px; height: 12px; border: 0; border-radius: 9999px; background: #FFFFFF; }
.demo-clock { min-width: 80px; text-align: right; font-family: var(--mono); font-size: 12px; line-height: 16px; color: #7A7A7A; }
.demo .ic-pause { display: none; }
.demo.playing .ic-play { display: none; }
.demo.playing .ic-pause { display: block; }

.demo.settled .ch { transition: max-width 400ms var(--ease), opacity 300ms var(--ease), box-shadow 300ms var(--ease); }
.demo.settled .dcard-bar i { transition: width 500ms var(--ease), background-color 300ms var(--ease); }
.demo.settled .demo-gauge-fill { transition: width 500ms var(--ease), background-color 300ms var(--ease); }
.demo.settled .demo-gauge-mark { transition: left 500ms var(--ease); }
.demo.settled .dcard-dot, .demo.settled .dcard-word, .demo.settled .dcard-pushtxt { transition: color 300ms var(--ease), background-color 300ms var(--ease); }

@media (max-width: 1100px) {
    .demo-cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 760px) {
    .demo { padding: 16px; }
    .demo-url { font-size: 16px; line-height: 24px; }
    .demo-result { grid-template-columns: 1fr; gap: 16px; }
    .demo-gaugebox { padding-top: 24px; }
}
"""

# Timeline engine

DEMO_JS = """
const Demo = (() => {
    const N = 8, LEAD = 1400, SLOT = 900, OUT = 2000;
    const TOTAL = LEAD + N * SLOT + OUT;
    const ERASABLE = [3, 4, 5, 7];
    const COLORS = { '-1': '#E5484D', '0': '#E2A336', '1': '#30A46C' };
    const WORDS = { '-1': 'Risky', '0': 'Suspicious', '1': 'Safe' };
    const reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const S = { root: null, d: null, chars: [], t: 0, playing: false, raf: 0, last: 0, pct: null, tweenRaf: 0 };

    const $d = (id) => document.getElementById(id);
    const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
    const ease = (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2);
    const lerp = (a, b, p) => a + (b - a) * p;
    const sigmoid = (z) => 1 / (1 + Math.exp(-z));
    const toneColor = (pct) => (pct >= 70 ? '#E5484D' : (pct >= 50 ? '#E2A336' : '#30A46C'));
    const toneLabel = (pct) => (pct >= 70 ? 'Likely phishing' : (pct >= 50 ? 'Suspicious' : 'Looks legitimate'));
    const signed = (v) => (v >= 0 ? '+' : '\\u2212') + Math.abs(v).toFixed(2);
    const clock = (ms) => Math.floor(ms / 60000) + ':' + String(Math.round(ms / 1000) % 60).padStart(2, '0');

    function setText(el, text) { if (el && el.textContent !== text) el.textContent = text; }
    function slotOf(t) {
        const k = t - LEAD;
        if (k < 0 || k >= N * SLOT) return null;
        return { i: Math.floor(k / SLOT), u: k % SLOT };
    }
    function phase(t, i) {
        const u = t - (LEAD + i * SLOT);
        return { u, stamp: ease(clamp((u - 700) / 200)), landed: u >= 700 };
    }
    function rectOf(range) {
        const a = S.chars[range[0]], b = S.chars[Math.max(range[0], range[1] - 1)];
        return { left: a.offsetLeft, width: b.offsetLeft + b.offsetWidth - a.offsetLeft };
    }
    function logitAt(t) {
        const d = S.d;
        let z = d.prior;
        for (let i = 0; i < N; i++) z += d.shaps[i] * phase(t, i).stamp;
        return z + d.rest * ease(clamp((t - (LEAD + N * SLOT + 300)) / 900));
    }

    function renderCaption(t) {
        const d = S.d, act = slotOf(t);
        let main, sub;
        if (t < 600) { main = 'Reading the address'; sub = 'This is the link exactly as it was pasted.'; }
        else if (t < LEAD) { main = 'Splitting the check into 8 parts'; sub = 'Each part looks at a different piece of the address.'; }
        else if (act) {
            main = 'Part ' + (act.i + 1) + ' of 8: ' + d.labels[act.i];
            sub = act.u >= 700 ? d.phrases[act.i][String(d.vec[act.i])] : 'Looking at this piece of the address';
        } else {
            const bad = d.vec.filter((v) => v < 1).length;
            main = 'Result';
            sub = bad === 0 ? 'All 8 parts look safe.' : bad + ' of 8 parts look risky or suspicious. Each one moved the score.';
        }
        setText($d('demo-cap-main'), main);
        setText($d('demo-cap-sub'), sub);
    }

    function markColors(t) {
        const d = S.d, colors = new Array(S.chars.length).fill(null);
        for (let i = 0; i < N; i++) {
            if (d.vec[i] >= 1 || phase(t, i).stamp <= 0) continue;
            d.marks[i].forEach(([s, e]) => { for (let c = s; c < e; c++) colors[c] = COLORS[String(d.vec[i])]; });
        }
        return colors;
    }
    function erasedChars() {
        const d = S.d, erased = new Set();
        ERASABLE.forEach((i) => {
            if (d.vec[i] !== 1 || d.base_vec[i] >= 1) return;
            d.marks[i].forEach(([s, e]) => { for (let c = s; c < e; c++) erased.add(c); });
        });
        return erased;
    }
    function renderUrl(t) {
        const d = S.d, act = slotOf(t);
        const urlIn = ease(clamp(t / 500));
        const focus = act ? Math.min(ease(clamp(act.u / 200)), 1 - ease(clamp((act.u - 780) / 120))) : 0;
        const range = act ? d.ranges[act.i] : [0, 0];
        const colors = markColors(t), erased = erasedChars();
        $d('demo-url').style.opacity = String(urlIn);
        S.chars.forEach((ch, c) => {
            const inside = c >= range[0] && c < range[1];
            ch.style.opacity = act && !inside ? String(lerp(1, 0.28, focus)) : '1';
            ch.style.boxShadow = colors[c] ? 'inset 0 -2px 0 ' + colors[c] : 'none';
            ch.classList.toggle('erased', erased.has(c));
        });
    }
    function renderBracket(t) {
        const d = S.d, act = slotOf(t), br = $d('demo-bracket');
        if (!act) { br.style.opacity = '0'; return; }
        const cur = rectOf(d.ranges[act.i]);
        const prev = act.i > 0 ? rectOf(d.ranges[act.i - 1]) : { left: cur.left + cur.width / 2, width: 0 };
        const g = ease(clamp(act.u / 250));
        br.style.left = lerp(prev.left, cur.left, g) + 'px';
        br.style.width = lerp(prev.width, cur.width, g) + 'px';
        br.style.background = act.u >= 700 ? COLORS[String(d.vec[act.i])] : '#FFFFFF';
        br.style.opacity = '1';
    }
    function renderChip(t) {
        const chip = $d('demo-chip'), act = slotOf(t);
        const fly = act ? ease(clamp((act.u - 250) / 450)) : 0;
        if (!act || fly <= 0 || act.u >= 700) { chip.style.opacity = '0'; return; }
        const stage = S.root.getBoundingClientRect();
        const from = $d('demo-bracket').getBoundingClientRect();
        const to = $d('dslice-' + act.i).getBoundingClientRect();
        setText(chip, S.d.chips[act.i]);
        const x = lerp(from.left - stage.left, to.left - stage.left + 8, fly);
        const y = lerp(from.bottom - stage.top + 4, to.top - stage.top + 8, fly);
        chip.style.transform = 'translate(' + x + 'px, ' + y + 'px)';
        chip.style.opacity = String(1 - ease(clamp((fly - 0.85) / 0.15)));
    }

    function renderCard(t, i, act, maxAbs, totalAbs) {
        const d = S.d, p = phase(t, i), v = String(d.vec[i]), shap = d.shaps[i];
        const card = $d('dcard-' + i), cardIn = ease(clamp((t - (600 + i * 70)) / 300));
        card.style.opacity = String(cardIn);
        card.style.transform = 'translateY(' + (1 - cardIn) * 8 + 'px)';
        card.classList.toggle('active', !!act && act.i === i);
        const slice = $d('dslice-' + i);
        slice.classList.toggle('empty', !p.landed);
        setText(slice, p.landed ? d.chips[i] : '');
        const verd = $d('dverd-' + i);
        verd.style.opacity = String(p.stamp);
        verd.querySelector('.dcard-dot').style.background = COLORS[v];
        const word = verd.querySelector('.dcard-word');
        word.style.color = COLORS[v];
        setText(word, WORDS[v]);
        const sharePct = Math.round(Math.abs(shap) / totalAbs * 100);
        setText($d('dshare-' + i), sharePct + '% of decision');
        const find = $d('dfind-' + i);
        find.style.opacity = String(p.stamp);
        setText(find, d.phrases[i][v]);
        const dir = shap > 0.005 ? 'risk' : (shap < -0.005 ? 'safe' : 'none');
        const color = dir === 'risk' ? '#E5484D' : (dir === 'safe' ? '#30A46C' : '#7A7A7A');
        const bar = $d('dbar-' + i);
        bar.style.width = (p.stamp * Math.abs(shap) / maxAbs * 100).toFixed(1) + '%';
        bar.style.background = color;
        const push = $d('dpush-' + i);
        push.style.color = color;
        push.style.opacity = String(p.stamp);
        setText(push, dir === 'none' ? 'No push on the score' : (dir === 'risk' ? 'Pushes toward phishing ' : 'Pushes toward safe ') + signed(shap));
    }
    function renderCards(t) {
        const absList = S.d.shaps.map(Math.abs);
        const maxAbs = Math.max(0.1, ...absList);
        const totalAbs = Math.max(0.01, absList.reduce((a, b) => a + b, 0));
        const act = slotOf(t);
        for (let i = 0; i < N; i++) renderCard(t, i, act, maxAbs, totalAbs);
    }

    function showPct(value) {
        const el = $d('demo-score');
        cancelAnimationFrame(S.tweenRaf);
        if (!S.root.classList.contains('settled') || S.pct === null) { S.pct = value; setText(el, value.toFixed(1) + '%'); return; }
        const from = S.pct, t0 = performance.now();
        const step = (now) => {
            const p = ease(clamp((now - t0) / 500));
            S.pct = lerp(from, value, p);
            setText(el, S.pct.toFixed(1) + '%');
            if (p < 1) S.tweenRaf = requestAnimationFrame(step);
        };
        S.tweenRaf = requestAnimationFrame(step);
    }
    function renderResult(t) {
        const pct = sigmoid(logitAt(t)) * 100, color = toneColor(pct);
        $d('demo-result').style.opacity = String(ease(clamp((t - 500) / 400)));
        const fill = $d('demo-gauge-fill');
        fill.style.width = pct.toFixed(2) + '%';
        fill.style.background = color;
        $d('demo-gauge-mark').style.left = pct.toFixed(2) + '%';
        const prior = $d('demo-gauge-prior');
        prior.style.left = (sigmoid(S.d.prior) * 100).toFixed(2) + '%';
        prior.style.opacity = String(ease(clamp((t - 600) / 400)));
        showPct(pct);
        const verdict = $d('demo-verdict');
        verdict.style.opacity = String(ease(clamp((t - (LEAD + N * SLOT + 500)) / 500)));
        $d('demo-verdict-dot').style.background = color;
        setText($d('demo-verdict-txt'), toneLabel(pct));
        verdict.style.color = color;
    }
    function renderControls(t) {
        $d('demo-scrub').value = String(Math.round(t));
        setText($d('demo-clock'), clock(t) + ' / ' + clock(TOTAL));
        S.root.classList.toggle('playing', S.playing);
    }
    function render(t) {
        renderCaption(t);
        renderUrl(t);
        renderBracket(t);
        renderCards(t);
        renderChip(t);
        renderResult(t);
        renderControls(t);
    }

    function settle() { S.root.classList.add('settled'); }
    function tick(now) {
        if (!S.playing) return;
        S.t = Math.min(TOTAL, S.t + (now - S.last));
        S.last = now;
        if (S.t >= TOTAL) { S.playing = false; render(S.t); settle(); render(S.t); return; }
        render(S.t);
        S.raf = requestAnimationFrame(tick);
    }
    function play(from) {
        if (!S.root) return;
        if (from !== undefined) S.t = from;
        if (S.t >= TOTAL) S.t = 0;
        S.root.classList.remove('settled');
        S.pct = null;
        S.playing = true;
        S.last = performance.now();
        cancelAnimationFrame(S.raf);
        S.raf = requestAnimationFrame(tick);
    }
    function pause() {
        S.playing = false;
        cancelAnimationFrame(S.raf);
        if (S.root) renderControls(S.t);
    }
    function seek(t) {
        pause();
        S.t = clamp(Number(t), 0, TOTAL);
        S.root.classList.remove('settled');
        S.pct = null;
        render(S.t);
        if (S.t >= TOTAL) settle();
    }
    function init() {
        const root = $d('demo-stage');
        if (!root) return;
        cancelAnimationFrame(S.raf);
        S.root = root;
        S.d = JSON.parse(root.dataset.demo);
        S.chars = Array.from(root.querySelectorAll('.ch'));
        S.t = 0;
        if (reduced) { seek(TOTAL); return; }
        play(0);
    }
    function apply(vec, shaps) {
        if (!S.root) return;
        S.d.vec = vec;
        S.d.shaps = shaps;
        S.d.rest = 0;
        pause();
        S.t = TOTAL;
        settle();
        render(TOTAL);
    }
    function state() { return { vec: S.d ? S.d.vec : null, base: S.d ? S.d.base_vec : null, labels: S.d ? S.d.labels : [] }; }
    function ghost(prob) {
        const g = $d('demo-ghost');
        if (!g) return;
        g.hidden = prob === null;
        if (prob === null) return;
        g.style.left = prob.toFixed(2) + '%';
        setText($d('demo-ghost-tag'), 'Would become ' + prob.toFixed(1) + '%');
    }
    function focusPart(i) {
        if (!S.root) return;
        if (S.root.classList.contains('settled') && S.root.dataset.mode === 'live' && typeof setFeatureOverride === 'function') {
            setFeatureOverride(i, S.d.vec[i] < 1 ? 1 : -1);
            return;
        }
        seek(LEAD + i * SLOT + 740);
    }
    return {
        init, apply, state, ghost, focusPart,
        toggle: () => (S.playing ? pause() : play()),
        replay: () => play(0),
        scrub: (v) => seek(v),
        pause,
    };
})();
"""
