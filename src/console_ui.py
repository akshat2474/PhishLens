"""
HTML renderers for the PhishLens web console.
Data comes from src.vercel_console; styling and behavior come from src.console_assets.
"""

import html
import json
import time

from src.console_assets import CONSOLE_JS, PAGE_CSS
from src.feature_extractor import LIVE_FEATURES
from src.vercel_console import (
    DEFAULT_LIVE_URL,
    DEFAULT_UCI_IDX,
    URL_PRESETS,
    _clean_copy,
    _fmt_delta,
    _fmt_state_val,
    _parse_url_tokens,
    _resolve_rail_cells,
    _specimen_segments,
    build_client_lattice,
    diagnose_live,
    diagnose_uci,
    load_runtime_data,
    risk_tone,
)

TONES = {"critical": "#E5484D", "warning": "#E2A336", "safe": "#30A46C"}
RISK, SAFE, NEUTRAL, SNAP_RISK = TONES["critical"], TONES["safe"], "#7A7A7A", "#E57373"
TOP_DRIVERS = 8
TERNARY_LIVE_FEATURES = frozenset({"URL_Length", "having_Sub_Domain"})
VERDICT_LABELS = {"critical": "Likely phishing", "warning": "Suspicious", "safe": "Looks legitimate"}
SHORT_LIVE_LABELS = (
    "IP host",
    "URL length",
    "Shortener",
    "At symbol",
    "Redirect //",
    "Domain dash",
    "Subdomains",
    "HTTPS token",
)

FEATURE_NAMES = {
    "having_IP_Address": "IP address as host",
    "URL_Length": "URL length",
    "Shortining_Service": "Link shortener",
    "having_At_Symbol": "At symbol in URL",
    "double_slash_redirecting": "Double slash redirect",
    "Prefix_Suffix": "Dash in domain name",
    "having_Sub_Domain": "Subdomain depth",
    "SSLfinal_State": "SSL certificate",
    "Domain_registeration_length": "Registration length",
    "Favicon": "Favicon origin",
    "port": "Open ports",
    "HTTPS_token": "HTTPS in hostname",
    "Request_URL": "External resources",
    "URL_of_Anchor": "Anchor links",
    "Links_in_tags": "Script and meta links",
    "SFH": "Form handler",
    "Submitting_to_email": "Form posts to email",
    "Abnormal_URL": "Abnormal URL",
    "Redirect": "Redirect count",
    "on_mouseover": "Status bar tampering",
    "RightClick": "Right click disabled",
    "popUpWidnow": "Popup windows",
    "Iframe": "Hidden iframes",
    "age_of_domain": "Domain age",
    "DNSRecord": "DNS record",
    "web_traffic": "Web traffic",
    "Page_Rank": "Page rank",
    "Google_Index": "Search index",
    "Links_pointing_to_page": "Inbound links",
    "Statistical_report": "Threat reports",
}

LOGO_SVG = (
    '<svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">'
    '<circle cx="8" cy="8" r="6" stroke="#FFFFFF" stroke-width="1.5"/>'
    '<path d="M12.5 12.5L16.5 16.5" stroke="#FFFFFF" stroke-width="1.5" stroke-linecap="round"/>'
    '<circle cx="8" cy="8" r="2" fill="#FFFFFF"/></svg>'
)
ICON_PREV = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M10 4L6 8L10 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
ICON_NEXT = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6 4L10 8L6 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
ICON_SHUFFLE = '<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M2 4H4.5C6 4 7 5 8 8C9 11 10 12 11.5 12H14M14 12L12 10M14 12L12 14M2 12H4.5C5.4 12 6 11.6 6.6 10.8M9.4 5.2C10 4.4 10.6 4 11.5 4H14M14 4L12 2M14 4L12 6" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>'


def esc(text):
    """Escapes text for safe HTML interpolation."""
    return html.escape(str(text))


def feature_label(name):
    """Returns a readable sentence case label for a raw dataset feature key."""
    return FEATURE_NAMES.get(name, name.replace("_", " ").capitalize())


def clamp_pct(val):
    """Clamps a percentage into the 0 to 100 range."""
    return min(100.0, max(0.0, float(val)))


def _active(current, target, cls="active"):
    """Returns the given class when current matches target."""
    return cls if current == target else ""


# Verdict and 4-Stage Telemetry


def _morph_chars(escaped_seg):
    """Wraps targetable malicious characters in morphable inline spans."""
    out = escaped_seg.replace("-", '<span class="morph-token morph-dash" data-feat="Prefix_Suffix">-</span>')
    out = out.replace("@", '<span class="morph-token morph-at" data-feat="having_At_Symbol">@</span>')
    if "https" in out and "://" not in out:
        out = out.replace("https", '<span class="morph-token morph-https" data-feat="HTTPS_token">https</span>', 1)
    if "//" in out and "://" not in out:
        out = out.replace("//", '<span class="morph-token morph-slash" data-feat="double_slash_redirecting">/</span>/', 1)
    return out


def _segment_morph_wrap(idx, seg, inner):
    """Wraps subdomain or IP host segments in morphable feature containers."""
    if idx == 1 and seg != "none":
        return f'<span class="morph-token morph-sub" data-feat="having_Sub_Domain">{inner}</span>'
    if idx == 2 and seg.replace(".", "").isdigit():
        return f'<span class="morph-token morph-ip" data-feat="having_IP_Address">{inner}</span>'
    return inner


def _url_segment(idx, seg, shap_val):
    """Wraps one URL segment with morph targets and risk underlining."""
    inner = _segment_morph_wrap(idx, seg, _morph_chars(esc(seg)))
    if shap_val > 0.01:
        return f'<span class="url-seg url-risk" data-seg="{idx}" title="Raises risk by {_fmt_delta(shap_val, 3)} log odds">{inner}</span>'
    return f'<span class="url-seg" data-seg="{idx}">{inner}</span>'


def _render_url(url, result):
    """Renders the inspected address with morphable tokens and risky segments underlined."""
    tokens = _parse_url_tokens(url)
    shaps = {d["feature"]: d["shap_value"] for d in result["all_features"]}
    cells = _resolve_rail_cells(tokens, shaps)
    segments = _specimen_segments(tokens, cells)
    parts = "".join(_url_segment(i, seg, s) for i, (seg, s) in enumerate(segments))
    has_risk = any(s > 0.01 for _, s in segments)
    hint = '<div class="url-hint">Underlined parts raise the risk score. Click any recourse fix below to morph the URL live.</div>' if has_risk else ""
    return f'<div id="specimen-url" class="url">{parts}</div>{hint}'


def _render_gauge(risk_pct, color):
    """Renders a probability gauge with a mechanical needle, hover ghost, and threshold tick."""
    clamped = clamp_pct(risk_pct)
    return (
        f'<div class="gauge">'
        f'<div id="gauge-fill" class="gauge-fill" style="width: {clamped:.1f}%; background: {color};"></div>'
        f'<div id="gauge-ghost" class="gauge-ghost" hidden></div>'
        f'<div id="gauge-needle" class="gauge-needle" style="left: {clamped:.1f}%;"></div>'
        f'<div class="gauge-tick" title="Decision threshold"></div></div>'
        f'<div class="gauge-scale"><span>0% legitimate</span><span class="gauge-mid">Threshold 50%</span><span>100% phishing</span></div>'
    )


def _matrix_dot_rect(col, row, active_col, active_row):
    """Renders one 2x2 pixel combinatorial state node in the 64 by 9 lookup SVG."""
    is_act = col == active_col and row == active_row
    cls = "m-dot active" if is_act else "m-dot"
    size = 4 if is_act else 2
    offset = -1 if is_act else 0
    x, y = 12 + col * 6 + offset, 14 + row * 6 + offset
    return f'<rect class="{cls}" data-c="{col}" data-r="{row}" x="{x}" y="{y}" width="{size}" height="{size}"/>'


def _render_matrix_collapse(result):
    """Renders the 576-node (64x9) O(1) lookup grid and 90-degree orthogonal routing path."""
    col, row = result.get("matrix_coord", (0, 0))
    node_num = row * 64 + col + 1
    dx, dy = 13 + col * 6, 15 + row * 6
    dots = "".join(_matrix_dot_rect(c, r, col, row) for r in range(9) for c in range(64))
    route_d = f"M {dx} {dy} L {dx} 74 L 412 74 L 412 24"
    return (
        f'<div class="matrix-box">'
        f'<div class="matrix-head">'
        f'<span class="matrix-title">576 state precomputed lookup grid (64 binary × 9 ternary)</span>'
        f'<span id="matrix-coord-tag" class="matrix-meta">Node [{col}, {row}] (#{node_num} of 576) · O(1) hash fetch</span></div>'
        f'<svg id="matrix-svg" class="matrix-svg" viewBox="0 0 420 82" role="img" aria-label="576 state lookup matrix">'
        f'<line id="matrix-cross-v" x1="{dx}" y1="8" x2="{dx}" y2="68" stroke="#313131" stroke-width="1"/>'
        f'<line id="matrix-cross-h" x1="8" y1="{dy}" x2="396" y2="{dy}" stroke="#313131" stroke-width="1"/>'
        f'{dots}'
        f'<path id="matrix-ghost-path" class="matrix-ghost-path" d="" fill="none"/>'
        f'<path id="matrix-route-path" class="matrix-route-path" d="{route_d}" fill="none"/>'
        f'<circle id="matrix-route-term" cx="412" cy="24" r="2.5" fill="#FFFFFF"/></svg></div>'
    )


def _shred_token_block(idx, cell):
    """Renders one fractured URI token card for the lexical shredder."""
    label, val, feat_label, shap_val = cell
    risk_cls = " risk-lock" if shap_val > 0.01 else ""
    delta_col = SNAP_RISK if shap_val > 0.01 else (SAFE if shap_val < -0.01 else NEUTRAL)
    return (
        f'<div class="shred-block{risk_cls}" data-token-idx="{idx}">'
        f'<div class="shred-Head"><span class="shred-lbl">{esc(label)}</span>'
        f'<span class="shred-delta" style="color: {delta_col};">{_fmt_delta(shap_val, 2)}</span></div>'
        f'<div class="shred-val">{_morph_chars(esc(val))}</div>'
        f'<div class="shred-feat">{esc(feat_label)}</div></div>'
    )


def _vec_register_slot(idx, feat, val, caliper):
    """Renders one of the 8 Geist Mono feature vector slots beneath the fractured URL."""
    risk_cls = " risk-lock" if val < 0 else ""
    fmt_val = _fmt_state_val(val)
    return (
        f'<div id="vec-slot-{idx}" class="vec-slot{risk_cls}" data-feat="{feat}" data-idx="{idx}">'
        f'<span class="vec-lbl">{esc(SHORT_LIVE_LABELS[idx])}</span>'
        f'<span id="vec-digit-{idx}" class="vec-digit" data-final="{fmt_val}">{fmt_val}</span>'
        f'<span id="vec-cal-{idx}" class="vec-cal">{esc(caliper)}</span></div>'
    )


def _render_shredder(url, result):
    """Renders Stage 1: The Lexical Shredder, Caliper Ruler, and 8-digit Vector Lock."""
    tokens = _parse_url_tokens(url)
    shaps = {d["feature"]: d["shap_value"] for d in result["all_features"]}
    cells = _resolve_rail_cells(tokens, shaps)
    blocks = "".join(_shred_token_block(i, c) for i, c in enumerate(cells))
    vec = result.get("live_vector", [1] * 8)
    calipers = result.get("calipers", [""] * 8)
    slots = "".join(_vec_register_slot(i, LIVE_FEATURES[i], vec[i], calipers[i]) for i in range(8))
    char_len = len(url)
    len_pct = min(100.0, char_len / 100.0 * 100.0)
    return (
        f'<section id="shredder-stage" class="shredder scanning">'
        f'<div class="shredder-top">'
        f'<div class="shredder-title">Zero socket lexical shredder'
        f'<span class="shredder-sub">Fractures URI into 5 structural tokens and locks the 8 feature vector in under 1 ms</span></div>'
        f'<button type="button" class="btn" onclick="replayScan()">Replay scan</button></div>'
        f'<div class="shred-rail"><div id="scan-laser" class="scan-laser" aria-hidden="true"></div>{blocks}</div>'
        f'<div class="caliper-row"><span class="caliper-lbl">Length caliper: <strong id="caliper-len-num">{char_len}</strong> chars</span>'
        f'<div class="caliper-bar"><div class="caliper-fill" style="width: {len_pct:.1f}%;"></div>'
        f'<div class="caliper-tick" style="left: 54%;" title="54 char suspicious threshold"></div>'
        f'<div class="caliper-tick" style="left: 75%;" title="75 char phishing threshold"></div></div>'
        f'<span class="caliper-lbl">Thresholds 54 / 75</span></div>'
        f'<div class="vec-grid">{slots}</div></section>'
    )


def _render_verdict(url, note, risk_pct, result):
    """Renders verdict tag, inspected URL, 576-node lookup grid, score readout, and gauge."""
    tone = risk_tone(risk_pct)
    color = TONES[tone]
    return (
        f'<section class="verdict"><div>'
        f'<div class="tag"><span id="verdict-dot" class="dot" style="background: {color};"></span>'
        f'<span id="verdict-label-txt">{VERDICT_LABELS[tone]}</span>'
        f'<span class="tag-note">{esc(note)}</span></div>'
        f'{_render_url(url, result)}</div>'
        f'<div class="verdict-right">{_render_matrix_collapse(result)}'
        f'<div class="score"><div id="verdict-score-num" class="score-num" data-val="{risk_pct:.1f}">{risk_pct:.1f}%</div>'
        f'<div id="verdict-score-cap" class="score-cap">Phishing probability</div></div></div></section>'
        f'{_render_gauge(risk_pct, color)}'
        f'{_render_shredder(url, result)}'
    )


def _model_item(idx, entry):
    """Renders one model agreement readout with a hairline bar."""
    pct = clamp_pct(entry["prob_pct"])
    color = RISK if entry["verdict"] == "Phishing" else SAFE
    return (
        f'<div><div class="model-name">{esc(entry["name"])}</div>'
        f'<div id="model-val-{idx}" class="model-val">{pct:.1f}%</div>'
        f'<div class="model-track"><div id="model-fill-{idx}" class="model-fill" style="width: {pct:.1f}%; background: {color};"></div></div></div>'
    )


def _render_models(result):
    """Renders the three model agreement row."""
    items = "".join(_model_item(i, e) for i, e in enumerate(result["consensus"]))
    return f'<section class="models">{items}</section>'


# Stage 3: Shapley Spring-Stack and Drivers


def _logit_pct(logit_val):
    """Maps a log odds coordinate in [-4.5, 4.5] onto a [6%, 94%] horizontal track position."""
    clamped = max(-4.5, min(4.5, float(logit_val)))
    return 6.0 + (clamped + 4.5) / 9.0 * 88.0


def _spring_block(idx, item):
    """Renders one physics attribution block in the horizontal Shapley spring stack."""
    s_val = item["shap_value"]
    width_pct = max(2.2, min(22.0, abs(s_val) / 4.5 * 88.0))
    cls = "sblk-risk" if s_val >= 0 else "sblk-safe"
    short = feature_label(item["feature"]).split(" ")[0]
    return (
        f'<div id="sblk-{item["feature"]}" class="sblk {cls}" data-feat="{item["feature"]}" '
        f'style="width: {width_pct:.1f}%; animation-delay: {idx * 45}ms;" '
        f'title="{esc(feature_label(item["feature"]))}: {_fmt_delta(s_val, 3)} log odds">'
        f'<span class="sblk-txt">{esc(short)} {_fmt_delta(s_val, 2)}</span></div>'
    )


def _render_shapley_stack(result):
    """Renders Stage 3: The Shapley Spring-Stack log odds tug of war and sigmoid coupler."""
    base_val = float(result["base_value"])
    top_items = result["all_features"][:TOP_DRIVERS]
    net_logit = base_val + sum(d["shap_value"] for d in result["all_features"])
    prior_x = _logit_pct(base_val)
    net_x = _logit_pct(net_logit)
    risk_pct = result["phishing_probability"] * 100.0
    pos_blocks = "".join(_spring_block(i, d) for i, d in enumerate(top_items) if d["shap_value"] >= 0)
    neg_blocks = "".join(_spring_block(i, d) for i, d in enumerate(top_items) if d["shap_value"] < 0)
    return (
        f'<div class="spring-card">'
        f'<div class="spring-head">'
        f'<div><span class="spring-title">Shapley spring stack (TreeSHAP log odds tug of war)</span>'
        f'<span class="spring-sub">Red blocks shove the posterior axis right toward phishing; green blocks push it left toward legitimate</span></div>'
        f'<span id="spring-math-tag" class="spring-meta">Prior {_fmt_delta(base_val, 2)} \u2192 Net {_fmt_delta(net_logit, 2)} log odds ({risk_pct:.1f}%)</span></div>'
        f'<div class="sig-scale"><span>2%</span><span>12%</span><span>Threshold 50% (0.00)</span><span>88%</span><span>98%</span></div>'
        f'<div class="spring-stage">'
        f'<div class="zero-line" style="left: 50%;" title="0.00 log odds (50% threshold)"></div>'
        f'<div id="stack-prior-line" class="prior-line" style="left: {prior_x:.1f}%;"><span class="prior-tag">Base prior {_fmt_delta(base_val, 2)}</span></div>'
        f'<div class="tug-lanes">'
        f'<div id="tug-lane-neg" class="tug-lane tug-neg">{neg_blocks}</div>'
        f'<div id="tug-lane-pos" class="tug-lane tug-pos">{pos_blocks}</div></div>'
        f'<div id="stack-net-axis" class="net-axis" style="left: {net_x:.1f}%;">'
        f'<span id="stack-net-tag" class="net-tag">Posterior {_fmt_delta(net_logit, 2)}</span></div></div>'
        f'<div class="logit-scale"><span>\u22124.0 log odds</span><span>\u22122.0</span><span>0.0</span><span>+2.0</span><span>+4.0 log odds</span></div></div>'
    )


def _pick_button(idx, feat_name, opt, current):
    """Renders one counterfactual state button with hover preview and instant click morph."""
    return (
        f'<button type="button" class="pick-btn {_active(opt, current, "on")}" data-opt="{opt}" '
        f'onmouseenter="previewOverride({idx}, {opt})" onmouseleave="clearPreview()" '
        f'onclick="setFeatureOverride({idx}, {opt})">{_fmt_state_val(opt)}</button>'
    )


def _state_picker(item):
    """Renders the counterfactual state picker for a live lexical feature."""
    idx = LIVE_FEATURES.index(item["feature"])
    opts = (-1, 0, 1) if item["feature"] in TERNARY_LIVE_FEATURES else (-1, 1)
    buttons = "".join(_pick_button(idx, item["feature"], opt, item["value"]) for opt in opts)
    return f'<div class="pick" data-picker-idx="{idx}" title="Change this signal to morph the URL and score">{buttons}</div>'


def _driver_bar(feat_name, shap_val, max_abs, delay_ms):
    """Renders a diverging bar: right raises risk, left lowers it."""
    width = min(50.0, abs(shap_val) / max_abs * 50.0)
    side = "fill-up" if shap_val > 0 else "fill-down"
    return (
        f'<div class="track"><div id="drv-fill-{feat_name}" class="fill {side}" '
        f'style="width: {width:.1f}%; animation-delay: {delay_ms}ms;"></div></div>'
    )


def _driver_value_color(shap_val):
    """Colors the numeric contribution only when it is meaningful."""
    if abs(shap_val) < 0.005:
        return NEUTRAL
    return RISK if shap_val > 0 else SAFE


def _driver_row(mode, item, max_abs, idx):
    """Renders one feature contribution row."""
    feat = item["feature"]
    shap_val = item["shap_value"]
    extra = " driver-extra" if mode == "uci" and idx >= TOP_DRIVERS else ""
    picker = f"<div>{_state_picker(item)}</div>" if mode == "live" else ""
    return (
        f'<div id="drv-row-{feat}" class="driver{extra}" data-feat="{feat}"><div>'
        f'<div class="driver-name">{esc(feature_label(feat))}'
        f'<span id="drv-key-{feat}" class="driver-key">{esc(feat)} {_fmt_state_val(item["value"])}</span></div>'
        f'<div id="drv-txt-{feat}" class="driver-text">{esc(item["human_text"])}</div></div>'
        f'{picker}{_driver_bar(feat, shap_val, max_abs, min(idx, TOP_DRIVERS) * 40)}'
        f'<div id="drv-val-{feat}" class="driver-val" style="color: {_driver_value_color(shap_val)};">{_fmt_delta(shap_val, 3)}</div></div>'
    )


def _drivers_head(mode, has_overrides):
    """Renders the drivers section header with a mode specific control."""
    sub = (
        "Each signal pushes the score up or down. Click any state pill or recourse fix to morph the URL and waterfall."
        if mode == "live"
        else "Each signal pushes the score up or down, measured in TreeSHAP log odds."
    )
    toggle = (
        '<div class="seg"><button id="drivers-top-btn" type="button" class="seg-btn active" '
        'onclick="toggleDrivers(false)">Top 8</button><button id="drivers-all-btn" type="button" '
        'class="seg-btn" onclick="toggleDrivers(true)">All 30</button></div>'
    )
    reset = f'<button id="reset-overrides-btn" type="button" class="btn" onclick="resetLiveOverrides()"{"" if has_overrides else " hidden"}>Reset signals</button>'
    control = toggle if mode == "uci" else reset
    return (
        f'<div class="section-head"><div><div class="section-title">What drove this score</div>'
        f'<div class="section-sub">{sub}</div></div>{control}</div>'
    )


def _drivers_axis(mode):
    """Renders the axis caption above the diverging bars."""
    spacer = '<div class="axis-spacer"></div>' if mode == "live" else ""
    return (
        f'<div class="axis"><div class="axis-spacer"></div>{spacer}'
        f'<div class="axis-labels"><span>Lowers risk (legitimate)</span><span>Raises risk (phishing)</span></div>'
        f'<div style="text-align: right;">Log odds</div></div>'
    )


def _render_drivers(mode, result):
    """Renders the Shapley spring stack and individual feature contribution rows."""
    drivers = result["all_features"]
    max_abs = max([abs(d["shap_value"]) for d in drivers] + [0.1])
    rows = "".join(_driver_row(mode, item, max_abs, idx) for idx, item in enumerate(drivers))
    live_cls = " live" if mode == "live" else ""
    return (
        f'<section class="section"><div class="rule" style="margin-bottom: 32px;"></div>'
        f'{_drivers_head(mode, result.get("has_overrides", False))}'
        f'{_render_shapley_stack(result)}'
        f'<div id="drivers-list" class="drivers{live_cls}">{_drivers_axis(mode)}{rows}</div></section>'
    )


def _fix_row(hint):
    """Renders one interactive counterfactual recourse row that triggers inline URL morphing."""
    feat = hint["feature"]
    feat_idx = LIVE_FEATURES.index(feat) if feat in LIVE_FEATURES else -1
    sug_val = int(hint.get("suggested_value", 1))
    action_attrs = (
        f'onclick="applyCounterfactual({feat_idx}, {sug_val}, \'{feat}\')" '
        f'onmouseenter="previewOverride({feat_idx}, {sug_val})" onmouseleave="clearPreview()"'
        if feat_idx >= 0
        else f'onclick="morphUrlTokenOnly(\'{feat}\')"'
    )
    return (
        f'<div class="fix" data-fix-feat="{feat}" role="button" tabindex="0" {action_attrs}>'
        f'<div><div class="driver-name">{esc(feature_label(feat))}'
        f'<span class="fix-badge">Click to erase token &amp; morph score</span></div>'
        f'<div class="fix-text">{esc(_clean_copy(hint["guidance"]))}</div></div>'
        f'<div class="fix-gain">\u2212{hint["risk_reduction_pct"]:.1f}%</div></div>'
    )


def _render_fixes(hints):
    """Renders Stage 4: Counterfactual Morphing recourse cards."""
    hidden = "" if hints else " hidden"
    rows = "".join(_fix_row(h) for h in (hints or [])[:3])
    return (
        f'<section id="fixes-section" class="section"{hidden}><div class="section-head"><div>'
        f'<div class="section-title">What would lower the score (counterfactual morphing)</div>'
        f'<div class="section-sub">Click a recourse hint to physically erase the offending token from the URL and watch the gauge and Shapley bars collapse in sync.</div>'
        f'</div></div><div id="fixes-list">{rows}</div></section>'
    )


def _results_html(mode, url, note, result):
    """Assembles the full result block for one diagnosis."""
    risk_pct = result["phishing_probability"] * 100.0
    base_vec = json.dumps(result.get("base_vector", [1] * 8))
    live_vec = json.dumps(result.get("live_vector", [1] * 8))
    return (
        f'<div id="results-root" class="results" data-mode="{mode}" data-base-vec="{esc(base_vec)}" '
        f'data-live-vec="{esc(live_vec)}" data-base-val="{result["base_value"]:.4f}">'
        f'{_render_verdict(url, note, risk_pct, result)}'
        f'{_render_models(result)}{_render_drivers(mode, result)}'
        f'{_render_fixes(result.get("counterfactual_hints") or [])}</div>'
    )


def _live_payload(url, overrides):
    """Builds the API payload for a live URL diagnosis."""
    t0 = time.perf_counter()
    res = diagnose_live(url, overrides)
    ms = max(0.1, (time.perf_counter() - t0) * 1000.0)
    note = f"Eight address signals, scored in {ms:.1f} ms"
    return {
        "mode": "live",
        "clean_url": res["clean_url"],
        "has_overrides": res["has_overrides"],
        "feature_values": res["feature_values"],
        "risk_pct": round(res["phishing_probability"] * 100.0, 1),
        "html": _results_html("live", res["clean_url"], note, res),
    }


def _uci_payload(idx):
    """Builds the API payload for a benchmark record diagnosis."""
    res = diagnose_uci(idx)
    agree = "matches" if res["prediction"] == res["true_label"] else "differs from"
    note = f"Prediction {agree} ground truth ({res['true_label'].lower()})"
    return {
        "mode": "uci",
        "idx": res["idx"],
        "url": res["url"],
        "true_label": res["true_label"],
        "risk_pct": round(res["phishing_probability"] * 100.0, 1),
        "html": _results_html("uci", res["url"], note, res),
    }


def build_diagnose_payload(mode="uci", url=None, idx=DEFAULT_UCI_IDX, overrides=None):
    """Returns the JSON payload with rendered result HTML for the requested mode."""
    if mode == "live":
        return _live_payload(url, overrides)
    return _uci_payload(idx)


# Inspect tab


def _uci_controls(payload, total, is_active):
    """Renders the benchmark record bar."""
    hidden = "" if is_active else " hidden"
    return (
        f'<div id="controls-uci"{hidden}><div class="bar">'
        f'<span id="uci-url-text" class="bar-field">{esc(payload["url"])}</span>'
        f'<span id="uci-record-counter" class="counter">{payload["idx"] + 1:,} / {total:,}</span>'
        f'<button type="button" class="btn btn-icon" onclick="stepUci(-1)" aria-label="Previous record">{ICON_PREV}</button>'
        f'<button type="button" class="btn btn-icon" onclick="stepUci(1)" aria-label="Next record">{ICON_NEXT}</button>'
        f'<button type="button" class="btn btn-primary" onclick="pickRandomUci()">{ICON_SHUFFLE}Random</button>'
        f'<input id="uci-idx-input" type="hidden" value="{payload["idx"]}"></div></div>'
    )


def _live_controls(live_url, is_active):
    """Renders the live URL input bar and example presets."""
    hidden = "" if is_active else " hidden"
    presets = "".join(
        f'<button type="button" class="preset" onclick="scanPreset({esc(json.dumps(u))})">{esc(lbl)}</button>'
        for lbl, u in URL_PRESETS
    )
    return (
        f'<div id="controls-live" class="query"{hidden}>'
        f'<form class="bar" onsubmit="submitLiveScan(event)">'
        f'<input id="live-url-input" class="bar-field" type="text" value="{esc(live_url)}" '
        f'placeholder="Paste a URL to inspect" spellcheck="false" autocomplete="off">'
        f'<button type="submit" class="btn btn-primary">Analyze</button></form>'
        f'<div class="presets"><span class="presets-label">Try</span>{presets}</div></div>'
    )


def _render_inspect_tab(mode, live_url, uci_payload, total, active_payload):
    """Renders the inspect tab: intro, mode switch, query bar, and results."""
    return (
        '<div class="intro"><h1>Inspect a URL</h1>'
        '<p>See how likely an address is to be phishing, and which signals drove the score.</p></div>'
        f'<div class="query"><div class="seg">'
        f'<button id="mode-btn-uci" type="button" class="seg-btn {_active(mode, "uci")}" onclick="setInspectMode(\'uci\')">Benchmark records</button>'
        f'<button id="mode-btn-live" type="button" class="seg-btn {_active(mode, "live")}" onclick="setInspectMode(\'live\')">Your URL</button></div>'
        f'{_uci_controls(uci_payload, total, mode == "uci")}{_live_controls(live_url, mode == "live")}</div>'
        f'<div id="inspect-results">{active_payload["html"]}</div>'
    )


# Evaluation tab


def _svg_points(fpr_list, tpr_list):
    """Converts FPR and TPR lists into SVG polyline coordinates."""
    return " ".join(f"{56 + fx * 440:.1f},{256 - ty * 236:.1f}" for fx, ty in zip(fpr_list, tpr_list))


def _roc_grid():
    """Renders ROC chart gridlines and tick labels."""
    return "".join(
        f'<line x1="56" y1="{256 - v * 236:.1f}" x2="496" y2="{256 - v * 236:.1f}" stroke="#272727"/>'
        f'<text x="44" y="{260 - v * 236:.1f}" fill="#7A7A7A" font-family="Geist Mono" font-size="12" text-anchor="end">{v:.1f}</text>'
        f'<text x="{56 + v * 440:.1f}" y="278" fill="#7A7A7A" font-family="Geist Mono" font-size="12" text-anchor="middle">{v:.1f}</text>'
        for v in (0.0, 0.5, 1.0)
    )


def _roc_svg(scores):
    """Renders ROC curves for three models plus the live threshold marker."""
    curves = (
        ("xgboost_live_lexical_8", "#7A7A7A", "4 4"),
        ("random_forest_full_30", "#A1A1A1", "none"),
        ("xgboost_full_30", "#FFFFFF", "none"),
    )
    lines = "".join(
        f'<polyline fill="none" stroke="{c}" stroke-width="1.5" stroke-dasharray="{d}" '
        f'points="{_svg_points(scores[k]["curve_samples"]["fpr"], scores[k]["curve_samples"]["tpr"])}"/>'
        for k, c, d in curves
    )
    return (
        f'<svg class="roc" viewBox="0 0 520 290" role="img" aria-label="ROC curves">{_roc_grid()}'
        f'<line x1="56" y1="256" x2="496" y2="20" stroke="#313131" stroke-dasharray="2 4"/>{lines}'
        f'<circle id="roc-active-dot" class="roc-dot" cx="72" cy="30" r="5" fill="#E5484D" stroke="#181818" stroke-width="2"/></svg>'
    )


def _legend():
    """Renders the ROC chart legend."""
    items = (("XGBoost, 30 signals", "#FFFFFF"), ("Random forest", "#A1A1A1"), ("XGBoost, 8 address signals", "#7A7A7A"))
    return '<div class="legend">' + "".join(
        f'<span class="legend-item"><span class="legend-line" style="background: {c};"></span>{lbl}</span>'
        for lbl, c in items
    ) + "</div>"


def _cm_grid():
    """Renders the confusion matrix quadrants that the client script fills in."""
    cells = (
        ("tn", "Correctly passed", SAFE),
        ("fp", "False alarm", RISK),
        ("fn", "Missed phishing", RISK),
        ("tp", "Caught phishing", SAFE),
    )
    return '<div class="cm">' + "".join(
        f'<div class="cm-cell"><div class="cm-label"><span class="dot" style="background: {c};"></span>{lbl}</div>'
        f'<div id="cm-{k}-cnt" class="cm-count">0</div><div id="cm-{k}-pct" class="cm-pct">0.0% of test set</div>'
        f'<div class="cm-track"><div id="cm-{k}-bar" class="cm-fill" style="width: 0%; background: {c};"></div></div></div>'
        for k, lbl, c in cells
    ) + "</div>"


def _stat(label, value, value_id=""):
    """Renders a plain label and value statistic."""
    id_attr = f' id="{value_id}"' if value_id else ""
    return f'<div><div class="stat-label">{label}</div><div class="stat-val"{id_attr}>{value}</div></div>'


def _model_table(scores):
    """Renders the comparative model metrics table."""
    specs = (
        ("XGBoost", "30 signals", "xgboost_full_30"),
        ("Random forest", "30 signals", "random_forest_full_30"),
        ("Logistic regression", "30 signals", "logistic_regression_full_30"),
        ("XGBoost", "8 address signals", "xgboost_live_lexical_8"),
    )
    head = "".join(f"<th>{h}</th>" for h in ("Model", "Accuracy", "Precision", "Recall", "F1", "ROC AUC", "MCC"))
    rows = "".join(
        f'<tr><td>{name}<span class="sub">{sub}</span></td>'
        f'<td>{scores[k]["accuracy"] * 100:.2f}%</td><td>{scores[k]["precision"] * 100:.2f}%</td>'
        f'<td>{scores[k]["recall"] * 100:.2f}%</td><td>{scores[k]["f1"]:.3f}</td>'
        f'<td>{scores[k]["roc_auc"]:.3f}</td><td>{scores[k]["mcc"]:.3f}</td></tr>'
        for name, sub, k in specs
    )
    return f'<div class="table-wrap"><table class="table"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>'


def _threshold_card():
    """Renders the decision threshold slider with live precision and recall."""
    stats = (
        _stat("Precision", "0%", "kpi-prec-val") + _stat("Recall", "0%", "kpi-rec-val")
        + _stat("F1 score", "0", "kpi-f1-val") + _stat("False alarms / missed", "0 / 0", "kpi-fpfn-val")
    )
    return (
        '<div class="card"><div class="card-head"><span class="card-title">Decision threshold</span>'
        '<span class="card-meta">Flag as phishing when probability is at or above</span></div>'
        '<div class="slider-row"><input id="threshold-slider" class="range" type="range" min="0.05" max="0.95" '
        'step="0.05" value="0.50" oninput="drawEvalCharts()" aria-label="Decision threshold">'
        '<span id="thresh-readout" class="slider-val">0.50</span></div>'
        f'<div class="thresh-stats">{stats}</div></div>'
    )


def _importance_list(global_shap):
    """Renders global mean absolute TreeSHAP importance bars."""
    top = max([d["mean_shap"] for d in global_shap] + [0.1])
    rows = "".join(
        f'<div class="imp"><span class="imp-name">{esc(feature_label(d["feature"]))}</span>'
        f'<div class="imp-track"><div class="imp-fill" style="width: {d["mean_shap"] / top * 100:.1f}%; '
        f'background: {"#FFFFFF" if d["is_live"] else "#3A3A3A"};"></div></div>'
        f'<span class="imp-val">{d["mean_shap"]:.3f}</span></div>'
        for d in global_shap
    )
    return (
        '<section class="section"><div class="section-head"><div><div class="section-title">Most influential signals</div>'
        '<div class="section-sub">Mean absolute TreeSHAP value across the test set. Light bars can be read from the address alone.</div>'
        f'</div></div>{rows}</section>'
    )


def _render_eval_tab(data):
    """Renders the model evaluation tab."""
    scores = data["metrics"]["models"]
    best = scores["xgboost_full_30"]
    total = len(data["bundle"]["test_eval"]["y_true"])
    stats = (
        _stat("Accuracy", f'{best["accuracy"] * 100:.2f}%') + _stat("Recall", f'{best["recall"] * 100:.2f}%')
        + _stat("ROC AUC", f'{best["roc_auc"]:.3f}')
        + _stat("Address only accuracy", f'{scores["xgboost_live_lexical_8"]["accuracy"] * 100:.2f}%')
    )
    charts = (
        '<div class="split"><div class="card"><div class="card-head"><span class="card-title">ROC curve</span>'
        f'<span id="roc-coords-label" class="card-meta">FPR 0%  TPR 0%</span></div>{_roc_svg(scores)}{_legend()}</div>'
        '<div class="card"><div class="card-head"><span class="card-title">Outcomes at threshold</span>'
        f'<span class="card-meta">{total:,} records</span></div>{_cm_grid()}</div></div>'
    )
    return (
        '<div class="intro"><h1>Model evaluation</h1>'
        f'<p>Measured on a held out partition of {total:,} records the models never saw during training.</p></div>'
        f'<div class="stats">{stats}</div>'
        f'<section class="section"><div class="rule" style="margin-bottom: 32px;"></div>{_model_table(scores)}</section>'
        f'<section class="section">{_threshold_card()}{charts}</section>'
        f'{_importance_list(data["bundle"]["test_eval"]["global_shap"])}'
    )


# Catalog tab


def _catalog_card(name, meta, prevalence):
    """Renders one feature catalog card."""
    mode_tag = "Live lexical only" if meta.get("extractable_live", False) else "Offline network and DOM"
    group = _clean_copy(meta.get("group", ""))
    desc = _clean_copy(meta.get("description", ""))
    rule = _clean_copy(meta.get("rule", ""))
    search = f"{name} {feature_label(name)} {group} {desc} {rule}".lower()
    p_phish, p_susp, p_legit = prevalence
    return (
        f'<article class="cat" data-domain="{esc(group)}" data-mode="{mode_tag}" data-search="{esc(search)}">'
        f'<div class="cat-head"><div><div class="cat-name">{esc(feature_label(name))}</div>'
        f'<div class="cat-key">{esc(name)}</div></div><span class="cat-group">{esc(group)}</span></div>'
        f'<div class="cat-desc">{esc(desc)}</div><div class="cat-rule">{esc(rule)}</div>'
        f'<div class="prev"><div class="prev-track">'
        f'<div style="width: {p_phish:.1f}%; background: {RISK};"></div>'
        f'<div style="width: {p_susp:.1f}%; background: {TONES["warning"]};"></div>'
        f'<div style="width: {p_legit:.1f}%; background: #3A3A3A;"></div></div>'
        f'<div class="prev-legend"><span>Phishing {p_phish:.0f}%</span><span>Suspicious {p_susp:.0f}%</span>'
        f'<span>Normal {p_legit:.0f}%</span></div></div></article>'
    )


def _render_catalog_tab(data):
    """Renders the feature catalog tab with search and filters."""
    catalog = data["catalog"]
    count = len(catalog["features"])
    domains = "".join(
        f'<option value="{esc(_clean_copy(g))}">{esc(_clean_copy(g))}</option>'
        for g in ["All domains"] + list(catalog["feature_groups"].keys())
    )
    modes = "".join(f'<option value="{m}">{m}</option>' for m in ("All features", "Live lexical only", "Offline network and DOM"))
    cards = "".join(
        _catalog_card(name, meta, data["bundle"]["prevalence"].get(name, [0.0, 0.0, 100.0]))
        for name, meta in catalog["features"].items()
    )
    return (
        '<div class="intro"><h1>Feature catalog</h1>'
        f'<p>The {count} signals the models read, what each one checks, and how often it fires in the test set.</p></div>'
        '<div class="filters"><input id="cat-search-input" class="field field-grow" type="text" '
        'placeholder="Search signals" oninput="filterCatalog()" spellcheck="false">'
        f'<select id="cat-domain-select" class="field" onchange="filterCatalog()">{domains}</select>'
        f'<select id="cat-mode-select" class="field" onchange="filterCatalog()">{modes}</select>'
        f'<span id="cat-match-count" class="match">{count} of {count}</span></div>'
        f'<div class="cat-grid">{cards}</div>'
    )


# Page


def _render_nav(active_tab):
    """Renders the top navigation bar."""
    tabs = (("inspect", "Inspect"), ("eval", "Evaluation"), ("catalog", "Features"))
    buttons = "".join(
        f'<button type="button" data-tab="{tid}" class="nav-tab {_active(active_tab, tid)}" '
        f'onclick="switchTab(\'{tid}\')">{lbl}</button>'
        for tid, lbl in tabs
    )
    return (
        f'<header class="nav"><div class="brand">{LOGO_SVG}PhishLens</div>'
        f'<nav class="nav-tabs">{buttons}</nav><span class="nav-meta">XGBoost with TreeSHAP</span></header>'
        f'<div class="rule"></div>'
    )


def _panel(tab_id, active_tab, body):
    """Wraps tab content in a switchable panel."""
    return f'<main id="panel-{tab_id}" class="panel {_active(active_tab, tab_id)}">{body}</main>'


def _live_feat_meta(catalog):
    """Builds compact plain explanations for the 8 live features for client morphing."""
    out = {}
    for feat in LIVE_FEATURES:
        meta = catalog["features"].get(feat, {})
        out[feat] = {
            "label": feature_label(feat),
            "risk": _clean_copy(meta.get("plain_explanation_phishing", "")),
            "safe": _clean_copy(meta.get("plain_explanation_legit", "")),
        }
    return out


def render_full_page_html(mode="live", url=None, idx=DEFAULT_UCI_IDX, tab="inspect", overrides=None):
    """Renders the complete PhishLens console HTML document."""
    data = load_runtime_data()
    live_url = url or DEFAULT_LIVE_URL
    uci_payload = build_diagnose_payload("uci", idx=idx)
    active = build_diagnose_payload("live", url=live_url, overrides=overrides) if mode == "live" else uci_payload
    test_eval = data["bundle"]["test_eval"]
    total = len(test_eval["y_true"])
    boot = json.dumps({"y_true": test_eval["y_true"], "y_probs": test_eval["y_probs"]}, separators=(",", ":"))
    lattice = json.dumps(build_client_lattice(), separators=(",", ":"))
    feat_meta = json.dumps(_live_feat_meta(data["catalog"]), separators=(",", ":"))
    inspect = _render_inspect_tab(mode, live_url, uci_payload, total, active)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>PhishLens</title>'
        '<meta name="description" content="Explainable phishing URL detection with XGBoost and TreeSHAP.">'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@400;500&display=swap">'
        f'<style>{PAGE_CSS}</style></head><body><div class="page">{_render_nav(tab)}'
        f'{_panel("inspect", tab, inspect)}{_panel("eval", tab, _render_eval_tab(data))}'
        f'{_panel("catalog", tab, _render_catalog_tab(data))}'
        '<footer class="footer">PhishLens. Research prototype for explainable phishing detection.</footer>'
        f'</div><script>{CONSOLE_JS}\nwindow.__evalData = {boot};\nwindow.__liveLattice = {lattice};\nwindow.__featMeta = {feat_meta};\ninitTelemetry(); drawEvalCharts();</script></body></html>'
    )
