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
    diagnose_live,
    diagnose_uci,
    load_runtime_data,
    risk_tone,
)

TONES = {"critical": "#E5484D", "warning": "#E2A336", "safe": "#30A46C"}
RISK, SAFE, NEUTRAL = TONES["critical"], TONES["safe"], "#7A7A7A"
TOP_DRIVERS = 8
TERNARY_LIVE_FEATURES = frozenset({"URL_Length", "having_Sub_Domain"})
VERDICT_LABELS = {"critical": "Likely phishing", "warning": "Suspicious", "safe": "Looks legitimate"}

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
    '<circle cx="8" cy="8" r="6" stroke="#EDEDED" stroke-width="1.5"/>'
    '<path d="M12.5 12.5L16.5 16.5" stroke="#EDEDED" stroke-width="1.5" stroke-linecap="round"/>'
    '<circle cx="8" cy="8" r="2" fill="#EDEDED"/></svg>'
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


# Verdict


def _url_segment(seg, shap_val):
    """Wraps one URL segment, underlining parts that raise risk."""
    if shap_val > 0.01:
        return f'<span class="url-risk" title="Raises risk by {_fmt_delta(shap_val, 3)} log odds">{esc(seg)}</span>'
    return f"<span>{esc(seg)}</span>"


def _render_url(url, result):
    """Renders the inspected address with risky segments underlined."""
    tokens = _parse_url_tokens(url)
    shaps = {d["feature"]: d["shap_value"] for d in result["all_features"]}
    segments = _specimen_segments(tokens, _resolve_rail_cells(tokens, shaps))
    parts = "".join(_url_segment(seg, s) for seg, s in segments)
    has_risk = any(s > 0.01 for _, s in segments)
    hint = '<div class="url-hint">Underlined parts of the address raise the risk score.</div>' if has_risk else ""
    return f'<div class="url">{parts}</div>{hint}'


def _render_gauge(risk_pct, color):
    """Renders a thin probability gauge with a decision threshold tick at 50 percent."""
    return (
        f'<div class="gauge"><div class="gauge-fill" style="width: {clamp_pct(risk_pct):.1f}%; background: {color};"></div>'
        f'<div class="gauge-tick" title="Decision threshold"></div></div>'
        f'<div class="gauge-scale"><span>0</span><span class="gauge-mid">Threshold 50</span><span>100</span></div>'
    )


def _render_verdict(url, note, risk_pct, result):
    """Renders verdict tag, inspected URL, large probability readout, and gauge."""
    tone = risk_tone(risk_pct)
    color = TONES[tone]
    return (
        f'<section class="verdict"><div>'
        f'<div class="tag"><span class="dot" style="background: {color};"></span>{VERDICT_LABELS[tone]}'
        f'<span class="tag-note">{esc(note)}</span></div>'
        f'{_render_url(url, result)}</div>'
        f'<div class="score"><div id="verdict-score-num" class="score-num" data-val="{risk_pct:.1f}">{risk_pct:.1f}%</div>'
        f'<div class="score-cap">Phishing probability</div></div></section>'
        f'{_render_gauge(risk_pct, color)}'
    )


def _model_item(entry):
    """Renders one model agreement readout with a hairline bar."""
    pct = clamp_pct(entry["prob_pct"])
    color = RISK if entry["verdict"] == "Phishing" else SAFE
    return (
        f'<div><div class="model-name">{esc(entry["name"])}</div>'
        f'<div class="model-val">{pct:.1f}%</div>'
        f'<div class="model-track"><div class="model-fill" style="width: {pct:.1f}%; background: {color};"></div></div></div>'
    )


def _render_models(result):
    """Renders the three model agreement row."""
    return f'<section class="models">{"".join(map(_model_item, result["consensus"]))}</section>'


# Drivers


def _pick_button(idx, opt, current):
    """Renders one counterfactual state button for live mode."""
    return (
        f'<button type="button" class="pick-btn {_active(opt, current, "on")}" '
        f'onclick="setFeatureOverride({idx}, {opt})">{_fmt_state_val(opt)}</button>'
    )


def _state_picker(item):
    """Renders the counterfactual state picker for a live lexical feature."""
    idx = LIVE_FEATURES.index(item["feature"])
    opts = (-1, 0, 1) if item["feature"] in TERNARY_LIVE_FEATURES else (-1, 1)
    buttons = "".join(_pick_button(idx, opt, item["value"]) for opt in opts)
    return f'<div class="pick" title="Change this signal to see how the score moves">{buttons}</div>'


def _driver_bar(shap_val, max_abs, delay_ms):
    """Renders a diverging bar: right raises risk, left lowers it."""
    width = min(50.0, abs(shap_val) / max_abs * 50.0)
    side = "fill-up" if shap_val > 0 else "fill-down"
    return (
        f'<div class="track"><div class="fill {side}" '
        f'style="width: {width:.1f}%; animation-delay: {delay_ms}ms;"></div></div>'
    )


def _driver_value_color(shap_val):
    """Colors the numeric contribution only when it is meaningful."""
    if abs(shap_val) < 0.005:
        return NEUTRAL
    return RISK if shap_val > 0 else SAFE


def _driver_row(mode, item, max_abs, idx):
    """Renders one feature contribution row."""
    shap_val = item["shap_value"]
    extra = " driver-extra" if mode == "uci" and idx >= TOP_DRIVERS else ""
    picker = f"<div>{_state_picker(item)}</div>" if mode == "live" else ""
    return (
        f'<div class="driver{extra}"><div>'
        f'<div class="driver-name">{esc(feature_label(item["feature"]))}'
        f'<span class="driver-key">{esc(item["feature"])} {_fmt_state_val(item["value"])}</span></div>'
        f'<div class="driver-text">{esc(item["human_text"])}</div></div>'
        f'{picker}{_driver_bar(shap_val, max_abs, min(idx, TOP_DRIVERS) * 40)}'
        f'<div class="driver-val" style="color: {_driver_value_color(shap_val)};">{_fmt_delta(shap_val, 3)}</div></div>'
    )


def _drivers_head(mode, has_overrides):
    """Renders the drivers section header with a mode specific control."""
    sub = (
        "Each signal pushes the score up or down. Change a signal to see the effect."
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
        f'<div class="axis-labels"><span>Lowers risk</span><span>Raises risk</span></div>'
        f'<div style="text-align: right;">Log odds</div></div>'
    )


def _render_drivers(mode, result):
    """Renders the feature contribution section."""
    drivers = result["all_features"]
    max_abs = max([abs(d["shap_value"]) for d in drivers] + [0.1])
    rows = "".join(_driver_row(mode, item, max_abs, idx) for idx, item in enumerate(drivers))
    live_cls = " live" if mode == "live" else ""
    return (
        f'<section class="section"><div class="rule" style="margin-bottom: 32px;"></div>{_drivers_head(mode, result.get("has_overrides", False))}'
        f'<div class="drivers{live_cls}">{_drivers_axis(mode)}{rows}</div></section>'
    )


def _fix_row(hint):
    """Renders one counterfactual suggestion row."""
    return (
        f'<div class="fix"><div><div class="driver-name">{esc(feature_label(hint["feature"]))}</div>'
        f'<div class="fix-text">{esc(_clean_copy(hint["guidance"]))}</div></div>'
        f'<div class="fix-gain">\u2212{hint["risk_reduction_pct"]:.1f}%</div></div>'
    )


def _render_fixes(hints):
    """Renders counterfactual suggestions, or nothing when there are none."""
    if not hints:
        return ""
    return (
        f'<section class="section"><div class="section-head"><div>'
        f'<div class="section-title">What would lower the score</div>'
        f'<div class="section-sub">Single signal changes with the largest drop in phishing probability.</div>'
        f'</div></div>{"".join(_fix_row(h) for h in hints[:3])}</section>'
    )


def _results_html(mode, url, note, result):
    """Assembles the full result block for one diagnosis."""
    risk_pct = result["phishing_probability"] * 100.0
    return (
        f'<div class="results">{_render_verdict(url, note, risk_pct, result)}'
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
        ("xgboost_full_30", "#EDEDED", "none"),
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
    items = (("XGBoost, 30 signals", "#EDEDED"), ("Random forest", "#A1A1A1"), ("XGBoost, 8 address signals", "#7A7A7A"))
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
        f'background: {"#EDEDED" if d["is_live"] else "#3A3A3A"};"></div></div>'
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


def render_full_page_html(mode="uci", url=None, idx=DEFAULT_UCI_IDX, tab="inspect", overrides=None):
    """Renders the complete PhishLens console HTML document."""
    data = load_runtime_data()
    live_url = url or DEFAULT_LIVE_URL
    uci_payload = build_diagnose_payload("uci", idx=idx)
    active = build_diagnose_payload("live", url=live_url, overrides=overrides) if mode == "live" else uci_payload
    test_eval = data["bundle"]["test_eval"]
    total = len(test_eval["y_true"])
    boot = json.dumps({"y_true": test_eval["y_true"], "y_probs": test_eval["y_probs"]})
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
        f'</div><script>{CONSOLE_JS}\nwindow.__evalData = {boot}; drawEvalCharts();</script></body></html>'
    )
