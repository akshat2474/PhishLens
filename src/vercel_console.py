"""
Data layer for the PhishLens web console.
Loads the precomputed TreeSHAP bundle and assembles diagnoses for live URLs and benchmark records.
Rendering lives in src.console_ui.
"""

import gzip
import json
import os
import urllib.parse

from src.feature_extractor import LIVE_FEATURES, extract_live_lexical_features, sanitize_url

BUNDLE_PATH = os.path.join("artifacts", "vercel_runtime.json.gz")
CATALOG_PATH = os.path.join("data", "processed", "feature_catalog.json")
METRICS_PATH = os.path.join("artifacts", "model_metrics.json")

DEFAULT_LIVE_URL = "https://secure-auth-verification.example.org/portal"
DEFAULT_UCI_IDX = 835
URL_PRESETS = (
    ("IP host spoofing", "http://192.168.1.243/login/auth/verify"),
    ("Subdomain chain", "http://account.security.verify.login.portal.org/signin"),
    ("Brand hyphen trap", "http://https-paypal-account-update.com/auth"),
    ("Shortener redirect", "https://bit.ly/secure-account-redirect//http://evil.org"),
    ("Clean baseline", "https://www.github.com/explore"),
)
COPY_REPLACEMENTS = (
    ("->", "\u2192"),
    ("-1", "\u22121"),
    ("hyphen/dash ('-')", "dash"),
    ("contains '-'", "contains a dash"),
    ("non-standard", "nonstandard"),
    ("Right-clicking", "Right clicking"),
    ("Right-click", "Right click"),
    ("Long-term multi-year", "Long term multiyear"),
    ("credential-harvesting", "credential harvesting"),
    ("short-lived", "short lived"),
    ("High-traffic", "High traffic"),
    ("54-75", "54 to 75"),
    ("22-61", "22 to 61"),
    ("31-67", "31 to 67"),
    ("17-81", "17 to 81"),
    ("2-4", "2 to 4"),
    ("1-2", "1 to 2"),
)

_CACHE = None

def _clean_copy(text):
    """Sanitizes copy strings to avoid ASCII hyphens and arrows in UI prose."""
    out = str(text)
    for old, new in COPY_REPLACEMENTS:
        out = out.replace(old, new)
    return out


def _fmt_delta(val, decimals=4):
    """Formats signed floating point delta using Unicode minus without ASCII hyphen."""
    sign = "+" if val >= 0 else "\u2212"
    return f"{sign}{abs(val):.{decimals}f}"


def _fmt_state_val(val):
    """Formats discrete state value (+1, 0, -1) using Unicode minus."""
    if val < 0:
        return "\u22121"
    if val > 0:
        return "+1"
    return "0"


def load_runtime_data():
    """Loads compressed precomputed Shapley bundle, feature catalog, and metrics once."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    with gzip.open(BUNDLE_PATH, "rt", encoding="utf-8") as gz_file:
        bundle = json.load(gz_file)
    with open(CATALOG_PATH, "r", encoding="utf-8") as cat_file:
        catalog = json.load(cat_file)
    with open(METRICS_PATH, "r", encoding="utf-8") as met_file:
        metrics = json.load(met_file)
    _CACHE = {"bundle": bundle, "catalog": catalog, "metrics": metrics}
    return _CACHE


def risk_tone(risk_pct):
    """Maps a phishing probability percentage to severity tone."""
    if risk_pct >= 70:
        return "critical"
    if risk_pct >= 50:
        return "warning"
    return "safe"


def _extract_subdomain_and_host(netloc):
    """Separates registered host from any subdomain prefix."""
    if not netloc:
        return "none", ""
    if (netloc.count(".") == 3) and netloc.replace(".", "").isdigit():
        return "none", netloc
    parts = netloc.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return "none", netloc


def _parse_url_tokens(url):
    """Splits a URL into scheme, subdomain, host, path, and query tokens."""
    parsed = urllib.parse.urlsplit(url)
    subdomain, host = _extract_subdomain_and_host(parsed.netloc)
    return {
        "scheme": f"{parsed.scheme or 'http'}://",
        "subdomain": subdomain,
        "host": host,
        "path": parsed.path if parsed.path else "/",
        "query": parsed.query if parsed.query else "none",
    }


def _resolve_rail_cells(tokens, shaps):
    """Maps URL segments to corresponding Shapley attribution drivers."""
    scheme_shap = shaps.get("SSLfinal_State", shaps.get("HTTPS_token", 0.0))
    sub_shap = shaps.get("having_Sub_Domain", 0.0)
    use_ip = abs(shaps.get("having_IP_Address", 0.0)) > abs(shaps.get("Prefix_Suffix", 0.0))
    host_feat = "IP address" if use_ip else "Prefix suffix"
    host_shap = shaps.get("having_IP_Address", 0.0) if use_ip else shaps.get("Prefix_Suffix", 0.0)
    path_shap = shaps.get("URL_Length", 0.0)
    sec_feat, sec_shap = max(
        ((f, shaps.get(f, 0.0)) for f in ("Shortining_Service", "having_At_Symbol", "double_slash_redirecting")),
        key=lambda item: abs(item[1]),
    )
    sec_label = "Shortened URL" if sec_feat == "Shortining_Service" else "Symbol redirect"
    return [
        ("Scheme protocol", tokens["scheme"], "SSL state", scheme_shap),
        ("Subdomain", tokens["subdomain"], "Subdomain", sub_shap),
        ("Registered host", tokens["host"], host_feat, host_shap),
        ("Path destination", tokens["path"], "URL length", path_shap),
        ("Security flags", tokens["query"], sec_label, sec_shap),
    ]


def _assemble_attributions(features, vals, shaps, catalog):
    """Builds sorted attribution records from precomputed Shapley vectors."""
    out = []
    for feat_name, val, s_val in zip(features, vals, shaps):
        meta = catalog["features"].get(feat_name, {})
        is_risk = s_val > 0
        key = "plain_explanation_phishing" if is_risk else "plain_explanation_legit"
        out.append({
            "feature": feat_name,
            "value": int(val),
            "shap_value": round(float(s_val), 4),
            "abs_impact": round(abs(float(s_val)), 4),
            "pushes_toward": "Phishing" if is_risk else "Legitimate",
            "group": _clean_copy(meta.get("group", "General")),
            "human_text": _clean_copy(meta.get(key, "Feature impacts phishing probability.")),
        })
    out.sort(key=lambda item: item["abs_impact"], reverse=True)
    return out


def _aggregate_groups(attributions):
    """Sums signed Shapley contributions per security domain."""
    totals = {}
    for item in attributions:
        totals[item["group"]] = totals.get(item["group"], 0.0) + item["shap_value"]
    breakdown = [
        {
            "group": grp,
            "net_shap": round(float(tot), 4),
            "verdict": "Elevates Risk" if tot > 0 else "Supports Legitimacy",
        }
        for grp, tot in totals.items()
    ]
    breakdown.sort(key=lambda item: abs(item["net_shap"]), reverse=True)
    return breakdown


def _build_uci_consensus(rec):
    """Builds multi model consensus rows for a benchmark test record."""
    models = (
        ("XGBoost (30 features)", rec["prob"]),
        ("Random Forest (200 trees)", rec["rf_prob"]),
        ("Logistic Regression (L2)", rec["lr_prob"]),
    )
    return [
        {
            "name": name,
            "prob_pct": round(prob * 100.0, 1),
            "verdict": "Phishing" if prob >= 0.50 else "Legitimate",
        }
        for name, prob in models
    ]


BINARY_LIVE_INDICES = (0, 2, 3, 4, 5, 7)


def vec_to_coord(vec):
    """Maps an 8 feature live vector to its unique (col, row) in the 64 by 9 lattice."""
    col = 0
    for idx in BINARY_LIVE_INDICES:
        col = (col << 1) | (1 if vec[idx] > 0 else 0)
    row = (int(vec[1]) + 1) * 3 + (int(vec[6]) + 1)
    return col, max(0, min(8, row))


def _netloc_part(clean_url):
    """Returns lowercase netloc without port from a sanitized URL."""
    parsed = urllib.parse.urlsplit(clean_url)
    return (parsed.hostname or parsed.netloc.split(":")[0] or "").lower()


_CALIPER_PAIRS = {
    0: ("IPv4 literal", "DNS hostname"),
    2: ("Shortener", "Direct host"),
    3: ("@ in URI", "0 @ symbols"),
    4: ("Path //", "Single path"),
    7: ("https token", "Clean host"),
}


def _binary_caliper(idx, vec):
    """Returns the risk or safe caliper label for a binary lexical feature."""
    neg_lbl, pos_lbl = _CALIPER_PAIRS[idx]
    return neg_lbl if vec[idx] < 0 else pos_lbl


def _plural_unit(count, singular, plural):
    """Formats an integer count with its singular or plural noun."""
    return f"{count} {singular if count == 1 else plural}"


def measure_lexical_calipers(clean_url, vec):
    """Computes deterministic character and token measurements for the 8 live features."""
    host = _netloc_part(clean_url)
    trim_host = host[4:] if host.startswith("www.") else host
    return [
        _binary_caliper(0, vec),
        f"{len(clean_url)} chars",
        _binary_caliper(2, vec),
        _binary_caliper(3, vec),
        _binary_caliper(4, vec),
        _plural_unit(host.count("-"), "dash", "dashes"),
        _plural_unit(trim_host.count("."), "dot", "dots"),
        _binary_caliper(7, vec),
    ]


def build_client_lattice():
    """Returns compact 576 state lookup table and 64 by 9 probability grid for client morphing."""
    bundle = load_runtime_data()["bundle"]
    states = {}
    cells = [0.0] * 576
    for key, entry in bundle["live_grid"].items():
        vec = [int(x) for x in key.split(",")]
        col, row = vec_to_coord(vec)
        prob = round(float(entry["prob"]), 4)
        cells[row * 64 + col] = prob
        states[key] = [prob, [round(float(s), 4) for s in entry["shaps"]]]
    return {"base": round(float(bundle["live_base_value"]), 4), "cells": cells, "states": states}


def _valid_override(idx, val, vec_len):
    """Checks index bounds and discrete value domain for sandbox override."""
    return 0 <= idx < vec_len and val in (-1, 0, 1)


def _apply_live_overrides(feats_dict, overrides):
    """Applies optional integer overrides and returns vector plus changed flag."""
    base_vec = [int(feats_dict[f]) for f in LIVE_FEATURES]
    if not overrides:
        return base_vec, False
    vec = list(base_vec)
    for idx, val in overrides.items():
        if _valid_override(idx, val, len(vec)):
            vec[idx] = val
    return vec, vec != base_vec


def diagnose_live(raw_url, overrides=None):
    """Evaluates a URL or 8 feature sandbox vector from the precomputed live grid."""
    data = load_runtime_data()
    bundle = data["bundle"]
    clean_url = sanitize_url(raw_url or DEFAULT_LIVE_URL)
    extracted = extract_live_lexical_features(clean_url)
    base_vec = [int(extracted[f]) for f in LIVE_FEATURES]
    vec, has_overrides = _apply_live_overrides(extracted, overrides)
    entry = bundle["live_grid"][",".join(map(str, vec))]
    attributions = _assemble_attributions(LIVE_FEATURES, vec, entry["shaps"], data["catalog"])
    col, row = vec_to_coord(vec)
    return {
        "clean_url": clean_url,
        "has_overrides": has_overrides,
        "base_vector": base_vec,
        "live_vector": vec,
        "live_shaps": [round(float(s), 4) for s in entry["shaps"]],
        "calipers": measure_lexical_calipers(clean_url, vec),
        "matrix_coord": (col, row),
        "feature_values": dict(zip(LIVE_FEATURES, vec)),
        "prediction": "Phishing" if entry["prob"] >= 0.50 else "Legitimate",
        "phishing_probability": entry["prob"],
        "base_value": bundle["live_base_value"],
        "top_drivers": attributions,
        "all_features": attributions,
        "group_breakdown": _aggregate_groups(attributions),
        "counterfactual_hints": entry["hints"],
        "consensus": entry["consensus"],
    }


def diagnose_uci(idx):
    """Loads precomputed 30 feature explanation and consensus for a test partition record."""
    data = load_runtime_data()
    records = data["bundle"]["test_records"]
    safe_idx = max(0, min(int(idx), len(records) - 1))
    rec = records[safe_idx]
    features = list(data["catalog"]["features"].keys())
    attributions = _assemble_attributions(features, rec["vals"], rec["shaps"], data["catalog"])
    true_label = "Phishing" if rec["label"] == 1 else "Legitimate"
    clean_url = sanitize_url(rec["url"])
    lex_dict = extract_live_lexical_features(clean_url)
    lex_vec = [int(lex_dict[f]) for f in LIVE_FEATURES]
    shaps_by_name = dict(zip(features, rec["shaps"]))
    lex_shaps = [round(float(shaps_by_name.get(f, 0.0)), 4) for f in LIVE_FEATURES]
    return {
        "idx": safe_idx,
        "url": rec["url"],
        "clean_url": clean_url,
        "true_label": true_label,
        "base_vector": lex_vec,
        "live_vector": lex_vec,
        "live_shaps": lex_shaps,
        "calipers": measure_lexical_calipers(clean_url, lex_vec),
        "matrix_coord": vec_to_coord(lex_vec),
        "prediction": "Phishing" if rec["prob"] >= 0.50 else "Legitimate",
        "phishing_probability": rec["prob"],
        "base_value": data["bundle"]["full_base_value"],
        "top_drivers": attributions,
        "all_features": attributions,
        "group_breakdown": _aggregate_groups(attributions),
        "counterfactual_hints": rec["hints"],
        "consensus": _build_uci_consensus(rec),
    }


def _specimen_segments(tokens, cells):
    """Pairs non empty URL segments with their corresponding telemetry cell SHAP scores."""
    sub_prefix = f"{tokens['subdomain']}." if tokens["subdomain"] != "none" else ""
    q_suffix = f"?{tokens['query']}" if tokens["query"] != "none" else ""
    candidates = (
        (tokens["scheme"], cells[0][3]),
        (sub_prefix, cells[1][3]),
        (tokens["host"], cells[2][3]),
        (tokens["path"], cells[3][3]),
        (q_suffix, cells[4][3]),
    )
    return [(txt, s) for txt, s in candidates if txt]
