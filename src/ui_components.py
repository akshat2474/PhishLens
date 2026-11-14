"""
Reusable result and catalog rendering components for the PhishLens Streamlit interface.
Shared by the live URL scanner, UCI benchmark records, model evaluation, and feature catalog views.
"""

import html
import urllib.parse
import plotly.graph_objects as go
import streamlit as st

TONE_COLORS = {"critical": "#FF162A", "warning": "#F59E0B", "safe": "#05DF72"}
EVIDENCE_LIMIT = 3

RESULT_CSS = """
    /* Verdict Card */
    .verdict-card {
        background-color: #0E0C12;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
        box-shadow: 0 16px 36px rgba(0, 0, 0, 0.6);
    }
    .verdict-top {
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        gap: 24px;
    }
    .verdict-eyebrow {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 600;
    }
    .verdict-dot {
        width: 8px;
        height: 8px;
        border-radius: 2px;
    }
    .verdict-title {
        font-size: 24px;
        line-height: 32px;
        font-weight: 600;
        margin-top: 4px;
        text-wrap: balance;
    }
    .verdict-sub {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        margin-top: 4px;
        max-width: 520px;
        text-wrap: pretty;
    }
    .verdict-score {
        text-align: right;
        flex-shrink: 0;
    }
    .verdict-score-label {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
    }
    .verdict-score-value {
        font-family: 'Geist Mono', monospace;
        font-size: 36px;
        line-height: 40px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
    }
    .verdict-track {
        height: 8px;
        border-radius: 4px;
        background-color: #272727;
        margin-top: 24px;
        overflow: hidden;
    }
    .verdict-fill {
        height: 100%;
        border-radius: 4px;
    }

    /* Segmented Address Token Rail & Inline URL Specimen */
    .token-rail-deck {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 24px;
    }
    .token-rail-header {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        margin-bottom: 12px;
        gap: 8px;
    }
    .token-rail-title {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 600;
    }
    .token-rail-sub {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #616161;
    }
    .specimen-url-bar {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 12px;
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 24px;
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 4px;
        word-break: break-all;
    }
    .specimen-token {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #181818;
    }
    .specimen-token-risk {
        color: #e57373;
        border-color: #e57373;
    }
    .specimen-token-safe {
        color: #81c784;
        border-color: #272727;
    }
    .specimen-token-neutral {
        color: #9B9B9B;
        border-color: #272727;
    }
    .specimen-delta {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-variant-numeric: tabular-nums;
    }
    .token-rail-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 8px;
    }
    @media (max-width: 900px) {
        .token-rail-grid {
            grid-template-columns: repeat(2, 1fr);
        }
    }
    .token-rail-cell {
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
        transition: border-color 180ms cubic-bezier(0.16, 1, 0.3, 1), background-color 180ms cubic-bezier(0.16, 1, 0.3, 1);
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 8px;
        min-height: 96px;
        box-sizing: border-box;
    }
    .token-rail-type {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 500;
    }
    .token-rail-val {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        color: #FFFFFF;
        font-weight: 500;
        word-break: break-all;
    }
    .token-rail-badge {
        display: inline-flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #181818;
        border: 1px solid #272727;
        margin-top: 4px;
    }
    .token-rail-badge-risk {
        color: #e57373;
    }
    .token-rail-badge-safe {
        color: #81c784;
    }
    .token-rail-badge-neutral {
        color: #9B9B9B;
    }

    /* Population Ruler & Multi Model Consensus */
    .consensus-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
        box-sizing: border-box;
    }
    .consensus-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
    }
    .consensus-title {
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        color: #FFFFFF;
    }
    .consensus-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #1F1F1F;
    }
    .consensus-sub {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 16px;
        text-wrap: pretty;
    }
    .consensus-row {
        margin-bottom: 12px;
    }
    .consensus-row:last-child {
        margin-bottom: 0;
    }
    .consensus-row-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 12px;
        line-height: 16px;
        margin-bottom: 4px;
    }
    .consensus-name {
        color: #FFFFFF;
        font-weight: 500;
    }
    .consensus-meta {
        font-family: 'Geist Mono', monospace;
        color: #9B9B9B;
        font-variant-numeric: tabular-nums;
    }
    .consensus-track {
        height: 8px;
        background-color: #272727;
        border-radius: 4px;
        overflow: hidden;
    }
    .consensus-fill {
        height: 100%;
        border-radius: 4px;
    }
    .ruler-wrap {
        position: relative;
        padding: 24px 0 8px 0;
    }
    .ruler-track {
        display: flex;
        height: 12px;
        border-radius: 4px;
        overflow: hidden;
        border: 1px solid #272727;
    }
    .ruler-zone-safe {
        width: 50%;
        background-color: #1F1F1F;
    }
    .ruler-zone-warn {
        width: 20%;
        background-color: #272727;
    }
    .ruler-zone-crit {
        width: 30%;
        background-color: #313131;
    }
    .ruler-threshold {
        position: absolute;
        left: 50%;
        top: 16px;
        bottom: 4px;
        width: 2px;
        background-color: #616161;
    }
    .ruler-needle {
        position: absolute;
        top: 12px;
        width: 4px;
        height: 24px;
        border-radius: 2px;
        transform: translateX(-50%);
    }
    .ruler-tag {
        position: absolute;
        top: 0;
        transform: translateX(-50%);
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
    }
    .ruler-legend {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-top: 8px;
    }

    /* Telemetry Waterfall Ledger */
    .ledger-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        height: 100%;
        box-sizing: border-box;
    }
    .ledger-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
    }
    .ledger-table th {
        color: #9B9B9B;
        font-weight: 500;
        text-align: left;
        padding: 8px;
        background-color: #181818;
    }
    .ledger-table td {
        padding: 8px;
        font-variant-numeric: tabular-nums;
    }
    .ledger-table tbody tr:nth-child(even) td {
        background-color: #181818;
    }
    .ledger-row-risk {
        color: #e57373;
    }
    .ledger-row-safe {
        color: #81c784;
    }
    .ledger-row-total td {
        font-weight: 600;
        color: #FFFFFF;
        background-color: #1F1F1F;
    }

    /* Key Evidence Grid */
    .evidence-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }
    .evidence-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
    }
    .evidence-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
    }
    .evidence-name {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        word-break: break-all;
    }
    .evidence-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #1F1F1F;
        flex-shrink: 0;
    }
    .evidence-value {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-top: 8px;
    }
    .evidence-text {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        margin-top: 8px;
        text-wrap: pretty;
    }

    /* Counterfactual Recourse Diff Grid */
    .recourse-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 16px;
        margin-bottom: 24px;
    }
    .recourse-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        box-sizing: border-box;
    }
    .recourse-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
    }
    .recourse-name {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        color: #FFFFFF;
    }
    .recourse-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        color: #81c784;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        padding: 2px 8px;
        border-radius: 4px;
    }
    .recourse-state {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 12px;
    }
    .recourse-delta-row {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 4px;
        font-variant-numeric: tabular-nums;
    }
    .recourse-bars {
        display: flex;
        flex-direction: column;
        gap: 4px;
        margin-bottom: 12px;
    }
    .recourse-track {
        height: 4px;
        border-radius: 2px;
        background-color: #272727;
        overflow: hidden;
    }
    .recourse-fill {
        height: 100%;
        border-radius: 2px;
    }
    .recourse-text {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        text-wrap: pretty;
    }

    /* Console Table */
    .console-table-wrap {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        overflow-x: auto;
        margin-bottom: 24px;
    }
    .console-table {
        width: 100%;
        border-collapse: collapse;
        font-size: 14px;
        line-height: 20px;
    }
    .console-table th {
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        color: #9B9B9B;
        padding: 12px 16px;
        background-color: #181818;
    }
    .console-table td {
        padding: 12px 16px;
        color: #FFFFFF;
        font-variant-numeric: tabular-nums;
        background-color: #000000;
        transition: background-color 140ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .console-table tbody tr:nth-child(even) td {
        background-color: #181818;
    }
    .console-table tbody tr:hover td {
        background-color: #1F1F1F;
    }
    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(6px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .verdict-card,
    .token-rail-deck,
    .consensus-card,
    .ledger-card,
    .evidence-card,
    .recourse-card,
    .console-table-wrap,
    .catalog-card,
    .action-card {
        background-color: #000000;
        border: 1px solid #272727;
        animation: fadeInUp 260ms cubic-bezier(0.16, 1, 0.3, 1) both;
        transition: border-color 180ms cubic-bezier(0.16, 1, 0.3, 1), background-color 180ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .specimen-url-bar {
        background-color: #000000;
        border: 1px solid #272727;
    }
    .evidence-card:hover,
    .recourse-card:hover,
    .catalog-card:hover,
    .token-rail-cell:hover {
        border-color: #313131;
        background-color: #181818;
    }
    .verdict-fill,
    .consensus-fill,
    .recourse-fill {
        transition: width 320ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    @media (prefers-reduced-motion: reduce) {
        .verdict-card,
        .token-rail-deck,
        .consensus-card,
        .ledger-card,
        .evidence-card,
        .recourse-card,
        .console-table-wrap,
        .catalog-card,
        .action-card {
            animation: none;
            transition: none;
        }
        .verdict-fill,
        .consensus-fill,
        .recourse-fill {
            transition: none;
        }
    }
    .console-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        white-space: nowrap;
    }

    /* Feature Catalog Bento Matrix */
    .catalog-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 16px;
        margin-top: 16px;
        margin-bottom: 24px;
    }
    .catalog-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 12px;
        box-sizing: border-box;
    }
    .catalog-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
    }
    .catalog-name {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        color: #FFFFFF;
        word-break: break-all;
    }
    .catalog-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        flex-shrink: 0;
    }
    .catalog-domain {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
    }
    .catalog-desc {
        font-size: 14px;
        line-height: 20px;
        color: #FFFFFF;
        text-wrap: pretty;
    }
    .catalog-rule {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 8px 12px;
        word-break: break-word;
    }
    .prev-head {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 4px;
    }
    .prev-track {
        display: flex;
        height: 8px;
        border-radius: 4px;
        background-color: #272727;
        overflow: hidden;
    }
    .prev-legend {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-top: 4px;
    }

    /* Section Typography */
    .section-title {
        font-size: 18px;
        line-height: 28px;
        font-weight: 600;
        margin: 0 0 4px 0;
        text-wrap: balance;
    }
    .section-note {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        margin-bottom: 16px;
        text-wrap: pretty;
    }
    .action-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 12px;
    }

    @media (max-width: 900px) {
        .evidence-grid { grid-template-columns: 1fr; }
        .recourse-grid { grid-template-columns: 1fr; }
        .catalog-grid { grid-template-columns: 1fr; }
    }
"""


def risk_tone(risk_pct):
    """Maps a phishing probability percentage to a severity tone."""
    if risk_pct >= 70:
        return "critical"
    if risk_pct >= 50:
        return "warning"
    return "safe"


def inject_result_styles():
    """Injects the stylesheet used by the result components."""
    st.markdown(f"<style>{RESULT_CSS}</style>", unsafe_allow_html=True)


def section_header(title, note=None):
    """Renders a consistent section heading with an optional supporting line."""
    note_html = f'<div class="section-note">{note}</div>' if note else ""
    st.markdown(
        f'<div class="section-title">{title}</div>{note_html}',
        unsafe_allow_html=True,
    )


def kpi_tile(title, value, color="#FFFFFF"):
    """Renders a small labelled metric tile."""
    return (
        f'<div class="kpi-tile"><div class="kpi-title">{title}</div>'
        f'<div class="kpi-value" style="color: {color};">{value}</div></div>'
    )


def render_verdict(title, subtitle, risk_pct):
    """Renders the headline verdict with probability and a flat probability bar."""
    tone = risk_tone(risk_pct)
    color = TONE_COLORS[tone]
    st.markdown(
        f"""
        <div class="verdict-card">
            <div class="verdict-top">
                <div>
                    <div class="verdict-eyebrow">
                        <span class="verdict-dot" style="background-color: {color};"></span>
                        Automated classification
                    </div>
                    <div class="verdict-title" style="color: {color};">{title}</div>
                    <div class="verdict-sub">{subtitle}</div>
                </div>
                <div class="verdict-score">
                    <div class="verdict-score-label">Probability of phishing</div>
                    <div class="verdict-score-value" style="color: {color};">{risk_pct:.1f}%</div>
                </div>
            </div>
            <div class="verdict-track">
                <div class="verdict-fill" style="width: {risk_pct:.1f}%; background-color: {color};"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _resolve_rail_cells(tokens, shaps):
    """Maps parsed URL tokens to their corresponding Shapley attribution drivers."""
    scheme_shap = shaps.get("SSLfinal_State", shaps.get("HTTPS_token", 0.0))
    sub_shap = shaps.get("having_Sub_Domain", 0.0)

    is_ip_higher = abs(shaps.get("having_IP_Address", 0.0)) > abs(shaps.get("Prefix_Suffix", 0.0))
    host_feat = "IP address" if is_ip_higher else "Prefix suffix"
    host_shap = shaps.get("having_IP_Address", 0.0) if is_ip_higher else shaps.get("Prefix_Suffix", 0.0)

    path_shap = shaps.get("URL_Length", 0.0)

    sec_candidates = ["Shortining_Service", "having_At_Symbol", "double_slash_redirecting"]
    sec_feat, sec_shap = max(((f, shaps.get(f, 0.0)) for f in sec_candidates), key=lambda x: abs(x[1]))
    sec_label = "Shortened URL" if sec_feat == "Shortining_Service" else "Symbol redirect"

    return [
        ("Scheme protocol", tokens["scheme"], "SSL state", scheme_shap),
        ("Subdomain", tokens["subdomain"], "Subdomain", sub_shap),
        ("Registered host", tokens["host"], host_feat, host_shap),
        ("Path destination", tokens["path"], "URL length", path_shap),
        ("Security flags", tokens["query"], sec_label, sec_shap),
    ]


def _extract_subdomain_and_host(netloc):
    """Separates registered host from any subdomain prefix."""
    if not netloc:
        return "none", ""
    is_ip = (netloc.count(".") == 3) and netloc.replace(".", "").isdigit()
    if is_ip:
        return "none", netloc
    parts = netloc.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return "none", netloc


def _parse_url_tokens(url):
    """Splits URL into scheme, subdomain, host, path, and query tokens."""
    parsed = urllib.parse.urlsplit(url)
    subdomain, host = _extract_subdomain_and_host(parsed.netloc)
    scheme_str = f"{parsed.scheme or 'http'}://"
    path_str = parsed.path if parsed.path else "/"
    query_str = parsed.query if parsed.query else "none"
    return {
        "scheme": scheme_str,
        "subdomain": subdomain,
        "host": host,
        "path": path_str,
        "query": query_str,
    }


def _token_tone_and_delta(shap_val):
    """Maps a Shapley log odds score to rail badge class, span class, and signed label."""
    if shap_val > 0.01:
        return "token-rail-badge-risk", "specimen-token-risk", f"+{shap_val:.3f}"
    if shap_val < -0.01:
        return "token-rail-badge-safe", "specimen-token-safe", f"{shap_val:.3f}"
    return "token-rail-badge-neutral", "specimen-token-neutral", "0.000"


def _build_specimen_spans(tokens, cells):
    """Builds inline highlighted URL spans mapped to segment Shapley deltas."""
    segments = [
        (tokens["scheme"], cells[0][3]),
        (f"{tokens['subdomain']}." if tokens["subdomain"] != "none" else "", cells[1][3]),
        (tokens["host"], cells[2][3]),
        (tokens["path"], cells[3][3]),
        (f"?{tokens['query']}" if tokens["query"] != "none" else "", cells[4][3]),
    ]
    spans = []
    for text, shap_val in segments:
        if not text:
            continue
        _, span_cls, delta_str = _token_tone_and_delta(shap_val)
        spans.append(
            f'<span class="specimen-token {span_cls}">'
            f'{html.escape(text)}<span class="specimen-delta">{delta_str}</span></span>'
        )
    return "".join(spans)


def _format_rail_cell(type_label, val_str, feat_label, shap_val):
    """Renders HTML markup for an individual telemetry rail cell."""
    tone_class, _, impact_str = _token_tone_and_delta(shap_val)
    return (
        f'<div class="token-rail-cell">'
        f'<div><div class="token-rail-type">{type_label}</div>'
        f'<div class="token-rail-val">{html.escape(val_str)}</div></div>'
        f'<div class="token-rail-badge {tone_class}">'
        f'<span>{feat_label}</span><span>{impact_str}</span></div></div>'
    )


def render_segmented_token_rail(url, result):
    """Renders the inline annotated URL specimen banner and five compartment token rail."""
    tokens = _parse_url_tokens(url)
    shaps = {item["feature"]: item["shap_value"] for item in result.get("all_features", [])}
    cells = _resolve_rail_cells(tokens, shaps)
    specimen_html = _build_specimen_spans(tokens, cells)
    cell_htmls = [_format_rail_cell(t, v, f, s) for t, v, f, s in cells]

    st.markdown(
        f"""
        <div class="token-rail-deck">
            <div class="token-rail-header">
                <span class="token-rail-title">Segmented address telemetry rail</span>
                <span class="token-rail-sub">Inline token decomposition with signed Shapley attribution</span>
            </div>
            <div class="specimen-url-bar">{specimen_html}</div>
            <div class="token-rail-grid">
                {"".join(cell_htmls)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _consensus_summary(consensus_rows):
    """Computes consensus agreement badge label and color."""
    total = len(consensus_rows)
    if total == 0:
        return "No consensus data", "#9B9B9B"
    phish_votes = sum(1 for row in consensus_rows if row["verdict"] == "Phishing")
    majority = max(phish_votes, total - phish_votes)
    majority_label = "phishing" if phish_votes >= total - phish_votes else "legitimate"
    tone = "#e57373" if majority_label == "phishing" else "#81c784"
    return f"{majority} of {total} predict {majority_label}", tone


def _format_consensus_row(entry):
    """Formats one evaluator progress bar inside the consensus panel."""
    pct = min(100.0, max(0.0, float(entry["prob_pct"])))
    color = TONE_COLORS["critical"] if entry["verdict"] == "Phishing" else TONE_COLORS["safe"]
    name = html.escape(entry["name"])
    verdict = html.escape(entry["verdict"])
    return (
        f'<div class="consensus-row">'
        f'<div class="consensus-row-top">'
        f'<span class="consensus-name">{name}</span>'
        f'<span class="consensus-meta"><span style="color: {color};">{verdict}</span> {pct:.1f}%</span>'
        f'</div>'
        f'<div class="consensus-track">'
        f'<div class="consensus-fill" style="width: {pct:.1f}%; background-color: {color};"></div>'
        f'</div></div>'
    )


def render_consensus_and_ruler(result, risk_pct, secondary_kpi):
    """Renders population threshold ruler with telemetry tiles beside multi model consensus."""
    clamped = min(98.0, max(2.0, risk_pct))
    marker_color = TONE_COLORS[risk_tone(risk_pct)]
    base_v = result.get("base_value", 0.0)
    net_m = sum(d["shap_value"] for d in result.get("all_features", [])) + base_v
    consensus_rows = result.get("consensus", [])
    summary_text, summary_color = _consensus_summary(consensus_rows)
    rows_html = "".join(_format_consensus_row(entry) for entry in consensus_rows)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.markdown(
            f"""
            <div class="consensus-card">
                <div class="consensus-header">
                    <span class="consensus-title">Population risk ruler</span>
                    <span class="consensus-pill" style="color: {marker_color};">Threshold 50.0%</span>
                </div>
                <div class="ruler-wrap">
                    <div class="ruler-tag" style="left: {clamped:.1f}%; color: {marker_color};">{risk_pct:.1f}%</div>
                    <div class="ruler-track">
                        <div class="ruler-zone-safe"></div>
                        <div class="ruler-zone-warn"></div>
                        <div class="ruler-zone-crit"></div>
                    </div>
                    <div class="ruler-threshold"></div>
                    <div class="ruler-needle" style="left: {clamped:.1f}%; background-color: {marker_color};"></div>
                </div>
                <div class="ruler-legend">
                    <span>Legitimate zone</span>
                    <span>Suspicious zone</span>
                    <span>Critical phishing zone</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        k1, k2 = st.columns(2)
        k1.markdown(kpi_tile("Safe probability", f"{100 - risk_pct:.1f}%", TONE_COLORS["safe"]), unsafe_allow_html=True)
        k2.markdown(kpi_tile(*secondary_kpi), unsafe_allow_html=True)
        k3, k4 = st.columns(2)
        k3.markdown(kpi_tile("Base prior log odds", f"{base_v:+.3f}"), unsafe_allow_html=True)
        k4.markdown(kpi_tile("Net log odds margin", f"{net_m:+.3f}"), unsafe_allow_html=True)

    with col_right:
        st.markdown(
            f"""
            <div class="consensus-card" style="height: 100%;">
                <div class="consensus-header">
                    <span class="consensus-title">Multi model consensus</span>
                    <span class="consensus-pill" style="color: {summary_color};">{summary_text}</span>
                </div>
                <div class="consensus-sub">Independent evaluator risk scores across trained architectures and structural heuristics.</div>
                {rows_html}
            </div>
            """,
            unsafe_allow_html=True,
        )


def build_waterfall_figure(base_value, drivers):
    """Builds the TreeSHAP attribution waterfall chart charting prior to final score."""
    top_items = drivers[:6]
    labels = ["Base prior"] + [d["feature"] for d in top_items] + ["Net log odds"]
    measures = ["absolute"] + ["relative"] * len(top_items) + ["total"]
    y_values = [base_value] + [d["shap_value"] for d in top_items] + [0]
    texts = [f"{base_value:+.3f}"] + [f"{d['shap_value']:+.3f}" for d in top_items] + [""]

    fig = go.Figure(go.Waterfall(
        orientation="v",
        measure=measures,
        x=labels,
        textposition="outside",
        text=texts,
        textfont=dict(family="Geist Mono", size=11, color="#9B9B9B"),
        y=y_values,
        connector=dict(line=dict(color="#313131", width=1, dash="dot")),
        decreasing=dict(marker=dict(color="#81c784")),
        increasing=dict(marker=dict(color="#e57373")),
        totals=dict(marker=dict(color="#FFFFFF")),
    ))
    fig.update_layout(
        paper_bgcolor="#181818",
        plot_bgcolor="#181818",
        margin=dict(l=16, r=16, t=24, b=32),
        height=320,
        xaxis=dict(
            gridcolor="#272727",
            tickfont=dict(family="Geist Mono", size=11, color="#9B9B9B"),
        ),
        yaxis=dict(
            gridcolor="#272727",
            zerolinecolor="#313131",
            title="Log odds impact",
            title_font=dict(family="Geist", size=12, color="#9B9B9B"),
            tickfont=dict(family="Geist Mono", size=11, color="#9B9B9B"),
        ),
        showlegend=False,
    )
    return fig


def build_telemetry_ledger(base_value, drivers, prob_phishing):
    """Builds the telemetry ledger table tracking cumulative log odds deltas."""
    top_items = drivers[:6]
    cum_sum = base_value
    rows = [
        f'<tr><td style="color: #9B9B9B;">Base expectation</td>'
        f'<td style="text-align: right; color: #9B9B9B;">{base_value:+.3f}</td>'
        f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
    ]

    for d in top_items:
        s_val = d["shap_value"]
        cum_sum += s_val
        row_class = "ledger-row-risk" if s_val > 0 else "ledger-row-safe"
        rows.append(
            f'<tr><td style="color: #FFFFFF;">{html.escape(d["feature"])}</td>'
            f'<td style="text-align: right;" class="{row_class}">{s_val:+.3f}</td>'
            f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
        )

    risk_pct = prob_phishing * 100
    tone_color = TONE_COLORS[risk_tone(risk_pct)]

    return (
        f'<div class="ledger-card">'
        f'<div style="font-size: 12px; font-weight: 600; color: #9B9B9B; margin-bottom: 12px;">'
        f'Attribution log odds ledger</div>'
        f'<table class="ledger-table">'
        f'<thead><tr><th>Factor</th><th style="text-align: right;">Delta</th><th style="text-align: right;">Cumulative</th></tr></thead>'
        f'<tbody>{"".join(rows)}'
        f'<tr class="ledger-row-total"><td>Total net margin</td><td></td>'
        f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
        f'<tr><td style="color: #9B9B9B; padding-top: 8px;">Posterior risk</td><td></td>'
        f'<td style="text-align: right; font-weight: 600; padding-top: 8px; color: {tone_color};">{risk_pct:.1f}%</td></tr>'
        f'</tbody></table></div>'
    )


def render_evidence(drivers, limit=EVIDENCE_LIMIT):
    """Renders the strongest drivers as plain language evidence cards."""
    cards = []
    for d in drivers[:limit]:
        raises = d["shap_value"] > 0
        pill_color = TONE_COLORS["critical"] if raises else TONE_COLORS["safe"]
        pill_text = "Raises risk" if raises else "Lowers risk"
        cards.append(
            f'<div class="evidence-card"><div class="evidence-head">'
            f'<span class="evidence-name">{html.escape(d["feature"])}</span>'
            f'<span class="evidence-pill" style="color: {pill_color};">{pill_text}</span></div>'
            f'<div class="evidence-value">Shapley {d["shap_value"]:+.3f}</div>'
            f'<div class="evidence-text">{html.escape(d["human_text"])}</div></div>'
        )
    st.markdown(f'<div class="evidence-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def _format_recourse_card(hint, current_risk_pct):
    """Formats one counterfactual diff card showing state flip and dual probability bars."""
    cur_label = "suspicious" if hint["current_value"] == 0 else "phishing"
    new_pct = round(hint["new_phishing_probability"] * 100, 1)
    cur_bar = min(100.0, max(0.0, current_risk_pct))
    new_bar = min(100.0, max(0.0, new_pct))
    new_color = TONE_COLORS["safe"] if new_pct < 50 else TONE_COLORS["warning"]
    return (
        f'<div class="recourse-card">'
        f'<div class="recourse-head">'
        f'<span class="recourse-name">{html.escape(hint["feature"])}</span>'
        f'<span class="recourse-badge">Risk down {hint["risk_reduction_pct"]:.1f}%</span>'
        f'</div>'
        f'<div class="recourse-state">State transition: {cur_label} &#8594; legitimate norm</div>'
        f'<div class="recourse-delta-row">'
        f'<span>Phishing risk shift</span>'
        f'<span style="color: {new_color};">{current_risk_pct:.1f}% &#8594; {new_pct:.1f}%</span>'
        f'</div>'
        f'<div class="recourse-bars">'
        f'<div class="recourse-track"><div class="recourse-fill" style="width: {cur_bar:.1f}%; background-color: #e57373;"></div></div>'
        f'<div class="recourse-track"><div class="recourse-fill" style="width: {new_bar:.1f}%; background-color: {new_color};"></div></div>'
        f'</div>'
        f'<div class="recourse-text">{html.escape(hint["guidance"])}</div>'
        f'</div>'
    )


def render_recourse(hints, current_risk_pct=50.0):
    """Renders counterfactual diff cards, or a clean baseline message."""
    if not hints:
        st.markdown(
            '<div class="action-card"><div style="font-size: 14px; font-weight: 600;">Clean baseline structure</div>'
            '<div style="font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 4px;">'
            "No single change lowers the score noticeably. The evaluated properties match legitimate norms.</div></div>",
            unsafe_allow_html=True,
        )
        return
    cards = "".join(_format_recourse_card(hint, current_risk_pct) for hint in hints)
    st.markdown(f'<div class="recourse-grid">{cards}</div>', unsafe_allow_html=True)


def _format_table_cell(val, align):
    """Formats a single HTML console table cell with semantic status pills when applicable."""
    text = html.escape(str(val))
    badge_colors = {
        "Phishing": "#e57373",
        "Elevates Risk": "#e57373",
        "Suspicious": "#ffb74d",
        "Legitimate": "#81c784",
        "Supports Legitimacy": "#81c784",
    }
    if text in badge_colors:
        content = f'<span class="console-badge" style="color: {badge_colors[text]};">{text}</span>'
    else:
        content = text
    font_css = "font-family: 'Geist Mono', monospace;" if align == "right" else ""
    return f'<td style="text-align: {align}; {font_css}">{content}</td>'


def render_console_table(rows, columns):
    """Renders a styled graphite hairline table replacing raw dataframe widgets."""
    headers = "".join(
        f'<th style="text-align: {align};">{html.escape(label)}</th>'
        for _, label, align in columns
    )
    body_rows = []
    for row in rows:
        cells = "".join(_format_table_cell(row.get(key, ""), align) for key, _, align in columns)
        body_rows.append(f"<tr>{cells}</tr>")
    st.markdown(
        f'<div class="console-table-wrap"><table class="console-table">'
        f'<thead><tr>{headers}</tr></thead><tbody>{"".join(body_rows)}</tbody>'
        f'</table></div>',
        unsafe_allow_html=True,
    )


def _feature_prevalence(test_df, feat_name):
    """Calculates empirical percentages of phishing, suspicious, and legitimate values."""
    if feat_name not in test_df.columns or len(test_df) == 0:
        return 0.0, 0.0, 100.0
    total = float(len(test_df))
    series = test_df[feat_name]
    return (
        float((series == -1).sum()) * 100.0 / total,
        float((series == 0).sum()) * 100.0 / total,
        float((series == 1).sum()) * 100.0 / total,
    )


def _format_catalog_card(f_name, meta, prevalence):
    """Renders a single feature bento card with rule logic and prevalence bar."""
    is_live = meta.get("extractable_live", False)
    badge_text = "Live lexical" if is_live else ("Legacy API" if meta.get("deprecated", False) else "Offline record")
    badge_color = "#81c784" if is_live else "#9B9B9B"
    p_phish, p_susp, p_legit = prevalence

    return (
        f'<div class="catalog-card">'
        f'<div>'
        f'<div class="catalog-head">'
        f'<span class="catalog-name">{html.escape(f_name)}</span>'
        f'<span class="catalog-badge" style="color: {badge_color};">{badge_text}</span>'
        f'</div>'
        f'<div class="catalog-domain">{html.escape(meta.get("group", ""))}</div>'
        f'</div>'
        f'<div class="catalog-desc">{html.escape(meta.get("description", ""))}</div>'
        f'<div class="catalog-rule">{html.escape(meta.get("rule", ""))}</div>'
        f'<div>'
        f'<div class="prev-head"><span>Test partition prevalence</span>'
        f'<span>{p_phish:.0f}% / {p_susp:.0f}% / {p_legit:.0f}%</span></div>'
        f'<div class="prev-track">'
        f'<div style="width: {p_phish:.1f}%; background-color: #e57373;"></div>'
        f'<div style="width: {p_susp:.1f}%; background-color: #ffb74d;"></div>'
        f'<div style="width: {p_legit:.1f}%; background-color: #81c784;"></div>'
        f'</div>'
        f'<div class="prev-legend">'
        f'<span style="color: #e57373;">Phish</span>'
        f'<span style="color: #ffb74d;">Suspicious</span>'
        f'<span style="color: #81c784;">Normal</span>'
        f'</div>'
        f'</div>'
        f'</div>'
    )


def render_feature_catalog_grid(features_dict, test_df):
    """Renders a three column bento grid of documented features and class distributions."""
    if not features_dict:
        st.info("No features match the selected filters.")
        return
    cards = "".join(
        _format_catalog_card(name, meta, _feature_prevalence(test_df, name))
        for name, meta in features_dict.items()
    )
    st.markdown(f'<div class="catalog-grid">{cards}</div>', unsafe_allow_html=True)


def render_results_body(result, risk_pct, secondary_kpi, gauge_note, chart_note):
    """Renders consensus panel, waterfall ledger, evidence cards, and counterfactual recourse."""
    section_header("Telemetry and model consensus", gauge_note)
    render_consensus_and_ruler(result, risk_pct, secondary_kpi)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    section_header("TreeSHAP attribution waterfall ledger", chart_note)
    col_chart, col_ledger = st.columns([3, 2])
    with col_chart:
        st.plotly_chart(
            build_waterfall_figure(result.get("base_value", 0.0), result.get("top_drivers", [])),
            width="stretch",
        )
    with col_ledger:
        st.markdown(
            build_telemetry_ledger(
                result.get("base_value", 0.0),
                result.get("top_drivers", []),
                result.get("phishing_probability", 0.0),
            ),
            unsafe_allow_html=True,
        )

    section_header("Key evidence", "The strongest signals behind this result, in plain language.")
    render_evidence(result["top_drivers"])

    section_header("Actionable recourse", "Smallest single changes that reduce the phishing score.")
    render_recourse(result["counterfactual_hints"], current_risk_pct=risk_pct)
