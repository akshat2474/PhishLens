"""
Reusable result rendering components for the PhishLens Streamlit interface.
Shared by the live URL scanner and the UCI benchmark record views.
"""

import urllib.parse
import plotly.graph_objects as go
import streamlit as st

TONE_COLORS = {"critical": "#e57373", "warning": "#ffb74d", "safe": "#81c784"}
EVIDENCE_LIMIT = 3

RESULT_CSS = """
    /* Verdict Card */
    .verdict-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
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
        width: 6px;
        height: 6px;
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
        font-size: 32px;
        line-height: 40px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
    }
    .verdict-track {
        height: 6px;
        border-radius: 4px;
        background-color: #272727;
        margin-top: 24px;
        overflow: hidden;
    }
    .verdict-fill {
        height: 100%;
        border-radius: 4px;
    }

    /* Segmented Address Token Rail */
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
        font-size: 11px;
        line-height: 16px;
        color: #616161;
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
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 8px;
        min-height: 88px;
        box-sizing: border-box;
    }
    .token-rail-type {
        font-size: 11px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 500;
    }
    .token-rail-val {
        font-family: 'Geist Mono', monospace;
        font-size: 13px;
        line-height: 18px;
        color: #FFFFFF;
        font-weight: 500;
        word-break: break-all;
    }
    .token-rail-badge {
        display: inline-flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'Geist Mono', monospace;
        font-size: 10px;
        line-height: 14px;
        font-weight: 500;
        padding: 2px 6px;
        border-radius: 4px;
        margin-top: 4px;
    }
    .token-rail-badge-risk {
        background-color: #271b1d;
        border: 1px solid #481a1d;
        color: #e57373;
    }
    .token-rail-badge-safe {
        background-color: #16261c;
        border: 1px solid #1c3829;
        color: #81c784;
    }
    .token-rail-badge-neutral {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        color: #9B9B9B;
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
        font-size: 11px;
        line-height: 16px;
    }
    .ledger-table th {
        color: #9B9B9B;
        font-weight: 500;
        text-align: left;
        padding: 6px 8px;
        border-bottom: 1px solid #272727;
    }
    .ledger-table td {
        padding: 6px 8px;
        border-bottom: 1px solid #272727;
        font-variant-numeric: tabular-nums;
    }
    .ledger-row-risk {
        color: #e57373;
    }
    .ledger-row-safe {
        color: #81c784;
    }
    .ledger-row-total {
        font-weight: 600;
        color: #FFFFFF;
        border-top: 1px solid #313131;
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
        font-size: 13px;
        line-height: 20px;
        font-weight: 600;
        word-break: break-all;
    }
    .evidence-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 11px;
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
        font-size: 13px;
        line-height: 20px;
        color: #9B9B9B;
        margin-top: 8px;
        text-wrap: pretty;
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


def _format_rail_cell(type_label, val_str, feat_label, shap_val):
    """Renders HTML markup for an individual telemetry rail cell."""
    if shap_val > 0.01:
        tone_class = "token-rail-badge-risk"
        impact_str = f"+{shap_val:.3f}"
    elif shap_val < -0.01:
        tone_class = "token-rail-badge-safe"
        impact_str = f"{shap_val:.3f}"
    else:
        tone_class = "token-rail-badge-neutral"
        impact_str = "0.000"

    return (
        f'<div class="token-rail-cell">'
        f'<div><div class="token-rail-type">{type_label}</div>'
        f'<div class="token-rail-val">{val_str}</div></div>'
        f'<div class="token-rail-badge {tone_class}">'
        f'<span>{feat_label}</span><span>{impact_str}</span></div></div>'
    )


def render_segmented_token_rail(url, result):
    """Renders the signature segmented address telemetry rail with signed Shapley impact chips."""
    tokens = _parse_url_tokens(url)
    shaps = {item["feature"]: item["shap_value"] for item in result.get("all_features", [])}
    cells = _resolve_rail_cells(tokens, shaps)
    cell_htmls = [_format_rail_cell(t, v, f, s) for t, v, f, s in cells]

    st.markdown(
        f"""
        <div class="token-rail-deck">
            <div class="token-rail-header">
                <span class="token-rail-title">Segmented address telemetry rail</span>
                <span class="token-rail-sub">Structural token decomposition with signed Shapley attribution</span>
            </div>
            <div class="token-rail-grid">
                {"".join(cell_htmls)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def build_gauge_figure(risk_pct):
    """Builds the semicircle risk gauge with container-matched background."""
    color = TONE_COLORS[risk_tone(risk_pct)]
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_pct,
        number={"suffix": "%", "font": {"family": "Geist Mono", "size": 32, "color": "#FFFFFF"}},
        gauge={
            "axis": {
                "range": [0, 100],
                "tickcolor": "#9B9B9B",
                "tickwidth": 1,
                "tickfont": {"family": "Geist Mono", "size": 10, "color": "#9B9B9B"},
            },
            "bar": {"color": color, "thickness": 0.24},
            "bgcolor": "#1F1F1F",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50], "color": "#1F1F1F"},
                {"range": [50, 70], "color": "#272727"},
                {"range": [70, 100], "color": "#313131"},
            ],
        },
    ))
    fig.update_layout(
        paper_bgcolor="#181818",
        plot_bgcolor="#181818",
        margin=dict(l=16, r=16, t=20, b=10),
        height=200,
    )
    return fig


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
        textfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
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
            tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
        ),
        yaxis=dict(
            gridcolor="#272727",
            zerolinecolor="#313131",
            title="Log odds impact",
            title_font=dict(family="Geist", size=11, color="#9B9B9B"),
            tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
        ),
        showlegend=False,
    )
    return fig


def build_telemetry_ledger(base_value, drivers, prob_phishing):
    """Builds the telemetry ledger table tracking cumulative log odds deltas."""
    top_items = drivers[:6]
    cum_sum = base_value
    rows = []

    rows.append(
        f'<tr><td style="color: #9B9B9B;">Base expectation</td>'
        f'<td style="text-align: right; color: #9B9B9B;">{base_value:+.3f}</td>'
        f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
    )

    for d in top_items:
        s_val = d["shap_value"]
        cum_sum += s_val
        row_class = "ledger-row-risk" if s_val > 0 else "ledger-row-safe"
        rows.append(
            f'<tr><td style="color: #FFFFFF;">{d["feature"]}</td>'
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
        f'<tr style="border-top: 1px solid #272727;">'
        f'<td style="color: #9B9B9B; padding-top: 8px;">Posterior risk</td><td></td>'
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
            f'<span class="evidence-name">{d["feature"]}</span>'
            f'<span class="evidence-pill" style="color: {pill_color};">{pill_text}</span></div>'
            f'<div class="evidence-value">Shapley {d["shap_value"]:+.3f}</div>'
            f'<div class="evidence-text">{d["human_text"]}</div></div>'
        )
    st.markdown(f'<div class="evidence-grid">{"".join(cards)}</div>', unsafe_allow_html=True)


def render_recourse(hints):
    """Renders counterfactual recourse suggestions, or a clean baseline message."""
    if not hints:
        st.markdown(
            '<div class="action-card"><div style="font-size: 14px; font-weight: 600;">Clean baseline structure</div>'
            '<div style="font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 4px;">'
            "No single change lowers the score noticeably. The evaluated properties match legitimate norms.</div></div>",
            unsafe_allow_html=True,
        )
        return
    for hint in hints:
        st.markdown(
            f'<div class="action-card"><div style="display: flex; justify-content: space-between; margin-bottom: 4px;">'
            f'<span style="font-family: \'Geist Mono\'; font-size: 14px; font-weight: 600;">{hint["feature"]}</span>'
            f'<span style="font-family: \'Geist Mono\'; font-size: 12px; font-weight: 600; color: #81c784;">'
            f'Risk down {hint["risk_reduction_pct"]}%</span></div>'
            f'<div style="font-size: 14px; line-height: 20px; color: #9B9B9B;">{hint["guidance"]}</div></div>',
            unsafe_allow_html=True,
        )


def render_results_body(result, risk_pct, secondary_kpi, gauge_note, chart_note):
    """Renders gauge, waterfall ledger, evidence cards, and recourse for one explanation."""
    col_gauge, col_kpi = st.columns([1, 1])
    with col_gauge:
        section_header("Threat risk gauge", gauge_note)
        st.plotly_chart(build_gauge_figure(risk_pct), width="stretch")
    with col_kpi:
        section_header("Inference telemetry", "Key performance and baseline odds coordinates.")
        k1, k2 = st.columns(2)
        k1.markdown(kpi_tile("Safe probability", f"{100 - risk_pct:.1f}%", TONE_COLORS["safe"]), unsafe_allow_html=True)
        k2.markdown(kpi_tile(*secondary_kpi), unsafe_allow_html=True)
        k3, k4 = st.columns(2)
        base_v = result.get("base_value", 0.0)
        net_m = sum(d["shap_value"] for d in result.get("all_features", [])) + base_v
        k3.markdown(kpi_tile("Base prior log odds", f"{base_v:+.3f}"), unsafe_allow_html=True)
        k4.markdown(kpi_tile("Net log odds margin", f"{net_m:+.3f}"), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
    section_header(
        "TreeSHAP attribution waterfall ledger",
        "Step by step decomposition mapping prior baseline odds to posterior verdict.",
    )
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
    render_recourse(result["counterfactual_hints"])
