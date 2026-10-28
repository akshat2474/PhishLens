"""
Reusable result rendering components for the PhishLens Streamlit interface.
Shared by the live URL scanner and the UCI benchmark record views.
"""

import plotly.graph_objects as go
import streamlit as st

TONE_COLORS = {"critical": "#e57373", "warning": "#ffb74d", "safe": "#81c784"}
RISK_COLOR = "#c62828"
SAFE_COLOR = "#2e7d32"
EVIDENCE_LIMIT = 3

RESULT_CSS = """
    .verdict-card { padding: 24px; margin-bottom: 24px; }
    .verdict-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }
    .verdict-eyebrow { display: flex; align-items: center; gap: 8px; font-size: 12px; line-height: 16px; color: #9B9B9B; font-weight: 600; }
    .verdict-dot { width: 8px; height: 8px; border-radius: 9999px; }
    .verdict-title { font-size: 24px; line-height: 32px; font-weight: 600; margin-top: 4px; }
    .verdict-sub { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 4px; max-width: 520px; }
    .verdict-score { text-align: right; flex-shrink: 0; }
    .verdict-score-label { font-size: 12px; line-height: 16px; color: #9B9B9B; }
    .verdict-score-value { font-family: 'Geist Mono', monospace; font-size: 36px; line-height: 40px; font-weight: 700; }
    .verdict-track { height: 8px; border-radius: 9999px; background-color: #272727; margin-top: 24px; overflow: hidden; }
    .verdict-fill { height: 100%; border-radius: 9999px; }
    .evidence-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
    .evidence-card { background-color: #181818; border: 1px solid #272727; border-radius: 12px; padding: 16px; }
    .evidence-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .evidence-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; word-break: break-all; }
    .evidence-pill { font-size: 12px; line-height: 16px; font-weight: 600; padding: 2px 8px; border-radius: 9999px; border: 1px solid #313131; background-color: #1F1F1F; flex-shrink: 0; }
    .evidence-value { font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-top: 8px; }
    .evidence-text { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 8px; }
    .section-title { font-size: 18px; line-height: 28px; font-weight: 600; margin: 0 0 4px 0; }
    .section-note { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-bottom: 16px; }
    @media (max-width: 900px) { .evidence-grid { grid-template-columns: 1fr; } }
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
        f'<div class="kpi-value" style="font-size: 20px; color: {color};">{value}</div></div>'
    )


def render_verdict(title, subtitle, risk_pct):
    """Renders the headline verdict with probability and a flat probability bar."""
    tone = risk_tone(risk_pct)
    color = TONE_COLORS[tone]
    st.markdown(
        f"""
        <div class="verdict-card verdict-{tone}">
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


def build_gauge_figure(risk_pct):
    """Builds the semicircle risk gauge."""
    color = TONE_COLORS[risk_tone(risk_pct)]
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_pct,
        number={"suffix": "%", "font": {"family": "Geist Mono", "size": 32, "color": "#FFFFFF"}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#9B9B9B", "tickwidth": 1,
                     "tickfont": {"family": "Geist Mono", "size": 10, "color": "#9B9B9B"}},
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": "#1F1F1F",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 50], "color": "#181818"},
                {"range": [50, 70], "color": "#1F1F1F"},
                {"range": [70, 100], "color": "#272727"},
            ],
        },
    ))
    fig.update_layout(paper_bgcolor="#000000", plot_bgcolor="#000000",
                      margin=dict(l=24, r=24, t=16, b=8), height=220)
    return fig


def build_attribution_figure(drivers):
    """Builds the horizontal Shapley attribution bar chart for the top drivers."""
    ordered = drivers[::-1]
    values = [d["shap_value"] for d in ordered]
    fig = go.Figure(go.Bar(
        x=values,
        y=[d["feature"] for d in ordered],
        orientation="h",
        marker=dict(color=[RISK_COLOR if v > 0 else SAFE_COLOR for v in values]),
        text=[f"{v:+.3f}" for v in values],
        textposition="outside",
        textfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
        hoverinfo="text",
        hovertext=[f"{d['feature']}: {d['shap_value']:+.4f} ({d['human_text']})" for d in ordered],
    ))
    fig.update_layout(
        paper_bgcolor="#000000", plot_bgcolor="#181818",
        margin=dict(l=8, r=40, t=8, b=32), height=300,
        xaxis=dict(title="Shapley value (log odds)",
                   title_font=dict(family="Geist", size=11, color="#9B9B9B"),
                   gridcolor="#272727", zerolinecolor="#313131",
                   tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
        yaxis=dict(tickfont=dict(family="Geist Mono", size=11, color="#FFFFFF"), gridcolor="#000000"),
    )
    return fig


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
    """Renders gauge, attribution chart, evidence cards, and recourse for one explanation."""
    col_gauge, col_chart = st.columns([2, 3])
    with col_gauge:
        section_header("Threat risk gauge", gauge_note)
        st.plotly_chart(build_gauge_figure(risk_pct), width="stretch")
        k1, k2 = st.columns(2)
        k1.markdown(kpi_tile("Safe probability", f"{100 - risk_pct:.1f}%", TONE_COLORS["safe"]), unsafe_allow_html=True)
        k2.markdown(kpi_tile(*secondary_kpi), unsafe_allow_html=True)
    with col_chart:
        section_header("Shapley feature attribution", chart_note)
        st.plotly_chart(build_attribution_figure(result["top_drivers"]), width="stretch")

    section_header("Key evidence", "The strongest signals behind this result, in plain language.")
    render_evidence(result["top_drivers"])

    section_header("Actionable recourse", "Smallest single changes that reduce the phishing score.")
    render_recourse(result["counterfactual_hints"])
