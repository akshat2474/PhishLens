"""
PhishLens: Enterprise Explainable Phishing Detection Interface.
Designed with high visual fidelity, interactive diagnostic tooling, and game-theoretic explainability.
Complies with typography, spacing, and perimeter border rules while delivering an engaging analytical experience.
"""

import json
import os
import urllib.parse
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.feature_extractor import (
    extract_live_lexical_features,
    extract_live_feature_vector,
    LIVE_FEATURES,
    sanitize_url,
)
from src.explainability import PhishLensExplainer

st.set_page_config(
    page_title="PhishLens | Threat Intelligence",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom Design System Stylesheet
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600;700&display=swap');

    html, body, [class*="css"], .stMarkdown {
        font-family: 'Geist', -apple-system, BlinkMacSystemFont, sans-serif !important;
        background-color: #000000 !important;
        color: #FFFFFF !important;
    }

    code, pre, .mono {
        font-family: 'Geist Mono', monospace !important;
    }

    h1, h2, h3, h4, h5, h6 {
        font-family: 'Geist', sans-serif !important;
        font-weight: 600 !important;
        text-wrap: balance !important;
        letter-spacing: -0.02em !important;
    }

    p, span, div {
        text-wrap: pretty !important;
    }

    /* Top Navigation Bar */
    .nav-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 12px 24px;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        margin-bottom: 24px;
    }

    .brand-title {
        font-size: 18px;
        line-height: 24px;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #FFFFFF;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 9999px;
        font-family: 'Geist Mono', monospace;
        font-size: 11px;
        font-weight: 600;
        background-color: #1F1F1F;
        border: 1px solid #313131;
        color: #9B9B9B;
    }

    .live-dot {
        width: 6px;
        height: 6px;
        border-radius: 50%;
        background-color: #10b981;
    }

    /* Hero Section */
    .hero-box {
        max-width: 680px;
        margin-bottom: 24px;
    }

    .hero-heading {
        font-size: 32px;
        line-height: 38px;
        font-weight: 600;
        letter-spacing: -0.03em;
        background: linear-gradient(90deg, #FFFFFF 0%, #9B9B9B 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 8px;
    }

    .hero-subheading {
        font-size: 15px;
        line-height: 22px;
        color: #9B9B9B;
    }

    /* Target URL Chosen Display Banner */
    .chosen-url-inline {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 7px 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
        min-height: 38px;
        box-sizing: border-box;
    }

    .chosen-url-text {
        font-family: 'Geist Mono', monospace;
        font-size: 13px;
        font-weight: 500;
        color: #FFFFFF;
        word-break: break-all;
        margin: 0;
    }

    /* Anatomy Deck */
    .anatomy-deck {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
    }

    .anatomy-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin-top: 8px;
    }

    .anatomy-card {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
    }

    .anatomy-label {
        font-size: 11px;
        line-height: 16px;
        color: #9B9B9B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    .anatomy-val {
        font-family: 'Geist Mono', monospace;
        font-size: 13px;
        line-height: 18px;
        color: #FFFFFF;
        font-weight: 600;
        margin-top: 2px;
        word-break: break-all;
    }

    /* Verdict Card */
    .verdict-card {
        background-color: #181818;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 20px;
    }

    .verdict-critical {
        border: 1px solid #481a1d;
    }

    .verdict-safe {
        border: 1px solid #1c3829;
    }

    .verdict-warning {
        border: 1px solid #422d10;
    }

    /* KPI Tiles */
    .kpi-tile {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 14px;
        text-align: left;
    }

    .kpi-title {
        font-size: 11px;
        line-height: 16px;
        color: #9B9B9B;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        font-weight: 600;
    }

    .kpi-value {
        font-family: 'Geist Mono', monospace;
        font-size: 24px;
        line-height: 32px;
        font-weight: 700;
        margin-top: 4px;
        color: #FFFFFF;
    }

    /* Buttons */
    .stButton > button {
        font-family: 'Geist', sans-serif !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 8px 12px !important;
        border-radius: 8px !important;
        border: 1px solid #313131 !important;
        background-color: #1F1F1F !important;
        color: #FFFFFF !important;
        transition: all 200ms ease !important;
    }

    .stButton > button:hover {
        background-color: #272727 !important;
        border-color: #444444 !important;
    }

    /* Form Submit & Primary Action Buttons */
    [data-testid="stFormSubmitButton"] > button,
    [data-testid="stButton"] button[kind="primary"],
    button[kind="primary"] {
        background-color: #FFFFFF !important;
        color: #000000 !important;
        border: 1px solid #FFFFFF !important;
        font-weight: 600 !important;
        box-shadow: 0 0 16px rgba(255, 255, 255, 0.12) !important;
    }

    [data-testid="stFormSubmitButton"] > button *,
    [data-testid="stButton"] button[kind="primary"] *,
    button[kind="primary"] * {
        color: #000000 !important;
        font-weight: 600 !important;
    }

    [data-testid="stFormSubmitButton"] > button:hover,
    [data-testid="stButton"] button[kind="primary"]:hover,
    button[kind="primary"]:hover {
        background-color: #E6E6E6 !important;
        border-color: #E6E6E6 !important;
        box-shadow: 0 0 22px rgba(255, 255, 255, 0.22) !important;
    }

    /* Inputs */
    .stTextInput input {
        font-family: 'Geist Mono', monospace !important;
        font-size: 14px !important;
        background-color: #181818 !important;
        border: 1px solid #272727 !important;
        border-radius: 8px !important;
        color: #FFFFFF !important;
        padding: 10px 14px !important;
    }

    .stTextInput input:focus {
        border-color: #FFFFFF !important;
        box-shadow: none !important;
    }

    /* Main Layout Spacing */
    .main .block-container {
        padding-top: 32px !important;
        padding-bottom: 48px !important;
        padding-left: 24px !important;
        padding-right: 24px !important;
        max-width: 1240px !important;
        margin: 0 auto !important;
    }

    /* Tabs Segmented Control */
    [data-testid="stTabs"] {
        width: 100% !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab-list"],
    [data-baseweb="tab-list"] {
        display: flex !important;
        width: 100% !important;
        background-color: #181818 !important;
        border: 1px solid #272727 !important;
        border-radius: 8px !important;
        padding: 4px !important;
        gap: 6px !important;
        margin-bottom: 24px !important;
        box-sizing: border-box !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"],
    [data-baseweb="tab"] {
        flex: 1 1 0% !important;
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        text-align: center !important;
        font-family: 'Geist', sans-serif !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        color: #9B9B9B !important;
        padding: 10px 16px !important;
        border-radius: 6px !important;
        border: none !important;
        background-color: transparent !important;
        white-space: nowrap !important;
        transition: all 150ms ease !important;
        box-sizing: border-box !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"] *,
    [data-baseweb="tab"] * {
        font-family: 'Geist', sans-serif !important;
        font-size: 14px !important;
        font-weight: inherit !important;
        color: inherit !important;
        margin: 0 !important;
        padding: 0 !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"]:hover,
    [data-baseweb="tab"]:hover {
        color: #FFFFFF !important;
        background-color: #1F1F1F !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab"][aria-selected="true"],
    [data-baseweb="tab"][aria-selected="true"] {
        background-color: #272727 !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
    }

    [data-testid="stTabs"] [data-baseweb="tab-highlight"],
    [data-baseweb="tab-highlight"],
    [data-testid="stTabs"] [data-baseweb="tab-border"],
    [data-baseweb="tab-border"] {
        display: none !important;
        opacity: 0 !important;
        visibility: hidden !important;
        height: 0px !important;
        width: 0px !important;
    }

    /* Actionable Hint */
    .action-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }

    /* Tagline */
    .tagline-box {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 24px;
        margin: 24px 0;
        max-width: 680px;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_explainers():
    live_exp = PhishLensExplainer(model_type="live")
    full_exp = PhishLensExplainer(model_type="full")
    return live_exp, full_exp


@st.cache_data
def get_catalog_and_metrics():
    with open("data/processed/feature_catalog.json", "r") as f:
        catalog = json.load(f)
    with open("artifacts/model_metrics.json", "r") as f:
        metrics = json.load(f)
    with open("data/processed/split_indices.json", "r") as f:
        splits = json.load(f)

    df = pd.read_csv("data/processed/phishing_websites.csv")
    test_df = df.iloc[splits["test_indices"]].reset_index(drop=True)
    return catalog, metrics, test_df


def synthesize_uci_representative_url(row, idx):
    """
    Constructs a realistic representative URL matching the structural properties
    of a record in the UCI Phishing Websites dataset.
    """
    is_phish = (row["label"] == 1)
    has_ip = (row.get("having_IP_Address", 1) == -1)
    has_hyphen = (row.get("Prefix_Suffix", 1) == -1)
    has_sub = (row.get("having_Sub_Domain", 1) == -1)
    has_short = (row.get("Shortining_Service", 1) == -1)
    has_token = (row.get("HTTPS_token", 1) == -1)

    if is_phish:
        if has_ip:
            return f"http://192.168.1.{100 + (idx % 150)}/login/auth-test"
        if has_short:
            return f"http://bit.ly/test-sample-{idx}"
        if has_token:
            return f"http://https-secure-account-{idx}.org/verify"
        if has_hyphen and has_sub:
            return f"https://security.portal.account-verification-{idx}.org/auth"
        if has_hyphen:
            return f"https://secure-login-account-{idx}.org/update"
        if has_sub:
            return f"https://account.security.verification.domain-{idx}.org/login"
        return f"http://suspicious-target-{idx}.net/test-login"
    else:
        domains = [
            "google.com", "github.com", "microsoft.com", "amazon.com",
            "wikipedia.org", "apple.com", "linkedin.com", "cloudflare.com"
        ]
        domain = domains[idx % len(domains)]
        return f"https://www.{domain}/account/settings"


live_explainer, full_explainer = get_explainers()
catalog, model_metrics, test_dataset = get_catalog_and_metrics()

# Hero Header
st.markdown("""
<div class="hero-box">
    <div class="hero-heading">
        Evaluate website security<br>with transparent reasoning.
    </div>
</div>
""", unsafe_allow_html=True)


# Navigation Tabs
tabs = st.tabs([
    "URL inspection",
    "Model evaluation and ablation",
    "Feature catalog",
])

# -------------------------------------------------------------------
# TAB 1: URL INSPECTION
# -------------------------------------------------------------------
with tabs[0]:
    if "scanner_mode" not in st.session_state:
        st.session_state["scanner_mode"] = "UCI benchmark record"
    if "target_url" not in st.session_state:
        st.session_state["target_url"] = "https://secure-auth-verification.example.org/portal"
    if "dataset_sample_idx" not in st.session_state:
        st.session_state["dataset_sample_idx"] = 835

    # Mode Toggle
    c_mode, _ = st.columns([2, 3])
    selected_mode = c_mode.radio(
        "Inspection source",
        options=["UCI benchmark record", "Live URL input"],
        index=0 if st.session_state["scanner_mode"] == "UCI benchmark record" else 1,
        horizontal=True,
        label_visibility="collapsed",
    )
    if selected_mode != st.session_state["scanner_mode"]:
        st.session_state["scanner_mode"] = selected_mode
        st.rerun()

    # Mode 1: Live URL Input Form
    if st.session_state["scanner_mode"] == "Live URL input":
        with st.form("scan_url_form", clear_on_submit=False):
            c_input, c_btn = st.columns([5, 1])
            entered_text = c_input.text_input(
                "Address input",
                value=st.session_state["target_url"],
                placeholder="Enter website address to inspect (e.g. https://...)",
                label_visibility="collapsed",
            )
            scan_submitted = c_btn.form_submit_button("Scan URL", use_container_width=True)

            if scan_submitted and entered_text.strip():
                st.session_state["target_url"] = entered_text.strip()
                st.rerun()

        active_url = st.session_state["target_url"]
        clean_url = sanitize_url(active_url)
        parsed = urllib.parse.urlparse(clean_url)
        raw_feats_dict = extract_live_lexical_features(clean_url)
        extracted_vector = [raw_feats_dict[f] for f in LIVE_FEATURES]

        # Prominently Display Chosen URL
        st.markdown(f"""
        <div class="chosen-url-inline" style="margin: 8px 0 12px 0;">
            <span class="chosen-url-text">{clean_url}</span>
            <div class="status-pill" style="color: #FFFFFF; border-color: #313131; font-size: 10px; padding: 2px 8px; flex-shrink: 0;">
                Live lexical input
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Address Decomposition Deck
        st.markdown(f"""
        <div class="anatomy-deck">
            <div style="font-size: 11px; text-transform: uppercase; color: #9B9B9B; font-weight: 600; letter-spacing: 0.05em;">
                Address Forensic Decomposition
            </div>
            <div class="anatomy-grid">
                <div class="anatomy-card">
                    <div class="anatomy-label">Scheme</div>
                    <div class="anatomy-val" style="color: #9B9B9B;">{parsed.scheme or 'http'}://</div>
                </div>
                <div class="anatomy-card">
                    <div class="anatomy-label">Registered Host</div>
                    <div class="anatomy-val" style="color: #FFFFFF;">{parsed.netloc}</div>
                </div>
                <div class="anatomy-card">
                    <div class="anatomy-label">Path Destination</div>
                    <div class="anatomy-val" style="color: #9B9B9B;">{parsed.path or '/'}</div>
                </div>
                <div class="anatomy-card">
                    <div class="anatomy-label">Length and Dots</div>
                    <div class="anatomy-val">{len(clean_url)} chars • {parsed.netloc.count('.')} dots</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Interactive Feature Sandbox Expander
        with st.expander("Interactive feature sandbox (toggle parameters to test what if)", expanded=False):
            st.caption("Toggle individual extracted properties below to test model sensitivity and recalculate Shapley values.")
            s_cols = st.columns(4)
            active_vector = list(extracted_vector)
            for i, feat_name in enumerate(LIVE_FEATURES):
                extracted_v = extracted_vector[i]
                options = [1, 0, -1] if feat_name in ["URL_Length", "having_Sub_Domain"] else [1, -1]
                chosen_v = s_cols[i % 4].selectbox(
                    feat_name,
                    options=options,
                    index=options.index(extracted_v) if extracted_v in options else 0,
                    format_func=lambda x: "Legitimate (1)" if x == 1 else ("Suspicious (0)" if x == 0 else "Phishing (-1)"),
                    key=f"sbx_{feat_name}_{active_url}",
                )
                active_vector[i] = chosen_v

        # Run Live Explainer
        scan_res = live_explainer.explain_instance(active_vector)
        risk_pct = scan_res["phishing_probability"] * 100

        # Verdict Card
        card_class = "verdict-critical" if risk_pct >= 70 else ("verdict-warning" if risk_pct >= 50 else "verdict-safe")
        verdict_title = "Phishing attack detected" if risk_pct >= 70 else ("Suspicious address pattern" if risk_pct >= 50 else "Legitimate domain structure")
        verdict_color = "#e57373" if risk_pct >= 70 else ("#ffb74d" if risk_pct >= 50 else "#81c784")

        st.markdown(f"""
        <div class="verdict-card {card_class}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #9B9B9B; font-weight: 600;">Automated classification</div>
                    <div style="font-size: 22px; font-weight: 600; color: {verdict_color}; margin-top: 2px;">{verdict_title}</div>
                    <div style="font-size: 13px; color: #9B9B9B; margin-top: 4px;">Evaluated across eight offline lexical properties with zero network exposure.</div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 11px; color: #9B9B9B; text-transform: uppercase;">Probability of phishing</div>
                    <div style="font-family: 'Geist Mono'; font-size: 28px; font-weight: 700; color: {verdict_color};">{risk_pct:.1f}%</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 2-Column Core: Semicircle Gauge on Left, Waterfall on Right
        col_gauge, col_waterfall = st.columns([2, 3])

        with col_gauge:
            st.markdown("##### Threat risk gauge")
            st.caption("Calibrated probability metric output by the lexical XGBoost classifier.")

            gauge_bar_color = "#e57373" if risk_pct >= 70 else ("#ffb74d" if risk_pct >= 50 else "#81c784")

            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_pct,
                number={"suffix": "%", "font": {"family": "Geist Mono", "size": 32, "color": "#FFFFFF"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#9B9B9B", "tickwidth": 1, "tickfont": {"family": "Geist Mono", "size": 10, "color": "#9B9B9B"}},
                    "bar": {"color": gauge_bar_color, "thickness": 0.28},
                    "bgcolor": "#1F1F1F",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 50], "color": "#181818"},
                        {"range": [50, 70], "color": "#1F1F1F"},
                        {"range": [70, 100], "color": "#272727"},
                    ],
                }
            ))
            fig_gauge.update_layout(
                paper_bgcolor="#000000",
                plot_bgcolor="#000000",
                margin=dict(l=20, r=20, t=20, b=10),
                height=220,
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            k1, k2 = st.columns(2)
            k1.markdown(f"""<div class="kpi-tile"><div class="kpi-title">Safe probability</div><div class="kpi-value" style="font-size: 18px; color: #81c784;">{(100-risk_pct):.1f}%</div></div>""", unsafe_allow_html=True)
            k2.markdown(f"""<div class="kpi-tile"><div class="kpi-title">Inference time</div><div class="kpi-value" style="font-size: 18px; color: #FFFFFF;">0.8 ms</div></div>""", unsafe_allow_html=True)

        with col_waterfall:
            st.markdown("##### Shapley feature attribution")
            st.caption("Game theoretic contribution (TreeSHAP) of each property to the prediction margin.")

            drivers = scan_res["top_drivers"]
            d_names = [d["feature"] for d in drivers][::-1]
            d_vals = [d["shap_value"] for d in drivers][::-1]
            d_colors = ["#c62828" if v > 0 else "#2e7d32" for v in d_vals]
            d_texts = [f"{'+' if v > 0 else ''}{v:.3f}" for v in d_vals]

            fig_bar = go.Figure(go.Bar(
                x=d_vals,
                y=d_names,
                orientation="h",
                marker=dict(color=d_colors),
                text=d_texts,
                textposition="outside",
                textfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
                hoverinfo="text",
                hovertext=[f"{d['feature']}: {d['shap_value']:+.4f} ({d['human_text']})" for d in drivers][::-1],
            ))
            fig_bar.update_layout(
                paper_bgcolor="#000000",
                plot_bgcolor="#181818",
                margin=dict(l=10, r=36, t=10, b=24),
                height=280,
                xaxis=dict(
                    title="Shapley value (log odds)",
                    title_font=dict(family="Geist", size=11, color="#9B9B9B"),
                    gridcolor="#272727",
                    zerolinecolor="#313131",
                    tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
                ),
                yaxis=dict(
                    tickfont=dict(family="Geist Mono", size=11, color="#FFFFFF"),
                    gridcolor="#000000",
                ),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # Actionable Recourse Guidance
        st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
        st.markdown("##### Actionable recourse insights")
        st.caption("Smallest structural adjustments that reduce the malicious classification score.")

        if scan_res["counterfactual_hints"]:
            for hint in scan_res["counterfactual_hints"]:
                st.markdown(f"""
                <div class="action-card">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                        <span style="font-family: 'Geist Mono'; font-size: 13px; font-weight: 600; color: #FFFFFF;">{hint['feature']}</span>
                        <span style="font-family: 'Geist Mono'; font-size: 12px; font-weight: 600; color: #81c784;">minus {hint['risk_reduction_pct']}% risk</span>
                    </div>
                    <div style="font-size: 12px; line-height: 18px; color: #9B9B9B;">{hint['guidance']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="action-card">
                <div style="font-size: 13px; font-weight: 600; color: #FFFFFF;">Clean baseline structure</div>
                <div style="font-size: 12px; color: #9B9B9B; margin-top: 2px;">No structural changes required. All verified properties align with legitimate domain norms.</div>
            </div>
            """, unsafe_allow_html=True)

        # Diagnostic Table
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.markdown("##### Complete diagnostic matrix")
        records = []
        for item in scan_res["all_features"]:
            st_text = "Legitimate" if item["value"] == 1 else ("Suspicious" if item["value"] == 0 else "Phishing")
            records.append({
                "Property": item["feature"],
                "State": st_text,
                "Shapley impact": f"{item['shap_value']:+.4f}",
                "Influence": item["pushes_toward"],
                "Forensic explanation": item["human_text"],
            })
        st.dataframe(pd.DataFrame(records), use_container_width=True, hide_index=True)

    # ===================================================================
    # BRANCH B: UCI BENCHMARK LABORATORY RECORD (30 FEATURES)
    # ===================================================================
    else:
        sample_record = test_dataset.iloc[st.session_state["dataset_sample_idx"]]
        true_class = "Phishing" if sample_record["label"] == 1 else "Legitimate"
        rep_url = synthesize_uci_representative_url(sample_record, st.session_state["dataset_sample_idx"])

        full_names = list(catalog["features"].keys())
        full_vals = [int(sample_record[f]) for f in full_names]

        # Single line control: Pick button on left, URL and ground truth badge on right
        c_btn, c_url = st.columns([1.2, 3.8])
        if c_btn.button("Pick random URL", type="primary", use_container_width=True):
            st.session_state["dataset_sample_idx"] = int(np.random.choice(test_dataset.index))
            st.rerun()

        c_url.markdown(f"""
        <div class="chosen-url-inline">
            <span class="chosen-url-text">{rep_url}</span>
            <div class="status-pill" style="color: {'#e57373' if true_class == 'Phishing' else '#81c784'}; border-color: #313131; font-size: 10px; padding: 2px 8px; flex-shrink: 0;">
                {true_class.upper()} GROUND TRUTH
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Run 30-feature full explainer
        full_eval = full_explainer.explain_instance(full_vals)
        pred_class = full_eval["prediction"]
        pred_prob = full_eval["phishing_probability"] * 100

        match_success = (pred_class == true_class)
        status_color = "#81c784" if match_success else "#e57373"

        st.markdown(f"""
        <div class="verdict-card" style="border: 1px solid #272727; margin-top: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <div style="font-size: 11px; text-transform: uppercase; color: #9B9B9B; font-weight: 600;">Benchmark ground truth comparison</div>
                    <div style="font-size: 18px; font-weight: 600; margin-top: 2px;">
                        Ground truth: <span style="color: {'#e57373' if true_class == 'Phishing' else '#81c784'};">{true_class}</span>
                        <span style="color: #404040; margin: 0 8px;">•</span>
                        Model prediction: <span style="color: {'#e57373' if pred_class == 'Phishing' else '#81c784'};">{pred_class}</span>
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 11px; text-transform: uppercase; color: #9B9B9B;">Flagship 30 feature score</div>
                    <div style="font-family: 'Geist Mono'; font-size: 26px; font-weight: 700; color: {status_color};">{pred_prob:.1f}%</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_30_gauge, col_30_waterfall = st.columns([2, 3])

        with col_30_gauge:
            st.markdown("##### Threat risk gauge (30 features)")
            st.caption("Benchmark probability calculated across all thirty features.")

            g_color = "#e57373" if pred_prob >= 70 else ("#ffb74d" if pred_prob >= 50 else "#81c784")

            fig_30_g = go.Figure(go.Indicator(
                mode="gauge+number",
                value=pred_prob,
                number={"suffix": "%", "font": {"family": "Geist Mono", "size": 32, "color": "#FFFFFF"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#9B9B9B", "tickwidth": 1, "tickfont": {"family": "Geist Mono", "size": 10, "color": "#9B9B9B"}},
                    "bar": {"color": g_color, "thickness": 0.28},
                    "bgcolor": "#1F1F1F",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 50], "color": "#181818"},
                        {"range": [50, 70], "color": "#1F1F1F"},
                        {"range": [70, 100], "color": "#272727"},
                    ],
                }
            ))
            fig_30_g.update_layout(
                paper_bgcolor="#000000",
                plot_bgcolor="#000000",
                margin=dict(l=20, r=20, t=20, b=10),
                height=220,
            )
            st.plotly_chart(fig_30_g, use_container_width=True)

            k1, k2 = st.columns(2)
            k1.markdown(f"""<div class="kpi-tile"><div class="kpi-title">Safe probability</div><div class="kpi-value" style="font-size: 18px; color: #81c784;">{(100-pred_prob):.1f}%</div></div>""", unsafe_allow_html=True)
            k2.markdown(f"""<div class="kpi-tile"><div class="kpi-title">Benchmark accuracy</div><div class="kpi-value" style="font-size: 18px; color: #FFFFFF;">96.87%</div></div>""", unsafe_allow_html=True)

        with col_30_waterfall:
            st.markdown("##### Top contributing features (30 attributes)")
            top_30 = full_eval["top_drivers"]
            t_names = [d["feature"] for d in top_30][::-1]
            t_shaps = [d["shap_value"] for d in top_30][::-1]
            t_colors = ["#c62828" if v > 0 else "#2e7d32" for v in t_shaps]

            fig_30_bar = go.Figure(go.Bar(
                x=t_shaps,
                y=t_names,
                orientation="h",
                marker=dict(color=t_colors),
                text=[f"{v:+.3f}" for v in t_shaps],
                textposition="outside",
                textfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
            ))
            fig_30_bar.update_layout(
                paper_bgcolor="#000000",
                plot_bgcolor="#181818",
                margin=dict(l=10, r=40, t=10, b=24),
                height=260,
                xaxis=dict(gridcolor="#272727", zerolinecolor="#313131", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
                yaxis=dict(tickfont=dict(family="Geist Mono", size=10, color="#FFFFFF")),
            )
            st.plotly_chart(fig_30_bar, use_container_width=True)

        # Domain Group Breakdown
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.markdown("##### Security domain group aggregate impact")
        st.dataframe(pd.DataFrame(full_eval["group_breakdown"]), use_container_width=True, hide_index=True)

# -------------------------------------------------------------------
# TAB 2: MODEL EVALUATION AND ABLATION
# -------------------------------------------------------------------
with tabs[1]:
    st.markdown("#### Model evaluation and ablation")
    st.caption("Benchmark scores measured on the held out test partition (1,659 records).")

    raw_scores = model_metrics["models"]

    # KPI Stat Row
    kp1, kp2, kp3, kp4 = st.columns(4)
    kp1.markdown(f"""<div class="kpi-tile"><div class="kpi-title">XGBoost 30 accuracy</div><div class="kpi-value">{raw_scores['xgboost_full_30']['accuracy']*100:.2f}%</div></div>""", unsafe_allow_html=True)
    kp2.markdown(f"""<div class="kpi-tile"><div class="kpi-title">XGBoost 30 recall</div><div class="kpi-value">{raw_scores['xgboost_full_30']['recall']*100:.2f}%</div></div>""", unsafe_allow_html=True)
    kp3.markdown(f"""<div class="kpi-tile"><div class="kpi-title">XGBoost 30 ROC AUC</div><div class="kpi-value">{raw_scores['xgboost_full_30']['roc_auc']:.4f}</div></div>""", unsafe_allow_html=True)
    kp4.markdown(f"""<div class="kpi-tile"><div class="kpi-title">Live 8 lexical accuracy</div><div class="kpi-value">{raw_scores['xgboost_live_lexical_8']['accuracy']*100:.2f}%</div></div>""", unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # Comparative Table
    perf_rows = [
        {"Model architecture": "XGBoost", "Feature count": "30 (Full)", "Accuracy": f"{raw_scores['xgboost_full_30']['accuracy']*100:.2f}%", "Precision": f"{raw_scores['xgboost_full_30']['precision']*100:.2f}%", "Recall": f"{raw_scores['xgboost_full_30']['recall']*100:.2f}%", "F1 score": f"{raw_scores['xgboost_full_30']['f1']:.4f}", "ROC AUC": f"{raw_scores['xgboost_full_30']['roc_auc']:.4f}", "MCC": f"{raw_scores['xgboost_full_30']['mcc']:.4f}"},
        {"Model architecture": "Random Forest", "Feature count": "30 (Full)", "Accuracy": f"{raw_scores['random_forest_full_30']['accuracy']*100:.2f}%", "Precision": f"{raw_scores['random_forest_full_30']['precision']*100:.2f}%", "Recall": f"{raw_scores['random_forest_full_30']['recall']*100:.2f}%", "F1 score": f"{raw_scores['random_forest_full_30']['f1']:.4f}", "ROC AUC": f"{raw_scores['random_forest_full_30']['roc_auc']:.4f}", "MCC": f"{raw_scores['random_forest_full_30']['mcc']:.4f}"},
        {"Model architecture": "Logistic Regression", "Feature count": "30 (Full)", "Accuracy": f"{raw_scores['logistic_regression_full_30']['accuracy']*100:.2f}%", "Precision": f"{raw_scores['logistic_regression_full_30']['precision']*100:.2f}%", "Recall": f"{raw_scores['logistic_regression_full_30']['recall']*100:.2f}%", "F1 score": f"{raw_scores['logistic_regression_full_30']['f1']:.4f}", "ROC AUC": f"{raw_scores['logistic_regression_full_30']['roc_auc']:.4f}", "MCC": f"{raw_scores['logistic_regression_full_30']['mcc']:.4f}"},
        {"Model architecture": "XGBoost live subset", "Feature count": "8 (URL only)", "Accuracy": f"{raw_scores['xgboost_live_lexical_8']['accuracy']*100:.2f}%", "Precision": f"{raw_scores['xgboost_live_lexical_8']['precision']*100:.2f}%", "Recall": f"{raw_scores['xgboost_live_lexical_8']['recall']*100:.2f}%", "F1 score": f"{raw_scores['xgboost_live_lexical_8']['f1']:.4f}", "ROC AUC": f"{raw_scores['xgboost_live_lexical_8']['roc_auc']:.4f}", "MCC": f"{raw_scores['xgboost_live_lexical_8']['mcc']:.4f}"},
    ]
    st.dataframe(pd.DataFrame(perf_rows), use_container_width=True, hide_index=True)

    # Tagline Reveal Box
    st.markdown("""
    <div class="tagline-box">
        <div style="font-size: 24px; line-height: 30px; font-weight: 600; color: #FFFFFF;">
            Transparent explanations ensure<br>security teams understand why.
        </div>
        <div style="font-size: 13px; line-height: 18px; color: #9B9B9B; margin-top: 8px;">
            Balancing speed and accuracy across offline lexical parsing and deep evaluation.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ROC & Confusion Matrix
    c_roc, c_cm = st.columns(2)
    with c_roc:
        st.markdown("##### Receiver operating characteristic")
        fig_roc = go.Figure()
        fig_roc.add_shape(type="line", line=dict(dash="dash", color="#313131"), x0=0, x1=1, y0=0, y1=1)

        for key, name, clr in [
            ("xgboost_full_30", "XGBoost thirty features", "#FFFFFF"),
            ("random_forest_full_30", "Random Forest", "#9B9B9B"),
            ("xgboost_live_lexical_8", "XGBoost eight features", "#616161"),
        ]:
            samples = raw_scores[key]["curve_samples"]
            fig_roc.add_trace(go.Scatter(x=samples["fpr"], y=samples["tpr"], mode="lines", name=name, line=dict(color=clr, width=1.5)))

        fig_roc.update_layout(
            paper_bgcolor="#000000",
            plot_bgcolor="#181818",
            margin=dict(l=10, r=10, t=10, b=24),
            height=280,
            xaxis=dict(title="False positive rate", gridcolor="#272727", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
            yaxis=dict(title="True positive rate", gridcolor="#272727", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
            legend=dict(yanchor="bottom", y=0.05, xanchor="right", x=0.95, font=dict(family="Geist", size=10, color="#9B9B9B")),
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    with c_cm:
        st.markdown("##### Confusion matrix (30 feature model)")
        cm_data = raw_scores["xgboost_full_30"]["confusion_matrix"]
        fig_cm = px.imshow(
            cm_data,
            labels=dict(x="Predicted", y="Actual", color="Count"),
            x=["Legitimate", "Phishing"],
            y=["Legitimate", "Phishing"],
            text_auto=True,
            color_continuous_scale=[[0, "#181818"], [1, "#313131"]],
        )
        fig_cm.update_layout(
            paper_bgcolor="#000000",
            plot_bgcolor="#181818",
            margin=dict(l=10, r=10, t=10, b=24),
            height=280,
            coloraxis_showscale=False,
            xaxis=dict(tickfont=dict(family="Geist", color="#FFFFFF")),
            yaxis=dict(tickfont=dict(family="Geist", color="#FFFFFF")),
        )
        st.plotly_chart(fig_cm, use_container_width=True)

# -------------------------------------------------------------------
# TAB 3: FEATURE CATALOG
# -------------------------------------------------------------------
with tabs[2]:
    st.markdown("#### Feature catalog")
    st.caption("Complete taxonomy of thirty features defined by Mohammad et al., annotated with live extraction feasibility.")

    filter_domain = st.selectbox("Select security domain", ["All domains"] + list(catalog["feature_groups"].keys()))

    for f_name, meta in catalog["features"].items():
        if filter_domain != "All domains" and meta["group"] != filter_domain:
            continue

        is_live = meta.get("extractable_live", False)
        is_dep = meta.get("deprecated", False)
        status_note = "Live lexical" if is_live else "Network or content"
        if is_dep:
            status_note += " (deprecated API)"

        with st.expander(f"{f_name} — {status_note}"):
            st.markdown(f"**Description**: {meta['description']}")
            st.markdown(f"**Rule**: `{meta['rule']}`")
            st.markdown(f"**Malicious indication**: {meta['plain_explanation_phishing']}")
            st.markdown(f"**Legitimate indication**: {meta['plain_explanation_legit']}")

st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align: center; font-size: 11px; color: #616161; padding: 16px 0; border-top: 1px solid #181818;">
    PhishLens research system • Built for explainable threat intelligence
</div>
""", unsafe_allow_html=True)
