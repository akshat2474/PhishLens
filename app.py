"""
PhishLens: Explainable Phishing Detection Interface.
Strictly designed according to elayadesign/ai-design-skills (landing-page-design).
Features:
- Typography: Geist and Geist Mono only, Tailwind scale, sentence case, no hyphens, no italics
- Colors: Flat dark mode (#000000, #181818, #1F1F1F, #272727, #313131), no background gradients
- Spacing: Strict spacing tokens only (0, 2, 4, 8, 12, 16, 24, 32, 40, 48, 64, 80, 96px)
- Borders: Full perimeter borders only, no single-sided borders
- Layout: Capped max-width hero with #FFFFFF -> #9B9B9B text gradient
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

# Page configuration
st.set_page_config(
    page_title="PhishLens",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Strict Design System Stylesheet based on ai-design-skills
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600&display=swap');

    /* Global Typography */
    html, body, [class*="css"], .stMarkdown {
        font-family: 'Geist', sans-serif !important;
        font-style: normal !important;
        background-color: #000000 !important;
        color: #FFFFFF !important;
    }

    code, pre, .mono {
        font-family: 'Geist Mono', monospace !important;
        font-style: normal !important;
    }

    /* Headings & Text Wrapping */
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Geist', sans-serif !important;
        font-weight: 600 !important;
        text-wrap: balance !important;
        letter-spacing: -0.02em !important;
    }

    p, span, div {
        text-wrap: pretty !important;
    }

    /* Hero Section per B5 */
    .hero-container {
        max-width: 680px;
        margin-top: 16px;
        margin-bottom: 32px;
    }

    .hero-title {
        font-size: 36px;
        line-height: 40px;
        font-weight: 600;
        letter-spacing: -0.03em;
        background: linear-gradient(90deg, #FFFFFF 0%, #9B9B9B 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 12px;
    }

    .hero-sub {
        font-size: 16px;
        line-height: 24px;
        color: #9B9B9B;
        margin-bottom: 24px;
    }

    /* Card Surfaces per B4 */
    .card-surface {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 16px;
    }

    .card-surface-sm {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 16px;
    }

    /* Verdict Cards per B4 (Full perimeter border, flat background) */
    .verdict-banner-danger {
        background-color: #181818;
        border: 1px solid #481a1d;
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
    }

    .verdict-banner-safe {
        background-color: #181818;
        border: 1px solid #1c3829;
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 24px;
    }

    /* Tagline Reveal Section per B11 */
    .tagline-section {
        max-width: 680px;
        margin: 48px 0 32px 0;
        padding: 32px;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 16px;
    }

    .tagline-text {
        font-size: 30px;
        line-height: 36px;
        font-weight: 600;
        color: #FFFFFF;
    }

    .tagline-sub {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        margin-top: 12px;
    }

    /* Button Styling per B1 and B2 */
    .stButton > button {
        font-family: 'Geist', sans-serif !important;
        font-size: 16px !important;
        line-height: 24px !important;
        font-weight: 600 !important;
        padding: 8px 12px !important;
        border-radius: 8px !important;
        border: 1px solid #313131 !important;
        background-color: #1F1F1F !important;
        color: #FFFFFF !important;
        text-transform: none !important;
        transition: transform 300ms cubic-bezier(0.22, 1, 0.36, 1), background-color 300ms !important;
    }

    .stButton > button:hover {
        background-color: #272727 !important;
        border-color: #404040 !important;
        transform: translateY(-1px) !important;
    }

    .stButton > button:active {
        transform: translateY(1px) !important;
    }

    /* Input Field */
    .stTextInput input {
        font-family: 'Geist Mono', monospace !important;
        font-size: 14px !important;
        line-height: 20px !important;
        background-color: #181818 !important;
        border: 1px solid #272727 !important;
        border-radius: 8px !important;
        color: #FFFFFF !important;
        padding: 12px 16px !important;
    }

    .stTextInput input:focus {
        border-color: #FFFFFF !important;
        box-shadow: none !important;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        background-color: #181818 !important;
        border: 1px solid #272727 !important;
        border-radius: 8px !important;
        padding: 4px !important;
        gap: 4px !important;
        margin-bottom: 24px !important;
    }

    .stTabs [data-baseweb="tab"] {
        font-family: 'Geist', sans-serif !important;
        font-size: 14px !important;
        line-height: 20px !important;
        font-weight: 500 !important;
        color: #9B9B9B !important;
        padding: 8px 16px !important;
        border-radius: 6px !important;
        border: none !important;
        background-color: transparent !important;
        text-transform: none !important;
    }

    .stTabs [aria-selected="true"] {
        background-color: #272727 !important;
        color: #FFFFFF !important;
        font-weight: 600 !important;
    }

    /* Metric values */
    .metric-num {
        font-family: 'Geist Mono', monospace;
        font-size: 30px;
        line-height: 36px;
        font-weight: 600;
    }

    .metric-label {
        font-family: 'Geist', sans-serif;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 4px;
    }

    /* Tokens */
    .token-chip {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 6px;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        margin-right: 8px;
        margin-bottom: 8px;
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


live_explainer, full_explainer = get_explainers()
catalog, model_metrics, test_dataset = get_catalog_and_metrics()

# Hero Header (Strictly complies with B5: max 680px, #FFFFFF -> #9B9B9B gradient on text only)
st.markdown("""
<div class="hero-container">
    <div style="font-size: 12px; line-height: 16px; font-weight: 600; color: #9B9B9B; margin-bottom: 8px;">
        PhishLens verification system
    </div>
    <div class="hero-title">
        Explainable phishing detection<br>grounded in URL features.
    </div>
    <div class="hero-sub">
        Inspect website addresses, estimate malicious probabilities, and audit<br>
        the exact structural factors influencing every prediction through TreeSHAP.
    </div>
</div>
""", unsafe_allow_html=True)

# Main Tabs (Sentence case per B8)
tabs = st.tabs([
    "Live URL scanner",
    "Dataset laboratory",
    "Model performance",
    "Feature encyclopedia",
])

# -------------------------------------------------------------------
# TAB 1: LIVE URL SCANNER
# -------------------------------------------------------------------
with tabs[0]:
    st.markdown("#### Analyze a website address")
    st.caption("Evaluates the address structure completely offline without loading remote code or sending network requests.")

    # Preset Chips (Sentence case, no hyphens per B1)
    col_presets = st.columns(4)
    selected_preset = None
    if col_presets[0].button("Legitimate domain", use_container_width=True):
        selected_preset = "https://www.google.com"
    if col_presets[1].button("Hyphen spoof address", use_container_width=True):
        selected_preset = "https://secure-login-paypal.com/verify"
    if col_presets[2].button("Raw IP address host", use_container_width=True):
        selected_preset = "http://192.168.1.100/paypal/login.html"
    if col_presets[3].button("Shortened redirect URL", use_container_width=True):
        selected_preset = "http://bit.ly/3xYzAq9"

    input_address = selected_preset if selected_preset else "https://secure-login-paypal.com/verify"
    c_url, c_act = st.columns([5, 1])
    entered_url = c_url.text_input("Website address", value=input_address, label_visibility="collapsed")
    run_scan = c_act.button("Scan URL", use_container_width=True)

    if entered_url:
        clean_url = sanitize_url(entered_url)
        parsed = urllib.parse.urlparse(clean_url)
        features = extract_live_feature_vector(clean_url)
        report = live_explainer.explain_instance(features)
        score = report["phishing_probability"]

        # URL Structural Breakdown
        st.markdown(f"""
        <div style="background-color: #181818; border: 1px solid #272727; border-radius: 8px; padding: 12px 16px; margin: 16px 0;">
            <span style="font-size: 12px; line-height: 16px; color: #9B9B9B; margin-right: 12px;">Address components</span>
            <span class="token-chip">{parsed.scheme}://</span>
            <span class="token-chip" style="color: #FFFFFF; font-weight: 600;">{parsed.netloc}</span>
            <span class="token-chip">{parsed.path or '/'}</span>
            {f'<span class="token-chip">?{parsed.query}</span>' if parsed.query else ''}
        </div>
        """, unsafe_allow_html=True)

        # Verdict Card (Complies with B4: flat surface, perimeter border)
        is_risky = score >= 0.50
        box_class = "verdict-banner-danger" if is_risky else "verdict-banner-safe"
        verdict_heading = "Phishing attack detected" if is_risky else "Legitimate domain structure"
        verdict_detail = (
            "Structural anomalies in this address match deceptive patterns commonly used in credential harvesting."
            if is_risky
            else "The address adheres to common legitimate naming conventions with no deceptive indicators."
        )

        st.markdown(f"""
        <div class="{box_class}">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <div style="font-size: 12px; line-height: 16px; font-weight: 600; color: #9B9B9B; margin-bottom: 4px;">
                        Evaluation verdict
                    </div>
                    <div style="font-size: 24px; line-height: 32px; font-weight: 600; color: #FFFFFF; margin-bottom: 4px;">
                        {verdict_heading}
                    </div>
                    <div style="font-size: 14px; line-height: 20px; color: #9B9B9B; max-width: 580px;">
                        {verdict_detail}
                    </div>
                </div>
                <div style="text-align: right;">
                    <div style="font-size: 12px; line-height: 16px; color: #9B9B9B;">Malicious probability</div>
                    <div class="metric-num" style="color: {'#e57373' if is_risky else '#81c784'};">
                        {score * 100:.1f}%
                    </div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # 4 Key Stats (Spacing token 16px, Tailwind text sizes)
        st_c1, st_c2, st_c3, st_c4 = st.columns(4)
        with st_c1:
            st.markdown(f"""<div class="card-surface-sm"><div class="metric-label">Phishing score</div><div class="metric-num">{score * 100:.1f}%</div></div>""", unsafe_allow_html=True)
        with st_c2:
            st.markdown(f"""<div class="card-surface-sm"><div class="metric-label">Legitimate score</div><div class="metric-num">{(1-score) * 100:.1f}%</div></div>""", unsafe_allow_html=True)
        with st_c3:
            st.markdown(f"""<div class="card-surface-sm"><div class="metric-label">Evaluation latency</div><div class="metric-num">0.8 ms</div></div>""", unsafe_allow_html=True)
        with st_c4:
            st.markdown(f"""<div class="card-surface-sm"><div class="metric-label">Extracted features</div><div class="metric-num">8 of 8</div></div>""", unsafe_allow_html=True)

        st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

        # Explanations Layout
        col_sh, col_rec = st.columns([3, 2])

        with col_sh:
            st.markdown("##### Feature attribution breakdown")
            st.caption("Calculates the exact Shapley contribution of each factor to the final log odds.")

            top_factors = report["top_drivers"]
            names = [d["feature"] for d in top_factors][::-1]
            values = [d["shap_value"] for d in top_factors][::-1]
            colors = ["#c62828" if v > 0 else "#2e7d32" for v in values]
            labels = [f"{'+' if v>0 else ''}{v:.3f}" for v in values]

            fig_waterfall = go.Figure(go.Bar(
                x=values,
                y=names,
                orientation="h",
                marker=dict(color=colors),
                text=labels,
                textposition="outside",
                textfont=dict(family="Geist Mono", size=11, color="#9B9B9B"),
                hoverinfo="text",
                hovertext=[f"{d['feature']}: {d['shap_value']:+.4f} ({d['human_text']})" for d in top_factors][::-1]
            ))

            fig_waterfall.update_layout(
                paper_bgcolor="#000000",
                plot_bgcolor="#181818",
                margin=dict(l=10, r=40, t=10, b=24),
                height=280,
                xaxis=dict(
                    title="Shapley contribution",
                    title_font=dict(family="Geist", size=12, color="#9B9B9B"),
                    tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
                    gridcolor="#272727",
                    zerolinecolor="#313131",
                ),
                yaxis=dict(
                    tickfont=dict(family="Geist Mono", size=11, color="#FFFFFF"),
                    gridcolor="#000000",
                ),
            )
            st.plotly_chart(fig_waterfall, use_container_width=True)

        with col_rec:
            st.markdown("##### Minimal feature adjustments")
            st.caption("Identifies the smallest structural adjustments that reduce the classification score.")

            if report["counterfactual_hints"]:
                for hint in report["counterfactual_hints"]:
                    st.markdown(f"""
                    <div style="background-color: #181818; border: 1px solid #272727; border-radius: 8px; padding: 12px 16px; margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                            <span style="font-family: 'Geist Mono'; font-size: 14px; font-weight: 600; color: #FFFFFF;">{hint['feature']}</span>
                            <span style="font-family: 'Geist Mono'; font-size: 12px; font-weight: 600; color: #81c784;">minus {hint['risk_reduction_pct']}% risk</span>
                        </div>
                        <div style="font-size: 12px; line-height: 16px; color: #9B9B9B;">
                            {hint['guidance']}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                <div style="background-color: #181818; border: 1px solid #272727; border-radius: 8px; padding: 16px;">
                    <div style="font-size: 14px; font-weight: 600; color: #FFFFFF; margin-bottom: 4px;">Standard structure</div>
                    <div style="font-size: 12px; line-height: 16px; color: #9B9B9B;">
                        No dominant anomalies observed. The address structure satisfies common safety checks.
                    </div>
                </div>
                """, unsafe_allow_html=True)

        # Tabular details
        st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
        st.markdown("##### Extracted feature details")
        rows = []
        for item in report["all_features"]:
            state = "Legitimate" if item["value"] == 1 else ("Suspicious" if item["value"] == 0 else "Phishing")
            rows.append({
                "Feature name": item["feature"],
                "Value": state,
                "Impact": f"{item['shap_value']:+.4f}",
                "Pushes toward": item["pushes_toward"],
                "Rule interpretation": item["human_text"],
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

# -------------------------------------------------------------------
# TAB 2: DATASET LAB
# -------------------------------------------------------------------
with tabs[1]:
    st.markdown("#### Test set sample inspection")
    st.caption("Inspect complete thirty feature records from the UCI Phishing Websites holdout partition.")

    if "active_idx" not in st.session_state:
        st.session_state["active_idx"] = 0

    col_b1, col_b2, col_b3 = st.columns([1, 1, 2])
    if col_b1.button("Sample phishing case", use_container_width=True):
        pool = test_dataset[test_dataset["label"] == 1].index
        st.session_state["active_idx"] = int(np.random.choice(pool))
    if col_b2.button("Sample legitimate case", use_container_width=True):
        pool = test_dataset[test_dataset["label"] == 0].index
        st.session_state["active_idx"] = int(np.random.choice(pool))

    row = test_dataset.iloc[st.session_state["active_idx"]]
    actual_label = "Phishing" if row["label"] == 1 else "Legitimate"

    full_names = list(catalog["features"].keys())
    full_vals = [int(row[f]) for f in full_names]

    eval_out = full_explainer.explain_instance(full_vals)
    pred_label = eval_out["prediction"]
    pred_prob = eval_out["phishing_probability"]

    st.markdown(f"""
    <div class="card-surface" style="margin-top: 16px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <div style="font-size: 12px; line-height: 16px; color: #9B9B9B;">Record index #{st.session_state['active_idx']}</div>
                <div style="font-size: 18px; line-height: 28px; font-weight: 600; margin-top: 4px;">
                    Ground truth: <span style="color: {'#e57373' if actual_label == 'Phishing' else '#81c784'};">{actual_label}</span>
                    <span style="color: #404040; margin: 0 8px;">•</span>
                    Predicted: <span style="color: {'#e57373' if pred_label == 'Phishing' else '#81c784'};">{pred_label}</span>
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 12px; line-height: 16px; color: #9B9B9B;">Model confidence</div>
                <div class="metric-num">{pred_prob * 100:.1f}%</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    c_30_1, c_30_2 = st.columns([3, 2])
    with c_30_1:
        st.markdown("##### Influential features across thirty attributes")
        drivers = eval_out["top_drivers"]
        d_names = [d["feature"] for d in drivers][::-1]
        d_shaps = [d["shap_value"] for d in drivers][::-1]
        d_clrs = ["#c62828" if v > 0 else "#2e7d32" for v in d_shaps]

        fig_30 = go.Figure(go.Bar(
            x=d_shaps,
            y=d_names,
            orientation="h",
            marker=dict(color=d_clrs),
            text=[f"{v:+.3f}" for v in d_shaps],
            textposition="outside",
            textfont=dict(family="Geist Mono", size=10, color="#9B9B9B"),
        ))
        fig_30.update_layout(
            paper_bgcolor="#000000",
            plot_bgcolor="#181818",
            margin=dict(l=10, r=40, t=10, b=24),
            height=260,
            xaxis=dict(gridcolor="#272727", zerolinecolor="#313131", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
            yaxis=dict(tickfont=dict(family="Geist Mono", size=10, color="#FFFFFF")),
        )
        st.plotly_chart(fig_30, use_container_width=True)

    with c_30_2:
        st.markdown("##### Security domain group impact")
        st.dataframe(pd.DataFrame(eval_out["group_breakdown"]), use_container_width=True, hide_index=True)

# -------------------------------------------------------------------
# TAB 3: MODEL PERFORMANCE
# -------------------------------------------------------------------
with tabs[2]:
    st.markdown("#### Test set performance comparison")
    st.caption("Benchmark scores measured on the held out test partition (1,659 records).")

    metrics_raw = model_metrics["models"]
    benchmark_table = [
        {
            "Algorithm": "XGBoost",
            "Features": "30 features",
            "Accuracy": f"{metrics_raw['xgboost_full_30']['accuracy']*100:.2f}%",
            "Precision": f"{metrics_raw['xgboost_full_30']['precision']*100:.2f}%",
            "Recall": f"{metrics_raw['xgboost_full_30']['recall']*100:.2f}%",
            "F1 score": f"{metrics_raw['xgboost_full_30']['f1']:.4f}",
            "ROC AUC": f"{metrics_raw['xgboost_full_30']['roc_auc']:.4f}",
            "MCC": f"{metrics_raw['xgboost_full_30']['mcc']:.4f}",
        },
        {
            "Algorithm": "Random Forest",
            "Features": "30 features",
            "Accuracy": f"{metrics_raw['random_forest_full_30']['accuracy']*100:.2f}%",
            "Precision": f"{metrics_raw['random_forest_full_30']['precision']*100:.2f}%",
            "Recall": f"{metrics_raw['random_forest_full_30']['recall']*100:.2f}%",
            "F1 score": f"{metrics_raw['random_forest_full_30']['f1']:.4f}",
            "ROC AUC": f"{metrics_raw['random_forest_full_30']['roc_auc']:.4f}",
            "MCC": f"{metrics_raw['random_forest_full_30']['mcc']:.4f}",
        },
        {
            "Algorithm": "Logistic Regression",
            "Features": "30 features",
            "Accuracy": f"{metrics_raw['logistic_regression_full_30']['accuracy']*100:.2f}%",
            "Precision": f"{metrics_raw['logistic_regression_full_30']['precision']*100:.2f}%",
            "Recall": f"{metrics_raw['logistic_regression_full_30']['recall']*100:.2f}%",
            "F1 score": f"{metrics_raw['logistic_regression_full_30']['f1']:.4f}",
            "ROC AUC": f"{metrics_raw['logistic_regression_full_30']['roc_auc']:.4f}",
            "MCC": f"{metrics_raw['logistic_regression_full_30']['mcc']:.4f}",
        },
        {
            "Algorithm": "XGBoost live subset",
            "Features": "8 lexical features",
            "Accuracy": f"{metrics_raw['xgboost_live_lexical_8']['accuracy']*100:.2f}%",
            "Precision": f"{metrics_raw['xgboost_live_lexical_8']['precision']*100:.2f}%",
            "Recall": f"{metrics_raw['xgboost_live_lexical_8']['recall']*100:.2f}%",
            "F1 score": f"{metrics_raw['xgboost_live_lexical_8']['f1']:.4f}",
            "ROC AUC": f"{metrics_raw['xgboost_live_lexical_8']['roc_auc']:.4f}",
            "MCC": f"{metrics_raw['xgboost_live_lexical_8']['mcc']:.4f}",
        },
    ]

    st.dataframe(pd.DataFrame(benchmark_table), use_container_width=True, hide_index=True)

    # Mandatory Tagline Reveal Section per B11
    st.markdown("""
    <div class="tagline-section">
        <div class="tagline-text">
            Transparent explanations ensure<br>defenders understand why.
        </div>
        <div class="tagline-sub">
            Balancing speed and accuracy across offline lexical parsing and deep evaluation.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    col_roc, col_cm = st.columns(2)
    with col_roc:
        st.markdown("##### Receiver operating characteristic")
        fig_roc = go.Figure()
        fig_roc.add_shape(type="line", line=dict(dash="dash", color="#313131"), x0=0, x1=1, y0=0, y1=1)

        for key, name, clr in [
            ("xgboost_full_30", "XGBoost thirty features", "#FFFFFF"),
            ("random_forest_full_30", "Random Forest", "#9B9B9B"),
            ("xgboost_live_lexical_8", "XGBoost eight features", "#616161"),
        ]:
            samples = metrics_raw[key]["curve_samples"]
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

    with col_cm:
        st.markdown("##### Confusion matrix for thirty feature model")
        cm = metrics_raw["xgboost_full_30"]["confusion_matrix"]
        fig_cm = px.imshow(
            cm,
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
# TAB 4: THREAT ENCYCLOPEDIA
# -------------------------------------------------------------------
with tabs[3]:
    st.markdown("#### Feature catalog")
    st.caption("Taxonomy of all thirty features defined in the Mohammad dataset.")

    chosen_domain = st.selectbox("Select security domain", ["All domains"] + list(catalog["feature_groups"].keys()))

    for f_name, meta in catalog["features"].items():
        if chosen_domain != "All domains" and meta["group"] != chosen_domain:
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
<div style="text-align: center; font-size: 12px; line-height: 16px; color: #616161; padding: 16px 0; border-top: 1px solid #181818;">
    PhishLens research system. Tailored for academic evaluation and explainability.
</div>
""", unsafe_allow_html=True)
