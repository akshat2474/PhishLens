"""
PhishLens: Enterprise Explainable Phishing Detection Interface.
Designed with high visual fidelity, interactive diagnostic tooling, and game-theoretic explainability.
Complies with typography, spacing, and perimeter border rules while delivering an engaging analytical experience.
"""

import json
import os
import time
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
from src.ui_components import (
    inject_result_styles,
    render_results_body,
    render_segmented_token_rail,
    render_verdict,
    risk_tone,
    section_header,
)

VERDICT_TITLES = {
    "critical": "Phishing attack detected",
    "warning": "Suspicious address pattern",
    "safe": "Legitimate domain structure",
}
STATE_LABELS = {1: "Legitimate", 0: "Suspicious", -1: "Phishing"}

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

    /* Status Metadata Chip */
    .status-pill {
        display: inline-flex;
        align-items: center;
        padding: 4px 8px;
        border-radius: 4px;
        font-family: 'Geist Mono', monospace;
        font-size: 11px;
        font-weight: 500;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        color: #9B9B9B;
    }

    /* Hero Section */
    .hero-box {
        max-width: 680px;
        margin-bottom: 24px;
    }

    .hero-heading {
        font-size: 32px;
        line-height: 40px;
        font-weight: 600;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #FFFFFF 0%, #9B9B9B 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-wrap: balance;
        margin-bottom: 8px;
    }

    /* Target URL Chosen Display Banner */
    .chosen-url-inline {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 8px 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
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

    /* KPI Tiles */
    .kpi-tile {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        text-align: left;
    }

    .kpi-title {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 600;
    }

    .kpi-value {
        font-family: 'Geist Mono', monospace;
        font-size: 24px;
        line-height: 32px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
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
        transition: background-color 150ms ease, border-color 150ms ease !important;
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
        border-radius: 8px !important;
        padding: 8px 12px !important;
        font-weight: 600 !important;
        box-shadow: none !important;
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
        color: #000000 !important;
        box-shadow: none !important;
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


def _synthesize_legitimate_url(idx):
    """Generates a representative legitimate domain URL."""
    domains = [
        "google.com", "github.com", "microsoft.com", "amazon.com",
        "wikipedia.org", "apple.com", "linkedin.com", "cloudflare.com"
    ]
    domain = domains[idx % len(domains)]
    return f"https://www.{domain}/account/settings"


def _synthesize_domain_phishing_url(row, idx):
    """Generates a synthetic domain phishing URL based on structural anomalies."""
    has_hyphen = row.get("Prefix_Suffix", 1) == -1
    has_sub = row.get("having_Sub_Domain", 1) == -1
    if has_hyphen and has_sub:
        return f"https://security.portal.account-verification-{idx}.org/auth"
    if has_hyphen:
        return f"https://secure-login-account-{idx}.org/update"
    if has_sub:
        return f"https://account.security.verification.domain-{idx}.org/login"
    return f"http://suspicious-target-{idx}.net/test-login"


def _synthesize_phishing_url(row, idx):
    """Generates a synthetic attack URL demonstrating matched phishing anomalies."""
    if row.get("having_IP_Address", 1) == -1:
        return f"http://192.168.1.{100 + (idx % 150)}/login/auth-test"
    if row.get("Shortining_Service", 1) == -1:
        return f"http://bit.ly/test-sample-{idx}"
    if row.get("HTTPS_token", 1) == -1:
        return f"http://https-secure-account-{idx}.org/verify"
    return _synthesize_domain_phishing_url(row, idx)


def synthesize_uci_representative_url(row, idx):
    """Constructs a realistic representative URL matching UCI dataset record properties."""
    if row.get("label", 0) == 1:
        return _synthesize_phishing_url(row, idx)
    return _synthesize_legitimate_url(idx)


inject_result_styles()
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
            scan_submitted = c_btn.form_submit_button("Scan URL", width="stretch")

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

        # Run live explainer and time the full explanation
        started = time.perf_counter()
        scan_res = live_explainer.explain_instance(active_vector)
        explain_ms = (time.perf_counter() - started) * 1000
        risk_pct = scan_res["phishing_probability"] * 100

        render_verdict(
            VERDICT_TITLES[risk_tone(risk_pct)],
            "Evaluated across eight offline lexical properties with zero network exposure.",
            risk_pct,
        )
        render_segmented_token_rail(clean_url, scan_res)
        render_results_body(
            scan_res, risk_pct,
            ("Explanation time", f"{explain_ms:.1f} ms"),
            "Probability from the lexical XGBoost classifier.",
            "Contribution of each property to the prediction (TreeSHAP).",
        )

        section_header("Complete diagnostic matrix", "Every evaluated property with its state and Shapley impact.")
        records = [
            {
                "Property": item["feature"],
                "State": STATE_LABELS[item["value"]],
                "Shapley impact": f"{item['shap_value']:+.4f}",
                "Influence": item["pushes_toward"],
                "Forensic explanation": item["human_text"],
            }
            for item in scan_res["all_features"]
        ]
        st.dataframe(pd.DataFrame(records), width="stretch", hide_index=True)

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
        if c_btn.button("Pick random URL", type="primary", width="stretch"):
            st.session_state["dataset_sample_idx"] = int(np.random.choice(test_dataset.index))
            st.rerun()

        c_url.markdown(f"""
        <div class="chosen-url-inline">
            <span class="chosen-url-text">{rep_url}</span>
            <div class="status-pill" style="color: {'#e57373' if true_class == 'Phishing' else '#81c784'}; border-color: #313131; font-size: 10px; padding: 2px 8px; flex-shrink: 0;">
                Ground truth: {true_class.lower()}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # Run 30 feature explainer and time the full explanation
        started = time.perf_counter()
        full_eval = full_explainer.explain_instance(full_vals)
        explain_ms = (time.perf_counter() - started) * 1000
        pred_class = full_eval["prediction"]
        risk_pct = full_eval["phishing_probability"] * 100
        agreement = "The prediction matches." if pred_class == true_class else "The prediction does not match."

        render_verdict(
            f"Model predicts {pred_class.lower()}",
            f"Ground truth is {true_class.lower()}. {agreement}",
            risk_pct,
        )
        render_segmented_token_rail(rep_url, full_eval)
        benchmark_accuracy = model_metrics["models"]["xgboost_full_30"]["accuracy"] * 100
        render_results_body(
            full_eval, risk_pct,
            ("Benchmark accuracy", f"{benchmark_accuracy:.2f}%"),
            "Probability from the 30 feature XGBoost model.",
            "Contribution of each of the 30 attributes (TreeSHAP).",
        )

        section_header("Security domain impact", "Net Shapley contribution summed per feature domain.")
        st.dataframe(pd.DataFrame(full_eval["group_breakdown"]), width="stretch", hide_index=True)

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
    st.dataframe(pd.DataFrame(perf_rows), width="stretch", hide_index=True)

    # ROC & Confusion Matrix
    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)
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
            paper_bgcolor="#181818",
            plot_bgcolor="#181818",
            margin=dict(l=16, r=16, t=16, b=24),
            height=280,
            xaxis=dict(title="False positive rate", gridcolor="#272727", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
            yaxis=dict(title="True positive rate", gridcolor="#272727", tickfont=dict(family="Geist Mono", size=10, color="#9B9B9B")),
            legend=dict(yanchor="bottom", y=0.05, xanchor="right", x=0.95, font=dict(family="Geist", size=10, color="#9B9B9B")),
        )
        st.plotly_chart(fig_roc, width="stretch")

    with c_cm:
        st.markdown("##### Confusion matrix (30 feature model)")
        cm_data = raw_scores["xgboost_full_30"]["confusion_matrix"]
        fig_cm = px.imshow(
            cm_data,
            labels=dict(x="Predicted", y="Actual", color="Count"),
            x=["Legitimate", "Phishing"],
            y=["Legitimate", "Phishing"],
            text_auto=True,
            color_continuous_scale=[[0, "#1F1F1F"], [1, "#313131"]],
        )
        fig_cm.update_layout(
            paper_bgcolor="#181818",
            plot_bgcolor="#181818",
            margin=dict(l=16, r=16, t=16, b=24),
            height=280,
            coloraxis_showscale=False,
            xaxis=dict(tickfont=dict(family="Geist", color="#FFFFFF")),
            yaxis=dict(tickfont=dict(family="Geist", color="#FFFFFF")),
        )
        st.plotly_chart(fig_cm, width="stretch")

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
