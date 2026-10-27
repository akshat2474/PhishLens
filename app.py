"""
PhishLens: Explainable Phishing Detection Dashboard.
Streamlit application featuring:
1. Live URL Scanner with safe lexical feature extraction and TreeSHAP waterfall.
2. Dataset Lab for exploring 30-feature holdout test samples and what-if simulation.
3. Model Benchmark & Ablation Studio (ROC, PR, Confusion Matrix, Metrics).
4. Feature Rule & Threat Encyclopedia based on the Mohammad et al. dataset taxonomy.
"""

import json
import os
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
    page_title="PhishLens | Explainable Phishing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .phish-verdict-danger {
        background-color: #fee2e2;
        color: #991b1b;
        border-left: 6px solid #ef4444;
        padding: 16px;
        border-radius: 6px;
        font-weight: 600;
    }
    .phish-verdict-safe {
        background-color: #dcfce7;
        color: #166534;
        border-left: 6px solid #22c55e;
        padding: 16px;
        border-radius: 6px;
        font-weight: 600;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_explainers():
    """Initializes and caches both live and full TreeSHAP explainers."""
    live_exp = PhishLensExplainer(model_type="live")
    full_exp = PhishLensExplainer(model_type="full")
    return live_exp, full_exp


@st.cache_data
def get_catalog_and_metrics():
    """Loads feature catalog, model metrics, and test dataset partition."""
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

# Sidebar Information
with st.sidebar:
    st.title("🛡️ PhishLens")
    st.markdown("**Explainable Phishing Detection Using URL Feature Analysis & Machine Learning**")
    st.divider()
    st.markdown("### 📌 Project Metadata")
    st.markdown("- **Benchmark Dataset**: UCI Phishing Websites")
    st.markdown("- **Total Dataset Size**: 11,055 records")
    st.markdown("- **Production Model**: XGBoost (XAI: TreeSHAP)")
    st.markdown("- **Dual Paths**: Pure Lexical Live Path vs Full 30-Feature Lab Path")
    st.divider()
    st.markdown("### ⚙️ Quick Samples")
    sample_choice = st.selectbox(
        "Load Example URL:",
        [
            "Select sample...",
            "https://www.google.com (Legitimate)",
            "http://192.168.1.100/paypal-update/login.html (Phishing - IP)",
            "https://secure-login-paypal.com/verify (Phishing - Hyphen Spoof)",
            "http://bit.ly/3xYzAq9 (Phishing - Obfuscated Shortener)",
            "https://login.security.account.update.bank.com (Phishing - Deep Subdomain)",
        ]
    )

st.title("🛡️ PhishLens: Explainable Phishing Detection System")
st.caption("Investigate URL vulnerabilities, predict phishing likelihood, and diagnose feature attributions with game-theoretic XAI.")

tabs = st.tabs([
    "🔍 Live URL Scanner",
    "🧪 Dataset Lab (30 Features)",
    "📊 Model Benchmark & Ablation",
    "📖 Feature Rule Encyclopedia",
])

# ---------------------------------------------------------
# TAB 1: LIVE URL SCANNER
# ---------------------------------------------------------
with tabs[0]:
    st.subheader("Real-Time URL Lexical Scanner")
    st.markdown(
        "Analyzes the structural and lexical characteristics of a URL **strictly offline (< 1ms)** "
        "without triggering active network scans or downloading untrusted remote web payloads."
    )

    default_val = ""
    if sample_choice != "Select sample...":
        default_val = sample_choice.split(" ")[0]

    url_input = st.text_input("Enter Target Website URL:", value=default_val, placeholder="e.g. https://secure-login.paypal-verification.com")

    col_btn, col_clear = st.columns([1, 5])
    scan_clicked = col_btn.button("Inspect URL", type="primary", use_container_width=True)

    if url_input and (scan_clicked or default_val):
        with st.spinner("Extracting lexical features and computing TreeSHAP attributions..."):
            features_dict = extract_live_lexical_features(url_input)
            feature_vector = extract_live_feature_vector(url_input)
            result = live_explainer.explain_instance(feature_vector)

            prob = result["phishing_probability"]
            is_phishing = prob >= 0.50

            st.divider()

            # Verdict Display
            v_col1, v_col2, v_col3 = st.columns([2, 1, 1])
            with v_col1:
                if prob >= 0.70:
                    st.markdown(
                        f"""<div class="phish-verdict-danger">
                        🚨 High Risk Phishing Alert<br>
                        <span style="font-size: 0.9em; font-weight: normal;">
                        This URL displays strong deceptive structural anomalies indicative of a phishing attack.
                        </span>
                        </div>""",
                        unsafe_allow_html=True,
                    )
                elif prob >= 0.50:
                    st.markdown(
                        f"""<div class="phish-verdict-danger" style="background-color: #fffbeb; color: #92400e; border-left-color: #f59e0b;">
                        ⚠️ Suspicious / Borderline Risk<br>
                        <span style="font-size: 0.9em; font-weight: normal;">
                        This URL has questionable lexical attributes. Exercise heightened caution before providing credentials.
                        </span>
                        </div>""",
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""<div class="phish-verdict-safe">
                        ✅ Likely Legitimate<br>
                        <span style="font-size: 0.9em; font-weight: normal;">
                        Lexical patterns match conventional legitimate domain structures.
                        </span>
                        </div>""",
                        unsafe_allow_html=True,
                    )

            with v_col2:
                st.metric("Phishing Probability", f"{prob * 100:.1f}%")
            with v_col3:
                st.metric("Legitimate Probability", f"{result['legitimate_probability'] * 100:.1f}%")

            st.progress(prob)

            st.markdown("### 🧬 Explainable AI: Feature Attribution Waterfall")
            st.markdown(
                "Shapley Additive exPlanations (TreeSHAP) quantify each feature's contribution. "
                "**Red bars** push the score toward **Phishing**, while **Green bars** push toward **Legitimate**."
            )

            # Interactive Plotly Bar Chart for SHAP Attributions
            top_drivers = result["top_drivers"]
            feat_names = [d["feature"] for d in top_drivers][::-1]
            shap_vals = [d["shap_value"] for d in top_drivers][::-1]
            colors = ["#ef4444" if val > 0 else "#22c55e" for val in shap_vals]
            hover_texts = [f"<b>{d['feature']}</b> ({d['value']})<br>{d['human_text']}" for d in top_drivers][::-1]

            fig_shap = go.Figure(
                go.Bar(
                    x=shap_vals,
                    y=feat_names,
                    orientation="h",
                    marker_color=colors,
                    hovertext=hover_texts,
                    hoverinfo="text",
                )
            )
            fig_shap.update_layout(
                xaxis_title="Shapley Value (Log-Odds Impact on Phishing Risk)",
                yaxis_title="Extracted Lexical Feature",
                margin=dict(l=20, r=20, t=20, b=20),
                height=320,
            )
            st.plotly_chart(fig_shap, use_container_width=True)

            # Counterfactual Recourse
            st.markdown("### 💡 Counterfactual Recourse & What-If Guidance")
            if result["counterfactual_hints"]:
                st.info("The system identified the minimal modifications that would decrease the phishing probability:")
                for hint in result["counterfactual_hints"]:
                    st.markdown(f"- 🔄 **{hint['guidance']}** *(Expected new probability: {hint['new_phishing_probability']*100:.1f}%)*")
            else:
                st.success("No critical security anomalies detected in the URL structure requiring remediation.")

            # Extracted Feature Inspection Table
            st.markdown("### 📋 Complete Lexical Extraction Breakdown")
            table_rows = []
            for item in result["all_features"]:
                val_repr = "1 (Legitimate)" if item["value"] == 1 else ("0 (Suspicious)" if item["value"] == 0 else "-1 (Phishing)")
                table_rows.append({
                    "Feature": item["feature"],
                    "Extracted Value": val_repr,
                    "Impact": f"{item['shap_value']:+.4f}",
                    "Direction": item["pushes_toward"],
                    "Diagnostic Context": item["human_text"],
                })
            st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

# ---------------------------------------------------------
# TAB 2: DATASET LAB (30 FEATURES)
# ---------------------------------------------------------
with tabs[1]:
    st.subheader("Dataset Lab: 30-Feature Holdout Test Inspector")
    st.markdown(
        "Inspect verified instances from the **UCI Phishing Websites holdout test set** ($N = 1,659$). "
        "Evaluate the benchmark 30-feature XGBoost model (96.9% accuracy) against ground-truth labels, or simulate custom configurations."
    )

    col_s1, col_s2, col_s3 = st.columns([1, 1, 2])
    load_phish = col_s1.button("🎲 Sample Random Phishing Site")
    load_legit = col_s2.button("🎲 Sample Random Legitimate Site")

    if "lab_sample" not in st.session_state:
        st.session_state["lab_sample"] = test_dataset.iloc[0].to_dict()

    if load_phish:
        phish_pool = test_dataset[test_dataset["label"] == 1]
        st.session_state["lab_sample"] = phish_pool.sample(1, random_state=int(np.random.randint(10000))).iloc[0].to_dict()
    elif load_legit:
        legit_pool = test_dataset[test_dataset["label"] == 0]
        st.session_state["lab_sample"] = legit_pool.sample(1, random_state=int(np.random.randint(10000))).iloc[0].to_dict()

    curr_sample = st.session_state["lab_sample"]
    actual_label = "Phishing" if curr_sample["label"] == 1 else "Legitimate"

    st.markdown(f"**Ground Truth Target Label**: `{'🚨 ' + actual_label if actual_label == 'Phishing' else '✅ ' + actual_label}`")

    # Grouped feature editor
    full_feature_names = list(catalog["features"].keys())
    input_values = []

    with st.expander("🛠️ Inspect and Adjust the 30 Feature Values", expanded=False):
        st.caption("You can modify individual feature values (-1 = Phishing, 0 = Suspicious, 1 = Legitimate) to test model behavior.")
        cols = st.columns(3)
        for i, feat in enumerate(full_feature_names):
            c = cols[i % 3]
            current_f_val = int(curr_sample.get(feat, 1))
            new_f_val = c.selectbox(
                f"{feat}",
                options=[-1, 0, 1],
                index=[-1, 0, 1].index(current_f_val) if current_f_val in [-1, 0, 1] else 2,
                key=f"lab_feat_{feat}",
            )
            input_values.append(new_f_val)

    if not input_values:
        input_values = [int(curr_sample.get(f, 1)) for f in full_feature_names]

    # Run inference & explainability on full 30 features
    full_result = full_explainer.explain_instance(input_values)
    pred_phish_prob = full_result["phishing_probability"]
    pred_label = full_result["prediction"]

    st.divider()
    m_col1, m_col2, m_col3 = st.columns(3)
    m_col1.metric("Predicted Class", pred_label, delta="Match" if pred_label == actual_label else "Mismatch")
    m_col2.metric("Phishing Probability", f"{pred_phish_prob * 100:.1f}%")
    m_col3.metric("Baseline Expected Value", f"{full_result['base_value']:.4f}")

    # Top drivers for 30-feature model
    col_t1, col_t2 = st.columns([3, 2])
    with col_t1:
        st.markdown("#### Primary Influential Features (TreeSHAP)")
        top_f = full_result["top_drivers"]
        f_names = [d["feature"] for d in top_f][::-1]
        f_shaps = [d["shap_value"] for d in top_f][::-1]
        f_colors = ["#ef4444" if val > 0 else "#22c55e" for val in f_shaps]

        fig_full = go.Figure(go.Bar(
            x=f_shaps,
            y=f_names,
            orientation="h",
            marker_color=f_colors,
        ))
        fig_full.update_layout(
            xaxis_title="Shapley Value",
            yaxis_title="Feature Name",
            margin=dict(l=10, r=10, t=10, b=10),
            height=300,
        )
        st.plotly_chart(fig_full, use_container_width=True)

    with col_t2:
        st.markdown("#### Group Impact Breakdown")
        group_df = pd.DataFrame(full_result["group_breakdown"])
        st.dataframe(group_df, use_container_width=True)

# ---------------------------------------------------------
# TAB 3: MODEL BENCHMARK & ABLATION
# ---------------------------------------------------------
with tabs[2]:
    st.subheader("Model Benchmark & Feature Ablation Studio")
    st.markdown(
        "Academic evaluation comparing multiple algorithmic paradigms and evaluating the performance difference "
        "between the **Full 30-Feature Benchmark Model** and the **Live-Deployable Pure-URL Lexical Model**."
    )

    models_data = model_metrics["models"]
    comp_records = []
    model_display_names = {
        "logistic_regression_full_30": "Logistic Regression (30 Feat)",
        "random_forest_full_30": "Random Forest (30 Feat)",
        "xgboost_full_30": "XGBoost Flagship (30 Feat)",
        "xgboost_live_lexical_8": "XGBoost Lexical Live (8 Feat)",
    }

    for m_key, m_val in models_data.items():
        comp_records.append({
            "Model Architecture": model_display_names.get(m_key, m_key),
            "Accuracy": f"{m_val['accuracy'] * 100:.2f}%",
            "Precision": f"{m_val['precision'] * 100:.2f}%",
            "Recall (Catch Phish)": f"{m_val['recall'] * 100:.2f}%",
            "F1-Score": f"{m_val['f1']:.4f}",
            "ROC-AUC": f"{m_val['roc_auc']:.4f}",
            "PR-AUC": f"{m_val['pr_auc']:.4f}",
            "MCC": f"{m_val['mcc']:.4f}",
        })

    st.markdown("### 🏆 Comprehensive Test Set Performance (N = 1,659)")
    st.dataframe(pd.DataFrame(comp_records), use_container_width=True)

    # Ablation highlight card
    ablation = model_metrics.get("feature_ablation", {})
    st.info(
        f"**Academic Ablation Insight**: Pruning from 30 features (which include extinct services like Alexa Rank & PageRank) "
        f"to 8 pure lexical URL features incurs an accuracy delta of {ablation.get('accuracy_delta', 0.2098)*100:.1f}%, "
        f"while achieving **instantaneous sub-millisecond execution (< 1ms)** and eliminating external network dependencies."
    )

    # ROC Curves comparison
    c_roc, c_cm = st.columns(2)
    with c_roc:
        st.markdown("#### Receiver Operating Characteristic (ROC)")
        fig_roc = go.Figure()
        fig_roc.add_shape(type="line", line=dict(dash="dash", color="gray"), x0=0, x1=1, y0=0, y1=1)

        for m_key in ["xgboost_full_30", "random_forest_full_30", "xgboost_live_lexical_8"]:
            samples = models_data[m_key]["curve_samples"]
            fig_roc.add_trace(go.Scatter(
                x=samples["fpr"],
                y=samples["tpr"],
                mode="lines",
                name=f"{model_display_names[m_key]} (AUC: {models_data[m_key]['roc_auc']})",
            ))

        fig_roc.update_layout(
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate (Recall)",
            legend=dict(yanchor="bottom", y=0.05, xanchor="right", x=0.95),
            margin=dict(l=20, r=20, t=20, b=20),
            height=340,
        )
        st.plotly_chart(fig_roc, use_container_width=True)

    with c_cm:
        st.markdown("#### Flagship XGBoost (Full 30) Confusion Matrix")
        cm_data = models_data["xgboost_full_30"]["confusion_matrix"]
        cm_labels = ["Legitimate (0)", "Phishing (1)"]
        fig_cm = px.imshow(
            cm_data,
            labels=dict(x="Predicted Label", y="True Label", color="Count"),
            x=cm_labels,
            y=cm_labels,
            text_auto=True,
            color_continuous_scale="Blues",
        )
        fig_cm.update_layout(margin=dict(l=20, r=20, t=20, b=20), height=340)
        st.plotly_chart(fig_cm, use_container_width=True)

# ---------------------------------------------------------
# TAB 4: FEATURE RULE ENCYCLOPEDIA
# ---------------------------------------------------------
with tabs[3]:
    st.subheader("Feature Rule & Threat Encyclopedia")
    st.markdown(
        "Comprehensive taxonomy of the 30 features defined by Mohammad, Thabtah, and McCluskey (2012/2015), "
        "including exact heuristic thresholds, live feasibility analysis, and deprecation notes."
    )

    selected_group = st.selectbox(
        "Filter by Security Domain:",
        ["All Categories"] + list(catalog["feature_groups"].keys()),
    )

    features_meta = catalog["features"]
    for feat_name, feat_info in features_meta.items():
        if selected_group != "All Categories" and feat_info["group"] != selected_group:
            continue

        is_live = feat_info.get("extractable_live", False)
        is_dep = feat_info.get("deprecated", False)

        badge_live = "⚡ Live Extractable" if is_live else "🌐 Requires Network/DOM"
        badge_dep = " | ⚠️ Deprecated/Obsolete" if is_dep else ""

        with st.expander(f"{feat_name} [{feat_info['group']}] - {badge_live}{badge_dep}"):
            st.markdown(f"**Description**: {feat_info['description']}")
            st.markdown(f"**Rule Definition**: `{feat_info['rule']}`")
            st.markdown(f"**Why it indicates Phishing**: {feat_info['plain_explanation_phishing']}")
            st.markdown(f"**Why it indicates Legitimate**: {feat_info['plain_explanation_legit']}")
            if is_dep:
                st.warning(
                    f"**Deprecation Notice**: '{feat_name}' historically relied on retired APIs "
                    "(e.g., Alexa Traffic Rank or Google PageRank). In PhishLens, this feature is preserved for historical benchmark "
                    "reproducibility on the UCI dataset but excluded from live zero-network inference."
                )

st.divider()
st.caption("PhishLens © 2026 | Explainable Phishing Detection System | Dual Inference Architecture")
