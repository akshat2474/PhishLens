"""
Precomputes a compact gzipped JSON runtime bundle for serverless Vercel deployment.
Exports exact TreeSHAP attributions, consensus probabilities, counterfactual hints,
ROC/threshold test arrays, and feature prevalence statistics without needing heavy
C-extension libraries (XGBoost, SHAP, scikit-learn, SciPy, Numba) inside serverless bundles.
"""

import gzip
import itertools
import json
import os
import numpy as np
import pandas as pd

from src.explainability import PhishLensExplainer

OUTPUT_BUNDLE_PATH = os.path.join("artifacts", "vercel_runtime.json.gz")
LEGIT_DOMAINS = (
    "google.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "wikipedia.org",
    "apple.com",
    "linkedin.com",
    "cloudflare.com",
)


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
    """Generates a synthetic attack URL matching dataset anomalies."""
    if row.get("having_IP_Address", 1) == -1:
        return f"http://192.168.1.{100 + (idx % 150)}/login/auth-test"
    if row.get("Shortining_Service", 1) == -1:
        return f"http://bit.ly/test-sample-{idx}"
    if row.get("HTTPS_token", 1) == -1:
        return f"http://https-secure-account-{idx}.org/verify"
    return _synthesize_domain_phishing_url(row, idx)


def _synthesize_uci_url(row, idx):
    """Builds a deterministic representative URL for a UCI benchmark test row."""
    if row.get("label", 0) == 1:
        return _synthesize_phishing_url(row, idx)
    domain = LEGIT_DOMAINS[idx % len(LEGIT_DOMAINS)]
    return f"https://www.{domain}/account/settings"


def _build_counterfactual_entry(feat_name, current_val, current_prob, new_prob):
    """Formats a single counterfactual hint matching PhishLensExplainer schema."""
    delta = current_prob - new_prob
    return {
        "feature": feat_name,
        "current_value": int(current_val),
        "suggested_value": 1,
        "risk_reduction_pct": round(delta * 100.0, 2),
        "new_phishing_probability": round(new_prob, 4),
        "guidance": (
            f"If '{feat_name}' met legitimate criteria, "
            f"phishing probability would drop by {delta * 100:.1f}%."
        ),
    }


def _compute_live_hints(prob_lookup, feats, vec, cur_prob):
    """Computes counterfactual recourse hints for one 8-feature lexical vector."""
    hints = []
    for idx, feat_name in enumerate(feats):
        if vec[idx] >= 1:
            continue
        perturbed = list(vec)
        perturbed[idx] = 1
        new_prob = prob_lookup[tuple(perturbed)]
        if cur_prob - new_prob > 0.01:
            hints.append(_build_counterfactual_entry(feat_name, vec[idx], cur_prob, new_prob))
    hints.sort(key=lambda item: item["risk_reduction_pct"], reverse=True)
    return hints[:4]


def _feature_domain(feat_name):
    """Returns allowed discrete integer values for one live feature."""
    return [-1, 0, 1] if feat_name in ("URL_Length", "having_Sub_Domain") else [-1, 1]


def _format_live_entry(live_exp, x_row, prob, s_vec, base_val, hints):
    """Serializes one live grid state into probability, SHAPs, consensus, and hints."""
    net_log_odds = float(base_val) + float(np.sum(s_vec))
    consensus = live_exp._compute_model_consensus(x_row, prob, net_log_odds)
    return {
        "prob": round(prob, 4),
        "shaps": [round(float(v), 4) for v in s_vec],
        "consensus": consensus,
        "hints": hints,
    }


def _build_live_grid(live_exp):
    """Precomputes exact probabilities, TreeSHAP values, consensus, and hints for all 576 live states."""
    feats = list(live_exp.features)
    all_vecs = list(itertools.product(*map(_feature_domain, feats)))
    x_grid = np.array(all_vecs, dtype=float)
    probs = live_exp.model.predict_proba(x_grid)[:, 1]
    shap_res = live_exp.tree_explainer(x_grid)
    base_val = round(float(shap_res.base_values[0]), 4)
    prob_lookup = dict(zip(all_vecs, map(float, probs)))

    grid = {}
    for row_idx, vec in enumerate(all_vecs):
        p = float(probs[row_idx])
        hints = _compute_live_hints(prob_lookup, feats, vec, p)
        key = ",".join(map(str, vec))
        grid[key] = _format_live_entry(
            live_exp,
            x_grid[row_idx : row_idx + 1],
            p,
            shap_res.values[row_idx],
            shap_res.base_values[row_idx],
            hints,
        )
    return base_val, grid


def _collect_row_hints(candidates, x_test, new_probs, full_probs, feats):
    """Groups valid counterfactual risk reductions (> 1%) by row index."""
    hints_by_row = [[] for _ in range(len(x_test))]
    for job_idx, (r_idx, c_idx) in enumerate(candidates):
        cur_p = float(full_probs[r_idx])
        new_p = float(new_probs[job_idx])
        if cur_p - new_p > 0.01:
            entry = _build_counterfactual_entry(feats[c_idx], int(x_test[r_idx, c_idx]), cur_p, new_p)
            hints_by_row[int(r_idx)].append(entry)
    return hints_by_row


def _compute_batch_full_hints(full_exp, x_test, full_probs):
    """Vectorizes counterfactual risk drops across all 1,659 test records."""
    candidates = np.argwhere(x_test < 1)
    if len(candidates) == 0:
        return [[] for _ in range(len(x_test))]
    x_perturbed = x_test[candidates[:, 0]].copy()
    x_perturbed[np.arange(len(candidates)), candidates[:, 1]] = 1.0
    new_probs = full_exp.model.predict_proba(x_perturbed)[:, 1]
    hints_by_row = _collect_row_hints(candidates, x_test, new_probs, full_probs, list(full_exp.features))
    for hints in hints_by_row:
        hints.sort(key=lambda item: item["risk_reduction_pct"], reverse=True)
    return [hints[:4] for hints in hints_by_row]


def _format_test_record(idx, row_dict, y_val, x_row, probs_tuple, shaps_row, hints):
    """Formats one precomputed benchmark test record for the runtime bundle."""
    prob_xgb, prob_rf, prob_lr = probs_tuple
    return {
        "idx": idx,
        "label": int(y_val),
        "url": _synthesize_uci_url(row_dict, idx),
        "vals": list(map(int, x_row)),
        "prob": round(float(prob_xgb), 4),
        "rf_prob": round(float(prob_rf), 4),
        "lr_prob": round(float(prob_lr), 4),
        "shaps": [round(float(v), 4) for v in shaps_row],
        "hints": hints,
    }


def _build_test_eval(feats, y_true, full_probs, shap_values, live_features):
    """Computes compact evaluation arrays and top twelve global TreeSHAP rankings."""
    mean_abs = np.mean(np.abs(shap_values[:250]), axis=0)
    ranked = sorted(zip(feats, mean_abs), key=lambda pair: pair[1], reverse=True)[:12]
    live_set = set(live_features)
    return {
        "y_true": list(map(int, y_true)),
        "y_probs": [round(float(v), 4) for v in full_probs],
        "global_shap": [
            {"feature": f, "mean_shap": round(float(val), 4), "is_live": f in live_set}
            for f, val in ranked
        ],
    }


def _build_test_records(full_exp, test_df):
    """Evaluates all test records with XGBoost, RF, LR, exact TreeSHAP, and recourse hints."""
    feats = list(full_exp.features)
    x_test = test_df[feats].values.astype(float)
    y_true = test_df["label"].values.astype(int)
    full_probs = full_exp.model.predict_proba(x_test)[:, 1]
    rf_probs = full_exp.rf_model.predict_proba(x_test)[:, 1]
    lr_probs = full_exp.lr_model.predict_proba(x_test)[:, 1]
    shap_res = full_exp.tree_explainer(x_test)
    hints_by_row = _compute_batch_full_hints(full_exp, x_test, full_probs)

    records = [
        _format_test_record(
            idx,
            test_df.iloc[idx].to_dict(),
            y_true[idx],
            x_test[idx],
            (full_probs[idx], rf_probs[idx], lr_probs[idx]),
            shap_res.values[idx],
            hints_by_row[idx],
        )
        for idx in range(len(test_df))
    ]
    test_eval = _build_test_eval(feats, y_true, full_probs, shap_res.values, full_exp.catalog["live_lexical_features"])
    return round(float(shap_res.base_values[0]), 4), records, test_eval


def _compute_prevalence(test_df, features):
    """Computes test partition class prevalence percentages for each feature."""
    total = float(len(test_df))
    out = {}
    for feat in features:
        s = test_df[feat]
        out[feat] = [
            round(float((s == -1).sum()) * 100.0 / total, 1),
            round(float((s == 0).sum()) * 100.0 / total, 1),
            round(float((s == 1).sum()) * 100.0 / total, 1),
        ]
    return out


def build_vercel_bundle(output_path=OUTPUT_BUNDLE_PATH):
    """Builds and writes the compressed serverless runtime bundle."""
    live_exp = PhishLensExplainer(model_type="live")
    full_exp = PhishLensExplainer(model_type="full")
    with open(os.path.join("data", "processed", "split_indices.json"), "r") as f:
        splits = json.load(f)
    df = pd.read_csv(os.path.join("data", "processed", "phishing_websites.csv"))
    test_df = df.iloc[splits["test_indices"]].reset_index(drop=True)

    live_base, live_grid = _build_live_grid(live_exp)
    full_base, test_records, test_eval = _build_test_records(full_exp, test_df)
    prevalence = _compute_prevalence(test_df, list(full_exp.features))

    bundle = {
        "live_base_value": live_base,
        "live_grid": live_grid,
        "full_base_value": full_base,
        "test_records": test_records,
        "test_eval": test_eval,
        "prevalence": prevalence,
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with gzip.open(output_path, "wt", encoding="utf-8") as gz_file:
        json.dump(bundle, gz_file, separators=(",", ":"))
    return os.path.getsize(output_path)


if __name__ == "__main__":
    size_bytes = build_vercel_bundle()
    print(f"[OK] Built {OUTPUT_BUNDLE_PATH} ({size_bytes / 1024:.1f} KB)")
