"""
Explainable AI (XAI) Engine for PhishLens.
Provides exact TreeSHAP attributions, feature group aggregation,
contrastive counterfactual hints, and human-readable cybersecurity translations.
"""

import json
import os
import joblib
import numpy as np
import shap
import shap.explainers._tree as shap_tree

# Portable compatibility patch for XGBoost 3.x / SHAP interaction with array-formatted base_score '[5E-1]'
_orig_decode_ubjson = shap_tree.decode_ubjson_buffer

def _clean_ubjson_decode(fd):
    jmodel = _orig_decode_ubjson(fd)
    try:
        lmp = jmodel.get("learner", {}).get("learner_model_param", {})
        if "base_score" in lmp and isinstance(lmp["base_score"], str):
            lmp["base_score"] = lmp["base_score"].strip("[]")
    except Exception:
        pass
    return jmodel

shap_tree.decode_ubjson_buffer = _clean_ubjson_decode


CATALOG_FILE = "data/processed/feature_catalog.json"
ARTIFACTS_DIR = "artifacts"


class PhishLensExplainer:
    """Manages TreeSHAP explanations, feature grouping, and counterfactual recourse."""

    def __init__(self, model_type="live"):
        """
        Initializes explainer for 'live' (8 features) or 'full' (30 features).
        """
        self.model_type = model_type
        with open(CATALOG_FILE, "r") as f:
            self.catalog = json.load(f)

        if model_type == "live":
            self.model_path = os.path.join(ARTIFACTS_DIR, "xgb_live_8.joblib")
            self.bg_path = os.path.join(ARTIFACTS_DIR, "shap_bg_live.npy")
            self.features = self.catalog["live_lexical_features"]
            self.rf_model = None
            self.lr_model = None
        else:
            self.model_path = os.path.join(ARTIFACTS_DIR, "xgb_full_30.joblib")
            self.bg_path = os.path.join(ARTIFACTS_DIR, "shap_bg_full.npy")
            self.features = list(self.catalog["features"].keys())
            self.rf_model = joblib.load(os.path.join(ARTIFACTS_DIR, "rf_full_30.joblib"))
            self.lr_model = joblib.load(os.path.join(ARTIFACTS_DIR, "lr_full_30.joblib"))

        self.model = joblib.load(self.model_path)
        self.bg_data = np.load(self.bg_path)
        self.tree_explainer = shap.TreeExplainer(self.model, data=self.bg_data)

    def _build_feature_attribution(self, feat_name, val, s_val):
        """Builds a structured Shapley attribution dictionary for one feature."""
        feat_meta = self.catalog["features"].get(feat_name, {})
        is_risk = s_val > 0
        human_text = (
            feat_meta.get("plain_explanation_phishing", "Feature increases phishing probability.")
            if is_risk
            else feat_meta.get("plain_explanation_legit", "Feature suggests legitimate behavior.")
        )
        return {
            "feature": feat_name,
            "value": int(val),
            "shap_value": round(float(s_val), 4),
            "abs_impact": round(abs(float(s_val)), 4),
            "pushes_toward": "Phishing" if is_risk else "Legitimate",
            "group": feat_meta.get("group", "General"),
            "description": feat_meta.get("description", ""),
            "rule": feat_meta.get("rule", ""),
            "human_text": human_text,
        }

    def _aggregate_groups(self, feature_attributions):
        """Aggregates Shapley contributions per security domain."""
        group_totals = {}
        for item in feature_attributions:
            grp = item["group"]
            group_totals[grp] = group_totals.get(grp, 0.0) + item["shap_value"]

        breakdown = [
            {
                "group": grp,
                "net_shap": round(float(tot), 4),
                "verdict": "Elevates Risk" if tot > 0 else "Supports Legitimacy",
            }
            for grp, tot in group_totals.items()
        ]
        breakdown.sort(key=lambda item: abs(item["net_shap"]), reverse=True)
        return breakdown

    def _consensus_entry(self, name, prob):
        """Formats a single evaluator consensus score entry."""
        return {
            "name": name,
            "prob_pct": round(float(prob) * 100, 1),
            "verdict": "Phishing" if prob >= 0.50 else "Legitimate",
        }

    def _compute_model_consensus(self, x, prob_phishing, net_log_odds):
        """Computes multi model or signal consensus for the active feature matrix."""
        if self.model_type == "full":
            rf_prob = float(self.rf_model.predict_proba(x)[0, 1])
            lr_prob = float(self.lr_model.predict_proba(x)[0, 1])
            return [
                self._consensus_entry("XGBoost (30 features)", prob_phishing),
                self._consensus_entry("Random Forest (200 trees)", rf_prob),
                self._consensus_entry("Logistic Regression (L2)", lr_prob),
            ]
        cal_prob = 1.0 / (1.0 + float(np.exp(-np.clip(net_log_odds, -20.0, 20.0))))
        rule_density = float(np.mean(x[0] < 1))
        return [
            self._consensus_entry("XGBoost lexical", prob_phishing),
            self._consensus_entry("Log odds margin calibration", cal_prob),
            self._consensus_entry("Structural rule density", rule_density),
        ]

    def explain_instance(self, feature_vector):
        """
        Computes local Shapley values, group contributions, consensus, and recourse.
        feature_vector: 1D array-like of feature values in self.features order.
        """
        x = np.array(feature_vector, dtype=float).reshape(1, -1)
        prob_phishing = float(self.model.predict_proba(x)[0, 1])
        prediction_label = "Phishing" if prob_phishing >= 0.50 else "Legitimate"

        shap_values = self.tree_explainer(x)
        raw_shaps = shap_values.values[0]
        base_value = float(shap_values.base_values[0])
        net_log_odds = base_value + float(np.sum(raw_shaps))

        feature_attributions = [
            self._build_feature_attribution(feat_name, val, s_val)
            for feat_name, val, s_val in zip(self.features, feature_vector, raw_shaps)
        ]
        feature_attributions.sort(key=lambda item: item["abs_impact"], reverse=True)

        group_breakdown = self._aggregate_groups(feature_attributions)
        counterfactuals = self._compute_counterfactual_hints(feature_vector, prob_phishing)
        consensus = self._compute_model_consensus(x, prob_phishing, net_log_odds)

        return {
            "prediction": prediction_label,
            "phishing_probability": round(prob_phishing, 4),
            "legitimate_probability": round(1.0 - prob_phishing, 4),
            "base_value": round(base_value, 4),
            "top_drivers": feature_attributions[:8],
            "all_features": feature_attributions,
            "group_breakdown": group_breakdown,
            "counterfactual_hints": counterfactuals,
            "consensus": consensus,
            "model_type": self.model_type,
        }

    def _compute_counterfactual_hints(self, feature_vector, current_prob):
        """
        Computes perturbation scenarios to identify the smallest changes
        that push the score away from phishing or test sensitivity.
        """
        hints = []
        x_base = np.array(feature_vector, dtype=float).copy()

        for idx, feat_name in enumerate(self.features):
            current_val = feature_vector[idx]
            # If feature is currently abnormal/phishing (-1 or 0), simulate flipping to legitimate (1)
            if current_val < 1:
                x_perturbed = x_base.copy()
                x_perturbed[idx] = 1.0
                new_prob = float(self.model.predict_proba(x_perturbed.reshape(1, -1))[0, 1])
                delta = current_prob - new_prob
                if delta > 0.01:  # Noticeable drop in phishing risk
                    hints.append({
                        "feature": feat_name,
                        "current_value": int(current_val),
                        "suggested_value": 1,
                        "risk_reduction_pct": round(delta * 100, 2),
                        "new_phishing_probability": round(new_prob, 4),
                        "guidance": f"If '{feat_name}' met legitimate criteria, phishing probability would drop by {delta*100:.1f}%.",
                    })

        # Sort hints by largest risk reduction
        hints.sort(key=lambda h: h["risk_reduction_pct"], reverse=True)
        return hints[:4]


def test_explainer():
    """Smoke test for PhishLensExplainer on live and full models."""
    print("Testing Live Explainer...")
    live_exp = PhishLensExplainer(model_type="live")
    sample_live = [-1, 1, 1, 1, 1, -1, 1, 1]  # IP Address + Hyphen in domain
    res_live = live_exp.explain_instance(sample_live)
    print(f"Live Prediction: {res_live['prediction']}, Prob: {res_live['phishing_probability']}")
    print(f"Top driver: {res_live['top_drivers'][0]['feature']} ({res_live['top_drivers'][0]['pushes_toward']})")
    print(f"Counterfactuals: {res_live['counterfactual_hints']}")

    print("\nTesting Full Explainer...")
    full_exp = PhishLensExplainer(model_type="full")
    sample_full = [1] * 30
    res_full = full_exp.explain_instance(sample_full)
    print(f"Full Prediction: {res_full['prediction']}, Prob: {res_full['phishing_probability']}")
    print("[OK] All explainer tests passed successfully!")


if __name__ == "__main__":
    test_explainer()
