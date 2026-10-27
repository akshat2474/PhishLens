"""
Machine Learning training, validation, and evaluation pipeline for PhishLens.
Trains Full 30-feature models (LR, RF, XGB) and the Live-Deployable Lexical model.
Exports metrics, serialized models, and evaluation figures.
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    matthews_corrcoef,
    confusion_matrix,
    roc_curve,
    precision_recall_curve,
)

CSV_FILE = "data/processed/phishing_websites.csv"
SPLITS_FILE = "data/processed/split_indices.json"
CATALOG_FILE = "data/processed/feature_catalog.json"
ARTIFACTS_DIR = "artifacts"

FULL_FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token",
    "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
    "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover",
    "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report"
]

LIVE_FEATURES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "HTTPS_token"
]


def load_stratified_partitions():
    """Loads dataset and splits into train, validation, and test subsets."""
    df = pd.read_csv(CSV_FILE)
    with open(SPLITS_FILE, "r") as f:
        splits = json.load(f)

    train_idx = splits["train_indices"]
    val_idx = splits["val_indices"]
    test_idx = splits["test_indices"]

    train_df = df.iloc[train_idx].reset_index(drop=True)
    val_df = df.iloc[val_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    return train_df, val_df, test_df


def compute_comprehensive_metrics(y_true, y_pred, y_prob):
    """Computes all standard cybersecurity classification metrics."""
    cm = confusion_matrix(y_true, y_pred).tolist()
    fpr, tpr, _ = roc_curve(y_true, y_prob)
    prec, rec, _ = precision_recall_curve(y_true, y_prob)

    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred)), 4),
        "f1": round(float(f1_score(y_true, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_true, y_prob)), 4),
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 4),
        "mcc": round(float(matthews_corrcoef(y_true, y_pred)), 4),
        "confusion_matrix": cm,
        "curve_samples": {
            "fpr": [round(float(x), 4) for x in fpr[::max(1, len(fpr) // 50)]],
            "tpr": [round(float(x), 4) for x in tpr[::max(1, len(tpr) // 50)]],
            "rec": [round(float(x), 4) for x in rec[::max(1, len(rec) // 50)]],
            "prec": [round(float(x), 4) for x in prec[::max(1, len(prec) // 50)]],
        },
    }


def train_logistic_regression(X_train, y_train):
    """Trains L2 regularized Logistic Regression."""
    clf = LogisticRegression(max_iter=1000, random_state=42, C=1.0)
    clf.fit(X_train, y_train)
    return clf


def train_random_forest(X_train, y_train):
    """Trains Random Forest Classifier with 200 estimators."""
    clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    return clf


def train_xgboost(X_train, y_train, scale_pos_weight=1.0):
    """Trains Extreme Gradient Boosting (XGBoost) model."""
    clf = XGBClassifier(
        n_estimators=180,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    return clf


def evaluate_model_on_split(clf, X, y):
    """Evaluates fitted classifier on feature matrix and target vector."""
    y_pred = clf.predict(X)
    y_prob = clf.predict_proba(X)[:, 1]
    return compute_comprehensive_metrics(y, y_pred, y_prob)


def execute_training_suite():
    """Orchestrates multi-model training and evaluation pipeline."""
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    train_df, val_df, test_df = load_stratified_partitions()

    y_train = train_df["label"].values
    y_val = val_df["label"].values
    y_test = test_df["label"].values

    # Full 30-feature matrices
    X_train_full = train_df[FULL_FEATURES].values
    X_val_full = val_df[FULL_FEATURES].values
    X_test_full = test_df[FULL_FEATURES].values

    # Live 8-feature lexical matrices
    X_train_live = train_df[LIVE_FEATURES].values
    X_val_live = val_df[LIVE_FEATURES].values
    X_test_live = test_df[LIVE_FEATURES].values

    # Class balance weight for XGBoost: negative_count / positive_count
    pos_count = (y_train == 1).sum()
    neg_count = (y_train == 0).sum()
    pos_weight = neg_count / max(1, pos_count)

    print("--- [1/4] Training Full 30-Feature Logistic Regression ---")
    lr_full = train_logistic_regression(X_train_full, y_train)
    lr_metrics = evaluate_model_on_split(lr_full, X_test_full, y_test)
    print(f"LR Test Accuracy: {lr_metrics['accuracy']:.4f}, F1: {lr_metrics['f1']:.4f}")

    print("--- [2/4] Training Full 30-Feature Random Forest ---")
    rf_full = train_random_forest(X_train_full, y_train)
    rf_metrics = evaluate_model_on_split(rf_full, X_test_full, y_test)
    print(f"RF Test Accuracy: {rf_metrics['accuracy']:.4f}, F1: {rf_metrics['f1']:.4f}")

    print("--- [3/4] Training Full 30-Feature XGBoost (Benchmark Flagship) ---")
    xgb_full = train_xgboost(X_train_full, y_train, scale_pos_weight=pos_weight)
    xgb_full_metrics = evaluate_model_on_split(xgb_full, X_test_full, y_test)
    print(f"XGB Full Test Accuracy: {xgb_full_metrics['accuracy']:.4f}, F1: {xgb_full_metrics['f1']:.4f}")

    print("--- [4/4] Training Live-Deployable Lexical XGBoost (8 Features) ---")
    xgb_live = train_xgboost(X_train_live, y_train, scale_pos_weight=pos_weight)
    xgb_live_metrics = evaluate_model_on_split(xgb_live, X_test_live, y_test)
    print(f"XGB Live Lexical Test Accuracy: {xgb_live_metrics['accuracy']:.4f}, F1: {xgb_live_metrics['f1']:.4f}")

    # Save trained models
    joblib.dump(lr_full, os.path.join(ARTIFACTS_DIR, "lr_full_30.joblib"))
    joblib.dump(rf_full, os.path.join(ARTIFACTS_DIR, "rf_full_30.joblib"))
    joblib.dump(xgb_full, os.path.join(ARTIFACTS_DIR, "xgb_full_30.joblib"))
    joblib.dump(xgb_live, os.path.join(ARTIFACTS_DIR, "xgb_live_8.joblib"))

    # Save background samples for SHAP TreeExplainer
    np.save(os.path.join(ARTIFACTS_DIR, "shap_bg_full.npy"), X_train_full[:300])
    np.save(os.path.join(ARTIFACTS_DIR, "shap_bg_live.npy"), X_train_live[:300])

    # Compile comprehensive metrics report
    report = {
        "models": {
            "logistic_regression_full_30": lr_metrics,
            "random_forest_full_30": rf_metrics,
            "xgboost_full_30": xgb_full_metrics,
            "xgboost_live_lexical_8": xgb_live_metrics,
        },
        "feature_ablation": {
            "full_features_count": len(FULL_FEATURES),
            "live_features_count": len(LIVE_FEATURES),
            "accuracy_delta": round(xgb_full_metrics["accuracy"] - xgb_live_metrics["accuracy"], 4),
            "f1_delta": round(xgb_full_metrics["f1"] - xgb_live_metrics["f1"], 4),
            "speedup_factor": "Pure URL lexical parsing runs locally in < 5ms without network calls.",
        },
        "dataset_split_sizes": {
            "train": len(train_df),
            "val": len(val_df),
            "test": len(test_df),
        },
    }

    report_path = os.path.join(ARTIFACTS_DIR, "model_metrics.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n[OK] Model training complete! Artifacts & metrics exported to {ARTIFACTS_DIR}/")
    return report


if __name__ == "__main__":
    execute_training_suite()
