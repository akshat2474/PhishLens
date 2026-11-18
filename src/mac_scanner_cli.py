"""
CLI bridge for the PhishLens macOS Flutter desktop application.
Runs the 8-feature lexical extractor, looks up the precomputed XGBoost + TreeSHAP diagnosis,
and performs a safe, non-rendering HTTP/SSL reachability check to verify whether the link works.
"""

import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from src.console_ui import FEATURE_NAMES
from src.feature_extractor import LIVE_FEATURES
from src.vercel_console import diagnose_live


def _probe_reachability(url, timeout=4.0):
    """Performs a safe HTTP HEAD/GET probe to check if the link works without executing page scripts."""
    t0 = time.perf_counter()
    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "PhishLens-Mac-Inspector/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            ms = round((time.perf_counter() - t0) * 1000.0, 1)
            final_url = resp.geturl() or url
            return {
                "works": 200 <= resp.status < 400,
                "status_code": int(resp.status),
                "status_text": f"HTTP {resp.status} {resp.reason}",
                "latency_ms": ms,
                "final_url": final_url,
                "redirected": final_url.rstrip("/") != url.rstrip("/"),
                "ssl_valid": final_url.lower().startswith("https://"),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return {
            "works": False,
            "status_code": int(exc.code),
            "status_text": f"HTTP {exc.code} {exc.reason}",
            "latency_ms": ms,
            "final_url": url,
            "redirected": False,
            "ssl_valid": url.lower().startswith("https://"),
            "error": str(exc.reason),
        }
    except Exception as exc:
        ms = round((time.perf_counter() - t0) * 1000.0, 1)
        return {
            "works": False,
            "status_code": 0,
            "status_text": "Unreachable",
            "latency_ms": ms,
            "final_url": url,
            "redirected": False,
            "ssl_valid": False,
            "error": str(exc),
        }


def scan_url_for_mac(raw_url):
    """Runs PhishLens lexical + TreeSHAP analysis and live link reachability check."""
    t0 = time.perf_counter()
    diag = diagnose_live(raw_url)
    ml_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    clean_url = diag["clean_url"]
    reach = _probe_reachability(clean_url)

    features = []
    for item in diag["all_features"]:
        fname = item["feature"]
        features.append({
            "key": fname,
            "label": FEATURE_NAMES.get(fname, fname),
            "value": item["value"],
            "shap": item["shap_value"],
            "pushes_toward": item["pushes_toward"],
            "explanation": item["human_text"],
        })

    return {
        "clean_url": clean_url,
        "prediction": diag["prediction"],
        "phishing_probability": round(float(diag["phishing_probability"]), 4),
        "risk_pct": round(float(diag["phishing_probability"]) * 100.0, 1),
        "base_value": round(float(diag["base_value"]), 4),
        "ml_latency_ms": ml_ms,
        "feature_order": list(LIVE_FEATURES),
        "features": features,
        "consensus": diag["consensus"],
        "hints": diag["counterfactual_hints"],
        "reachability": reach,
    }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://www.github.com/explore"
    print(json.dumps(scan_url_for_mac(target)))
