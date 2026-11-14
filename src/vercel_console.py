"""
Lightweight HTML/WSGI renderer for the PhishLens Telemetry Console on Vercel.
Reads precomputed TreeSHAP attributions and evaluation arrays from gzipped JSON
so zero heavy C-extension ML libraries are needed at serverless runtime.
"""

import gzip
import html
import json
import os
import time
import urllib.parse

from src.feature_extractor import LIVE_FEATURES, extract_live_lexical_features, sanitize_url

BUNDLE_PATH = os.path.join("artifacts", "vercel_runtime.json.gz")
CATALOG_PATH = os.path.join("data", "processed", "feature_catalog.json")
METRICS_PATH = os.path.join("artifacts", "model_metrics.json")

DEFAULT_LIVE_URL = "https://secure-auth-verification.example.org/portal"
DEFAULT_UCI_IDX = 835
TONE_COLORS = {"critical": "#e57373", "warning": "#ffb74d", "safe": "#81c784"}
STATE_LABELS = {1: "Legitimate", 0: "Suspicious", -1: "Phishing"}
VERDICT_TITLES = {
    "critical": "Phishing attack detected",
    "warning": "Suspicious address pattern",
    "safe": "Legitimate domain structure",
}
URL_PRESETS = (
    ("IP host spoofing", "http://192.168.1.243/login/auth/verify"),
    ("Subdomain chain", "http://account.security.verify.login.portal.org/signin"),
    ("Brand hyphen trap", "http://https-paypal-account-update.com/auth"),
    ("Shortener redirect", "https://bit.ly/secure-account-redirect//http://evil.org"),
    ("Clean baseline", "https://www.github.com/explore"),
)
BADGE_COLORS = {
    "Phishing": "#e57373",
    "Elevates Risk": "#e57373",
    "Suspicious": "#ffb74d",
    "Legitimate": "#81c784",
    "Supports Legitimacy": "#81c784",
}

_CACHE = None

PAGE_CSS = """
    :root { color-scheme: dark; }
    * { box-sizing: border-box; font-style: normal !important; }
    html, body {
        margin: 0;
        padding: 0;
        background-color: #000000;
        color: #FFFFFF;
        font-family: 'Geist', sans-serif;
        -webkit-font-smoothing: antialiased;
    }
    code, pre, .mono { font-family: 'Geist Mono', monospace; }
    h1, h2, h3, h4, h5 {
        font-family: 'Geist', sans-serif;
        font-weight: 600;
        letter-spacing: -0.02em;
        text-wrap: balance;
        margin: 0;
    }
    p, span, div { text-wrap: pretty; }
    .container {
        max-width: 1240px;
        margin: 0 auto;
        padding: 32px 24px 48px 24px;
    }
    .hero-box { max-width: 680px; margin-bottom: 24px; }
    .hero-heading {
        font-size: 36px;
        line-height: 40px;
        font-weight: 600;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #FFFFFF 0%, #9B9B9B 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-wrap: balance;
        margin-bottom: 8px;
    }
    .tab-bar {
        display: flex;
        width: 100%;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
        margin-bottom: 24px;
    }
    .tab-btn {
        flex: 1 1 0%;
        font-family: 'Geist', sans-serif;
        font-size: 14px;
        line-height: 20px;
        font-weight: 500;
        color: #9B9B9B;
        padding: 8px 16px;
        border-radius: 4px;
        border: none;
        background-color: transparent;
        cursor: pointer;
        text-align: center;
        white-space: nowrap;
        transition: background-color 150ms ease, color 150ms ease;
    }
    .tab-btn:hover { color: #FFFFFF; background-color: #1F1F1F; }
    .tab-btn.active { background-color: #272727; color: #FFFFFF; font-weight: 600; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .mode-switch {
        display: inline-flex;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
        margin-bottom: 16px;
    }
    .mode-btn {
        font-family: 'Geist', sans-serif;
        font-size: 14px;
        line-height: 20px;
        font-weight: 500;
        color: #9B9B9B;
        background-color: transparent;
        border: none;
        border-radius: 4px;
        padding: 8px 12px;
        cursor: pointer;
    }
    .mode-btn:hover { color: #FFFFFF; background-color: #1F1F1F; }
    .mode-btn.active { background-color: #272727; color: #FFFFFF; font-weight: 600; }
    .btn {
        font-family: 'Geist', sans-serif;
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        padding: 8px 12px;
        border-radius: 8px;
        border: 1px solid #313131;
        background-color: #1F1F1F;
        color: #FFFFFF;
        cursor: pointer;
        transition: background-color 150ms ease, border-color 150ms ease;
    }
    .btn:hover { background-color: #272727; border-color: #616161; }
    .btn-primary {
        background-color: #FFFFFF;
        color: #000000;
        border: 1px solid #FFFFFF;
    }
    .btn-primary:hover { background-color: #E6E6E6; border-color: #E6E6E6; color: #000000; }
    .preset-label {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 600;
        margin-bottom: 8px;
    }
    .preset-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 8px;
        margin-bottom: 12px;
    }
    .form-row {
        display: grid;
        grid-template-columns: 5fr 1fr;
        gap: 12px;
        margin-bottom: 12px;
    }
    .uci-bar {
        display: grid;
        grid-template-columns: 1.2fr 3.8fr;
        gap: 12px;
        margin-bottom: 16px;
        align-items: stretch;
    }
    .text-input, .select-input {
        width: 100%;
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        color: #FFFFFF;
        padding: 8px 12px;
        outline: none;
    }
    .select-input { font-family: 'Geist', sans-serif; }
    .text-input:focus, .select-input:focus { border-color: #FFFFFF; }
    .chosen-url-inline {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 8px 12px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 12px;
    }
    .chosen-url-text {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        font-weight: 500;
        color: #FFFFFF;
        word-break: break-all;
    }
    .status-pill {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        color: #9B9B9B;
        flex-shrink: 0;
    }
    .sandbox-details {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 12px 16px;
        margin: 12px 0 24px 0;
    }
    .sandbox-details summary {
        cursor: pointer;
        font-size: 14px;
        line-height: 20px;
        font-weight: 500;
        color: #FFFFFF;
    }
    .sandbox-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-top: 12px;
    }
    .field-label {
        display: block;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 4px;
    }
    .verdict-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 24px;
        margin-top: 16px;
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
    .verdict-dot { width: 8px; height: 8px; border-radius: 2px; }
    .verdict-title { font-size: 24px; line-height: 32px; font-weight: 600; margin-top: 4px; }
    .verdict-sub { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 4px; max-width: 520px; }
    .verdict-score { text-align: right; flex-shrink: 0; }
    .verdict-score-label { font-size: 12px; line-height: 16px; color: #9B9B9B; }
    .verdict-score-value {
        font-family: 'Geist Mono', monospace;
        font-size: 36px;
        line-height: 40px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
    }
    .verdict-track { height: 8px; border-radius: 4px; background-color: #272727; margin-top: 24px; overflow: hidden; }
    .verdict-fill { height: 100%; border-radius: 4px; }
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
    .token-rail-title { font-size: 12px; line-height: 16px; color: #9B9B9B; font-weight: 600; }
    .token-rail-sub { font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #616161; }
    .specimen-url-bar {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 12px;
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 24px;
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 4px;
        word-break: break-all;
    }
    .specimen-token {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #181818;
    }
    .specimen-token-risk { color: #e57373; border-color: #e57373; }
    .specimen-token-safe { color: #81c784; border-color: #272727; }
    .specimen-token-neutral { color: #9B9B9B; border-color: #272727; }
    .specimen-delta { font-size: 12px; line-height: 16px; color: #9B9B9B; font-variant-numeric: tabular-nums; }
    .token-rail-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
    .token-rail-cell {
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 8px;
        min-height: 96px;
    }
    .token-rail-type { font-size: 12px; line-height: 16px; color: #9B9B9B; font-weight: 500; }
    .token-rail-val {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        color: #FFFFFF;
        font-weight: 500;
        word-break: break-all;
    }
    .token-rail-badge {
        display: inline-flex;
        justify-content: space-between;
        align-items: center;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #181818;
        border: 1px solid #272727;
        margin-top: 4px;
    }
    .token-rail-badge-risk { color: #e57373; }
    .token-rail-badge-safe { color: #81c784; }
    .token-rail-badge-neutral { color: #9B9B9B; }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
    .waterfall-grid { display: grid; grid-template-columns: 3fr 2fr; gap: 16px; margin-bottom: 24px; }
    .kpi-grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .kpi-grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 16px; }
    .kpi-tile {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        text-align: left;
    }
    .kpi-title { font-size: 12px; line-height: 16px; color: #9B9B9B; font-weight: 600; }
    .kpi-value {
        font-family: 'Geist Mono', monospace;
        font-size: 24px;
        line-height: 32px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
        margin-top: 4px;
        color: #FFFFFF;
    }
    .consensus-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
    }
    .consensus-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; }
    .consensus-title { font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
    .consensus-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #1F1F1F;
    }
    .consensus-sub { font-size: 12px; line-height: 16px; color: #9B9B9B; margin-bottom: 16px; }
    .consensus-row { margin-bottom: 12px; }
    .consensus-row:last-child { margin-bottom: 0; }
    .consensus-row-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 12px;
        line-height: 16px;
        margin-bottom: 4px;
    }
    .consensus-name { color: #FFFFFF; font-weight: 500; }
    .consensus-meta { font-family: 'Geist Mono', monospace; color: #9B9B9B; font-variant-numeric: tabular-nums; }
    .consensus-track { height: 8px; background-color: #272727; border-radius: 4px; overflow: hidden; }
    .consensus-fill { height: 100%; border-radius: 4px; }
    .ruler-wrap { position: relative; padding: 24px 0 8px 0; }
    .ruler-track { display: flex; height: 12px; border-radius: 4px; overflow: hidden; border: 1px solid #272727; }
    .ruler-zone-safe { width: 50%; background-color: #1F1F1F; }
    .ruler-zone-warn { width: 20%; background-color: #272727; }
    .ruler-zone-crit { width: 30%; background-color: #313131; }
    .ruler-threshold { position: absolute; left: 50%; top: 16px; bottom: 4px; width: 2px; background-color: #616161; }
    .ruler-needle { position: absolute; top: 12px; width: 4px; height: 24px; border-radius: 2px; transform: translateX(-50%); }
    .ruler-tag {
        position: absolute;
        top: 0;
        transform: translateX(-50%);
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
        white-space: nowrap;
    }
    .ruler-legend {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-top: 8px;
    }
    .plot-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 12px;
    }
    .ledger-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        height: 100%;
    }
    .ledger-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
    }
    .ledger-table th { color: #9B9B9B; font-weight: 500; text-align: left; padding: 8px; }
    .ledger-table td { padding: 8px; font-variant-numeric: tabular-nums; }
    .ledger-row-risk { color: #e57373; }
    .ledger-row-safe { color: #81c784; }
    .ledger-row-total { font-weight: 600; color: #FFFFFF; }
    .evidence-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 24px; }
    .evidence-card { background-color: #181818; border: 1px solid #272727; border-radius: 12px; padding: 16px; }
    .evidence-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .evidence-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; word-break: break-all; }
    .evidence-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        padding: 2px 8px;
        border-radius: 4px;
        border: 1px solid #272727;
        background-color: #1F1F1F;
        flex-shrink: 0;
    }
    .evidence-value { font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-top: 8px; }
    .evidence-text { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 8px; }
    .recourse-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; }
    .recourse-card { background-color: #181818; border: 1px solid #272727; border-radius: 12px; padding: 16px; }
    .recourse-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px; }
    .recourse-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
    .recourse-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        color: #81c784;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        padding: 2px 8px;
        border-radius: 4px;
    }
    .recourse-state { font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-bottom: 12px; }
    .recourse-delta-row {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 4px;
        font-variant-numeric: tabular-nums;
    }
    .recourse-bars { display: flex; flex-direction: column; gap: 4px; margin-bottom: 12px; }
    .recourse-track { height: 4px; border-radius: 2px; background-color: #272727; overflow: hidden; }
    .recourse-fill { height: 100%; border-radius: 2px; }
    .recourse-text { font-size: 14px; line-height: 20px; color: #9B9B9B; }
    .console-table-wrap {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        overflow-x: auto;
        margin-bottom: 24px;
    }
    .console-table { width: 100%; border-collapse: collapse; font-size: 14px; line-height: 20px; }
    .console-table th {
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        color: #9B9B9B;
        padding: 12px 16px;
        background-color: #1F1F1F;
    }
    .console-table td { padding: 12px 16px; color: #FFFFFF; font-variant-numeric: tabular-nums; }
    .console-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        white-space: nowrap;
    }
    .section-title { font-size: 18px; line-height: 28px; font-weight: 600; margin: 0 0 4px 0; text-wrap: balance; }
    .section-note { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-bottom: 16px; }
    .action-card { background-color: #181818; border: 1px solid #272727; border-radius: 12px; padding: 16px; margin-bottom: 12px; }
    .slider-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .slider-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .range-input { width: 100%; accent-color: #FFFFFF; cursor: pointer; }
    .catalog-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 16px; margin-bottom: 24px; }
    .catalog-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 12px;
    }
    .catalog-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .catalog-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; word-break: break-all; }
    .catalog-badge {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        padding: 2px 8px;
        border-radius: 4px;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        flex-shrink: 0;
    }
    .catalog-domain { font-size: 12px; line-height: 16px; color: #9B9B9B; margin-top: 4px; }
    .catalog-desc { font-size: 14px; line-height: 20px; color: #FFFFFF; }
    .catalog-rule {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        background-color: #1F1F1F;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 8px 12px;
        word-break: break-word;
    }
    .prev-head { display: flex; justify-content: space-between; font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-bottom: 4px; }
    .prev-track { display: flex; height: 8px; border-radius: 4px; background-color: #272727; overflow: hidden; }
    .prev-legend { display: flex; justify-content: space-between; font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-top: 4px; }
    .footer-note { text-align: center; font-size: 12px; line-height: 16px; color: #9B9B9B; padding: 16px 0; margin-top: 32px; }
    @media (max-width: 900px) {
        .preset-grid, .sandbox-grid, .token-rail-grid, .kpi-grid-4 { grid-template-columns: repeat(2, 1fr); }
        .form-row, .uci-bar, .two-col, .waterfall-grid, .evidence-grid, .recourse-grid, .catalog-grid { grid-template-columns: 1fr; }
    }
"""

CONSOLE_JS = """
    function switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-panel').forEach(p => {
            p.classList.toggle('active', p.id === 'panel-' + tabName);
        });
        if (tabName === 'eval') {
            drawEvalCharts();
        } else if (tabName === 'inspect' && window.__lastWaterfall) {
            drawWaterfall(window.__lastWaterfall);
        }
    }

    function drawWaterfall(wf) {
        window.__lastWaterfall = wf;
        if (!window.Plotly || !document.getElementById('waterfall-plot')) return;
        const trace = {
            type: 'waterfall',
            orientation: 'v',
            measure: wf.measures,
            x: wf.x,
            y: wf.y,
            text: wf.texts,
            textposition: 'outside',
            textfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' },
            connector: { line: { color: '#313131', width: 1, dash: 'dot' } },
            decreasing: { marker: { color: '#81c784' } },
            increasing: { marker: { color: '#e57373' } },
            totals: { marker: { color: '#FFFFFF' } }
        };
        const layout = {
            paper_bgcolor: '#181818',
            plot_bgcolor: '#181818',
            font: { family: 'Geist, sans-serif', color: '#9B9B9B' },
            margin: { l: 48, r: 16, t: 24, b: 48 },
            height: 320,
            xaxis: { gridcolor: '#272727', tickfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' } },
            yaxis: {
                gridcolor: '#272727',
                zerolinecolor: '#313131',
                title: { text: 'Log odds impact', font: { family: 'Geist', size: 12, color: '#9B9B9B' } },
                tickfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' }
            },
            showlegend: false
        };
        Plotly.react('waterfall-plot', [trace], layout, { displayModeBar: false, responsive: true });
    }

    function syncSandboxValues(fv) {
        if (!fv) return;
        Object.keys(fv).forEach(k => {
            const el = document.getElementById('sbx-' + k);
            if (el) el.value = String(fv[k]);
        });
    }

    async function loadDiagnosis(params) {
        const qs = new URLSearchParams(params).toString();
        const res = await fetch('/api/diagnose?' + qs);
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('inspect-results').innerHTML = data.html;
        if (data.mode === 'uci' && data.url) {
            document.getElementById('uci-url-text').textContent = data.url;
            const pill = document.getElementById('uci-truth-pill');
            pill.textContent = 'Ground truth: ' + data.true_label.toLowerCase();
            pill.style.color = data.true_label === 'Phishing' ? '#e57373' : '#81c784';
            document.getElementById('uci-idx-input').value = String(data.idx);
        }
        if (data.mode === 'live' && data.feature_values) {
            syncSandboxValues(data.feature_values);
            if (data.clean_url) {
                document.getElementById('live-url-display').textContent = data.clean_url;
            }
        }
        drawWaterfall(data.waterfall);
    }

    function setInspectMode(mode) {
        document.getElementById('mode-btn-uci').classList.toggle('active', mode === 'uci');
        document.getElementById('mode-btn-live').classList.toggle('active', mode === 'live');
        document.getElementById('controls-uci').style.display = mode === 'uci' ? 'block' : 'none';
        document.getElementById('controls-live').style.display = mode === 'live' ? 'block' : 'none';
        if (mode === 'uci') {
            const idx = document.getElementById('uci-idx-input').value || '835';
            loadDiagnosis({ mode: 'uci', idx });
        } else {
            const url = document.getElementById('live-url-input').value.trim();
            loadDiagnosis({ mode: 'live', url });
        }
    }

    function scanPreset(url) {
        document.getElementById('live-url-input').value = url;
        loadDiagnosis({ mode: 'live', url });
    }

    function submitLiveScan(ev) {
        ev.preventDefault();
        const url = document.getElementById('live-url-input').value.trim();
        if (url) loadDiagnosis({ mode: 'live', url });
    }

    function onSandboxChange() {
        const url = document.getElementById('live-url-input').value.trim();
        const params = { mode: 'live', url };
        document.querySelectorAll('.sbx-select').forEach(el => {
            params['f_' + el.dataset.idx] = el.value;
        });
        loadDiagnosis(params);
    }

    function pickRandomUci() {
        const total = window.__evalData ? window.__evalData.y_true.length : 1659;
        const idx = Math.floor(Math.random() * total);
        loadDiagnosis({ mode: 'uci', idx });
    }

    function computeThresholdStats(thresh) {
        const yt = window.__evalData.y_true;
        const yp = window.__evalData.y_probs;
        let tp = 0, fp = 0, tn = 0, fn = 0;
        for (let i = 0; i < yt.length; i++) {
            const pred = yp[i] >= thresh ? 1 : 0;
            if (yt[i] === 1 && pred === 1) tp++;
            else if (yt[i] === 0 && pred === 1) fp++;
            else if (yt[i] === 0 && pred === 0) tn++;
            else fn++;
        }
        const precision = tp / Math.max(1, tp + fp);
        const recall = tp / Math.max(1, tp + fn);
        const f1 = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
        const fpr = fp / Math.max(1, tn + fp);
        return { precision, recall, f1, fp, fn, fpr, cm: [[tn, fp], [fn, tp]] };
    }

    function drawEvalCharts() {
        if (!window.Plotly || !window.__evalData || !document.getElementById('roc-plot')) return;
        const slider = document.getElementById('threshold-slider');
        const thresh = parseFloat(slider ? slider.value : '0.50');
        const stats = computeThresholdStats(thresh);

        document.getElementById('thresh-readout').textContent = thresh.toFixed(2);
        document.getElementById('kpi-prec-lbl').textContent = 'Precision at ' + thresh.toFixed(2);
        document.getElementById('kpi-rec-lbl').textContent = 'Recall at ' + thresh.toFixed(2);
        document.getElementById('kpi-f1-lbl').textContent = 'F1 score at ' + thresh.toFixed(2);
        document.getElementById('kpi-prec-val').textContent = (stats.precision * 100).toFixed(2) + '%';
        document.getElementById('kpi-rec-val').textContent = (stats.recall * 100).toFixed(2) + '%';
        document.getElementById('kpi-f1-val').textContent = stats.f1.toFixed(4);
        document.getElementById('kpi-fpfn-val').textContent = stats.fp + ' / ' + stats.fn;
        document.getElementById('cm-title').textContent = 'Confusion matrix at threshold ' + thresh.toFixed(2);

        const roc = window.__evalData.roc;
        const rocTraces = [
            { x: [0, 1], y: [0, 1], mode: 'lines', showlegend: false, line: { dash: 'dash', color: '#313131', width: 1 } },
            { x: roc.xgb30.fpr, y: roc.xgb30.tpr, mode: 'lines', name: 'XGBoost thirty features', line: { color: '#FFFFFF', width: 1.5 } },
            { x: roc.rf30.fpr, y: roc.rf30.tpr, mode: 'lines', name: 'Random Forest', line: { color: '#9B9B9B', width: 1.5 } },
            { x: roc.xgb8.fpr, y: roc.xgb8.tpr, mode: 'lines', name: 'XGBoost eight features', line: { color: '#616161', width: 1.5 } },
            { x: [stats.fpr], y: [stats.recall], mode: 'markers', name: 'Active threshold', marker: { color: '#e57373', size: 8, line: { color: '#FFFFFF', width: 1.5 } } }
        ];
        Plotly.react('roc-plot', rocTraces, {
            paper_bgcolor: '#181818', plot_bgcolor: '#181818',
            font: { family: 'Geist, sans-serif', color: '#9B9B9B' },
            margin: { l: 48, r: 16, t: 16, b: 40 }, height: 280,
            xaxis: { title: 'False positive rate', gridcolor: '#272727', tickfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' } },
            yaxis: { title: 'True positive rate', gridcolor: '#272727', tickfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' } },
            legend: { yanchor: 'bottom', y: 0.05, xanchor: 'right', x: 0.95, font: { family: 'Geist', size: 11, color: '#9B9B9B' } }
        }, { displayModeBar: false, responsive: true });

        Plotly.react('cm-plot', [{
            type: 'heatmap',
            z: stats.cm,
            x: ['Legitimate', 'Phishing'],
            y: ['Legitimate', 'Phishing'],
            text: stats.cm.map(r => r.map(v => String(v))),
            texttemplate: '%{text}',
            textfont: { family: 'Geist Mono', size: 14, color: '#FFFFFF' },
            colorscale: [[0, '#1F1F1F'], [1, '#313131']],
            showscale: false
        }], {
            paper_bgcolor: '#181818', plot_bgcolor: '#181818',
            font: { family: 'Geist, sans-serif', color: '#FFFFFF' },
            margin: { l: 80, r: 16, t: 16, b: 48 }, height: 280,
            xaxis: { title: 'Predicted', tickfont: { family: 'Geist', color: '#FFFFFF' } },
            yaxis: { title: 'Actual', autorange: 'reversed', tickfont: { family: 'Geist', color: '#FFFFFF' } }
        }, { displayModeBar: false, responsive: true });

        const gs = window.__evalData.global_shap.slice().reverse();
        Plotly.react('global-shap-plot', [{
            type: 'bar',
            x: gs.map(d => d.mean_shap),
            y: gs.map(d => d.feature),
            orientation: 'h',
            marker: { color: gs.map(d => d.is_live ? '#FFFFFF' : '#616161') },
            text: gs.map(d => d.mean_shap.toFixed(3)),
            textposition: 'outside',
            textfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' }
        }], {
            paper_bgcolor: '#181818', plot_bgcolor: '#181818',
            font: { family: 'Geist, sans-serif', color: '#9B9B9B' },
            margin: { l: 192, r: 48, t: 16, b: 40 }, height: 360,
            xaxis: { title: 'Mean absolute Shapley magnitude', gridcolor: '#272727', tickfont: { family: 'Geist Mono', size: 11, color: '#9B9B9B' } },
            yaxis: { gridcolor: '#181818', tickfont: { family: 'Geist Mono', size: 11, color: '#FFFFFF' } },
            showlegend: false
        }, { displayModeBar: false, responsive: true });
    }

    function filterCatalog() {
        const domain = document.getElementById('cat-domain-select').value;
        const mode = document.getElementById('cat-mode-select').value;
        document.querySelectorAll('.catalog-card').forEach(card => {
            const okDomain = (domain === 'All domains') || (card.dataset.domain === domain);
            const okMode = (mode === 'All features') || (card.dataset.mode === mode);
            card.style.display = (okDomain && okMode) ? 'flex' : 'none';
        });
    }
"""


def load_runtime_data():
    """Loads compressed precomputed Shapley bundle, feature catalog, and metrics once."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    with gzip.open(BUNDLE_PATH, "rt", encoding="utf-8") as gz_file:
        bundle = json.load(gz_file)
    with open(CATALOG_PATH, "r", encoding="utf-8") as cat_file:
        catalog = json.load(cat_file)
    with open(METRICS_PATH, "r", encoding="utf-8") as met_file:
        metrics = json.load(met_file)
    _CACHE = {"bundle": bundle, "catalog": catalog, "metrics": metrics}
    return _CACHE


def risk_tone(risk_pct):
    """Maps a phishing probability percentage to severity tone."""
    if risk_pct >= 70:
        return "critical"
    if risk_pct >= 50:
        return "warning"
    return "safe"


def _token_tone_and_delta(shap_val):
    """Maps a Shapley log odds value to rail badge class, span class, and signed label."""
    if shap_val > 0.01:
        return "token-rail-badge-risk", "specimen-token-risk", f"+{shap_val:.3f}"
    if shap_val < -0.01:
        return "token-rail-badge-safe", "specimen-token-safe", f"{shap_val:.3f}"
    return "token-rail-badge-neutral", "specimen-token-neutral", "0.000"


def _extract_subdomain_and_host(netloc):
    """Separates registered host from any subdomain prefix."""
    if not netloc:
        return "none", ""
    if (netloc.count(".") == 3) and netloc.replace(".", "").isdigit():
        return "none", netloc
    parts = netloc.split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return "none", netloc


def _parse_url_tokens(url):
    """Splits a URL into scheme, subdomain, host, path, and query tokens."""
    parsed = urllib.parse.urlsplit(url)
    subdomain, host = _extract_subdomain_and_host(parsed.netloc)
    return {
        "scheme": f"{parsed.scheme or 'http'}://",
        "subdomain": subdomain,
        "host": host,
        "path": parsed.path if parsed.path else "/",
        "query": parsed.query if parsed.query else "none",
    }


def _resolve_rail_cells(tokens, shaps):
    """Maps URL segments to corresponding Shapley attribution drivers."""
    scheme_shap = shaps.get("SSLfinal_State", shaps.get("HTTPS_token", 0.0))
    sub_shap = shaps.get("having_Sub_Domain", 0.0)
    use_ip = abs(shaps.get("having_IP_Address", 0.0)) > abs(shaps.get("Prefix_Suffix", 0.0))
    host_feat = "IP address" if use_ip else "Prefix suffix"
    host_shap = shaps.get("having_IP_Address", 0.0) if use_ip else shaps.get("Prefix_Suffix", 0.0)
    path_shap = shaps.get("URL_Length", 0.0)
    sec_feat, sec_shap = max(
        ((f, shaps.get(f, 0.0)) for f in ("Shortining_Service", "having_At_Symbol", "double_slash_redirecting")),
        key=lambda item: abs(item[1]),
    )
    sec_label = "Shortened URL" if sec_feat == "Shortining_Service" else "Symbol redirect"
    return [
        ("Scheme protocol", tokens["scheme"], "SSL state", scheme_shap),
        ("Subdomain", tokens["subdomain"], "Subdomain", sub_shap),
        ("Registered host", tokens["host"], host_feat, host_shap),
        ("Path destination", tokens["path"], "URL length", path_shap),
        ("Security flags", tokens["query"], sec_label, sec_shap),
    ]


def _assemble_attributions(features, vals, shaps, catalog):
    """Builds sorted attribution records from precomputed Shapley vectors."""
    out = []
    for feat_name, val, s_val in zip(features, vals, shaps):
        meta = catalog["features"].get(feat_name, {})
        is_risk = s_val > 0
        key = "plain_explanation_phishing" if is_risk else "plain_explanation_legit"
        out.append({
            "feature": feat_name,
            "value": int(val),
            "shap_value": round(float(s_val), 4),
            "abs_impact": round(abs(float(s_val)), 4),
            "pushes_toward": "Phishing" if is_risk else "Legitimate",
            "group": meta.get("group", "General"),
            "human_text": meta.get(key, "Feature impacts phishing probability."),
        })
    out.sort(key=lambda item: item["abs_impact"], reverse=True)
    return out


def _aggregate_groups(attributions):
    """Sums signed Shapley contributions per security domain."""
    totals = {}
    for item in attributions:
        totals[item["group"]] = totals.get(item["group"], 0.0) + item["shap_value"]
    breakdown = [
        {
            "group": grp,
            "net_shap": round(float(tot), 4),
            "verdict": "Elevates Risk" if tot > 0 else "Supports Legitimacy",
        }
        for grp, tot in totals.items()
    ]
    breakdown.sort(key=lambda item: abs(item["net_shap"]), reverse=True)
    return breakdown


def _build_uci_consensus(rec):
    """Builds multi model consensus rows for a benchmark test record."""
    models = (
        ("XGBoost (30 features)", rec["prob"]),
        ("Random Forest (200 trees)", rec["rf_prob"]),
        ("Logistic Regression (L2)", rec["lr_prob"]),
    )
    return [
        {
            "name": name,
            "prob_pct": round(prob * 100.0, 1),
            "verdict": "Phishing" if prob >= 0.50 else "Legitimate",
        }
        for name, prob in models
    ]


def _valid_override(idx, val, vec_len):
    """Checks index bounds and discrete value domain for sandbox override."""
    return 0 <= idx < vec_len and val in (-1, 0, 1)


def _apply_live_overrides(feats_dict, overrides):
    """Applies optional integer overrides for interactive what if sandbox controls."""
    vec = [int(feats_dict[f]) for f in LIVE_FEATURES]
    if not overrides:
        return vec
    for idx, val in overrides.items():
        if _valid_override(idx, val, len(vec)):
            vec[idx] = val
    return vec


def diagnose_live(raw_url, overrides=None):
    """Evaluates a URL or 8 feature sandbox vector from the precomputed live grid."""
    data = load_runtime_data()
    bundle = data["bundle"]
    clean_url = sanitize_url(raw_url or DEFAULT_LIVE_URL)
    extracted = extract_live_lexical_features(clean_url)
    vec = _apply_live_overrides(extracted, overrides)
    entry = bundle["live_grid"][",".join(str(v) for v in vec)]
    attributions = _assemble_attributions(LIVE_FEATURES, vec, entry["shaps"], data["catalog"])
    return {
        "clean_url": clean_url,
        "feature_values": dict(zip(LIVE_FEATURES, vec)),
        "prediction": "Phishing" if entry["prob"] >= 0.50 else "Legitimate",
        "phishing_probability": entry["prob"],
        "base_value": bundle["live_base_value"],
        "top_drivers": attributions[:8],
        "all_features": attributions,
        "group_breakdown": _aggregate_groups(attributions),
        "counterfactual_hints": entry["hints"],
        "consensus": entry["consensus"],
    }


def diagnose_uci(idx):
    """Loads precomputed 30 feature explanation and consensus for a test partition record."""
    data = load_runtime_data()
    records = data["bundle"]["test_records"]
    safe_idx = max(0, min(int(idx), len(records) - 1))
    rec = records[safe_idx]
    features = list(data["catalog"]["features"].keys())
    attributions = _assemble_attributions(features, rec["vals"], rec["shaps"], data["catalog"])
    true_label = "Phishing" if rec["label"] == 1 else "Legitimate"
    return {
        "idx": safe_idx,
        "url": rec["url"],
        "true_label": true_label,
        "prediction": "Phishing" if rec["prob"] >= 0.50 else "Legitimate",
        "phishing_probability": rec["prob"],
        "base_value": data["bundle"]["full_base_value"],
        "top_drivers": attributions[:8],
        "all_features": attributions,
        "group_breakdown": _aggregate_groups(attributions),
        "counterfactual_hints": rec["hints"],
        "consensus": _build_uci_consensus(rec),
    }


def _render_verdict_html(title, subtitle, risk_pct):
    """Renders headline classification card and flat risk bar."""
    color = TONE_COLORS[risk_tone(risk_pct)]
    return (
        f'<div class="verdict-card"><div class="verdict-top"><div>'
        f'<div class="verdict-eyebrow"><span class="verdict-dot" style="background-color: {color};"></span>'
        f'Automated classification</div>'
        f'<div class="verdict-title" style="color: {color};">{html.escape(title)}</div>'
        f'<div class="verdict-sub">{html.escape(subtitle)}</div></div>'
        f'<div class="verdict-score"><div class="verdict-score-label">Probability of phishing</div>'
        f'<div class="verdict-score-value" style="color: {color};">{risk_pct:.1f}%</div></div></div>'
        f'<div class="verdict-track"><div class="verdict-fill" style="width: {risk_pct:.1f}%; background-color: {color};"></div></div></div>'
    )


def _format_specimen_span(txt, shap_val):
    """Formats one highlighted inline segment span inside the URL specimen banner."""
    _, span_cls, delta_str = _token_tone_and_delta(shap_val)
    return (
        f'<span class="specimen-token {span_cls}">{html.escape(txt)}'
        f'<span class="specimen-delta">{delta_str}</span></span>'
    )


def _format_rail_cell_html(type_lbl, val_str, feat_lbl, shap_val):
    """Formats one compartment cell inside the five cell telemetry rail."""
    badge_cls, _, delta_str = _token_tone_and_delta(shap_val)
    return (
        f'<div class="token-rail-cell"><div><div class="token-rail-type">{html.escape(type_lbl)}</div>'
        f'<div class="token-rail-val">{html.escape(val_str)}</div></div>'
        f'<div class="token-rail-badge {badge_cls}">'
        f'<span>{html.escape(feat_lbl)}</span><span>{delta_str}</span></div></div>'
    )


def _specimen_segments(tokens, cells):
    """Pairs non empty URL segments with their corresponding telemetry cell SHAP scores."""
    sub_prefix = f"{tokens['subdomain']}." if tokens["subdomain"] != "none" else ""
    q_suffix = f"?{tokens['query']}" if tokens["query"] != "none" else ""
    candidates = (
        (tokens["scheme"], cells[0][3]),
        (sub_prefix, cells[1][3]),
        (tokens["host"], cells[2][3]),
        (tokens["path"], cells[3][3]),
        (q_suffix, cells[4][3]),
    )
    return [(txt, s) for txt, s in candidates if txt]


def _render_token_rail_html(url, result):
    """Renders inline annotated URL specimen banner and five cell telemetry rail."""
    tokens = _parse_url_tokens(url)
    shaps = {item["feature"]: item["shap_value"] for item in result["all_features"]}
    cells = _resolve_rail_cells(tokens, shaps)
    spans = "".join(_format_specimen_span(txt, s) for txt, s in _specimen_segments(tokens, cells))
    boxes = "".join(_format_rail_cell_html(t, v, f, s) for t, v, f, s in cells)
    return (
        f'<div class="token-rail-deck"><div class="token-rail-header">'
        f'<span class="token-rail-title">Segmented address telemetry rail</span>'
        f'<span class="token-rail-sub">Inline token decomposition with signed Shapley attribution</span></div>'
        f'<div class="specimen-url-bar">{spans}</div>'
        f'<div class="token-rail-grid">{boxes}</div></div>'
    )


def _format_consensus_row_html(entry):
    """Formats one progress bar row in the multi model consensus card."""
    is_phish = entry["verdict"] == "Phishing"
    color = TONE_COLORS["critical"] if is_phish else TONE_COLORS["safe"]
    pct = min(100.0, max(0.0, float(entry["prob_pct"])))
    return (
        f'<div class="consensus-row"><div class="consensus-row-top">'
        f'<span class="consensus-name">{html.escape(entry["name"])}</span>'
        f'<span class="consensus-meta"><span style="color: {color};">'
        f'{html.escape(entry["verdict"])}</span> {pct:.1f}%</span></div>'
        f'<div class="consensus-track"><div class="consensus-fill" style="width: {pct:.1f}%; '
        f'background-color: {color};"></div></div></div>'
    )


def _consensus_header_meta(c_rows):
    """Computes consensus pill label and tone across evaluators."""
    phish_votes = sum(1 for r in c_rows if r["verdict"] == "Phishing")
    maj = max(phish_votes, len(c_rows) - phish_votes)
    maj_lbl = "phishing" if phish_votes >= len(c_rows) - phish_votes else "legitimate"
    color = "#e57373" if maj_lbl == "phishing" else "#81c784"
    return f"{maj} of {len(c_rows)} predict {maj_lbl}", color


def _format_ruler_and_kpis(risk_pct, sec_title, sec_val, base_v, net_m):
    """Formats the population risk ruler box and four summary KPI tiles."""
    clamped = min(98.0, max(2.0, risk_pct))
    marker_color = TONE_COLORS[risk_tone(risk_pct)]
    ruler = (
        f'<div class="consensus-card" style="margin-bottom: 12px;"><div class="consensus-header">'
        f'<span class="consensus-title">Population risk ruler</span>'
        f'<span class="consensus-pill" style="color: {marker_color};">Threshold 50.0%</span></div>'
        f'<div class="ruler-wrap"><div class="ruler-tag" style="left: {clamped:.1f}%; color: {marker_color};">{risk_pct:.1f}%</div>'
        f'<div class="ruler-track"><div class="ruler-zone-safe"></div><div class="ruler-zone-warn"></div><div class="ruler-zone-crit"></div></div>'
        f'<div class="ruler-threshold"></div><div class="ruler-needle" style="left: {clamped:.1f}%; background-color: {marker_color};"></div></div>'
        f'<div class="ruler-legend"><span>Legitimate zone</span><span>Suspicious zone</span><span>Critical phishing zone</span></div></div>'
    )
    kpis = (
        f'<div class="kpi-grid-2">'
        f'<div class="kpi-tile"><div class="kpi-title">Safe probability</div><div class="kpi-value" style="color: {TONE_COLORS["safe"]};">{100 - risk_pct:.1f}%</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">{html.escape(sec_title)}</div><div class="kpi-value">{html.escape(sec_val)}</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">Base prior log odds</div><div class="kpi-value">{base_v:+.3f}</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">Net log odds margin</div><div class="kpi-value">{net_m:+.3f}</div></div>'
        f'</div>'
    )
    return f"<div>{ruler}{kpis}</div>"


def _render_consensus_ruler_html(result, risk_pct, sec_title, sec_val):
    """Renders population threshold ruler with KPI tiles beside multi model consensus."""
    base_v = result["base_value"]
    net_m = sum(d["shap_value"] for d in result["all_features"]) + base_v
    c_rows = result["consensus"]
    sum_text, sum_color = _consensus_header_meta(c_rows)
    bars_html = "".join(map(_format_consensus_row_html, c_rows))
    left = _format_ruler_and_kpis(risk_pct, sec_title, sec_val, base_v, net_m)
    right = (
        f'<div class="consensus-card" style="height: 100%;"><div class="consensus-header">'
        f'<span class="consensus-title">Multi model consensus</span>'
        f'<span class="consensus-pill" style="color: {sum_color};">{sum_text}</span></div>'
        f'<div class="consensus-sub">Independent evaluator risk scores across trained architectures and structural heuristics.</div>'
        f'{bars_html}</div>'
    )
    return f'<div class="two-col">{left}<div>{right}</div></div>'


def _render_ledger_html(base_value, drivers, prob_phishing):
    """Renders cumulative attribution log odds table alongside the waterfall chart."""
    top_items = drivers[:6]
    cum_sum = base_value
    rows = [
        f'<tr><td style="color: #9B9B9B;">Base expectation</td>'
        f'<td style="text-align: right; color: #9B9B9B;">{base_value:+.3f}</td>'
        f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
    ]
    for d in top_items:
        s_val = d["shap_value"]
        cum_sum += s_val
        cls = "ledger-row-risk" if s_val > 0 else "ledger-row-safe"
        rows.append(
            f'<tr><td style="color: #FFFFFF;">{html.escape(d["feature"])}</td>'
            f'<td style="text-align: right;" class="{cls}">{s_val:+.3f}</td>'
            f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
        )
    risk_pct = prob_phishing * 100.0
    tone_color = TONE_COLORS[risk_tone(risk_pct)]
    return (
        f'<div class="ledger-card"><div style="font-size: 12px; font-weight: 600; color: #9B9B9B; margin-bottom: 12px;">'
        f'Attribution log odds ledger</div><table class="ledger-table"><thead><tr>'
        f'<th>Factor</th><th style="text-align: right;">Delta</th><th style="text-align: right;">Cumulative</th></tr></thead>'
        f'<tbody>{"".join(rows)}<tr class="ledger-row-total"><td>Total net margin</td><td></td>'
        f'<td style="text-align: right; color: #FFFFFF;">{cum_sum:+.3f}</td></tr>'
        f'<tr><td style="color: #9B9B9B; padding-top: 8px;">Posterior risk</td><td></td>'
        f'<td style="text-align: right; font-weight: 600; padding-top: 8px; color: {tone_color};">{risk_pct:.1f}%</td></tr>'
        f'</tbody></table></div>'
    )


def _render_evidence_html(drivers):
    """Renders top three evidence cards in plain security terms."""
    cards = []
    for d in drivers[:3]:
        raises = d["shap_value"] > 0
        pill_color = TONE_COLORS["critical"] if raises else TONE_COLORS["safe"]
        pill_text = "Raises risk" if raises else "Lowers risk"
        cards.append(
            f'<div class="evidence-card"><div class="evidence-head">'
            f'<span class="evidence-name">{html.escape(d["feature"])}</span>'
            f'<span class="evidence-pill" style="color: {pill_color};">{pill_text}</span></div>'
            f'<div class="evidence-value">Shapley {d["shap_value"]:+.3f}</div>'
            f'<div class="evidence-text">{html.escape(d["human_text"])}</div></div>'
        )
    return f'<div class="evidence-grid">{"".join(cards)}</div>'


def _render_recourse_html(hints, current_risk_pct):
    """Renders counterfactual diff cards or clean baseline notice."""
    if not hints:
        return (
            '<div class="action-card"><div style="font-size: 14px; font-weight: 600;">Clean baseline structure</div>'
            '<div style="font-size: 14px; line-height: 20px; color: #9B9B9B; margin-top: 4px;">'
            'No single change lowers the score noticeably. The evaluated properties match legitimate norms.</div></div>'
        )
    cards = []
    for h in hints:
        cur_label = "suspicious" if h["current_value"] == 0 else "phishing"
        new_pct = round(h["new_phishing_probability"] * 100.0, 1)
        new_color = TONE_COLORS["safe"] if new_pct < 50 else TONE_COLORS["warning"]
        cards.append(
            f'<div class="recourse-card"><div class="recourse-head">'
            f'<span class="recourse-name">{html.escape(h["feature"])}</span>'
            f'<span class="recourse-badge">Risk down {h["risk_reduction_pct"]:.1f}%</span></div>'
            f'<div class="recourse-state">State transition: {cur_label} &#8594; legitimate norm</div>'
            f'<div class="recourse-delta-row"><span>Phishing risk shift</span>'
            f'<span style="color: {new_color};">{current_risk_pct:.1f}% &#8594; {new_pct:.1f}%</span></div>'
            f'<div class="recourse-bars">'
            f'<div class="recourse-track"><div class="recourse-fill" style="width: {min(100.0, max(0.0, current_risk_pct)):.1f}%; background-color: #e57373;"></div></div>'
            f'<div class="recourse-track"><div class="recourse-fill" style="width: {min(100.0, max(0.0, new_pct)):.1f}%; background-color: {new_color};"></div></div></div>'
            f'<div class="recourse-text">{html.escape(h["guidance"])}</div></div>'
        )
    return f'<div class="recourse-grid">{"".join(cards)}</div>'


def _format_table_cell(val, align):
    """Formats one console table cell with semantic pills where matching."""
    text = html.escape(str(val))
    if text in BADGE_COLORS:
        content = f'<span class="console-badge" style="color: {BADGE_COLORS[text]};">{text}</span>'
    else:
        content = text
    font_css = "font-family: 'Geist Mono', monospace;" if align == "right" else ""
    return f'<td style="text-align: {align}; {font_css}">{content}</td>'


def _render_console_table(rows, columns):
    """Renders a graphite console HTML table."""
    headers = "".join(f'<th style="text-align: {align};">{html.escape(label)}</th>' for _, label, align in columns)
    body = "".join(
        f'<tr>{"".join(_format_table_cell(row.get(k, ""), a) for k, _, a in columns)}</tr>'
        for row in rows
    )
    return f'<div class="console-table-wrap"><table class="console-table"><thead><tr>{headers}</tr></thead><tbody>{body}</tbody></table></div>'


def _build_waterfall_payload(base_value, drivers):
    """Serializes top Shapley contributors into Plotly waterfall arrays."""
    top_items = drivers[:6]
    return {
        "x": ["Base prior"] + [d["feature"] for d in top_items] + ["Net log odds"],
        "measures": ["absolute"] + ["relative"] * len(top_items) + ["total"],
        "y": [base_value] + [d["shap_value"] for d in top_items] + [0],
        "texts": [f"{base_value:+.3f}"] + [f"{d['shap_value']:+.3f}" for d in top_items] + [""],
    }


def _render_sec_header(title, note):
    """Formats a consistent section title and muted subtitle."""
    return f'<div class="section-title">{html.escape(title)}</div><div class="section-note">{html.escape(note)}</div>'


def _compose_results_html(url, result, verdict_title, verdict_sub, sec_kpi, gauge_note, chart_note, table_title, table_sub, rows, cols):
    """Assembles the shared Tab 1 inspection body across verdict, rail, consensus, charts, and table."""
    risk_pct = result["phishing_probability"] * 100.0
    parts = [
        _render_verdict_html(verdict_title, verdict_sub, risk_pct),
        _render_token_rail_html(url, result),
        _render_sec_header("Telemetry and model consensus", gauge_note),
        _render_consensus_ruler_html(result, risk_pct, sec_kpi[0], sec_kpi[1]),
        _render_sec_header("TreeSHAP attribution waterfall ledger", chart_note),
        f'<div class="waterfall-grid"><div class="plot-card"><div id="waterfall-plot"></div></div>'
        f'<div>{_render_ledger_html(result["base_value"], result["top_drivers"], result["phishing_probability"])}</div></div>',
        _render_sec_header("Key evidence", "The strongest signals behind this result, in plain language."),
        _render_evidence_html(result["top_drivers"]),
        _render_sec_header("Actionable recourse", "Smallest single changes that reduce the phishing score."),
        _render_recourse_html(result["counterfactual_hints"], risk_pct),
        _render_sec_header(table_title, table_sub),
        _render_console_table(rows, cols),
    ]
    return "".join(parts)


def build_diagnose_payload(mode="uci", url=None, idx=DEFAULT_UCI_IDX, overrides=None):
    """Produces full inspection HTML and waterfall chart payload for live URL or UCI mode."""
    t0 = time.perf_counter()
    data = load_runtime_data()
    if mode == "live":
        res = diagnose_live(url, overrides)
        ms = max(0.1, (time.perf_counter() - t0) * 1000.0)
        risk_pct = res["phishing_probability"] * 100.0
        rows = [
            {
                "Property": item["feature"],
                "State": STATE_LABELS[item["value"]],
                "Shapley impact": f"{item['shap_value']:+.4f}",
                "Influence": item["pushes_toward"],
                "Forensic explanation": item["human_text"],
            }
            for item in res["all_features"]
        ]
        cols = [
            ("Property", "Property", "left"), ("State", "State", "left"),
            ("Shapley impact", "Shapley impact", "right"), ("Influence", "Influence", "left"),
            ("Forensic explanation", "Forensic explanation", "left"),
        ]
        body_html = _compose_results_html(
            res["clean_url"], res, VERDICT_TITLES[risk_tone(risk_pct)],
            "Evaluated across eight offline lexical properties with zero network exposure.",
            ("Explanation time", f"{ms:.1f} ms"),
            "Probability from the lexical XGBoost classifier.",
            "Contribution of each property to the prediction (TreeSHAP).",
            "Complete diagnostic matrix", "Every evaluated property with its state and Shapley impact.",
            rows, cols,
        )
        return {
            "mode": "live", "clean_url": res["clean_url"], "feature_values": res["feature_values"],
            "html": body_html, "waterfall": _build_waterfall_payload(res["base_value"], res["top_drivers"]),
        }

    res = diagnose_uci(idx)
    acc = data["metrics"]["models"]["xgboost_full_30"]["accuracy"] * 100.0
    agree = "The prediction matches." if res["prediction"] == res["true_label"] else "The prediction does not match."
    rows = [
        {"group": r["group"], "net_shap": f"{r['net_shap']:+.4f}", "verdict": r["verdict"]}
        for r in res["group_breakdown"]
    ]
    cols = [("group", "Security domain", "left"), ("net_shap", "Net Shapley delta", "right"), ("verdict", "Domain impact", "left")]
    body_html = _compose_results_html(
        res["url"], res, f"Model predicts {res['prediction'].lower()}",
        f"Ground truth is {res['true_label'].lower()}. {agree}",
        ("Benchmark accuracy", f"{acc:.2f}%"),
        "Probability from the 30 feature XGBoost model.",
        "Contribution of each of the 30 attributes (TreeSHAP).",
        "Security domain impact", "Net Shapley contribution summed per feature domain.",
        rows, cols,
    )
    return {
        "mode": "uci", "idx": res["idx"], "url": res["url"], "true_label": res["true_label"],
        "html": body_html, "waterfall": _build_waterfall_payload(res["base_value"], res["top_drivers"]),
    }


def _render_sandbox_controls(feature_values):
    """Builds interactive what if parameter controls for the eight live lexical features."""
    blocks = []
    for idx, feat in enumerate(LIVE_FEATURES):
        cur = int(feature_values.get(feat, 1))
        opts = (1, 0, -1) if feat in ("URL_Length", "having_Sub_Domain") else (1, -1)
        option_tags = "".join(
            f'<option value="{v}" {"selected" if v == cur else ""}>{STATE_LABELS[v]} ({v})</option>'
            for v in opts
        )
        blocks.append(
            f'<div><label class="field-label" for="sbx-{feat}">{feat}</label>'
            f'<select id="sbx-{feat}" data-idx="{idx}" class="select-input sbx-select" onchange="onSandboxChange()">'
            f'{option_tags}</select></div>'
        )
    return (
        f'<details class="sandbox-details"><summary>Interactive feature sandbox (toggle parameters to test what if)</summary>'
        f'<div class="section-note" style="margin-top: 8px;">Toggle individual extracted properties below to test model sensitivity and inspect exact TreeSHAP deltas.</div>'
        f'<div class="sandbox-grid">{"".join(blocks)}</div></details>'
    )


def _format_uci_controls(uci_res, is_active):
    """Formats the UCI benchmark record selector and ground truth banner."""
    display = "block" if is_active else "none"
    truth_color = "#e57373" if uci_res["true_label"] == "Phishing" else "#81c784"
    return (
        f'<div id="controls-uci" style="display: {display};"><div class="uci-bar">'
        f'<div style="display: flex; gap: 8px;"><button type="button" class="btn btn-primary" style="width: 100%;" onclick="pickRandomUci()">Pick random URL</button>'
        f'<input id="uci-idx-input" type="hidden" value="{uci_res["idx"]}"></div>'
        f'<div class="chosen-url-inline"><span id="uci-url-text" class="chosen-url-text">{html.escape(uci_res["url"])}</span>'
        f'<span id="uci-truth-pill" class="status-pill" style="color: {truth_color};">Ground truth: {uci_res["true_label"].lower()}</span>'
        f'</div></div></div>'
    )


def _format_live_controls(live_url, is_active, sandbox_vals):
    """Formats attack preset buttons, URL scan form, and interactive sandbox controls."""
    display = "block" if is_active else "none"
    preset_btns = "".join(
        f'<button type="button" class="btn" onclick="scanPreset({json.dumps(u)})">{html.escape(lbl)}</button>'
        for lbl, u in URL_PRESETS
    )
    return (
        f'<div id="controls-live" style="display: {display};">'
        f'<div class="preset-label">Attack archetype presets</div>'
        f'<div class="preset-grid">{preset_btns}</div>'
        f'<form class="form-row" onsubmit="submitLiveScan(event)">'
        f'<input id="live-url-input" type="text" class="text-input" value="{html.escape(live_url)}" placeholder="Enter website address to inspect (e.g. https://...)">'
        f'<button type="submit" class="btn btn-primary">Scan URL</button></form>'
        f'<div class="chosen-url-inline"><span id="live-url-display" class="chosen-url-text">{html.escape(sanitize_url(live_url))}</span>'
        f'<span class="status-pill" style="color: #FFFFFF;">Live lexical input</span></div>'
        f'{_render_sandbox_controls(sandbox_vals)}</div>'
    )


def _render_inspect_tab(mode, live_url, uci_res, live_payload, diag_payload):
    """Renders Tab 1 mode toggle, preset buttons, sandbox, and result container."""
    sandbox_vals = live_payload.get("feature_values", {f: 1 for f in LIVE_FEATURES})
    uci_controls = _format_uci_controls(uci_res, mode == "uci")
    live_controls = _format_live_controls(live_url, mode == "live", sandbox_vals)
    uci_cls = "active" if mode == "uci" else ""
    live_cls = "active" if mode == "live" else ""
    mode_bar = (
        f'<div class="mode-switch">'
        f'<button id="mode-btn-uci" type="button" class="mode-btn {uci_cls}" onclick="setInspectMode(\'uci\')">UCI benchmark record</button>'
        f'<button id="mode-btn-live" type="button" class="mode-btn {live_cls}" onclick="setInspectMode(\'live\')">Live URL input</button>'
        f'</div>'
    )
    return f'{mode_bar}{uci_controls}{live_controls}<div id="inspect-results">{diag_payload["html"]}</div>'


def _render_eval_tab(data):
    """Renders Tab 2 model evaluation KPIs, table, interactive threshold simulator, and plots."""
    scores = data["metrics"]["models"]
    top_kpis = (
        f'<div class="kpi-grid-4">'
        f'<div class="kpi-tile"><div class="kpi-title">XGBoost 30 accuracy</div><div class="kpi-value">{scores["xgboost_full_30"]["accuracy"]*100:.2f}%</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">XGBoost 30 recall</div><div class="kpi-value">{scores["xgboost_full_30"]["recall"]*100:.2f}%</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">XGBoost 30 ROC AUC</div><div class="kpi-value">{scores["xgboost_full_30"]["roc_auc"]:.4f}</div></div>'
        f'<div class="kpi-tile"><div class="kpi-title">Live 8 lexical accuracy</div><div class="kpi-value">{scores["xgboost_live_lexical_8"]["accuracy"]*100:.2f}%</div></div>'
        f'</div>'
    )
    model_specs = (
        ("XGBoost", "30 (Full)", "xgboost_full_30"),
        ("Random Forest", "30 (Full)", "random_forest_full_30"),
        ("Logistic Regression", "30 (Full)", "logistic_regression_full_30"),
        ("XGBoost live subset", "8 (URL only)", "xgboost_live_lexical_8"),
    )
    perf_rows = [
        {
            "Model architecture": name, "Features": feat_txt,
            "Accuracy": f"{scores[key]['accuracy']*100:.2f}%", "Precision": f"{scores[key]['precision']*100:.2f}%",
            "Recall": f"{scores[key]['recall']*100:.2f}%", "F1 score": f"{scores[key]['f1']:.4f}",
            "ROC AUC": f"{scores[key]['roc_auc']:.4f}", "MCC": f"{scores[key]['mcc']:.4f}",
        }
        for name, feat_txt, key in model_specs
    ]
    perf_cols = [
        ("Model architecture", "Model architecture", "left"), ("Features", "Features", "left"),
        ("Accuracy", "Accuracy", "right"), ("Precision", "Precision", "right"),
        ("Recall", "Recall", "right"), ("F1 score", "F1 score", "right"),
        ("ROC AUC", "ROC AUC", "right"), ("MCC", "MCC", "right"),
    ]
    slider_box = (
        '<div class="slider-card"><div class="slider-head">'
        '<span class="consensus-title">Classification probability threshold</span>'
        '<span id="thresh-readout" class="consensus-pill" style="color: #FFFFFF;">0.50</span></div>'
        '<input id="threshold-slider" class="range-input" type="range" min="0.05" max="0.95" step="0.05" value="0.50" oninput="drawEvalCharts()">'
        '</div>'
    )
    thresh_kpis = (
        '<div class="kpi-grid-4">'
        '<div class="kpi-tile"><div id="kpi-prec-lbl" class="kpi-title">Precision at 0.50</div><div id="kpi-prec-val" class="kpi-value">0.00%</div></div>'
        '<div class="kpi-tile"><div id="kpi-rec-lbl" class="kpi-title">Recall at 0.50</div><div id="kpi-rec-val" class="kpi-value">0.00%</div></div>'
        '<div class="kpi-tile"><div id="kpi-f1-lbl" class="kpi-title">F1 score at 0.50</div><div id="kpi-f1-val" class="kpi-value">0.0000</div></div>'
        '<div class="kpi-tile"><div class="kpi-title">False positives / Missed</div><div id="kpi-fpfn-val" class="kpi-value">0 / 0</div></div>'
        '</div>'
    )
    plots = (
        '<div class="two-col">'
        '<div class="plot-card"><div class="preset-label" style="margin: 4px 0 8px 8px;">Receiver operating characteristic</div><div id="roc-plot"></div></div>'
        '<div class="plot-card"><div id="cm-title" class="preset-label" style="margin: 4px 0 8px 8px;">Confusion matrix at threshold 0.50</div><div id="cm-plot"></div></div>'
        '</div>'
        + _render_sec_header("Global TreeSHAP feature importance", "Mean absolute Shapley magnitude across test records. White bars mark live lexical features and grey bars mark offline attributes.")
        + '<div class="plot-card"><div id="global-shap-plot"></div></div>'
    )
    return (
        _render_sec_header("Model evaluation and ablation", "Benchmark scores measured on the held out test partition (1,659 records).")
        + top_kpis
        + _render_console_table(perf_rows, perf_cols)
        + _render_sec_header("Interactive decision threshold simulator", "Adjust the probability threshold to balance false alarms against missed phishing attacks.")
        + slider_box + thresh_kpis + plots
    )


def _format_catalog_card(name, meta, prevalence):
    """Formats one bento card inside Tab 3 Feature catalog."""
    is_live = meta.get("extractable_live", False)
    mode_tag = "Live lexical only" if is_live else "Offline network and DOM"
    badge_text = "Live lexical" if is_live else ("Legacy API" if meta.get("deprecated", False) else "Offline record")
    badge_color = "#81c784" if is_live else "#9B9B9B"
    p_phish, p_susp, p_legit = prevalence
    rule_clean = meta.get("rule", "").replace("->", "&#8594;")
    return (
        f'<div class="catalog-card" data-domain="{html.escape(meta.get("group", ""))}" data-mode="{mode_tag}">'
        f'<div><div class="catalog-head"><span class="catalog-name">{html.escape(name)}</span>'
        f'<span class="catalog-badge" style="color: {badge_color};">{badge_text}</span></div>'
        f'<div class="catalog-domain">{html.escape(meta.get("group", ""))}</div></div>'
        f'<div class="catalog-desc">{html.escape(meta.get("description", ""))}</div>'
        f'<div class="catalog-rule">{rule_clean}</div>'
        f'<div><div class="prev-head"><span>Test partition prevalence</span>'
        f'<span>{p_phish:.0f}% / {p_susp:.0f}% / {p_legit:.0f}%</span></div>'
        f'<div class="prev-track"><div style="width: {p_phish:.1f}%; background-color: #e57373;"></div>'
        f'<div style="width: {p_susp:.1f}%; background-color: #ffb74d;"></div>'
        f'<div style="width: {p_legit:.1f}%; background-color: #81c784;"></div></div>'
        f'<div class="prev-legend"><span style="color: #e57373;">Phish</span>'
        f'<span style="color: #ffb74d;">Suspicious</span><span style="color: #81c784;">Normal</span></div></div></div>'
    )


def _render_catalog_tab(data):
    """Renders Tab 3 security domain filters and three column feature bento grid."""
    catalog = data["catalog"]
    prev_map = data["bundle"]["prevalence"]
    domain_opts = "".join(
        f'<option value="{html.escape(g)}">{html.escape(g)}</option>'
        for g in ["All domains"] + list(catalog["feature_groups"].keys())
    )
    mode_opts = "".join(
        f'<option value="{html.escape(m)}">{html.escape(m)}</option>'
        for m in ("All features", "Live lexical only", "Offline network and DOM")
    )
    filters = (
        f'<div class="two-col">'
        f'<div><label class="field-label" for="cat-domain-select">Select security domain</label>'
        f'<select id="cat-domain-select" class="select-input" onchange="filterCatalog()">{domain_opts}</select></div>'
        f'<div><label class="field-label" for="cat-mode-select">Select extraction mode</label>'
        f'<select id="cat-mode-select" class="select-input" onchange="filterCatalog()">{mode_opts}</select></div></div>'
    )
    cards = "".join(
        _format_catalog_card(name, meta, prev_map.get(name, [0.0, 0.0, 100.0]))
        for name, meta in catalog["features"].items()
    )
    return (
        _render_sec_header("Feature catalog", "Complete taxonomy of thirty features defined by Mohammad et al., annotated with empirical partition prevalence.")
        + filters + f'<div class="catalog-grid">{cards}</div>'
    )


def _build_eval_bootstrap(data):
    """Builds JSON bootstrap arrays for client side ROC curves, threshold simulator, and global SHAP."""
    scores = data["metrics"]["models"]
    return {
        "y_true": data["bundle"]["test_eval"]["y_true"],
        "y_probs": data["bundle"]["test_eval"]["y_probs"],
        "global_shap": data["bundle"]["test_eval"]["global_shap"],
        "roc": {
            "xgb30": scores["xgboost_full_30"]["curve_samples"],
            "rf30": scores["random_forest_full_30"]["curve_samples"],
            "xgb8": scores["xgboost_live_lexical_8"]["curve_samples"],
        },
    }


def _active_cls(current, target):
    """Returns active CSS class token when current matches target."""
    return "active" if current == target else ""


def _render_tab_bar(active_tab):
    """Renders the segmented navigation control across all three views."""
    tab_defs = (
        ("inspect", "URL inspection"),
        ("eval", "Model evaluation and ablation"),
        ("catalog", "Feature catalog"),
    )
    return "".join(
        f'<button type="button" data-tab="{tid}" class="tab-btn {_active_cls(active_tab, tid)}" '
        f'onclick="switchTab(\'{tid}\')">{lbl}</button>'
        for tid, lbl in tab_defs
    )


def render_full_page_html(mode="uci", url=None, idx=DEFAULT_UCI_IDX, tab="inspect", overrides=None):
    """Renders the complete standalone PhishLens Telemetry Console HTML document."""
    data = load_runtime_data()
    live_url = url or DEFAULT_LIVE_URL
    uci_payload = build_diagnose_payload("uci", idx=idx)
    live_payload = build_diagnose_payload("live", url=live_url, overrides=overrides)
    active_diag = live_payload if mode == "live" else uci_payload
    inspect_html = _render_inspect_tab(mode, live_url, uci_payload, live_payload, active_diag)
    boot_script = (
        f'window.__evalData = {json.dumps(_build_eval_bootstrap(data))};'
        f'drawWaterfall({json.dumps(active_diag["waterfall"])});'
        f'drawEvalCharts();'
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>PhishLens | Threat Intelligence</title>'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600;700&display=swap">'
        '<script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>'
        f'<style>{PAGE_CSS}</style></head><body><div class="container">'
        '<div class="hero-box"><div class="hero-heading">Evaluate website security<br>with transparent reasoning.</div></div>'
        f'<div class="tab-bar">{_render_tab_bar(tab)}</div>'
        f'<div id="panel-inspect" class="tab-panel {_active_cls(tab, "inspect")}">{inspect_html}</div>'
        f'<div id="panel-eval" class="tab-panel {_active_cls(tab, "eval")}">{_render_eval_tab(data)}</div>'
        f'<div id="panel-catalog" class="tab-panel {_active_cls(tab, "catalog")}">{_render_catalog_tab(data)}</div>'
        '<div class="footer-note">PhishLens research system &#8226; Built for explainable threat intelligence</div>'
        f'</div><script>{CONSOLE_JS}\n{boot_script}</script></body></html>'
    )
