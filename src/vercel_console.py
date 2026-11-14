"""
Vercel Geist black and white Split Pane Forensic Workbench for PhishLens.
Renders native SVG/CSS visualizations, inline What If attribution toggles,
threshold simulator, and feature taxonomy from precomputed TreeSHAP bundles.
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
COPY_REPLACEMENTS = (
    ("->", "\u2192"),
    ("-1", "\u22121"),
    ("non-standard", "nonstandard"),
    ("Right-clicking", "Right clicking"),
    ("Right-click", "Right click"),
    ("Long-term multi-year", "Long term multiyear"),
    ("credential-harvesting", "credential harvesting"),
    ("short-lived", "short lived"),
    ("High-traffic", "High traffic"),
    ("54-75", "54 to 75"),
    ("22-61", "22 to 61"),
    ("31-67", "31 to 67"),
    ("17-81", "17 to 81"),
    ("2-4", "2 to 4"),
    ("1-2", "1 to 2"),
)

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

    @keyframes fadeInUp {
        from { opacity: 0; transform: translateY(6px); }
        to { opacity: 1; transform: translateY(0); }
    }
    .workbench-fade {
        animation: fadeInUp 260ms cubic-bezier(0.16, 1, 0.3, 1);
    }

    /* Top Vercel Chrome */
    .topbar {
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 12px 16px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        flex-wrap: wrap;
    }
    .brand-group {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .brand-name {
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        color: #FFFFFF;
    }
    .brand-sep {
        color: #313131;
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
    }
    .brand-sub {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
    }
    .tab-bar {
        display: inline-flex;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
    }
    .tab-btn {
        font-family: 'Geist', sans-serif;
        font-size: 14px;
        line-height: 20px;
        font-weight: 500;
        color: #9B9B9B;
        padding: 4px 12px;
        border-radius: 4px;
        border: none;
        background-color: transparent;
        cursor: pointer;
        white-space: nowrap;
        transition: background-color 150ms ease, color 150ms ease, transform 240ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .tab-btn:hover { color: #FFFFFF; background-color: #1F1F1F; }
    .tab-btn.active { background-color: #272727; color: #FFFFFF; font-weight: 600; }
    .status-chip {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 12px;
        border-radius: 8px;
        border: 1px solid #272727;
        background-color: #181818;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
    }
    .status-dot { width: 8px; height: 8px; border-radius: 9999px; background-color: #81c784; }

    .container {
        max-width: 1440px;
        margin: 0 auto;
        padding: 24px 32px 64px 32px;
    }
    .hero-band {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        gap: 24px;
        margin-bottom: 16px;
        flex-wrap: wrap;
    }
    .hero-box { max-width: 680px; }
    .hero-heading {
        font-size: 30px;
        line-height: 36px;
        font-weight: 600;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #FFFFFF 0%, #9B9B9B 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-wrap: balance;
    }
    .hero-sub {
        font-size: 14px;
        line-height: 20px;
        color: #9B9B9B;
        margin-top: 4px;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; animation: fadeInUp 260ms cubic-bezier(0.16, 1, 0.3, 1); }

    /* Command Omnibox Bar */
    .omnibox {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        margin-bottom: 24px;
    }
    .omnibox-top {
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }
    .mode-switch {
        display: inline-flex;
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 4px;
        gap: 4px;
        flex-shrink: 0;
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
        padding: 4px 12px;
        cursor: pointer;
        transition: background-color 150ms ease, color 150ms ease;
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
        white-space: nowrap;
        transition: background-color 150ms ease, border-color 150ms ease, color 150ms ease, transform 240ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .btn:hover { background-color: #272727; border-color: #616161; }
    .btn:active, .preset-pill:active, .state-pill:active { transform: scale(0.985); }
    .btn-primary {
        background-color: #FFFFFF;
        color: #000000;
        border: 1px solid #FFFFFF;
    }
    .btn-primary:hover { background-color: #E6E6E6; border-color: #E6E6E6; color: #000000; }

    .omnibox-controls { flex: 1 1 0%; min-width: 280px; }
    .scan-form { display: flex; gap: 8px; align-items: center; }
    .text-input, .select-input {
        width: 100%;
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        color: #FFFFFF;
        padding: 8px 12px;
        outline: none;
        transition: border-color 150ms ease;
    }
    .select-input { font-family: 'Geist', sans-serif; background-color: #181818; }
    .text-input:focus, .select-input:focus { border-color: #FFFFFF; }

    .preset-strip {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
        margin-top: 12px;
    }
    .preset-caption {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 500;
    }
    .preset-pill {
        font-family: 'Geist', sans-serif;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        color: #9B9B9B;
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 6px;
        padding: 4px 12px;
        cursor: pointer;
        transition: background-color 150ms ease, border-color 150ms ease, color 150ms ease, transform 240ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .preset-pill:hover { background-color: #1F1F1F; border-color: #313131; color: #FFFFFF; }

    .uci-controls-row {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
    }
    .uci-url-box {
        flex: 1 1 0%;
        min-width: 240px;
        background-color: #000000;
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
        white-space: nowrap;
    }
    .record-counter {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-variant-numeric: tabular-nums;
        padding: 0 4px;
    }

    /* Split Pane Forensic Workbench */
    .workbench-grid {
        display: grid;
        grid-template-columns: 380px minmax(0, 1fr);
        gap: 24px;
        align-items: start;
    }
    .dossier-sticky {
        position: sticky;
        top: 24px;
        display: flex;
        flex-direction: column;
        gap: 16px;
    }
    .canvas-col {
        display: flex;
        flex-direction: column;
        gap: 16px;
        min-width: 0;
    }
    .panel {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
    }
    .panel-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 12px;
    }
    .panel-title {
        font-size: 14px;
        line-height: 20px;
        font-weight: 600;
        color: #FFFFFF;
    }
    .panel-meta {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
    }

    /* Verdict Dossier Card */
    .verdict-eyebrow {
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 500;
        margin-bottom: 8px;
    }
    .verdict-dot { width: 8px; height: 8px; border-radius: 2px; flex-shrink: 0; }
    .verdict-score-row {
        display: flex;
        justify-content: space-between;
        align-items: baseline;
        gap: 12px;
        margin-bottom: 4px;
    }
    .verdict-score-value {
        font-family: 'Geist Mono', monospace;
        font-size: 36px;
        line-height: 40px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
    }
    .verdict-title { font-size: 18px; line-height: 28px; font-weight: 600; margin-bottom: 4px; }
    .verdict-sub { font-size: 14px; line-height: 20px; color: #9B9B9B; margin-bottom: 16px; }
    .ruler-wrap { position: relative; padding: 16px 0 8px 0; }
    .ruler-track {
        display: flex;
        height: 8px;
        border-radius: 4px;
        overflow: hidden;
        border: 1px solid #272727;
    }
    .ruler-zone-safe { width: 50%; background-color: #000000; }
    .ruler-zone-warn { width: 20%; background-color: #1F1F1F; }
    .ruler-zone-crit { width: 30%; background-color: #313131; }
    .ruler-threshold { position: absolute; left: 50%; top: 12px; bottom: 4px; width: 2px; background-color: #FFFFFF; opacity: 0.45; }
    .ruler-needle {
        position: absolute;
        top: 8px;
        width: 4px;
        height: 24px;
        border-radius: 2px;
        transform: translateX(-50%);
        transition: left 320ms cubic-bezier(0.16, 1, 0.3, 1), background-color 200ms ease;
    }
    .ruler-legend {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        margin-bottom: 16px;
    }

    /* Architectural 1px Hairline Grids (zero one-sided borders) */
    .hairline-grid-2, .hairline-grid-4, .hairline-grid-5, .hairline-rows {
        display: grid;
        gap: 1px;
        background-color: #272727;
        border: 1px solid #272727;
        border-radius: 8px;
        overflow: hidden;
    }
    .hairline-grid-2 { grid-template-columns: repeat(2, 1fr); }
    .hairline-grid-4 { grid-template-columns: repeat(4, 1fr); }
    .hairline-grid-5 { grid-template-columns: repeat(5, 1fr); }
    .hairline-rows { grid-template-columns: 1fr; }
    .h-cell {
        background-color: #000000;
        padding: 12px;
        min-width: 0;
    }
    .h-cell-surface { background-color: #181818; padding: 12px; min-width: 0; }
    .cell-label {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        font-weight: 500;
    }
    .cell-value {
        font-family: 'Geist Mono', monospace;
        font-size: 18px;
        line-height: 28px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
        color: #FFFFFF;
        margin-top: 2px;
    }

    /* Consensus List */
    .consensus-row { margin-bottom: 12px; }
    .consensus-row:last-child { margin-bottom: 0; }
    .consensus-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 12px;
        line-height: 16px;
        margin-bottom: 4px;
    }
    .consensus-name { color: #FFFFFF; font-weight: 500; }
    .consensus-meta { font-family: 'Geist Mono', monospace; color: #9B9B9B; font-variant-numeric: tabular-nums; }
    .bar-track { height: 6px; background-color: #272727; border-radius: 4px; overflow: hidden; }
    .bar-fill {
        height: 100%;
        border-radius: 4px;
        transition: width 320ms cubic-bezier(0.16, 1, 0.3, 1), background-color 200ms ease;
    }

    /* Recourse Diff Stack */
    .recourse-list { display: flex; flex-direction: column; gap: 12px; }
    .recourse-item {
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 12px;
    }
    .recourse-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
    }
    .recourse-feat { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
    .recourse-meta { font-family: 'Geist Mono', monospace; font-size: 12px; line-height: 16px; color: #9B9B9B; margin-bottom: 8px; }
    .recourse-bars { display: flex; flex-direction: column; gap: 4px; margin-bottom: 8px; }
    .recourse-track { height: 4px; background-color: #272727; border-radius: 2px; overflow: hidden; }
    .recourse-fill { height: 100%; border-radius: 2px; transition: width 320ms cubic-bezier(0.16, 1, 0.3, 1); }
    .recourse-copy { font-size: 12px; line-height: 16px; color: #9B9B9B; }

    /* URL X-Ray Anatomy Specimen */
    .specimen-url-bar {
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        font-family: 'Geist Mono', monospace;
        font-size: 18px;
        line-height: 28px;
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: 8px;
        word-break: break-all;
    }
    .specimen-token {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 4px 8px;
        border-radius: 6px;
        border: 1px solid #272727;
        background-color: #181818;
    }
    .specimen-token-risk { color: #e57373; border-color: #e57373; }
    .specimen-token-safe { color: #81c784; border-color: #313131; }
    .specimen-token-neutral { color: #9B9B9B; border-color: #272727; }
    .specimen-delta { font-size: 12px; line-height: 16px; color: #9B9B9B; font-variant-numeric: tabular-nums; }
    .rail-val {
        font-family: 'Geist Mono', monospace;
        font-size: 14px;
        line-height: 20px;
        color: #FFFFFF;
        word-break: break-all;
        margin: 4px 0 8px 0;
    }
    .rail-badge {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
    }

    /* Unified Diverging Butterfly Attribution Rows */
    .attr-row {
        background-color: #000000;
        padding: 12px 16px;
        display: grid;
        grid-template-columns: minmax(0, 1.4fr) auto minmax(180px, 1fr) 72px;
        gap: 16px;
        align-items: center;
        transition: background-color 150ms ease;
    }
    .attr-row:hover { background-color: #181818; }
    .attr-extra-hidden { display: none; }
    .attr-feat-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .attr-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; }
    .attr-domain {
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 4px;
        padding: 0 8px;
    }
    .attr-copy { font-size: 12px; line-height: 16px; color: #9B9B9B; margin-top: 4px; }
    .state-toggle-group {
        display: inline-flex;
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 6px;
        padding: 2px;
        gap: 2px;
    }
    .state-pill {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 500;
        color: #9B9B9B;
        background-color: transparent;
        border: none;
        border-radius: 4px;
        padding: 4px 8px;
        cursor: pointer;
        transition: background-color 150ms ease, color 150ms ease, transform 240ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .state-pill:hover { background-color: #272727; color: #FFFFFF; }
    .state-pill.active-risk { background-color: #e57373; color: #000000; font-weight: 600; }
    .state-pill.active-warn { background-color: #ffb74d; color: #000000; font-weight: 600; }
    .state-pill.active-safe { background-color: #FFFFFF; color: #000000; font-weight: 600; }

    /* Diverging Butterfly Zero Axis */
    .butterfly-wrap {
        position: relative;
        height: 24px;
        display: flex;
        align-items: center;
    }
    .butterfly-track {
        position: relative;
        width: 100%;
        height: 8px;
        background-color: #1F1F1F;
        border-radius: 4px;
        overflow: hidden;
    }
    .butterfly-zero {
        position: absolute;
        left: 50%;
        top: 0;
        bottom: 0;
        width: 2px;
        background-color: #616161;
        transform: translateX(-50%);
        z-index: 2;
    }
    .butterfly-fill-right {
        position: absolute;
        left: 50%;
        top: 0;
        bottom: 0;
        background-color: #e57373;
        transition: width 320ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .butterfly-fill-left {
        position: absolute;
        right: 50%;
        top: 0;
        bottom: 0;
        background-color: #81c784;
        transition: width 320ms cubic-bezier(0.16, 1, 0.3, 1);
    }
    .attr-delta {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        text-align: right;
        font-variant-numeric: tabular-nums;
    }

    /* Tab 2 Evaluation SVG & Confusion Matrix */
    .eval-split { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
    .slider-row {
        display: flex;
        align-items: center;
        gap: 16px;
        margin-bottom: 16px;
    }
    .range-input { width: 100%; accent-color: #FFFFFF; cursor: pointer; }
    .svg-box { width: 100%; display: block; }
    .cm-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1px;
        background-color: #272727;
        border: 1px solid #272727;
        border-radius: 8px;
        overflow: hidden;
    }
    .cm-cell {
        background-color: #000000;
        padding: 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 8px;
        min-height: 120px;
    }
    .cm-count {
        font-family: 'Geist Mono', monospace;
        font-size: 30px;
        line-height: 36px;
        font-weight: 600;
        font-variant-numeric: tabular-nums;
        color: #FFFFFF;
    }
    .global-row {
        display: grid;
        grid-template-columns: 180px 1fr 64px;
        gap: 12px;
        align-items: center;
        padding: 8px 12px;
        background-color: #000000;
    }

    /* Hairline Console Table */
    .table-row-8 { grid-template-columns: 1.5fr 1fr repeat(6, 0.8fr); }
    .table-cell-head {
        background-color: #181818;
        padding: 12px;
        font-size: 12px;
        line-height: 16px;
        font-weight: 600;
        color: #9B9B9B;
    }
    .table-cell {
        background-color: #000000;
        padding: 12px;
        font-size: 14px;
        line-height: 20px;
        font-variant-numeric: tabular-nums;
    }

    /* Feature Catalog Tab 3 */
    .catalog-filters {
        display: grid;
        grid-template-columns: 2fr 1fr 1fr;
        gap: 12px;
        margin-bottom: 16px;
    }
    .catalog-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
    .catalog-card {
        background-color: #181818;
        border: 1px solid #272727;
        border-radius: 12px;
        padding: 16px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        gap: 12px;
        transition: border-color 150ms ease;
    }
    .catalog-card:hover { border-color: #313131; }
    .catalog-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .catalog-name { font-family: 'Geist Mono', monospace; font-size: 14px; line-height: 20px; font-weight: 600; color: #FFFFFF; word-break: break-all; }
    .catalog-rule {
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
        background-color: #000000;
        border: 1px solid #272727;
        border-radius: 8px;
        padding: 8px 12px;
        word-break: break-word;
    }
    .prev-head, .prev-legend {
        display: flex;
        justify-content: space-between;
        font-family: 'Geist Mono', monospace;
        font-size: 12px;
        line-height: 16px;
        color: #9B9B9B;
    }
    .prev-track { display: flex; height: 8px; border-radius: 4px; background-color: #272727; overflow: hidden; margin: 4px 0; }
    .footer-note { text-align: center; font-size: 12px; line-height: 16px; color: #9B9B9B; padding: 24px 0 0 0; }

    @media (max-width: 1024px) {
        .workbench-grid { grid-template-columns: 1fr; }
        .dossier-sticky { position: static; }
        .attr-row { grid-template-columns: 1fr; gap: 8px; }
        .eval-split, .catalog-filters, .catalog-grid { grid-template-columns: 1fr; }
        .hairline-grid-4, .hairline-grid-5 { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 640px) {
        .container { padding: 16px 16px 48px 16px; }
        .hairline-grid-2, .hairline-grid-4, .hairline-grid-5 { grid-template-columns: 1fr; }
    }
"""

CONSOLE_JS = """
    function tweenTextNumber(el, targetVal, decimals, suffix) {
        if (!el) return;
        const startVal = parseFloat(el.dataset.val || String(targetVal));
        el.dataset.val = String(targetVal);
        if (Math.abs(targetVal - startVal) < 0.01) {
            el.textContent = targetVal.toFixed(decimals) + suffix;
            return;
        }
        const t0 = performance.now();
        const dur = 260;
        function step(now) {
            const p = Math.min(1, (now - t0) / dur);
            const eased = 1 - Math.pow(1 - p, 3);
            const cur = startVal + (targetVal - startVal) * eased;
            el.textContent = cur.toFixed(decimals) + suffix;
            if (p < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    function switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.tab === tabName);
        });
        document.querySelectorAll('.tab-panel').forEach(p => {
            p.classList.toggle('active', p.id === 'panel-' + tabName);
        });
        if (tabName === 'eval') drawEvalCharts();
    }

    function setInspectMode(mode) {
        document.getElementById('mode-btn-uci').classList.toggle('active', mode === 'uci');
        document.getElementById('mode-btn-live').classList.toggle('active', mode === 'live');
        document.getElementById('controls-uci').style.display = mode === 'uci' ? 'block' : 'none';
        document.getElementById('controls-live').style.display = mode === 'live' ? 'block' : 'none';
        window.__liveOverrides = {};
        if (mode === 'uci') {
            const idx = document.getElementById('uci-idx-input').value || '835';
            loadDiagnosis({ mode: 'uci', idx });
        } else {
            const url = document.getElementById('live-url-input').value.trim();
            loadDiagnosis({ mode: 'live', url });
        }
    }

    async function loadDiagnosis(params) {
        const container = document.getElementById('inspect-results');
        const prevScoreEl = document.getElementById('verdict-score-num');
        const prevScore = prevScoreEl ? parseFloat(prevScoreEl.dataset.val || prevScoreEl.textContent) : null;
        const qs = new URLSearchParams(params).toString();
        const res = await fetch('/api/diagnose?' + qs);
        if (!res.ok) return;
        const data = await res.json();
        container.innerHTML = data.html;
        if (data.mode === 'uci' && data.url) {
            document.getElementById('uci-url-text').textContent = data.url;
            const pill = document.getElementById('uci-truth-pill');
            pill.textContent = 'Ground truth: ' + data.true_label.toLowerCase();
            pill.style.color = data.true_label === 'Phishing' ? '#e57373' : '#81c784';
            document.getElementById('uci-idx-input').value = String(data.idx);
            const ctr = document.getElementById('uci-record-counter');
            if (ctr) ctr.textContent = '#' + (data.idx + 1) + ' of 1,659';
        }
        if (data.mode === 'live') {
            const rst = document.getElementById('reset-overrides-btn');
            if (rst) rst.style.display = data.has_overrides ? 'inline-flex' : 'none';
        }
        const newScoreEl = document.getElementById('verdict-score-num');
        if (newScoreEl && prevScore !== null && !Number.isNaN(prevScore)) {
            newScoreEl.dataset.val = String(prevScore);
            tweenTextNumber(newScoreEl, data.risk_pct, 1, '%');
        }
    }

    function scanPreset(url) {
        window.__liveOverrides = {};
        document.getElementById('live-url-input').value = url;
        loadDiagnosis({ mode: 'live', url });
    }

    function submitLiveScan(ev) {
        ev.preventDefault();
        window.__liveOverrides = {};
        const url = document.getElementById('live-url-input').value.trim();
        if (url) loadDiagnosis({ mode: 'live', url });
    }

    function setFeatureOverride(idx, val) {
        window.__liveOverrides = window.__liveOverrides || {};
        window.__liveOverrides['f_' + idx] = val;
        const url = document.getElementById('live-url-input').value.trim();
        loadDiagnosis(Object.assign({ mode: 'live', url }, window.__liveOverrides));
    }

    function resetLiveOverrides() {
        window.__liveOverrides = {};
        const url = document.getElementById('live-url-input').value.trim();
        loadDiagnosis({ mode: 'live', url });
    }

    function pickRandomUci() {
        const total = window.__evalData ? window.__evalData.y_true.length : 1659;
        loadDiagnosis({ mode: 'uci', idx: Math.floor(Math.random() * total) });
    }

    function stepUci(delta) {
        const total = window.__evalData ? window.__evalData.y_true.length : 1659;
        const cur = parseInt(document.getElementById('uci-idx-input').value || '835', 10);
        const nxt = (cur + delta + total) % total;
        loadDiagnosis({ mode: 'uci', idx: nxt });
    }

    function toggleUciRows(showAll) {
        document.getElementById('uci-top-btn').classList.toggle('active', !showAll);
        document.getElementById('uci-all-btn').classList.toggle('active', showAll);
        document.querySelectorAll('.attr-extra-row').forEach(el => {
            el.classList.toggle('attr-extra-hidden', !showAll);
        });
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
        return { precision, recall, f1, tp, fp, tn, fn, fpr, total: yt.length };
    }

    function rocPointsAttr(fprArr, tprArr) {
        const x0 = 56, y0 = 256, w = 440, h = 236;
        return fprArr.map((fx, i) => (x0 + fx * w).toFixed(1) + ',' + (y0 - tprArr[i] * h).toFixed(1)).join(' ');
    }

    function drawEvalCharts() {
        if (!window.__evalData || !document.getElementById('threshold-slider')) return;
        const thresh = parseFloat(document.getElementById('threshold-slider').value);
        const s = computeThresholdStats(thresh);

        document.getElementById('thresh-readout').textContent = thresh.toFixed(2);
        document.getElementById('kpi-prec-lbl').textContent = 'Precision at ' + thresh.toFixed(2);
        document.getElementById('kpi-rec-lbl').textContent = 'Recall at ' + thresh.toFixed(2);
        document.getElementById('kpi-f1-lbl').textContent = 'F1 score at ' + thresh.toFixed(2);
        document.getElementById('kpi-prec-val').textContent = (s.precision * 100).toFixed(2) + '%';
        document.getElementById('kpi-rec-val').textContent = (s.recall * 100).toFixed(2) + '%';
        document.getElementById('kpi-f1-val').textContent = s.f1.toFixed(4);
        document.getElementById('kpi-fpfn-val').textContent = s.fp + ' / ' + s.fn;

        const cx = (56 + s.fpr * 440).toFixed(1);
        const cy = (256 - s.recall * 236).toFixed(1);
        const dot = document.getElementById('roc-active-dot');
        const gx = document.getElementById('roc-guide-x');
        const gy = document.getElementById('roc-guide-y');
        if (dot) { dot.setAttribute('cx', cx); dot.setAttribute('cy', cy); }
        if (gx) { gx.setAttribute('x1', cx); gx.setAttribute('x2', cx); gx.setAttribute('y1', cy); }
        if (gy) { gy.setAttribute('y1', cy); gy.setAttribute('y2', cy); gy.setAttribute('x2', cx); }
        const rocCoords = document.getElementById('roc-coords-label');
        if (rocCoords) rocCoords.textContent = 'FPR ' + (s.fpr * 100).toFixed(2) + '%  TPR ' + (s.recall * 100).toFixed(2) + '%';

        [['tn', s.tn], ['fp', s.fp], ['fn', s.fn], ['tp', s.tp]].forEach(([k, val]) => {
            const pct = (val * 100 / Math.max(1, s.total)).toFixed(1);
            document.getElementById('cm-' + k + '-cnt').textContent = String(val);
            document.getElementById('cm-' + k + '-pct').textContent = pct + '% of test set';
            document.getElementById('cm-' + k + '-bar').style.width = pct + '%';
        });
    }

    function filterCatalog() {
        const q = (document.getElementById('cat-search-input').value || '').toLowerCase().trim();
        const domain = document.getElementById('cat-domain-select').value;
        const mode = document.getElementById('cat-mode-select').value;
        let visible = 0, total = 0;
        document.querySelectorAll('.catalog-card').forEach(card => {
            total++;
            const okDomain = (domain === 'All domains') || (card.dataset.domain === domain);
            const okMode = (mode === 'All features') || (card.dataset.mode === mode);
            const okQuery = !q || (card.dataset.search || '').includes(q);
            const show = okDomain && okMode && okQuery;
            card.style.display = show ? 'flex' : 'none';
            if (show) visible++;
        });
        const badge = document.getElementById('cat-match-count');
        if (badge) badge.textContent = visible + ' of ' + total + ' features';
    }
"""


def _clean_copy(text):
    """Sanitizes copy strings to avoid ASCII hyphens and arrows in UI prose."""
    out = str(text)
    for old, new in COPY_REPLACEMENTS:
        out = out.replace(old, new)
    return out


def _fmt_delta(val, decimals=4):
    """Formats signed floating point delta using Unicode minus without ASCII hyphen."""
    sign = "+" if val >= 0 else "\u2212"
    return f"{sign}{abs(val):.{decimals}f}"


def _fmt_state_val(val):
    """Formats discrete state value (+1, 0, -1) using Unicode minus."""
    if val < 0:
        return "\u22121"
    if val > 0:
        return "+1"
    return "0"


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
    """Maps a Shapley log odds value to badge color, span class, and signed delta."""
    if shap_val > 0.01:
        return TONE_COLORS["critical"], "specimen-token-risk", _fmt_delta(shap_val, 3)
    if shap_val < -0.01:
        return TONE_COLORS["safe"], "specimen-token-safe", _fmt_delta(shap_val, 3)
    return "#9B9B9B", "specimen-token-neutral", "0.000"


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
            "group": _clean_copy(meta.get("group", "General")),
            "human_text": _clean_copy(meta.get(key, "Feature impacts phishing probability.")),
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
    """Applies optional integer overrides and returns vector plus changed flag."""
    base_vec = [int(feats_dict[f]) for f in LIVE_FEATURES]
    if not overrides:
        return base_vec, False
    vec = list(base_vec)
    for idx, val in overrides.items():
        if _valid_override(idx, val, len(vec)):
            vec[idx] = val
    return vec, vec != base_vec


def diagnose_live(raw_url, overrides=None):
    """Evaluates a URL or 8 feature sandbox vector from the precomputed live grid."""
    data = load_runtime_data()
    bundle = data["bundle"]
    clean_url = sanitize_url(raw_url or DEFAULT_LIVE_URL)
    extracted = extract_live_lexical_features(clean_url)
    vec, has_overrides = _apply_live_overrides(extracted, overrides)
    entry = bundle["live_grid"][",".join(map(str, vec))]
    attributions = _assemble_attributions(LIVE_FEATURES, vec, entry["shaps"], data["catalog"])
    return {
        "clean_url": clean_url,
        "has_overrides": has_overrides,
        "feature_values": dict(zip(LIVE_FEATURES, vec)),
        "prediction": "Phishing" if entry["prob"] >= 0.50 else "Legitimate",
        "phishing_probability": entry["prob"],
        "base_value": bundle["live_base_value"],
        "top_drivers": attributions,
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
        "top_drivers": attributions,
        "all_features": attributions,
        "group_breakdown": _aggregate_groups(attributions),
        "counterfactual_hints": rec["hints"],
        "consensus": _build_uci_consensus(rec),
    }


def _render_verdict_dossier_card(title, subtitle, risk_pct, result, sec_title, sec_val):
    """Renders left dossier verdict hero, integrated threshold ruler, and 2x2 hairline telemetry."""
    color = TONE_COLORS[risk_tone(risk_pct)]
    clamped = min(98.0, max(2.0, risk_pct))
    base_v = result["base_value"]
    net_m = sum(d["shap_value"] for d in result["all_features"]) + base_v
    return (
        f'<div class="panel workbench-fade">'
        f'<div class="verdict-eyebrow"><span class="verdict-dot" style="background-color: {color};"></span>Automated classification</div>'
        f'<div class="verdict-score-row">'
        f'<div id="verdict-score-num" class="verdict-score-value" data-val="{risk_pct:.1f}" style="color: {color};">{risk_pct:.1f}%</div>'
        f'<span class="status-pill" style="color: {color};">Threshold 50.0%</span></div>'
        f'<div class="verdict-title" style="color: {color};">{html.escape(title)}</div>'
        f'<div class="verdict-sub">{html.escape(subtitle)}</div>'
        f'<div class="ruler-wrap"><div class="ruler-track"><div class="ruler-zone-safe"></div><div class="ruler-zone-warn"></div><div class="ruler-zone-crit"></div></div>'
        f'<div class="ruler-threshold"></div><div class="ruler-needle" style="left: {clamped:.1f}%; background-color: {color};"></div></div>'
        f'<div class="ruler-legend"><span>0% Safe</span><span>50% Cutoff</span><span>100% Phish</span></div>'
        f'<div class="hairline-grid-2">'
        f'<div class="h-cell"><div class="cell-label">Safe probability</div><div class="cell-value" style="color: {TONE_COLORS["safe"]};">{100.0 - risk_pct:.1f}%</div></div>'
        f'<div class="h-cell"><div class="cell-label">{html.escape(sec_title)}</div><div class="cell-value">{html.escape(sec_val)}</div></div>'
        f'<div class="h-cell"><div class="cell-label">Base prior log odds</div><div class="cell-value">{_fmt_delta(base_v, 3)}</div></div>'
        f'<div class="h-cell"><div class="cell-label">Net log odds margin</div><div class="cell-value">{_fmt_delta(net_m, 3)}</div></div>'
        f'</div></div>'
    )


def _format_consensus_row_html(entry):
    """Formats one progress bar row in the multi model consensus card."""
    is_phish = entry["verdict"] == "Phishing"
    color = TONE_COLORS["critical"] if is_phish else TONE_COLORS["safe"]
    pct = min(100.0, max(0.0, float(entry["prob_pct"])))
    return (
        f'<div class="consensus-row"><div class="consensus-top">'
        f'<span class="consensus-name">{html.escape(entry["name"])}</span>'
        f'<span class="consensus-meta"><span style="color: {color};">'
        f'{html.escape(entry["verdict"])}</span> {pct:.1f}%</span></div>'
        f'<div class="bar-track"><div class="bar-fill" style="width: {pct:.1f}%; '
        f'background-color: {color};"></div></div></div>'
    )


def _consensus_header_meta(c_rows):
    """Computes consensus pill label and tone across evaluators."""
    phish_votes = sum(1 for r in c_rows if r["verdict"] == "Phishing")
    maj = max(phish_votes, len(c_rows) - phish_votes)
    maj_lbl = "phishing" if phish_votes >= len(c_rows) - phish_votes else "legitimate"
    color = TONE_COLORS["critical"] if maj_lbl == "phishing" else TONE_COLORS["safe"]
    return f"{maj} of {len(c_rows)} predict {maj_lbl}", color


def _render_consensus_card(result):
    """Renders three model consensus card inside the left sticky dossier."""
    c_rows = result["consensus"]
    sum_text, sum_color = _consensus_header_meta(c_rows)
    bars = "".join(map(_format_consensus_row_html, c_rows))
    return (
        f'<div class="panel workbench-fade"><div class="panel-head">'
        f'<span class="panel-title">Multi model consensus</span>'
        f'<span class="status-pill" style="color: {sum_color};">{sum_text}</span></div>'
        f'{bars}</div>'
    )


def _format_recourse_item(hint, current_risk_pct):
    """Formats one compact counterfactual diff card for the left dossier."""
    cur_lbl = "suspicious" if hint["current_value"] == 0 else "phishing"
    new_pct = round(hint["new_phishing_probability"] * 100.0, 1)
    new_color = TONE_COLORS["safe"] if new_pct < 50 else TONE_COLORS["warning"]
    return (
        f'<div class="recourse-item"><div class="recourse-head">'
        f'<span class="recourse-feat">{html.escape(hint["feature"])}</span>'
        f'<span class="status-pill" style="color: #81c784;">Down {hint["risk_reduction_pct"]:.1f}%</span></div>'
        f'<div class="recourse-meta">{cur_lbl} &#8594; legitimate norm ({current_risk_pct:.1f}% &#8594; {new_pct:.1f}%)</div>'
        f'<div class="recourse-bars">'
        f'<div class="recourse-track"><div class="recourse-fill" style="width: {min(100.0, max(0.0, current_risk_pct)):.1f}%; background-color: #e57373;"></div></div>'
        f'<div class="recourse-track"><div class="recourse-fill" style="width: {min(100.0, max(0.0, new_pct)):.1f}%; background-color: {new_color};"></div></div>'
        f'</div><div class="recourse-copy">{html.escape(_clean_copy(hint["guidance"]))}</div></div>'
    )


def _render_recourse_card(hints, current_risk_pct):
    """Renders counterfactual recourse diff list or clean baseline notice."""
    if not hints:
        body = (
            '<div class="recourse-item"><div style="font-size: 14px; font-weight: 600;">Clean baseline structure</div>'
            '<div class="recourse-copy" style="margin-top: 4px;">No single change lowers the score noticeably. Evaluated properties match legitimate norms.</div></div>'
        )
    else:
        body = f'<div class="recourse-list">{"".join(_format_recourse_item(h, current_risk_pct) for h in hints[:3])}</div>'
    return (
        f'<div class="panel workbench-fade"><div class="panel-head">'
        f'<span class="panel-title">Actionable recourse</span>'
        f'<span class="panel-meta">Minimal flip impact</span></div>{body}</div>'
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


def _render_anatomy_card(url, result):
    """Renders interactive URL specimen ribbon and five cell hairline token strip."""
    tokens = _parse_url_tokens(url)
    shaps = {item["feature"]: item["shap_value"] for item in result["all_features"]}
    cells = _resolve_rail_cells(tokens, shaps)
    spans = "".join(
        f'<span class="specimen-token {_token_tone_and_delta(s)[1]}">{html.escape(txt)}'
        f'<span class="specimen-delta">{_token_tone_and_delta(s)[2]}</span></span>'
        for txt, s in _specimen_segments(tokens, cells)
    )
    boxes = "".join(
        f'<div class="h-cell"><div class="cell-label">{html.escape(t)}</div>'
        f'<div class="rail-val">{html.escape(v)}</div>'
        f'<div class="rail-badge"><span style="color: #9B9B9B;">{html.escape(f)}</span>'
        f'<span style="color: {_token_tone_and_delta(s)[0]};">{_token_tone_and_delta(s)[2]}</span></div></div>'
        for t, v, f, s in cells
    )
    return (
        f'<div class="panel workbench-fade"><div class="panel-head">'
        f'<span class="panel-title">Segmented URL anatomy</span>'
        f'<span class="panel-meta">Signed TreeSHAP token attribution</span></div>'
        f'<div class="specimen-url-bar">{spans}</div>'
        f'<div class="hairline-grid-5">{boxes}</div></div>'
    )


STATE_TONE_COLOR_MAP = {-1: TONE_COLORS["critical"], 0: TONE_COLORS["warning"], 1: TONE_COLORS["safe"]}
STATE_ACTIVE_CLASS_MAP = {-1: "active-risk", 0: "active-warn", 1: "active-safe"}
TERNARY_LIVE_FEATURES = frozenset({"URL_Length", "having_Sub_Domain"})


def _state_pill_button(idx, opt, current_val):
    """Formats a single counterfactual state pill button for live mode."""
    active_cls = STATE_ACTIVE_CLASS_MAP.get(opt, "") if opt == current_val else ""
    return (
        f'<button type="button" class="state-pill {active_cls}" onclick="setFeatureOverride({idx}, {opt})">'
        f'{_fmt_state_val(opt)}</button>'
    )


def _format_state_control(mode, item):
    """Renders interactive state buttons in live mode or state badge in UCI mode."""
    feat = item["feature"]
    val = item["value"]
    if mode != "live":
        cls_color = STATE_TONE_COLOR_MAP.get(val, TONE_COLORS["safe"])
        return f'<span class="status-pill" style="color: {cls_color};">{STATE_LABELS[val]} ({_fmt_state_val(val)})</span>'

    idx = LIVE_FEATURES.index(feat)
    opts = (-1, 0, 1) if feat in TERNARY_LIVE_FEATURES else (-1, 1)
    btns = "".join(_state_pill_button(idx, opt, val) for opt in opts)
    return f'<div class="state-toggle-group" title="Click state to test sensitivity">{btns}</div>'


def _delta_color(shap_v):
    """Selects signed color for a Shapley delta readout."""
    if shap_v >= 0:
        return TONE_COLORS["critical"]
    return TONE_COLORS["safe"] if shap_v < -0.005 else "#9B9B9B"


def _butterfly_bar_html(shap_v, max_abs):
    """Builds left/right diverging butterfly bar element for a Shapley value."""
    width_pct = min(48.0, (abs(shap_v) / max_abs) * 48.0)
    fill_cls = "butterfly-fill-right" if shap_v >= 0 else "butterfly-fill-left"
    return f'<div class="{fill_cls}" style="width: {width_pct:.1f}%;"></div>'


def _format_attribution_row(mode, item, max_abs, row_idx):
    """Formats one unified diverging butterfly attribution row."""
    shap_v = item["shap_value"]
    bar_html = _butterfly_bar_html(shap_v, max_abs)
    delta_color = _delta_color(shap_v)
    extra_cls = " attr-extra-row attr-extra-hidden" if (mode == "uci" and row_idx >= 10) else ""
    return (
        f'<div class="attr-row{extra_cls}">'
        f'<div><div class="attr-feat-row"><span class="attr-name">{html.escape(item["feature"])}</span>'
        f'<span class="attr-domain">{html.escape(item["group"])}</span></div>'
        f'<div class="attr-copy">{html.escape(item["human_text"])}</div></div>'
        f'<div>{_format_state_control(mode, item)}</div>'
        f'<div class="butterfly-wrap"><div class="butterfly-track"><div class="butterfly-zero"></div>{bar_html}</div></div>'
        f'<div class="attr-delta" style="color: {delta_color};">{_fmt_delta(shap_v, 4)}</div></div>'
    )


def _render_domain_strip(group_breakdown):
    """Renders four cell hairline security domain net Shapley impact strip."""
    cells = "".join(
        f'<div class="h-cell"><div class="cell-label">{html.escape(g["group"])}</div>'
        f'<div class="cell-value" style="color: {TONE_COLORS["critical"] if g["net_shap"] > 0 else TONE_COLORS["safe"]};">'
        f'{_fmt_delta(g["net_shap"], 3)}</div></div>'
        for g in group_breakdown
    )
    return f'<div style="margin-top: 16px;"><div class="preset-caption" style="margin-bottom: 8px;">Security domain net log odds impact</div><div class="hairline-grid-4">{cells}</div></div>'


def _render_attribution_card(mode, result):
    """Renders log odds waterfall strip plus unified diverging Shapley attribution list."""
    drivers = result["all_features"]
    base_v = result["base_value"]
    risk_push = sum(d["shap_value"] for d in drivers if d["shap_value"] > 0)
    safe_pull = sum(d["shap_value"] for d in drivers if d["shap_value"] < 0)
    net_m = base_v + risk_push + safe_pull
    max_abs = max([abs(d["shap_value"]) for d in drivers] + [0.1])

    wf_strip = (
        f'<div class="hairline-grid-4" style="margin-bottom: 16px;">'
        f'<div class="h-cell"><div class="cell-label">Base expectation</div><div class="cell-value">{_fmt_delta(base_v, 3)}</div></div>'
        f'<div class="h-cell"><div class="cell-label">Risk drivers push</div><div class="cell-value" style="color: #e57373;">{_fmt_delta(risk_push, 3)}</div></div>'
        f'<div class="h-cell"><div class="cell-label">Safe signals pull</div><div class="cell-value" style="color: #81c784;">{_fmt_delta(safe_pull, 3)}</div></div>'
        f'<div class="h-cell"><div class="cell-label">Net log odds margin</div><div class="cell-value">{_fmt_delta(net_m, 3)}</div></div>'
        f'</div>'
    )
    toggle_html = (
        '<div class="mode-switch">'
        '<button id="uci-top-btn" type="button" class="mode-btn active" onclick="toggleUciRows(false)">Top 10 drivers</button>'
        '<button id="uci-all-btn" type="button" class="mode-btn" onclick="toggleUciRows(true)">All 30 features</button></div>'
        if mode == "uci"
        else '<span class="panel-meta">Click state pills (\u22121 / 0 / +1) to test counterfactual impact</span>'
    )
    rows_html = "".join(
        _format_attribution_row(mode, item, max_abs, idx)
        for idx, item in enumerate(drivers)
    )
    domain_footer = _render_domain_strip(result["group_breakdown"]) if mode == "uci" else ""
    return (
        f'<div class="panel workbench-fade"><div class="panel-head">'
        f'<span class="panel-title">TreeSHAP attribution and sensitivity</span>{toggle_html}</div>'
        f'{wf_strip}<div class="hairline-rows">{rows_html}</div>{domain_footer}</div>'
    )


def build_diagnose_payload(mode="uci", url=None, idx=DEFAULT_UCI_IDX, overrides=None):
    """Produces split pane dossier and X-ray attribution HTML for live URL or UCI mode."""
    t0 = time.perf_counter()
    data = load_runtime_data()
    if mode == "live":
        res = diagnose_live(url, overrides)
        ms = max(0.1, (time.perf_counter() - t0) * 1000.0)
        risk_pct = res["phishing_probability"] * 100.0
        dossier = (
            _render_verdict_dossier_card(
                VERDICT_TITLES[risk_tone(risk_pct)],
                "Evaluated across eight offline lexical properties with zero network exposure.",
                risk_pct, res, "Inference latency", f"{ms:.1f} ms",
            )
            + _render_consensus_card(res)
            + _render_recourse_card(res["counterfactual_hints"], risk_pct)
        )
        canvas = _render_anatomy_card(res["clean_url"], res) + _render_attribution_card("live", res)
        return {
            "mode": "live",
            "clean_url": res["clean_url"],
            "has_overrides": res["has_overrides"],
            "feature_values": res["feature_values"],
            "risk_pct": round(risk_pct, 1),
            "html": f'<div class="workbench-grid"><div class="dossier-sticky">{dossier}</div><div class="canvas-col">{canvas}</div></div>',
        }

    res = diagnose_uci(idx)
    risk_pct = res["phishing_probability"] * 100.0
    acc = data["metrics"]["models"]["xgboost_full_30"]["accuracy"] * 100.0
    agree = "The prediction matches." if res["prediction"] == res["true_label"] else "The prediction does not match."
    dossier = (
        _render_verdict_dossier_card(
            f"Model predicts {res['prediction'].lower()}",
            f"Ground truth is {res['true_label'].lower()}. {agree}",
            risk_pct, res, "Benchmark accuracy", f"{acc:.2f}%",
        )
        + _render_consensus_card(res)
        + _render_recourse_card(res["counterfactual_hints"], risk_pct)
    )
    canvas = _render_anatomy_card(res["url"], res) + _render_attribution_card("uci", res)
    return {
        "mode": "uci",
        "idx": res["idx"],
        "url": res["url"],
        "true_label": res["true_label"],
        "risk_pct": round(risk_pct, 1),
        "html": f'<div class="workbench-grid"><div class="dossier-sticky">{dossier}</div><div class="canvas-col">{canvas}</div></div>',
    }


def _format_uci_controls(uci_res, is_active):
    """Formats command omnibox UCI benchmark record stepper and banner."""
    display = "block" if is_active else "none"
    truth_color = "#e57373" if uci_res["true_label"] == "Phishing" else "#81c784"
    return (
        f'<div id="controls-uci" style="display: {display};"><div class="uci-controls-row">'
        f'<button type="button" class="btn btn-primary" onclick="pickRandomUci()">Pick random record</button>'
        f'<button type="button" class="btn" onclick="stepUci(-1)" title="Previous record">Prev</button>'
        f'<span id="uci-record-counter" class="record-counter">#{uci_res["idx"] + 1} of 1,659</span>'
        f'<button type="button" class="btn" onclick="stepUci(1)" title="Next record">Next</button>'
        f'<input id="uci-idx-input" type="hidden" value="{uci_res["idx"]}">'
        f'<div class="uci-url-box"><span id="uci-url-text" class="chosen-url-text">{html.escape(uci_res["url"])}</span>'
        f'<span id="uci-truth-pill" class="status-pill" style="color: {truth_color};">Ground truth: {uci_res["true_label"].lower()}</span>'
        f'</div></div></div>'
    )


def _format_live_controls(live_url, is_active, has_overrides):
    """Formats command omnibox URL scanner input, reset button, and preset pills."""
    display = "block" if is_active else "none"
    rst_display = "inline-flex" if has_overrides else "none"
    preset_btns = "".join(
        f'<button type="button" class="preset-pill" onclick="scanPreset({json.dumps(u)})">{html.escape(lbl)}</button>'
        for lbl, u in URL_PRESETS
    )
    return (
        f'<div id="controls-live" style="display: {display};">'
        f'<form class="scan-form" onsubmit="submitLiveScan(event)">'
        f'<input id="live-url-input" type="text" class="text-input" value="{html.escape(live_url)}" placeholder="Enter website address to inspect (e.g. https://...)">'
        f'<button type="submit" class="btn btn-primary">Scan URL</button>'
        f'<button id="reset-overrides-btn" type="button" class="btn" style="display: {rst_display};" onclick="resetLiveOverrides()">Reset overrides</button></form>'
        f'<div class="preset-strip"><span class="preset-caption">Presets</span>{preset_btns}</div></div>'
    )


def _render_inspect_tab(mode, live_url, uci_res, live_res, active_payload):
    """Renders Tab 1 command omnibox bar above the split pane forensic workbench."""
    uci_cls = "active" if mode == "uci" else ""
    live_cls = "active" if mode == "live" else ""
    omnibox = (
        f'<div class="omnibox"><div class="omnibox-top">'
        f'<div class="mode-switch">'
        f'<button id="mode-btn-uci" type="button" class="mode-btn {uci_cls}" onclick="setInspectMode(\'uci\')">UCI benchmark</button>'
        f'<button id="mode-btn-live" type="button" class="mode-btn {live_cls}" onclick="setInspectMode(\'live\')">Live URL scanner</button></div>'
        f'<div class="omnibox-controls">'
        f'{_format_uci_controls(uci_res, mode == "uci")}'
        f'{_format_live_controls(live_url, mode == "live", live_res["has_overrides"])}'
        f'</div></div></div>'
    )
    return f'{omnibox}<div id="inspect-results">{active_payload["html"]}</div>'


def _svg_polyline(fpr_list, tpr_list):
    """Converts FPR/TPR lists into SVG polyline coordinate string."""
    return " ".join(f"{56 + fx * 440:.1f},{256 - ty * 236:.1f}" for fx, ty in zip(fpr_list, tpr_list))


def _render_roc_svg(scores):
    """Builds standalone vector SVG ROC curve without external plotting libraries."""
    grid_lines = "".join(
        f'<line x1="56" y1="{256 - v * 236:.1f}" x2="496" y2="{256 - v * 236:.1f}" stroke="#272727" stroke-width="1"/>'
        f'<line x1="{56 + v * 440:.1f}" y1="20" x2="{56 + v * 440:.1f}" y2="256" stroke="#272727" stroke-width="1"/>'
        f'<text x="48" y="{260 - v * 236:.1f}" fill="#9B9B9B" font-family="Geist Mono" font-size="11" text-anchor="end">{v:.2f}</text>'
        f'<text x="{56 + v * 440:.1f}" y="274" fill="#9B9B9B" font-family="Geist Mono" font-size="11" text-anchor="middle">{v:.2f}</text>'
        for v in (0.0, 0.25, 0.50, 0.75, 1.0)
    )
    p_xgb30 = _svg_polyline(scores["xgboost_full_30"]["curve_samples"]["fpr"], scores["xgboost_full_30"]["curve_samples"]["tpr"])
    p_rf30 = _svg_polyline(scores["random_forest_full_30"]["curve_samples"]["fpr"], scores["random_forest_full_30"]["curve_samples"]["tpr"])
    p_xgb8 = _svg_polyline(scores["xgboost_live_lexical_8"]["curve_samples"]["fpr"], scores["xgboost_live_lexical_8"]["curve_samples"]["tpr"])
    return (
        f'<svg class="svg-box" viewBox="0 0 520 296" xmlns="http://www.w3.org/2000/svg">'
        f'<rect x="56" y="20" width="440" height="236" fill="#000000" stroke="#272727"/>'
        f'{grid_lines}'
        f'<line x1="56" y1="256" x2="496" y2="20" stroke="#313131" stroke-dasharray="4 4" stroke-width="1"/>'
        f'<polyline fill="none" stroke="#616161" stroke-width="1.5" stroke-dasharray="4 4" points="{p_xgb8}"/>'
        f'<polyline fill="none" stroke="#9B9B9B" stroke-width="1.5" points="{p_rf30}"/>'
        f'<polyline fill="none" stroke="#FFFFFF" stroke-width="2" points="{p_xgb30}"/>'
        f'<line id="roc-guide-x" x1="72" y1="30" x2="72" y2="256" stroke="#616161" stroke-dasharray="3 3" stroke-width="1"/>'
        f'<line id="roc-guide-y" x1="56" y1="30" x2="72" y2="30" stroke="#616161" stroke-dasharray="3 3" stroke-width="1"/>'
        f'<circle id="roc-active-dot" cx="72" cy="30" r="5" fill="#e57373" stroke="#FFFFFF" stroke-width="1.5"/>'
        f'<text x="276" y="292" fill="#9B9B9B" font-family="Geist" font-size="11" text-anchor="middle">False positive rate</text>'
        f'</svg>'
    )


def _render_cm_matrix():
    """Renders 2x2 HTML/CSS hairline Confusion Matrix quadrants updated live in JS."""
    cells = (
        ("tn", "True negative", "Actual legitimate / Predicted legitimate", "#81c784"),
        ("fp", "False positive", "Actual legitimate / Predicted phishing", "#e57373"),
        ("fn", "False negative", "Actual phishing / Predicted legitimate", "#e57373"),
        ("tp", "True positive", "Actual phishing / Predicted phishing", "#81c784"),
    )
    items = "".join(
        f'<div class="cm-cell"><div><div class="cell-label" style="color: {color};">{lbl}</div>'
        f'<div style="font-size: 12px; color: #9B9B9B; margin-top: 2px;">{sub}</div></div>'
        f'<div id="cm-{key}-cnt" class="cm-count">0</div>'
        f'<div><div id="cm-{key}-pct" class="panel-meta">0.0% of test set</div>'
        f'<div class="bar-track" style="margin-top: 4px;"><div id="cm-{key}-bar" class="bar-fill" style="width: 0%; background-color: {color};"></div></div></div></div>'
        for key, lbl, sub, color in cells
    )
    return f'<div class="cm-grid">{items}</div>'


def _render_global_shap_panel(global_shap):
    """Renders native CSS twelve row Global TreeSHAP importance bar list."""
    top_val = max([d["mean_shap"] for d in global_shap] + [0.1])
    rows = "".join(
        f'<div class="global-row"><span class="attr-name" style="font-size: 12px;">{html.escape(d["feature"])}</span>'
        f'<div class="bar-track" style="height: 8px;"><div class="bar-fill" style="width: {(d["mean_shap"] / top_val) * 100:.1f}%; '
        f'background-color: {"#FFFFFF" if d["is_live"] else "#616161"};"></div></div>'
        f'<span class="attr-delta" style="color: #FFFFFF;">{d["mean_shap"]:.3f}</span></div>'
        for d in global_shap
    )
    return (
        f'<div class="panel"><div class="panel-head"><span class="panel-title">Global TreeSHAP feature importance</span>'
        f'<span class="panel-meta">White: live lexical / Grey: offline</span></div>'
        f'<div class="hairline-rows">{rows}</div></div>'
    )


def _render_eval_table(scores):
    """Renders four model comparative hairline grid table."""
    specs = (
        ("XGBoost", "30 (Full)", "xgboost_full_30"),
        ("Random Forest", "30 (Full)", "random_forest_full_30"),
        ("Logistic Regression", "30 (Full)", "logistic_regression_full_30"),
        ("XGBoost live subset", "8 (URL only)", "xgboost_live_lexical_8"),
    )
    hdrs = ("Model architecture", "Features", "Accuracy", "Precision", "Recall", "F1 score", "ROC AUC", "MCC")
    head_row = "".join(f'<div class="table-cell-head" style="text-align: {"right" if i >= 2 else "left"};">{h}</div>' for i, h in enumerate(hdrs))
    body_rows = "".join(
        f'<div class="table-cell">{name}</div><div class="table-cell mono" style="color: #9B9B9B;">{feat_lbl}</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["accuracy"]*100:.2f}%</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["precision"]*100:.2f}%</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["recall"]*100:.2f}%</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["f1"]:.4f}</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["roc_auc"]:.4f}</div>'
        f'<div class="table-cell mono" style="text-align: right;">{scores[k]["mcc"]:.4f}</div>'
        for name, feat_lbl, k in specs
    )
    return (
        '<div class="panel" style="margin-bottom: 16px;"><div class="panel-head">'
        '<span class="panel-title">Comparative model evaluation</span>'
        '<span class="panel-meta">Held out partition (1,659 records)</span></div>'
        f'<div class="hairline-rows table-row-8" style="overflow-x: auto;">{head_row}{body_rows}</div></div>'
    )


def _render_eval_tab(data):
    """Renders Tab 2 benchmark KPI strip, SVG threshold explorer, confusion matrix, and global SHAP."""
    scores = data["metrics"]["models"]
    top_kpis = (
        f'<div class="hairline-grid-4" style="margin-bottom: 16px;">'
        f'<div class="h-cell-surface"><div class="cell-label">XGBoost 30 accuracy</div><div class="cell-value">{scores["xgboost_full_30"]["accuracy"]*100:.2f}%</div></div>'
        f'<div class="h-cell-surface"><div class="cell-label">XGBoost 30 recall</div><div class="cell-value">{scores["xgboost_full_30"]["recall"]*100:.2f}%</div></div>'
        f'<div class="h-cell-surface"><div class="cell-label">XGBoost 30 ROC AUC</div><div class="cell-value">{scores["xgboost_full_30"]["roc_auc"]:.4f}</div></div>'
        f'<div class="h-cell-surface"><div class="cell-label">Live 8 lexical accuracy</div><div class="cell-value">{scores["xgboost_live_lexical_8"]["accuracy"]*100:.2f}%</div></div>'
        f'</div>'
    )
    thresh_card = (
        '<div class="panel" style="margin-bottom: 16px;"><div class="panel-head">'
        '<span class="panel-title">Interactive decision threshold simulator</span>'
        '<span id="thresh-readout" class="status-pill" style="color: #FFFFFF;">0.50</span></div>'
        '<div class="slider-row"><input id="threshold-slider" class="range-input" type="range" min="0.05" max="0.95" step="0.05" value="0.50" oninput="drawEvalCharts()"></div>'
        '<div class="hairline-grid-4">'
        '<div class="h-cell"><div id="kpi-prec-lbl" class="cell-label">Precision at 0.50</div><div id="kpi-prec-val" class="cell-value">0.00%</div></div>'
        '<div class="h-cell"><div id="kpi-rec-lbl" class="cell-label">Recall at 0.50</div><div id="kpi-rec-val" class="cell-value">0.00%</div></div>'
        '<div class="h-cell"><div id="kpi-f1-lbl" class="cell-label">F1 score at 0.50</div><div id="kpi-f1-val" class="cell-value">0.0000</div></div>'
        '<div class="h-cell"><div class="cell-label">False positives / Missed</div><div id="kpi-fpfn-val" class="cell-value">0 / 0</div></div>'
        '</div></div>'
    )
    svg_panel = (
        f'<div class="panel"><div class="panel-head"><span class="panel-title">Receiver operating characteristic</span>'
        f'<span id="roc-coords-label" class="panel-meta">FPR 0.00%  TPR 0.00%</span></div>{_render_roc_svg(scores)}'
        f'<div class="preset-strip"><span class="panel-meta" style="color: #FFFFFF;">White: XGBoost 30</span>'
        f'<span class="panel-meta">Grey: Random Forest</span><span class="panel-meta">Dashed: XGBoost 8</span></div></div>'
    )
    cm_panel = f'<div class="panel"><div class="panel-head"><span class="panel-title">Confusion matrix</span><span class="panel-meta">Live threshold counts</span></div>{_render_cm_matrix()}</div>'
    return (
        top_kpis + _render_eval_table(scores) + thresh_card
        + f'<div class="eval-split">{svg_panel}{cm_panel}</div>'
        + _render_global_shap_panel(data["bundle"]["test_eval"]["global_shap"])
    )


def _format_catalog_card(name, meta, prevalence):
    """Formats one feature catalog bento card."""
    is_live = meta.get("extractable_live", False)
    mode_tag = "Live lexical only" if is_live else "Offline network and DOM"
    badge_text = "Live lexical" if is_live else ("Legacy API" if meta.get("deprecated", False) else "Offline record")
    badge_color = "#81c784" if is_live else "#9B9B9B"
    p_phish, p_susp, p_legit = prevalence
    group_clean = _clean_copy(meta.get("group", ""))
    desc_clean = _clean_copy(meta.get("description", ""))
    rule_clean = _clean_copy(meta.get("rule", ""))
    search_blob = f"{name} {group_clean} {desc_clean} {rule_clean}".lower()
    return (
        f'<div class="catalog-card" data-domain="{html.escape(group_clean)}" data-mode="{mode_tag}" data-search="{html.escape(search_blob)}">'
        f'<div><div class="catalog-head"><span class="catalog-name">{html.escape(name)}</span>'
        f'<span class="status-pill" style="color: {badge_color};">{badge_text}</span></div>'
        f'<div class="cell-label" style="margin-top: 4px;">{html.escape(group_clean)}</div></div>'
        f'<div style="font-size: 14px; line-height: 20px;">{html.escape(desc_clean)}</div>'
        f'<div class="catalog-rule">{html.escape(rule_clean)}</div>'
        f'<div><div class="prev-head"><span>Test partition prevalence</span>'
        f'<span>{p_phish:.0f}% / {p_susp:.0f}% / {p_legit:.0f}%</span></div>'
        f'<div class="prev-track"><div style="width: {p_phish:.1f}%; background-color: #e57373;"></div>'
        f'<div style="width: {p_susp:.1f}%; background-color: #ffb74d;"></div>'
        f'<div style="width: {p_legit:.1f}%; background-color: #81c784;"></div></div>'
        f'<div class="prev-legend"><span style="color: #e57373;">Phish</span>'
        f'<span style="color: #ffb74d;">Suspicious</span><span style="color: #81c784;">Normal</span></div></div></div>'
    )


def _render_catalog_tab(data):
    """Renders Tab 3 live text search, domain filter, extraction filter, and bento grid."""
    catalog = data["catalog"]
    prev_map = data["bundle"]["prevalence"]
    domain_opts = "".join(
        f'<option value="{html.escape(_clean_copy(g))}">{html.escape(_clean_copy(g))}</option>'
        for g in ["All domains"] + list(catalog["feature_groups"].keys())
    )
    mode_opts = "".join(
        f'<option value="{m}">{m}</option>'
        for m in ("All features", "Live lexical only", "Offline network and DOM")
    )
    toolbar = (
        '<div class="panel" style="margin-bottom: 16px;"><div class="panel-head">'
        '<span class="panel-title">Feature taxonomy of thirty phishing signals</span>'
        f'<span id="cat-match-count" class="status-pill" style="color: #FFFFFF;">{len(catalog["features"])} of {len(catalog["features"])} features</span></div>'
        '<div class="catalog-filters">'
        '<input id="cat-search-input" type="text" class="text-input" placeholder="Search feature name, domain, or rule" oninput="filterCatalog()">'
        f'<select id="cat-domain-select" class="select-input" onchange="filterCatalog()">{domain_opts}</select>'
        f'<select id="cat-mode-select" class="select-input" onchange="filterCatalog()">{mode_opts}</select></div></div>'
    )
    cards = "".join(
        _format_catalog_card(name, meta, prev_map.get(name, [0.0, 0.0, 100.0]))
        for name, meta in catalog["features"].items()
    )
    return f'{toolbar}<div class="catalog-grid">{cards}</div>'


def _build_eval_bootstrap(data):
    """Builds JSON bootstrap arrays for client side threshold and confusion matrix updates."""
    return {
        "y_true": data["bundle"]["test_eval"]["y_true"],
        "y_probs": data["bundle"]["test_eval"]["y_probs"],
    }


def _active_cls(current, target):
    """Returns active CSS class token when current matches target."""
    return "active" if current == target else ""


def _render_topbar(active_tab):
    """Renders persistent Vercel monochrome navigation header and segmented tabs."""
    tab_defs = (("inspect", "URL inspection"), ("eval", "Model evaluation"), ("catalog", "Feature catalog"))
    tab_btns = "".join(
        f'<button type="button" data-tab="{tid}" class="tab-btn {_active_cls(active_tab, tid)}" '
        f'onclick="switchTab(\'{tid}\')">{lbl}</button>'
        for tid, lbl in tab_defs
    )
    triangle_svg = (
        '<svg width="16" height="14" viewBox="0 0 16 14" fill="none" aria-hidden="true">'
        '<path d="M8 0L16 14H0L8 0Z" fill="#FFFFFF"/></svg>'
    )
    return (
        f'<header class="topbar"><div class="brand-group">{triangle_svg}'
        f'<span class="brand-name">PhishLens</span><span class="brand-sep">/</span>'
        f'<span class="brand-sub">Threat intelligence</span></div>'
        f'<nav class="tab-bar">{tab_btns}</nav>'
        f'<div class="status-chip"><span class="status-dot"></span><span>TreeSHAP ready</span></div></header>'
    )


def render_full_page_html(mode="uci", url=None, idx=DEFAULT_UCI_IDX, tab="inspect", overrides=None):
    """Renders the complete standalone Vercel black and white PhishLens HTML document."""
    data = load_runtime_data()
    live_url = url or DEFAULT_LIVE_URL
    uci_payload = build_diagnose_payload("uci", idx=idx)
    live_payload = build_diagnose_payload("live", url=live_url, overrides=overrides)
    active_diag = live_payload if mode == "live" else uci_payload
    inspect_html = _render_inspect_tab(mode, live_url, uci_payload, live_payload, active_diag)
    boot_script = f'window.__evalData = {json.dumps(_build_eval_bootstrap(data))}; drawEvalCharts();'
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<title>PhishLens | Threat Intelligence</title>'
        '<link rel="preconnect" href="https://fonts.googleapis.com">'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500;600;700&display=swap">'
        f'<style>{PAGE_CSS}</style></head><body><div class="container">'
        f'{_render_topbar(tab)}'
        '<div class="hero-band"><div class="hero-box"><div class="hero-heading">Evaluate website security with transparent reasoning</div>'
        '<div class="hero-sub">Exact game theoretic feature attributions, population calibration, and actionable counterfactual recourse.</div></div></div>'
        f'<div id="panel-inspect" class="tab-panel {_active_cls(tab, "inspect")}">{inspect_html}</div>'
        f'<div id="panel-eval" class="tab-panel {_active_cls(tab, "eval")}">{_render_eval_tab(data)}</div>'
        f'<div id="panel-catalog" class="tab-panel {_active_cls(tab, "catalog")}">{_render_catalog_tab(data)}</div>'
        '<div class="footer-note">PhishLens research system &#8226; Built for explainable threat intelligence</div>'
        f'</div><script>{CONSOLE_JS}\n{boot_script}</script></body></html>'
    )
