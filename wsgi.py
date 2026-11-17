"""
Vercel Python (Flask WSGI) entrypoint for the PhishLens Telemetry Console.
"""

from flask import Flask, Response, jsonify, request

from src.console_ui import (
    DEFAULT_UCI_IDX,
    build_diagnose_payload,
    render_full_page_html,
)

app = Flask(__name__)


def _parse_int(raw_val, default_val):
    """Safely parses an integer query parameter with a default fallback."""
    if raw_val is None or raw_val == "":
        return default_val
    try:
        return int(raw_val)
    except (TypeError, ValueError):
        return default_val


def _parse_overrides(args):
    """Collects optional f_0..f_7 integer sandbox feature overrides."""
    overrides = {}
    for idx in range(8):
        parsed = _parse_int(args.get(f"f_{idx}"), None)
        if parsed in (-1, 0, 1):
            overrides[idx] = parsed
    return overrides or None


def _resolve_request_params(args):
    """Extracts validated mode, url, idx, tab, and overrides from query args."""
    mode = "uci" if args.get("mode") == "uci" else "live"
    tab = args.get("tab") if args.get("tab") in ("inspect", "eval", "catalog") else "inspect"
    url = args.get("url")
    idx = _parse_int(args.get("idx"), DEFAULT_UCI_IDX)
    return mode, url, idx, tab, _parse_overrides(args)


@app.route("/")
def index():
    """Renders the full PhishLens Telemetry Console page."""
    mode, url, idx, tab, overrides = _resolve_request_params(request.args)
    page_html = render_full_page_html(
        mode=mode,
        url=url,
        idx=idx,
        tab=tab,
        overrides=overrides,
    )
    return Response(page_html, status=200, mimetype="text/html")


@app.route("/api/diagnose")
def api_diagnose():
    """Returns precomputed TreeSHAP HTML fragment and waterfall arrays as JSON."""
    mode, url, idx, _, overrides = _resolve_request_params(request.args)
    payload = build_diagnose_payload(mode=mode, url=url, idx=idx, overrides=overrides)
    return jsonify(payload)


@app.route("/api/health")
def api_health():
    """Health check endpoint for Vercel deployment verification."""
    return jsonify({"status": "ok", "service": "phishlens"})
