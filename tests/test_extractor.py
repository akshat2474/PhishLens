"""
Unit tests for safe URL lexical feature extractor.
Tests all 8 features against edge cases and documented examples from the dataset rules.
"""

from src.feature_extractor import (
    extract_live_lexical_features,
    extract_live_feature_vector,
    LIVE_FEATURES,
)


def test_clean_legitimate_url():
    """A standard clean domain like google.com should score legitimate across all features."""
    url = "https://www.google.com"
    feats = extract_live_lexical_features(url)

    assert feats["having_IP_Address"] == 1
    assert feats["URL_Length"] == 1  # 22 chars < 54
    assert feats["Shortining_Service"] == 1
    assert feats["having_At_Symbol"] == 1
    assert feats["double_slash_redirecting"] == 1
    assert feats["Prefix_Suffix"] == 1
    assert feats["having_Sub_Domain"] == 1
    assert feats["HTTPS_token"] == 1


def test_ip_address_detection():
    """URLs using raw IP address should be flagged as phishing (-1)."""
    url = "http://192.168.1.1/login.php"
    feats = extract_live_lexical_features(url)
    assert feats["having_IP_Address"] == -1

    ipv6_url = "http://[2001:db8::1]/path"
    feats_v6 = extract_live_lexical_features(ipv6_url)
    assert feats_v6["having_IP_Address"] == -1


def test_url_length_thresholds():
    """Test short (<54), medium (54-75), and long (>75) URL lengths."""
    short_url = "https://example.com"
    medium_url = "https://example.com/" + "a" * 40  # len = 60
    long_url = "https://example.com/" + "a" * 70    # len = 90

    assert extract_live_lexical_features(short_url)["URL_Length"] == 1
    assert extract_live_lexical_features(medium_url)["URL_Length"] == 0
    assert extract_live_lexical_features(long_url)["URL_Length"] == -1


def test_shortening_service_detection():
    """Known shorteners like bit.ly or tinyurl.com should trigger -1."""
    short_url = "http://bit.ly/3xYz123"
    feats = extract_live_lexical_features(short_url)
    assert feats["Shortining_Service"] == -1


def test_at_symbol_detection():
    """URLs with '@' symbol should trigger -1."""
    url = "http://legit.com@phishing.site.ru"
    feats = extract_live_lexical_features(url)
    assert feats["having_At_Symbol"] == -1


def test_double_slash_redirect_detection():
    """Double slashes occurring after position 7 should trigger -1."""
    redirect_url = "http://legit.com//http://fake.com"
    feats = extract_live_lexical_features(redirect_url)
    assert feats["double_slash_redirecting"] == -1


def test_prefix_suffix_detection():
    """Domain with hyphen ('-') should trigger -1."""
    spoofed_url = "https://secure-paypal-login.com"
    feats = extract_live_lexical_features(spoofed_url)
    assert feats["Prefix_Suffix"] == -1


def test_deep_subdomain_detection():
    """
    Dots in host after omitting 'www.':
    1 dot (example.com) -> 1 (Legitimate)
    2 dots (pay.example.com) -> 0 (Suspicious)
    > 2 dots (secure.pay.example.com) -> -1 (Phishing)
    """
    sub_1 = "https://example.com"
    sub_2 = "https://pay.example.com"
    sub_3 = "https://secure.pay.example.com"

    assert extract_live_lexical_features(sub_1)["having_Sub_Domain"] == 1
    assert extract_live_lexical_features(sub_2)["having_Sub_Domain"] == 0
    assert extract_live_lexical_features(sub_3)["having_Sub_Domain"] == -1


def test_https_token_in_domain():
    """Domain embedding 'https' as a string token should trigger -1."""
    spoofed = "http://https-secure-bank.com"
    feats = extract_live_lexical_features(spoofed)
    assert feats["HTTPS_token"] == -1


def test_feature_vector_ordering():
    """Vector output must match LIVE_FEATURES length and ordering."""
    vec = extract_live_feature_vector("https://paypal-update.com/login")
    assert len(vec) == len(LIVE_FEATURES)
    assert all(v in [-1, 0, 1] for v in vec)


def test_walkthrough_geometry_points_at_real_characters():
    """Each of the 8 checks must highlight a real span of the address, and dashes must be found exactly."""
    from src.demo_stage import part_marks, part_ranges

    url = "http://https-paypal-account-update.com/auth"
    ranges = part_ranges(url)
    assert len(ranges) == 8
    assert all(0 <= s <= e <= len(url) for s, e in ranges)
    assert url[ranges[0][0]:ranges[0][1]] == "https-paypal-account-update.com"
    assert url[ranges[4][0]:ranges[4][1]] == "://"
    dashes = part_marks(url, ranges)[5]
    assert len(dashes) == 3
    assert all(url[s:e] == "-" for s, e in dashes)


def test_walkthrough_geometry_handles_userinfo_port_and_redirects():
    """User info, ports, at symbols, and embedded double slashes must land on the right characters."""
    from src.demo_stage import part_ranges

    url = "http://legit.com@evil.example.org:8080/a//http://x.io"
    ranges = part_ranges(url)
    assert url[ranges[0][0]:ranges[0][1]] == "evil.example.org"
    assert url[ranges[3][0]:ranges[3][1]] == "@"
    assert url[ranges[4][0]:ranges[4][1]] == "//"
    assert ranges[4][0] > 7


def test_lattice_and_walkthrough_stage_render():
    """The 576 state table must ship to the client and the stage must render 8 cards with its data."""
    from src.console_ui import build_diagnose_payload, render_full_page_html
    from src.vercel_console import build_client_lattice

    lattice = build_client_lattice()
    assert len(lattice["states"]) == 576

    payload = build_diagnose_payload("live", url="http://https-paypal-account-update.com/auth")
    page = payload["html"]
    assert 'id="demo-stage"' in page
    assert all(f'id="dcard-{i}"' in page for i in range(8))
    assert "data-demo=" in page
    assert 'id="fixes-section"' in page

    full_html = render_full_page_html(mode="live")
    assert "window.__liveLattice" in full_html
    assert "Demo.init()" in full_html
