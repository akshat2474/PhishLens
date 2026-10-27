"""
Safe URL Lexical Feature Extractor for PhishLens.
Extracts the 8 live-safe lexical attributes directly from the URL string
strictly following the Mohammad, Thabtah, & McCluskey rule definitions.
Executes completely offline in < 1ms with zero network scanning or payload fetching.
"""

import ipaddress
import re
import urllib.parse

# Canonical feature ordering expected by the live XGBoost model
LIVE_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
]

# Standard URL shortening domains
SHORTENING_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "rebrand.ly", "t.co", "is.gd",
    "ow.ly", "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr",
    "tiny.cc", "lnkd.in", "cutt.ly", "shorturl.at", "t2mio.com"
}


def sanitize_url(raw_url: str) -> str:
    """Ensures URL has a protocol scheme for reliable parsing."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    return url


def extract_ip_address_feature(hostname: str) -> int:
    """Rule: If domain part has an IP address -> Phishing (-1), otherwise Legitimate (1)."""
    if not hostname:
        return 1

    clean_host = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return -1
    except ValueError:
        pass

    # Check for hex-encoded IP addresses (e.g., 0x7b.0xac.0x12.0x34)
    if re.match(r"^0x[0-9a-fA-F]+\.", clean_host):
        return -1

    return 1


def extract_url_length_feature(url: str) -> int:
    """Rule: < 54 chars -> Legitimate (1), 54-75 -> Suspicious (0), > 75 -> Phishing (-1)."""
    length = len(url)
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def extract_shortening_service_feature(hostname: str) -> int:
    """Rule: Uses known shortening service -> Phishing (-1), otherwise Legitimate (1)."""
    if not hostname:
        return 1
    host = hostname.lower()
    for shortener in SHORTENING_DOMAINS:
        if host == shortener or host.endswith("." + shortener):
            return -1
    return 1


def extract_at_symbol_feature(url: str) -> int:
    """Rule: URL contains '@' symbol -> Phishing (-1), otherwise Legitimate (1)."""
    return -1 if "@" in url else 1


def extract_double_slash_feature(url: str) -> int:
    """Rule: Last occurrence of '//' > position 7 -> Phishing (-1), otherwise Legitimate (1)."""
    last_slash_pos = url.rfind("//")
    return -1 if last_slash_pos > 7 else 1


def extract_prefix_suffix_feature(hostname: str) -> int:
    """Rule: Domain part contains '-' -> Phishing (-1), otherwise Legitimate (1)."""
    if not hostname:
        return 1
    return -1 if "-" in hostname else 1


def extract_subdomain_feature(hostname: str) -> int:
    """
    Rule: After omitting 'www.' and common ccTLDs:
    1 dot remaining -> Legitimate (1) (e.g. example.com)
    2 dots remaining -> Suspicious (0) (e.g. pay.example.com)
    > 2 dots remaining -> Phishing (-1) (e.g. login.secure.pay.example.com)
    """
    if not hostname:
        return 1
    host = hostname.lower()
    if host.startswith("www."):
        host = host[4:]

    # Remove standard two-part ccTLDs like .co.uk, .gov.in, .edu.au if present
    cctld_pattern = r"\.(co|ac|gov|edu|org|net|mil|com)\.[a-z]{2}$"
    host = re.sub(cctld_pattern, ".tld", host)

    dots = host.count(".")
    if dots <= 1:
        return 1
    if dots == 2:
        return 0
    return -1


def extract_https_token_feature(hostname: str) -> int:
    """Rule: 'https' token inside domain part (e.g. 'https-paypal.com') -> Phishing (-1), otherwise Legitimate (1)."""
    if not hostname:
        return 1
    return -1 if "https" in hostname.lower() else 1


def extract_live_lexical_features(raw_url: str) -> dict:
    """
    Extracts all 8 lexical features from raw URL input.
    Returns dictionary of {feature_name: value} in {-1, 0, 1}.
    """
    url = sanitize_url(raw_url)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or parsed.netloc.split(":")[0]

    return {
        "having_IP_Address": extract_ip_address_feature(hostname),
        "URL_Length": extract_url_length_feature(url),
        "Shortining_Service": extract_shortening_service_feature(hostname),
        "having_At_Symbol": extract_at_symbol_feature(url),
        "double_slash_redirecting": extract_double_slash_feature(url),
        "Prefix_Suffix": extract_prefix_suffix_feature(hostname),
        "having_Sub_Domain": extract_subdomain_feature(hostname),
        "HTTPS_token": extract_https_token_feature(hostname),
    }


def extract_live_feature_vector(raw_url: str) -> list:
    """
    Extracts ordered list of features matching LIVE_FEATURES for direct model input.
    """
    feat_dict = extract_live_lexical_features(raw_url)
    return [feat_dict[f] for f in LIVE_FEATURES]
