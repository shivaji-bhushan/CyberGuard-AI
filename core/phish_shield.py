"""
CyberGuard AI — PhishShield Engine
Analyzes URLs, domains, and text messages for phishing, typosquatting,
brand impersonation, and social engineering urgency lures.
"""

import math
import re
from urllib.parse import urlparse

RISKY_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "icu",
    "monster", "cc", "work", "loan", "click", "rest", "surf", "date", "racing"
}

POPULAR_BRANDS = [
    ("paytm", "Paytm Digital Wallet / Bank"),
    ("sbi", "State Bank of India"),
    ("hdfc", "HDFC Bank"),
    ("icici", "ICICI Bank"),
    ("axis", "Axis Bank"),
    ("google", "Google Services"),
    ("microsoft", "Microsoft / Office365"),
    ("apple", "Apple iCloud / ID"),
    ("amazon", "Amazon Shopping / AWS"),
    ("netflix", "Netflix Streaming"),
    ("paypal", "PayPal Payments"),
    ("whatsapp", "WhatsApp Messenger"),
    ("phonepe", "PhonePe Payments"),
    ("gpay", "Google Pay"),
    ("uidai", "UIDAI Aadhaar Portal"),
    ("incometax", "Income Tax e-Filing")
]

URGENT_PHRASES = [
    (r"(electricity|power)\s+(disconnected|cut off|bill pending)", 30, "Electricity Disconnection Scam"),
    (r"(kyc|pan card|aadhaar)\s+(suspended|blocked|update|expired)", 35, "KYC / Account Suspension Lure"),
    (r"(lottery|winner|won|congratulations|cashback|reward)\s+(rs\.?|inr|\$|\d+)", 30, "Fraudulent Prize / Cashback Lure"),
    (r"(account|card|sim card)\s+(blocked|deactivated|frozen)\s+(today|tonight|within)", 35, "Urgent Deactivation Threat"),
    (r"(enter pin|send otp|share otp|verify details)", 25, "Credential / OTP Harvesting Prompt"),
    (r"(court order|police|cbi|arrest warrant|fir)", 40, "Legal Intimidation Scam"),
    (r"(refund|credited|transfer pending|claim now)", 20, "Fake Refund Claim")
]

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "banking", "update", "wallet", "kyc", "pan", "aadhaar", "auth",
    "password", "security", "credential", "session", "recover"
}

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmically generated strings."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def analyze_url(url: str) -> dict:
    """
    Performs comprehensive lexical, structural, and behavioral risk assessment of a URL.
    """
    flags = []
    risk_score = 0
    brand_spoofed = None

    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "http://" + cleaned_url

    try:
        parsed = urlparse(cleaned_url)
    except Exception:
        return {
            "is_phishing": True,
            "risk_score": 90,
            "confidence": 0.95,
            "threat_level": "CRITICAL",
            "flags": ["Malformed URL Syntax"],
            "brand_spoofed": None,
            "explanation": "URL failed RFC validation and contains invalid encoding.",
            "recommendation": "Do not open this malformed link."
        }

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    # 1. IP address in hostname check
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ip_pattern, hostname):
        risk_score += 40
        flags.append("Host is raw IP address (obfuscates domain registry)")

    # 2. Risky TLD check
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in RISKY_TLDS:
        risk_score += 25
        flags.append(f"High-abuse top-level domain: .{tld}")

    # 3. Excessive subdomain depth
    subdomains = hostname.split(".")[:-2] if len(hostname.split(".")) > 2 else []
    if len(subdomains) >= 3:
        risk_score += 20
        flags.append(f"Excessive subdomain nesting ({len(subdomains)} levels)")

    # 4. Brand Impersonation / Typosquatting in Hostname
    for brand_key, brand_name in POPULAR_BRANDS:
        # Check if brand appears in hostname but is NOT the true domain
        parts = hostname.split(".")
        root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        if brand_key in hostname and brand_key not in root_domain:
            risk_score += 45
            brand_spoofed = brand_name
            flags.append(f"Targeted Brand Impersonation: Claims to be {brand_name}")
            break
        elif brand_key in root_domain and root_domain not in [f"{brand_key}.com", f"{brand_key}.in", f"{brand_key}.org", f"{brand_key}.net"]:
            # e.g., paytm-support.com, sbi-online-service.in
            if any(sep in root_domain for sep in ["-", "_", "login", "update", "verify", "kyc"]):
                risk_score += 40
                brand_spoofed = brand_name
                flags.append(f"Typosquatted Brand Domain: {root_domain} mimics {brand_name}")
                break

    # 5. Sensitive Credential Harvesting Keywords in Path/Query
    path_tokens = set(re.split(r"[/._\-?=&]", path + " " + query))
    matching_keywords = path_tokens.intersection(SUSPICIOUS_PATH_KEYWORDS)
    if matching_keywords:
        risk_score += min(30, len(matching_keywords) * 10)
        flags.append(f"Credential harvesting keywords in path: {', '.join(sorted(matching_keywords))}")

    # 6. Punycode / Homoglyph check
    if "xn--" in hostname:
        risk_score += 35
        flags.append("IDN Homograph / Punycode characters detected in domain")

    # 7. Entropy check on hostname
    ent = calculate_entropy(hostname)
    if ent > 3.8 and len(hostname) > 18:
        risk_score += 15
        flags.append(f"High Shannon entropy ({ent}): Likely generated via DGA")

    # 8. Unencrypted HTTP with sensitive keywords
    if parsed.scheme == "http" and matching_keywords:
        risk_score += 15
        flags.append("Insecure plain HTTP protocol with authentication keywords")

    # Cap risk score
    risk_score = min(100, max(5, risk_score))
    confidence = round(min(0.99, 0.5 + (risk_score / 200)), 2)

    if risk_score >= 70:
        threat_level = "CRITICAL"
        explanation = f"Critical phishing threat detected. URL mimics {brand_spoofed or 'trusted services'} with high risk of credential harvesting."
        recommendation = "BLOCK IMMEDIATELY. Do not click, input credentials, or authenticate."
    elif risk_score >= 45:
        threat_level = "HIGH"
        explanation = "Suspicious link exhibiting multiple deceptive indicators and abnormal domain structure."
        recommendation = "Block or isolate link in sandbox environment."
    elif risk_score >= 25:
        threat_level = "MEDIUM"
        explanation = "Moderate anomalies detected. URL has unusual parameters or minor risk flags."
        recommendation = "Proceed with caution. Verify sender domain through out-of-band communication."
    else:
        threat_level = "LOW"
        explanation = "No overt phishing signatures or deceptive patterns observed."
        recommendation = "Link appears benign. Standard security practices apply."

    return {
        "target": url,
        "is_phishing": risk_score >= 45,
        "risk_score": risk_score,
        "confidence": confidence,
        "threat_level": threat_level,
        "brand_spoofed": brand_spoofed,
        "flags": flags if flags else ["Clean lexical profile"],
        "entropy": ent,
        "explanation": explanation,
        "recommendation": recommendation
    }

def analyze_message_text(text: str) -> dict:
    """
    Inspects SMS, WhatsApp, or email text for social engineering, urgent fraud lures,
    and embedded phishing URLs.
    """
    flags = []
    social_score = 0
    detected_lures = []

    # Detect URLs in text
    url_pattern = r"(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}/[^\s]*)"
    extracted_urls = re.findall(url_pattern, text, re.IGNORECASE)

    # Check urgent lure phrases
    text_lower = text.lower()
    for pattern, score_add, lure_name in URGENT_PHRASES:
        if re.search(pattern, text_lower):
            social_score += score_add
            detected_lures.append(lure_name)
            flags.append(f"Detected social engineering pattern: {lure_name}")

    # Analyze extracted URLs
    url_results = []
    for u in extracted_urls[:3]:
        u_res = analyze_url(u)
        url_results.append(u_res)
        if u_res["is_phishing"]:
            social_score += 35
            flags.append(f"Embedded malicious link: {u} (Risk {u_res['risk_score']}%)")

    total_risk = min(100, max(5, social_score))
    confidence = round(min(0.98, 0.45 + (total_risk / 200)), 2)

    return {
        "text_sample": text[:120] + "..." if len(text) > 120 else text,
        "is_phishing": total_risk >= 45,
        "risk_score": total_risk,
        "confidence": confidence,
        "threat_level": "CRITICAL" if total_risk >= 75 else ("HIGH" if total_risk >= 45 else ("MEDIUM" if total_risk >= 25 else "LOW")),
        "detected_lures": detected_lures,
        "extracted_urls": url_results,
        "flags": flags if flags else ["No suspicious social engineering triggers detected"],
        "explanation": f"Message exhibits {len(detected_lures)} high-urgency psychological triggers." if detected_lures else "Normal conversational tone without urgent scam patterns.",
        "recommendation": "DO NOT call the number or click embedded links. Report as phishing." if total_risk >= 45 else "Safe message."
    }

def scan_phishing_payload(payload: dict) -> dict:
    """Main dispatch function for PhishShield module."""
    if "url" in payload and payload["url"]:
        return analyze_url(payload["url"])
    elif "text" in payload and payload["text"]:
        return analyze_message_text(payload["text"])
    else:
        return {
            "error": "No URL or text payload provided for PhishShield analysis",
            "is_phishing": False,
            "risk_score": 0
        }


def analyze_phishing_event(url: str = "", text: str = "") -> dict:
    """
    Unified entrypoint for PhishShield analyzing both URL and message content.
    """
    url_res = analyze_url(url) if url else None
    text_res = analyze_message_text(text) if text else None

    scores = []
    if url_res:
        # Give url_res detected_brands list for brain correlation
        detected_brands = []
        if url_res.get("brand_spoofed"):
            detected_brands.append(url_res["brand_spoofed"].lower())
        for brand_k, _ in POPULAR_BRANDS:
            if brand_k in (url or "").lower() and brand_k not in detected_brands:
                detected_brands.append(brand_k)
        url_res["detected_brands"] = detected_brands
        scores.append(url_res.get("risk_score", 0))

    if text_res:
        scores.append(text_res.get("risk_score", 0))

    final_score = max(scores) if scores else 0
    if final_score >= 65:
        verdict = "CRITICAL PHISHING"
        threat_level = "CRITICAL" if final_score >= 80 else "HIGH"
    elif final_score >= 35:
        verdict = "SUSPICIOUS LURE"
        threat_level = "MEDIUM"
    else:
        verdict = "SAFE"
        threat_level = "LOW"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "threat_level": threat_level,
        "details": {
            "url_analysis": url_res or {"hostname": "", "flags": [], "detected_brands": []},
            "text_analysis": text_res or {"flags": []}
        }
    }

calculate_shannon_entropy = calculate_entropy
detect_brand_typosquatting = analyze_url

