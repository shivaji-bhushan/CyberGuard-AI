"""
CyberGuard AI — UPI Shield Engine
Detects digital payment fraud, fraudulent Virtual Payment Addresses (VPAs),
reverse collect request traps ("Enter PIN to receive money"),
and deceptive QR code payloads.
"""

import re
from urllib.parse import parse_qs, urlparse

# Standard Authorized Bank & PSP VPA Handle Suffixes (NPCI Approved)
AUTHORIZED_PSP_HANDLES = {
    "okhdfcbank", "okaxis", "oksbi", "okicici", "paytm", "ybl", "ibl",
    "axl", "apl", "ptaxis", "ptsbi", "pthdfc", "fbl", "barodampay",
    "aubank", "cnrb", "federal", "indus", "kotak", "pnb", "rbl", "yesbank"
}

# Impersonation keywords in VPA prefixes
FRAUD_VPA_KEYWORDS = [
    ("customercare", "Customer Support Impersonation"),
    ("helpdesk", "Helpdesk Impersonation"),
    ("support", "Support Agent Impersonation"),
    ("refund", "Fake Refund Department"),
    ("kyc", "KYC Verification Trap"),
    ("billdesk", "Utility Bill Impersonation"),
    ("electricity", "Electricity Board Impersonation"),
    ("powercorp", "Power Disconnection Impersonation"),
    ("reward", "Reward / Cashback Lure"),
    ("lottery", "Lottery Claim Scam"),
    ("army", "Military / Defense Personnel Impersonation"),
    ("cisf", "Paramilitary Officer Scam"),
    ("airtel", "Telecom Operator Impersonation"),
    ("jio", "Telecom Operator Impersonation"),
    ("bsnl", "Telecom Operator Impersonation"),
    ("toll", "FASTag Toll Scam")
]

UPI_SCAM_PATTERNS = [
    (r"(enter|input|type|provide)\s+(your\s+|secret\s+|6\s*digit\s+|4\s*digit\s+)?(upi\s+)?pin\s+(to\s+)?(receive|claim|accept|get|credit|verify)", 60, "Reverse Collect PIN Trap (Fatal UPI Rule Violation)"),
    (r"(send|enter)\s+otp\s+to\s+(receive|claim)", 45, "OTP Harvesting for Authorization"),
    (r"(scan|scan\s+this)\s+(qr|code)\s+(to\s+receive|to\s+get\s+money|for\s+cashback)", 45, "Reverse QR Code Payment Trap"),
    (r"(cisf|army\s+officer|defence|military|posted\s+in)\s+.*(transfer|pay|advance)", 35, "Military Personnel Marketplace Scam"),
    (r"(security\s+deposit|refundable\s+amount|processing\s+fee)\s+first", 30, "Advance Fee Fraud"),
    (r"(scratch\s+card|reward\s+point|gpay\s+reward|phonepe\s+cashback)", 25, "Fake Gamification / Scratch Card Lure")
]

def analyze_vpa(vpa: str) -> dict:
    """
    Validates a Virtual Payment Address (VPA / UPI ID) for syntax,
    handle legitimacy, and impersonation prefixes.
    """
    vpa = vpa.strip().lower()
    flags = []
    risk_score = 0
    detected_impersonation = None

    if "@" not in vpa:
        return {
            "vpa": vpa,
            "is_fraud": True,
            "risk_score": 85,
            "threat_level": "HIGH",
            "flags": ["Invalid VPA Syntax: Missing '@' delimiter"],
            "explanation": "Not a valid UPI Virtual Payment Address.",
            "recommendation": "Reject transaction immediately."
        }

    user_part, handle_part = vpa.split("@", 1)

    # 1. Check authorized PSP handle
    if handle_part not in AUTHORIZED_PSP_HANDLES:
        risk_score += 25
        flags.append(f"Uncommon / Non-standard PSP handle: @{handle_part}")

    # 2. Impersonation keyword check in username
    for keyword, label in FRAUD_VPA_KEYWORDS:
        if keyword in user_part:
            risk_score += 45
            detected_impersonation = label
            flags.append(f"Suspicious VPA Prefix: Contains '{keyword}' ({label})")
            break

    # 3. Numeric / Disposable / Random Entropy Check
    if re.search(r"\d{7,}", user_part):
        risk_score += 15
        flags.append("VPA username contains suspicious long random numeric sequence")

    # 4. Mixing multiple dots and dashes
    if user_part.count(".") >= 3 or user_part.count("-") >= 2:
        risk_score += 15
        flags.append("Deceptive punctuation structuring in VPA handle")

    risk_score = min(100, max(5, risk_score))
    threat_level = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 45 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "vpa": vpa,
        "is_fraud": risk_score >= 45,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "handle": f"@{handle_part}",
        "impersonation": detected_impersonation,
        "flags": flags if flags else ["Legitimate VPA handle structure"],
        "explanation": f"High probability of payment scam using {detected_impersonation}." if detected_impersonation else "VPA syntax and handle conform to standard banking protocols.",
        "recommendation": "DO NOT pay or approve collect requests from this VPA." if risk_score >= 45 else "VPA verified."
    }

def analyze_qr_payload(qr_string: str) -> dict:
    """
    Parses and scrutinizes a raw UPI QR string or `upi://pay` URI for parameter tampering.
    """
    qr_string = qr_string.strip()
    flags = []
    risk_score = 0

    if not qr_string.startswith("upi://pay"):
        return {
            "qr_payload": qr_string[:60] + "...",
            "is_fraud": True,
            "risk_score": 75,
            "threat_level": "HIGH",
            "flags": ["Non-Standard QR Scheme: Does not start with 'upi://pay'"],
            "explanation": "QR code does not contain a standard NPCI UPI payment intent URI.",
            "recommendation": "Do not scan this QR with UPI apps."
        }

    try:
        parsed = urlparse(qr_string)
        params = parse_qs(parsed.query)
    except Exception as e:
        return {
            "qr_payload": qr_string,
            "is_fraud": True,
            "risk_score": 80,
            "threat_level": "HIGH",
            "flags": [f"Malformed UPI QR URI: {str(e)}"],
            "explanation": "QR parameter decoding failed.",
            "recommendation": "Corrupted or malicious QR code."
        }

    pa = params.get("pa", [""])[0]  # Payee VPA
    pn = params.get("pn", [""])[0]  # Payee Name
    am = params.get("am", [""])[0]  # Amount
    cu = params.get("cu", ["INR"])[0]  # Currency

    if not pa:
        risk_score += 50
        flags.append("Missing Payee Address ('pa') parameter in QR")

    # Analyze Payee VPA
    vpa_res = analyze_vpa(pa) if pa else {}
    if vpa_res.get("is_fraud"):
        risk_score += vpa_res["risk_score"] // 2
        flags.extend(vpa_res.get("flags", []))

    # Name Mismatch / Deceptive Merchant Check
    pn_lower = pn.lower()
    if any(k[0] in pn_lower for k in FRAUD_VPA_KEYWORDS) and not any(official in pa for official in ["billdesk", "gov.in", "nic.in"]):
        risk_score += 35
        flags.append(f"Deceptive Payee Name ('{pn}') paired with private VPA ('{pa}')")

    # Locked Debit Amount Check
    if am and float(am) > 5000:
        risk_score += 20
        flags.append(f"Pre-locked high debit amount in QR: Rs. {am}")

    risk_score = min(100, max(10, risk_score))
    threat_level = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 45 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "qr_payload": qr_string[:75] + ("..." if len(qr_string) > 75 else ""),
        "payee_vpa": pa,
        "payee_name": pn,
        "amount": am if am else "Dynamic / Not Locked",
        "currency": cu,
        "is_fraud": risk_score >= 45,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "flags": flags if flags else ["Standard benign merchant/P2P QR payload"],
        "explanation": f"Deceptive QR code targeting unauthorized debit for {pn}." if risk_score >= 45 else "Valid QR payment code.",
        "recommendation": "DO NOT scan or approve. Verify payee identity." if risk_score >= 45 else "Safe to proceed."
    }

def analyze_payment_request(text: str, vpa: str = None, amount: float = None) -> dict:
    """
    Scrutinizes payment request communication, SMS alerts, and collect request descriptions.
    """
    flags = []
    scam_score = 0
    detected_schemes = []

    text_lower = text.lower()

    # Core UPI Golden Rule: You NEVER enter PIN to receive money!
    for pattern, score, scheme in UPI_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            scam_score += score
            detected_schemes.append(scheme)
            flags.append(f"CRITICAL VIOLATION: {scheme}")

    # Inspect VPA if provided
    vpa_analysis = None
    if vpa:
        vpa_analysis = analyze_vpa(vpa)
        if vpa_analysis["is_fraud"]:
            scam_score += 30
            flags.extend(vpa_analysis["flags"])

    total_risk = min(100, max(5, scam_score))
    threat_level = "CRITICAL" if total_risk >= 70 else ("HIGH" if total_risk >= 45 else ("MEDIUM" if total_risk >= 25 else "LOW"))

    return {
        "text_context": text[:100] + ("..." if len(text) > 100 else ""),
        "vpa": vpa,
        "amount": amount,
        "is_fraud": total_risk >= 45,
        "risk_score": total_risk,
        "threat_level": threat_level,
        "detected_schemes": detected_schemes,
        "vpa_analysis": vpa_analysis,
        "flags": flags if flags else ["Standard payment transaction context"],
        "golden_rule_violated": "Reverse Collect PIN Trap" in " ".join(detected_schemes),
        "explanation": "Scammer is attempting a reverse collect request: Asking user to enter UPI PIN to receive money, which actually deducts funds." if total_risk >= 50 else "Normal payment request.",
        "recommendation": "DECLINE COLLECT REQUEST IMMEDIATELY. Entering your UPI PIN will transfer your money to the attacker." if total_risk >= 45 else "Legitimate payment instruction."
    }

def scan_upi_payload(payload: dict) -> dict:
    """Main dispatch function for UPI Shield module."""
    if "qr_string" in payload and payload["qr_string"]:
        return analyze_qr_payload(payload["qr_string"])
    elif "text" in payload and payload["text"]:
        vpa = payload.get("vpa")
        amount = payload.get("amount")
        return analyze_payment_request(payload["text"], vpa, amount)
    elif "vpa" in payload and payload["vpa"]:
        return analyze_vpa(payload["vpa"])
    else:
        return {
            "error": "No VPA, QR code, or payment text payload provided",
            "is_fraud": False,
            "risk_score": 0
        }


def analyze_upi_event(vpa: str = "", amount: float = 0.0, context_text: str = "", qr_payload: str = "") -> dict:
    """
    Unified entrypoint for UPI Shield evaluating VPA handles, payment context, and QR payloads.
    """
    vpa_res = analyze_vpa(vpa) if vpa else None
    qr_res = analyze_qr_payload(qr_payload) if qr_payload else None
    context_res = analyze_payment_request(context_text, vpa, amount) if context_text else None

    # Enrich vpa_res with detected_brands for brain correlation
    if vpa_res:
        detected_brands = []
        for brand in ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "mahadiscom", "electricity"]:
            if brand in (vpa or "").lower():
                detected_brands.append(brand)
        vpa_res["detected_brands"] = detected_brands

    scores = []
    if vpa_res:
        scores.append(vpa_res.get("risk_score", 0))
    if qr_res:
        scores.append(qr_res.get("risk_score", 0))
    if context_res:
        scores.append(context_res.get("risk_score", 0))

    final_score = max(scores) if scores else 0
    if final_score >= 65:
        verdict = "CRITICAL FRAUD TRAP"
        threat_level = "CRITICAL" if final_score >= 80 else "HIGH"
    elif final_score >= 35:
        verdict = "SUSPICIOUS PAYMENT"
        threat_level = "MEDIUM"
    else:
        verdict = "SAFE"
        threat_level = "LOW"

    # Context analysis flags
    c_flags = context_res.get("flags", []) if context_res else []
    is_reverse = context_res.get("golden_rule_violated", False) if context_res else False

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "threat_level": threat_level,
        "details": {
            "vpa_analysis": vpa_res or {"flags": [], "detected_brands": []},
            "context_analysis": {
                "flags": c_flags,
                "is_reverse_collect_trap": is_reverse
            },
            "qr_analysis": qr_res or {"flags": []}
        }
    }

parse_upi_qr_string = analyze_qr_payload
detect_reverse_collect_trap = analyze_payment_request

