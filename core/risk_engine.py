"""
CyberGuard AI — Unified Risk & Policy Engine
Synthesizes heterogeneous risk scores from PhishShield, UPI Shield, and NetSentinel,
applies correlation boost factors, and issues policy-enforced responses:
SAFE, WARN, BLOCK, or ISOLATE.
"""

def calculate_composite_risk(modules_results: dict, correlation_matches: list) -> dict:
    """
    Computes unified composite risk score (0-100) and response decision.
    """
    scores = []
    weights = []

    # 1. Gather module scores and weights
    if "phish_shield" in modules_results and not modules_results["phish_shield"].get("error"):
        scores.append(modules_results["phish_shield"].get("risk_score", 0))
        weights.append(1.0)

    if "upi_shield" in modules_results and not modules_results["upi_shield"].get("error"):
        scores.append(modules_results["upi_shield"].get("risk_score", 0))
        weights.append(1.2)  # Higher weight due to direct financial impact

    if "net_sentinel" in modules_results and not modules_results["net_sentinel"].get("error"):
        scores.append(modules_results["net_sentinel"].get("risk_score", 0))
        weights.append(1.1)

    if not scores:
        return {
            "composite_score": 0,
            "threat_level": "LOW",
            "decision": "SAFE",
            "action_code": "ALLOW_EVENT",
            "explanation": "No active risk signals detected across security modules.",
            "enforced_actions": []
        }

    # Weighted baseline average
    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    total_weight = sum(weights)
    baseline_score = weighted_sum / max(1.0, total_weight)

    # Max individual score anchor
    max_individual = max(scores)

    # Correlation boost: Cross-threat signals confirm coordinated attack chain
    correlation_boost = 0
    if len(correlation_matches) >= 2:
        correlation_boost = 18
    elif len(correlation_matches) == 1:
        correlation_boost = 10

    # Composite formula: Correlation boost elevates highest individual threat anchor
    composite_score = round(min(100, max_individual + correlation_boost), 1)

    # Policy Decision Logic
    enforced_actions = []
    if composite_score >= 85:
        decision = "ISOLATE"
        threat_level = "CRITICAL"
        action_code = "QUARANTINE_AND_ISOLATE"
        enforced_actions = [
            "Terminate socket / network interface connection",
            "Blacklist malicious VPA handle at payment gateway level",
            "Add domain to firewall perimeter DNS sinkhole",
            "Quarantine host endpoint & lock compromised session token"
        ]
        explanation = "Critical multi-vector attack chain identified. Immediate full-scale containment required."
    elif composite_score >= 65:
        decision = "BLOCK"
        threat_level = "HIGH"
        action_code = "BLOCK_THREAT"
        enforced_actions = [
            "Block outbound HTTP/HTTPS request to malicious target",
            "Reject UPI payment transaction / reverse collect prompt",
            "Add IP/domain to temporary 24h perimeter blocklist"
        ]
        explanation = "High-confidence single or dual threat vector detected. Malicious activity actively blocked."
    elif composite_score >= 35:
        decision = "WARN"
        threat_level = "MEDIUM"
        action_code = "ADVISORY_ALERT"
        enforced_actions = [
            "Display prominent deceptive link / payment warning banner",
            "Prompt user with secondary multi-factor authentication",
            "Flag transaction for automated fraud telemetry review"
        ]
        explanation = "Suspicious signals or minor anomalies detected. Proceed with heightened vigilance."
    else:
        decision = "SAFE"
        threat_level = "LOW"
        action_code = "ALLOW_EVENT"
        enforced_actions = [
            "Allow connection / normal processing",
            "Log benign event telemetry"
        ]
        explanation = "Target complies with verified safety profiles."

    return {
        "composite_score": composite_score,
        "baseline_score": round(baseline_score, 1),
        "correlation_boost": correlation_boost,
        "threat_level": threat_level,
        "decision": decision,
        "action_code": action_code,
        "explanation": explanation,
        "enforced_actions": enforced_actions
    }
