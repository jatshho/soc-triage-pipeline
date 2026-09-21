RULE_BASE_SCORE = {
    "brute_force": 40,
    "port_scan": 30,
}

def score_finding(finding):
    score = RULE_BASE_SCORE.get(finding["rule"], 20)

    ti = finding.get("threat_intel") or {}
    abuse_score = ti.get("abuse_score")
    if abuse_score is not None:
        score += min(abuse_score, 100) * 0.5   # up to +50 points

    count = finding.get("count", 1)
    score += min(count, 20)                     # up to +20 points for volume

    return round(min(score, 100), 1)

def severity_label(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"
