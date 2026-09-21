import json
from datetime import datetime
from alerts.scoring import score_finding, severity_label

def deduplicate_findings(findings):
    """Merge findings that share the same rule + src_ip into a single finding,
    keeping the highest count and most recent timestamp seen."""
    merged = {}
    for f in findings:
        key = (f["rule"], f.get("src_ip"))
        if key not in merged:
            merged[key] = dict(f)
        else:
            existing = merged[key]
            existing["count"] = existing.get("count", 0) + f.get("count", 0)
            if f.get("last_seen", "") > existing.get("last_seen", ""):
                existing["last_seen"] = f["last_seen"]
    return list(merged.values())

def build_alerts(findings):
    findings = deduplicate_findings(findings)
    alerts = []
    for f in findings:
        score = score_finding(f)
        alerts.append({
            **f,
            "score": score,
            "severity": severity_label(score),
            "generated_at": datetime.utcnow().isoformat() + "Z",
        })
    alerts.sort(key=lambda a: a["score"], reverse=True)
    return alerts

def save_alerts(alerts, path="alerts/alerts.json"):
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    return path
