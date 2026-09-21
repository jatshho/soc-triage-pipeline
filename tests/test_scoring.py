from alerts.scoring import score_finding, severity_label

def test_score_increases_with_abuse_score():
    low = score_finding({"rule": "brute_force", "count": 5, "threat_intel": {"abuse_score": 0}})
    high = score_finding({"rule": "brute_force", "count": 5, "threat_intel": {"abuse_score": 90}})
    assert high > low

def test_severity_labels():
    assert severity_label(85) == "Critical"
    assert severity_label(65) == "High"
    assert severity_label(40) == "Medium"
    assert severity_label(10) == "Low"
