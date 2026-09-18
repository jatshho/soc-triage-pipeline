import yaml
from detections.rules import detect_brute_force

def run_detections(events, rules_config_path="config/rules.yaml"):
    with open(rules_config_path) as f:
        cfg = yaml.safe_load(f)

    findings = []
    bf_cfg = cfg.get("brute_force", {})
    if bf_cfg.get("enabled"):
        findings += detect_brute_force(
            events,
            threshold=bf_cfg.get("threshold", 5),
            window_seconds=bf_cfg.get("window_seconds", 60),
        )
    # Add calls to additional rule functions here as you build them out
    # (port_scan, impossible_travel, privilege_escalation, etc.)
    return findings
