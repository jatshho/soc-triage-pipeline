import argparse
from ingest.log_reader import read_lines
from ingest.log_generator import generate_auth_log
from parsers.normalizer import normalize_lines
from detections.engine import run_detections
from enrichment.threat_intel import enrich_findings
from alerts.alert_manager import build_alerts, save_alerts

def print_summary(alerts):
    if not alerts:
        print("No alerts generated.")
        return
    print(f"\n{len(alerts)} alert(s) generated:\n")
    for a in alerts:
        print(f"[{a['severity']:>8}] score={a['score']:<5} rule={a['rule']:<12} "
              f"src_ip={a.get('src_ip')} count={a.get('count')}")

def main():
    parser = argparse.ArgumentParser(description="SOC Triage Pipeline")
    parser.add_argument("--log", default="logs/sample_auth.log", help="Path to auth log")
    parser.add_argument("--generate", action="store_true", help="Generate a fresh synthetic log first")
    args = parser.parse_args()

    if args.generate:
        generate_auth_log(path=args.log)
        print(f"Generated synthetic log at {args.log}")

    lines = list(read_lines(args.log))
    events = normalize_lines(lines)
    print(f"Parsed {len(events)} normalized events from {len(lines)} raw lines")

    findings = run_detections(events)
    print(f"Detection engine produced {len(findings)} finding(s)")

    findings = enrich_findings(findings)
    alerts = build_alerts(findings)
    out_path = save_alerts(alerts)
    print(f"Saved alerts to {out_path}")

    print_summary(alerts)

if __name__ == "__main__":
    main()
