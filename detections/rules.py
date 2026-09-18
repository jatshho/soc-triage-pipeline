from collections import defaultdict
from datetime import datetime

def _parse_ts(ts_str, year=None):
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")

def detect_brute_force(events, threshold=5, window_seconds=60):
    """Flag a src_ip with >= threshold failed logins inside a rolling window."""
    failed = [e for e in events if e.event_action == "login_failed"]
    failed.sort(key=lambda e: _parse_ts(e.timestamp))

    alerts = []
    by_ip = defaultdict(list)
    for e in failed:
        ts = _parse_ts(e.timestamp)
        by_ip[e.src_ip].append((ts, e))
        # drop events outside the window
        window_start = ts.timestamp() - window_seconds
        by_ip[e.src_ip] = [(t, ev) for (t, ev) in by_ip[e.src_ip] if t.timestamp() >= window_start]

        if len(by_ip[e.src_ip]) >= threshold:
            alerts.append({
                "rule": "brute_force",
                "src_ip": e.src_ip,
                "count": len(by_ip[e.src_ip]),
                "window_seconds": window_seconds,
                "last_seen": e.timestamp,
                "user_targeted": e.user,
            })
            by_ip[e.src_ip] = []  # reset after firing so we do not spam duplicate alerts
    return alerts
