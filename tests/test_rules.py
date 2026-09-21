from parsers.schema import NormalizedEvent
from detections.rules import detect_brute_force

def _failed_event(ts, ip="203.0.113.55"):
    return NormalizedEvent(
        timestamp=ts, host="web01", source_type="ssh_auth",
        event_action="login_failed", user="admin", src_ip=ip,
    )

def test_brute_force_fires_above_threshold():
    events = [_failed_event(f"Jan 05 10:00:0{i}") for i in range(6)]
    alerts = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(alerts) == 1
    assert alerts[0]["src_ip"] == "203.0.113.55"

def test_brute_force_does_not_fire_below_threshold():
    events = [_failed_event(f"Jan 05 10:00:0{i}") for i in range(3)]
    alerts = detect_brute_force(events, threshold=5, window_seconds=60)
    assert len(alerts) == 0
