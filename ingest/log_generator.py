import random
from datetime import datetime, timedelta

USERS = ["alice", "bob", "carol", "deploy", "admin"]
NORMAL_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.18"]
ATTACKER_IP = "203.0.113.55"   # TEST-NET-3, safe placeholder address

def _line(ts, host, proc, pid, msg):
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} {proc}[{pid}]: {msg}"

def generate_auth_log(path="logs/sample_auth.log", start=None, normal_events=120, attack_events=25):
    start = start or datetime.now() - timedelta(hours=2)
    lines = []
    t = start

    # Normal successful logins spread over time
    for _ in range(normal_events):
        t += timedelta(seconds=random.randint(20, 90))
        user = random.choice(USERS)
        ip = random.choice(NORMAL_IPS)
        pid = random.randint(1000, 9999)
        lines.append(_line(t, "web01", "sshd", pid,
            f"Accepted password for {user} from {ip} port {random.randint(1024,65000)} ssh2"))

    # Injected brute-force burst from a single external IP
    burst_start = start + timedelta(minutes=45)
    t = burst_start
    for i in range(attack_events):
        t += timedelta(seconds=random.randint(1, 4))
        pid = random.randint(1000, 9999)
        lines.append(_line(t, "web01", "sshd", pid,
            f"Failed password for admin from {ATTACKER_IP} port {random.randint(1024,65000)} ssh2"))

    lines.sort()  # interleave chronologically (approx, good enough for demo data)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path

if __name__ == "__main__":
    out = generate_auth_log()
    print(f"Wrote synthetic log to {out}")
