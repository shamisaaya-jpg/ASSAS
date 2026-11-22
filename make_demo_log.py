"""Generate a realistic demo auth.log for the ASSAS dashboard."""
import random
from datetime import datetime, timedelta

random.seed(7)
lines = []
start = datetime(2026, 11, 21, 8, 0, 0)
pid = 1000


def add(ts, msg):
    global pid
    pid += 1
    lines.append((ts, f"{ts:%b %d %H:%M:%S} ubuntu sshd[{pid}]: {msg}"))


# Normal activity during the day
staff = [("aya", "192.168.56.1"), ("omar", "192.168.56.21"), ("sara", "192.168.56.22")]
for hour in range(8, 23):
    for _ in range(random.randint(2, 5)):
        user, ip = random.choice(staff)
        ts = start.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
        if random.random() < 0.15:
            add(ts, f"Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")
        add(ts + timedelta(seconds=5), f"Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2")

# Brute force from Kali at 22h, ending in a successful login
ts = start.replace(hour=22, minute=10)
for _ in range(60):
    user = random.choice(["root", "root", "admin", "test", "ubuntu"])
    prefix = "" if user == "root" else "invalid user "
    add(ts, f"Failed password for {prefix}{user} from 192.168.56.10 port {random.randint(40000, 60000)} ssh2")
    ts += timedelta(seconds=random.randint(1, 4))
add(ts + timedelta(seconds=3), "Accepted password for root from 192.168.56.10 port 51050 ssh2")

# Smaller scan from another host at 15h
ts = start.replace(hour=15, minute=30)
for _ in range(14):
    user = random.choice(["admin", "oracle", "postgres"])
    add(ts, f"Failed password for invalid user {user} from 10.0.0.23 port {random.randint(40000, 60000)} ssh2")
    ts += timedelta(seconds=random.randint(2, 6))

# A few sudo failures
for minute in (5, 6, 7):
    t = start.replace(hour=19, minute=minute)
    lines.append((t, f"{t:%b %d %H:%M:%S} ubuntu sudo: pam_unix(sudo:auth): authentication failure; "
                     "logname=aya uid=1000 euid=0 tty=/dev/pts/0 ruser=aya rhost=  user=aya"))

lines.sort()
with open("sample_logs/demo_attack.log", "w") as f:
    f.write("\n".join(line for _, line in lines) + "\n")
print(f"{len(lines)} lines written to sample_logs/demo_attack.log")
