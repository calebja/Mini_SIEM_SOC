"""
collector.py
The "Log Collector" stage of the pipeline. Reads raw logs from Windows,
Linux and the firewall (as if shipped over syslog/WEF from those machines)
and normalizes them into one unified `events` table so the detection engine
never has to know about source-specific formats.

Note: the `GT=` field on some lines is a scoring label injected by the lab
generator (like a red-team answer key). It is stored in its own gt_id
column purely for evaluate.py -- detection.py never reads it.
"""
import re
import sqlite3
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DB_PATH = os.path.join(DATA_DIR, "siem.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,       -- windows | linux | firewall
    host TEXT,
    event_code TEXT,
    event_type TEXT,
    user TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    bytes INTEGER,
    detail TEXT,
    raw TEXT,
    gt_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
"""


def strip_gt(line):
    m = re.search(r"GT=(\S+)", line)
    gt = m.group(1) if m else None
    clean = re.sub(r"[,|]?GT=\S+", "", line).rstrip()
    return clean, gt


def parse_windows(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        line, gt = strip_gt(line)
        parts = line.split("|")
        ts, host, code, etype = parts[0], parts[1], parts[2], parts[3]
        fields = {}
        for p in parts[4:]:
            if "=" in p:
                k, v = p.split("=", 1)
                fields[k] = v.strip('"')
        rows.append({
            "ts": ts, "source": "windows", "host": host, "event_code": code,
            "event_type": etype, "user": fields.get("User"),
            "src_ip": fields.get("SourceIP"), "dst_ip": None, "dst_port": None,
            "bytes": None, "detail": "; ".join(f"{k}={v}" for k, v in fields.items()),
            "raw": line, "gt_id": gt,
        })
    return rows


LINUX_MONTHS = {m: f"{i:02d}" for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def linux_ts_to_iso(month, day, time_str, year=2026):
    return f"{year}-{LINUX_MONTHS[month]}-{int(day):02d} {time_str}"


def parse_linux(path):
    rows = []
    sshd_failed = re.compile(r"sshd\[\d+\]: Failed password for (\S+) from (\S+) port (\d+)")
    sshd_ok = re.compile(r"sshd\[\d+\]: Accepted password for (\S+) from (\S+) port (\d+)")
    sudo_re = re.compile(r"sudo:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.+)")
    useradd_re = re.compile(r"useradd\[\d+\]: new user: name=(\S+?),")
    usermod_re = re.compile(r"usermod\[\d+\]: add '(\S+)' to group '(\S+)'")
    cron_re = re.compile(r"CRON\[\d+\]: \((\S+)\) CMD \((.+)\)")
    authkeys_re = re.compile(r"authorized_keys modified for user (\S+)")

    for line in open(path):
        line = line.strip()
        if not line:
            continue
        line, gt = strip_gt(line)
        m = re.match(r"(\w+) +(\d+) (\d\d:\d\d:\d\d) (\S+) (.+)", line)
        if not m:
            continue
        month, day, time_str, host, rest = m.groups()
        ts = linux_ts_to_iso(month, day, time_str)
        row = {"ts": ts, "source": "linux", "host": host, "event_code": None,
               "event_type": None, "user": None, "src_ip": None, "dst_ip": None,
               "dst_port": None, "bytes": None, "detail": rest, "raw": line, "gt_id": gt}

        if r := sshd_failed.search(rest):
            row.update(event_type="FAILED_LOGON", event_code="sshd_fail", user=r.group(1),
                       src_ip=r.group(2))
        elif r := sshd_ok.search(rest):
            row.update(event_type="SUCCESS_LOGON", event_code="sshd_ok", user=r.group(1),
                       src_ip=r.group(2))
        elif r := sudo_re.search(rest):
            row.update(event_type="SUDO_COMMAND", event_code="sudo", user=r.group(1),
                       detail=f"as={r.group(2)}; cmd={r.group(3)}")
        elif r := useradd_re.search(rest):
            row.update(event_type="USER_CREATED", event_code="useradd", user=r.group(1))
        elif r := usermod_re.search(rest):
            row.update(event_type="MEMBER_ADDED_TO_GROUP", event_code="usermod", user=r.group(1),
                       detail=f"group={r.group(2)}")
        elif r := cron_re.search(rest):
            row.update(event_type="CRON_JOB", event_code="cron", user=r.group(1),
                       detail=f"cmd={r.group(2)}")
        elif r := authkeys_re.search(rest):
            row.update(event_type="AUTHKEYS_MODIFIED", event_code="authkeys", user=r.group(1))
        else:
            row.update(event_type="OTHER", event_code="linux_misc")

        rows.append(row)
    return rows


def parse_firewall(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        line, gt = strip_gt(line)
        parts = line.split(",")
        ts, src, dst, port, proto, action, size = parts[:7]
        rows.append({
            "ts": ts, "source": "firewall", "host": "FW-EDGE01", "event_code": action,
            "event_type": "CONNECTION", "user": None, "src_ip": src, "dst_ip": dst,
            "dst_port": int(port), "bytes": int(size),
            "detail": f"proto={proto}; action={action}", "raw": line, "gt_id": gt,
        })
    return rows


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)

    all_rows = []
    all_rows += parse_windows(os.path.join(DATA_DIR, "windows_security.log"))
    all_rows += parse_linux(os.path.join(DATA_DIR, "linux_auth.log"))
    all_rows += parse_firewall(os.path.join(DATA_DIR, "firewall.log"))

    cols = ["ts", "source", "host", "event_code", "event_type", "user", "src_ip",
            "dst_ip", "dst_port", "bytes", "detail", "raw", "gt_id"]
    conn.executemany(
        f"INSERT INTO events ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
        [tuple(r.get(c) for c in cols) for r in all_rows],
    )
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Ingested {n} normalized events into {DB_PATH}")
    for src, cnt in conn.execute("SELECT source, COUNT(*) FROM events GROUP BY source"):
        print(f"  {src}: {cnt}")
    conn.close()


if __name__ == "__main__":
    main()
