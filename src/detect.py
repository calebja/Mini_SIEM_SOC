"""
detect.py
The Detection Engine. Reads normalized events from siem.db and runs 8
independent detectors, each producing alerts with severity, MITRE ATT&CK
mapping, concrete evidence and a recommended response. Writes results to
the `alerts` table and to data/alerts.json for the dashboard.

IMPORTANT: detectors only ever look at operational fields (timestamps,
users, IPs, ports, commands). They never read the gt_id column -- that
column exists solely so evaluate.py can score this file's output.
"""
import sqlite3
import json
import re
import os
import datetime
from collections import defaultdict

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DB_PATH = os.path.join(DATA_DIR, "siem.db")

ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    severity TEXT,
    src_ip TEXT,
    target_host TEXT,
    attack_type TEXT,
    mitre_technique TEXT,
    mitre_tactic TEXT,
    evidence TEXT,
    recommended_response TEXT,
    detector TEXT,
    confidence REAL
);
"""

SUSPICIOUS_PS_PATTERNS = [
    (r"-enc\b", "base64-encoded (-enc) command"),
    (r"-e\s+[A-Za-z0-9+/=]{20,}", "inline base64 blob passed as a command"),
    (r"-nop\b.*-w(indowstyle)?\s+hidden", "hidden window, no-profile launch flags"),
    (r"IEX\s*\(", "IEX (Invoke-Expression) download-and-run cradle"),
    (r"DownloadString|DownloadFile|Net\.WebClient", "remote script/file download cradle"),
    (r"Add-MpPreference\s+-ExclusionPath", "Defender exclusion path added via script"),
    (r"Invoke-Mimikatz|mimikatz", "credential-dumping tool referenced"),
    (r"whoami\s*/priv", "privilege enumeration command"),
    (r"Bypass\b", "execution-policy bypass flag"),
]

ts_fmt = "%Y-%m-%d %H:%M:%S"


def to_dt(s):
    return datetime.datetime.strptime(s, ts_fmt)


def fetch_all(conn):
    cur = conn.execute("SELECT * FROM events ORDER BY ts")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def make_alert(ts, severity, src_ip, target_host, attack_type, technique, tactic,
               evidence, response, detector, confidence):
    return {
        "ts": ts, "severity": severity, "src_ip": src_ip, "target_host": target_host,
        "attack_type": attack_type, "mitre_technique": technique, "mitre_tactic": tactic,
        "evidence": evidence, "recommended_response": response, "detector": detector,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# 1. Brute-force authentication
# ---------------------------------------------------------------------------
def detect_brute_force(events):
    alerts = []
    fails = [e for e in events if e["event_type"] == "FAILED_LOGON"]
    buckets = defaultdict(list)
    for e in fails:
        buckets[(e["src_ip"], e["host"])].append(e)
    for (src_ip, host), evs in buckets.items():
        evs.sort(key=lambda e: e["ts"])
        window = []
        for e in evs:
            t = to_dt(e["ts"])
            window = [w for w in window if (t - to_dt(w["ts"])).total_seconds() <= 300] + [e]
            if len(window) >= 8:
                success_after = [s for s in events if s["event_type"] == "SUCCESS_LOGON"
                                  and s["src_ip"] == src_ip and s["host"] == host
                                  and 0 <= (to_dt(s["ts"]) - t).total_seconds() <= 120]
                sev = "Critical" if success_after else "High"
                user = window[0]["user"]
                alerts.append(make_alert(
                    e["ts"], sev, src_ip, host, "brute_force", "T1110",
                    "Credential Access",
                    f"{len(window)} failed logons for user '{user}' from {src_ip} within 5 min"
                    + (f"; followed by a SUCCESSFUL logon at {success_after[0]['ts']}" if success_after else ""),
                    "Block source IP at the firewall/edge, force-reset the targeted account's password, "
                    "and enable account lockout / MFA on the exposed logon service."
                    + (" Investigate the account for compromise -- the brute force appears to have succeeded."
                       if success_after else ""),
                    "brute_force_v1", 0.95 if success_after else 0.85,
                ))
                window = []
    return alerts


# ---------------------------------------------------------------------------
# 2. Suspicious PowerShell
# ---------------------------------------------------------------------------
def detect_powershell(events):
    alerts = []
    for e in events:
        if e["event_type"] != "POWERSHELL_SCRIPTBLOCK":
            continue
        script = e["detail"] or ""
        hits = [label for pat, label in SUSPICIOUS_PS_PATTERNS if re.search(pat, script, re.I)]
        if hits:
            sev = "Critical" if len(hits) >= 2 else "High"
            alerts.append(make_alert(
                e["ts"], sev, e["src_ip"] or e["host"], e["host"], "suspicious_powershell",
                "T1059.001", "Execution",
                f"User '{e['user']}' ran PowerShell flagged for: {', '.join(hits)}. Command: {script}",
                "Isolate the host from the network, capture a memory image, terminate the process, "
                "and review PowerShell ScriptBlock logs on this host for the preceding 24h.",
                "powershell_v1", min(0.6 + 0.2 * len(hits), 0.95),
            ))
    return alerts


# ---------------------------------------------------------------------------
# 3. Port scanning
# ---------------------------------------------------------------------------
def detect_port_scan(events):
    alerts = []
    conns = [e for e in events if e["source"] == "firewall"]
    buckets = defaultdict(list)
    for e in conns:
        buckets[(e["src_ip"], e["dst_ip"])].append(e)
    for (src_ip, dst_ip), evs in buckets.items():
        evs.sort(key=lambda e: e["ts"])
        window = []
        for e in evs:
            t = to_dt(e["ts"])
            window = [w for w in window if (t - to_dt(w["ts"])).total_seconds() <= 120] + [e]
            ports = {w["dst_port"] for w in window}
            if len(ports) >= 15:
                deny_ratio = sum(1 for w in window if w["event_code"] == "DENY") / len(window)
                sev = "High" if deny_ratio > 0.5 else "Medium"
                alerts.append(make_alert(
                    e["ts"], sev, src_ip, dst_ip, "port_scan", "T1046",
                    "Discovery",
                    f"{len(ports)} distinct destination ports contacted on {dst_ip} from {src_ip} "
                    f"within 2 minutes ({int(deny_ratio*100)}% denied)",
                    "Block the source IP at the perimeter firewall, review IDS signatures for the "
                    "scanned host, and confirm no listening service was reachable that shouldn't be.",
                    "port_scan_v1", 0.9 if deny_ratio > 0.5 else 0.75,
                ))
                window = []
    return alerts


# ---------------------------------------------------------------------------
# 4. Impossible login (impossible travel)
# ---------------------------------------------------------------------------
GEO = {
    "203.0.113.7": "RU-Moscow", "198.51.100.23": "CN-Shanghai", "203.0.113.55": "NG-Lagos",
    "198.51.100.88": "BR-SaoPaulo", "192.0.2.10": "US-Ashburn", "192.0.2.44": "US-Ashburn",
    "203.0.113.90": "VN-Hanoi",
}


def detect_impossible_login(events):
    alerts = []
    successes = [e for e in events if e["event_type"] == "SUCCESS_LOGON" and e["src_ip"] in GEO]
    by_user = defaultdict(list)
    for e in successes:
        by_user[e["user"]].append(e)
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e["ts"])
        for a, b in zip(evs, evs[1:]):
            if a["src_ip"] == b["src_ip"]:
                continue
            dt_minutes = (to_dt(b["ts"]) - to_dt(a["ts"])).total_seconds() / 60
            if dt_minutes <= 60 and GEO.get(a["src_ip"]) != GEO.get(b["src_ip"]):
                alerts.append(make_alert(
                    b["ts"], "Critical", f"{a['src_ip']}|{b['src_ip']}", b["host"],
                    "impossible_login", "T1078", "Defense Evasion / Initial Access",
                    f"User '{user}' logged in from {GEO.get(a['src_ip'], a['src_ip'])} at {a['ts']} "
                    f"then from {GEO.get(b['src_ip'], b['src_ip'])} at {b['ts']} "
                    f"({dt_minutes:.0f} min apart -- not physically possible)",
                    "Force-expire the account's active sessions, require password reset and MFA "
                    "re-enrollment, and check for mailbox rules or OAuth grants added during the session.",
                    "impossible_login_v1", 0.9,
                ))
    return alerts


# ---------------------------------------------------------------------------
# 5. Privilege escalation
# ---------------------------------------------------------------------------
def detect_privesc(events):
    alerts = []
    # Linux: sudo to root followed quickly by sudoers/suid tampering
    sudo_events = [e for e in events if e["event_type"] == "SUDO_COMMAND"]
    by_host_user = defaultdict(list)
    for e in sudo_events:
        by_host_user[(e["host"], e["user"])].append(e)
    for (host, user), evs in by_host_user.items():
        evs.sort(key=lambda e: e["ts"])
        for i, e in enumerate(evs):
            cmd = e["detail"] or ""
            if "visudo" in cmd or "chmod u+s" in cmd or "/bin/bash" in cmd:
                t = to_dt(e["ts"])
                nearby = [x for x in evs if 0 <= (to_dt(x["ts"]) - t).total_seconds() <= 60]
                hour = t.hour
                after_hours = hour < 6 or hour >= 22
                if len(nearby) >= 2 or "chmod u+s" in cmd:
                    sev = "Critical" if "chmod u+s" in cmd else "High"
                    alerts.append(make_alert(
                        e["ts"], sev, e["host"], host, "privilege_escalation", "T1548.003",
                        "Privilege Escalation",
                        f"User '{user}' escalated via sudo on {host}: " +
                        "; ".join(f"{x['ts']} {x['detail']}" for x in nearby),
                        "Review the account's need for sudo access, audit /etc/sudoers and any "
                        "SUID bits changed on this host, and rotate credentials for the account used.",
                        "privesc_v1", 0.9 if after_hours else 0.75,
                    ))
    # Windows: privilege enumeration followed by special-privilege assignment
    ps = [e for e in events if e["event_type"] == "POWERSHELL_SCRIPTBLOCK" and "whoami /priv" in (e["detail"] or "")]
    priv_assign = [e for e in events if e["event_type"] == "SPECIAL_PRIVILEGES_ASSIGNED"]
    for p in ps:
        t = to_dt(p["ts"])
        follow = [x for x in priv_assign if x["host"] == p["host"] and x["user"] == p["user"]
                  and 0 <= (to_dt(x["ts"]) - t).total_seconds() <= 300]
        if follow:
            alerts.append(make_alert(
                follow[0]["ts"], "High", p["host"], p["host"], "privilege_escalation", "T1134",
                "Privilege Escalation",
                f"User '{p['user']}' enumerated privileges (whoami /priv) then was assigned "
                f"{follow[0]['detail']} within 5 minutes",
                "Investigate the process token for manipulation, verify the account's baseline "
                "privileges, and check for known token-impersonation tooling on the host.",
                "privesc_v1", 0.8,
            ))
    return alerts


# ---------------------------------------------------------------------------
# 6. New administrator accounts
# ---------------------------------------------------------------------------
def detect_new_admin(events):
    alerts = []
    creates = [e for e in events if e["event_type"] in ("USER_CREATED",)]
    group_adds = [e for e in events if e["event_type"] == "MEMBER_ADDED_TO_GROUP"]
    for c in creates:
        t = to_dt(c["ts"])
        new_acct = None
        m = re.search(r"NewAccount=(\S+)", c["detail"] or "")
        if m:
            new_acct = m.group(1)
        matches = [g for g in group_adds if g["host"] == c["host"]
                   and re.search(r"Account=" + re.escape(new_acct or ""), g["detail"] or "")
                   and 0 <= (to_dt(g["ts"]) - t).total_seconds() <= 120]
        if matches:
            hour = t.hour
            after_hours = hour < 6 or hour >= 21
            sev = "Critical" if after_hours else "High"
            alerts.append(make_alert(
                matches[0]["ts"], sev, c["host"], c["host"], "new_admin_account", "T1136.001",
                "Persistence",
                f"Account '{new_acct}' created by {c['user']} at {c['ts']} then immediately added "
                f"to an administrative group ({matches[0]['detail']})"
                + (" -- outside business hours" if after_hours else ""),
                "Disable the new account pending review, confirm who requested it through change "
                "management, and audit what that account has accessed since creation.",
                "new_admin_v1", 0.9 if after_hours else 0.75,
            ))
    # Linux equivalent: useradd followed by usermod into sudo
    useradds = [e for e in events if e["event_type"] == "USER_CREATED" and e["source"] == "linux"]
    usermods = [e for e in events if e["event_type"] == "MEMBER_ADDED_TO_GROUP" and e["source"] == "linux"]
    for u in useradds:
        t = to_dt(u["ts"])
        matches = [m for m in usermods if m["host"] == u["host"] and m["user"] == u["user"]
                   and 0 <= (to_dt(m["ts"]) - t).total_seconds() <= 60
                   and "sudo" in (m["detail"] or "")]
        if matches:
            hour = t.hour
            after_hours = hour < 6 or hour >= 21
            alerts.append(make_alert(
                matches[0]["ts"], "Critical" if after_hours else "High", u["host"], u["host"],
                "new_admin_account", "T1136.001", "Persistence",
                f"Linux account '{u['user']}' created then added to the sudo group within a minute"
                + (" -- overnight" if after_hours else ""),
                "Disable the account, confirm business justification, and audit sudoers changes "
                "on this host.",
                "new_admin_v1", 0.85,
            ))
    return alerts


# ---------------------------------------------------------------------------
# 7. Persistence mechanisms
# ---------------------------------------------------------------------------
SUSPICIOUS_PATH_HINTS = ["public", "programdata", "temp", "\\tmp\\", "/tmp/", ".hidden", "appdata"]


def detect_persistence(events):
    alerts = []
    for e in events:
        if e["event_type"] == "SCHEDULED_TASK_CREATED":
            cmd = (e["detail"] or "").lower()
            if any(h in cmd for h in SUSPICIOUS_PATH_HINTS):
                alerts.append(make_alert(
                    e["ts"], "High", e["host"], e["host"], "persistence", "T1053.005",
                    "Persistence",
                    f"Scheduled task '{re.search(r'TaskName=(\\S+)', e['detail']).group(1) if re.search(r'TaskName=(\\S+)', e['detail']) else '?'}' "
                    f"launches a binary from a user-writable path: {e['detail']}",
                    "Delete the scheduled task, quarantine the referenced binary for analysis, and "
                    "check Task Scheduler history for who created it.",
                    "persistence_v1", 0.85,
                ))
        elif e["event_type"] == "SERVICE_INSTALLED":
            cmd = (e["detail"] or "").lower()
            if any(h in cmd for h in SUSPICIOUS_PATH_HINTS):
                alerts.append(make_alert(
                    e["ts"], "High", e["host"], e["host"], "persistence", "T1543.003",
                    "Persistence",
                    f"New Windows service installed pointing at a non-standard path: {e['detail']}",
                    "Stop and delete the service, quarantine the binary, and review recent local "
                    "admin logons on this host.",
                    "persistence_v1", 0.85,
                ))
        elif e["event_type"] == "CRON_JOB":
            cmd = (e["detail"] or "").lower()
            if any(h in cmd for h in SUSPICIOUS_PATH_HINTS):
                alerts.append(make_alert(
                    e["ts"], "High", e["host"], e["host"], "persistence", "T1053.003",
                    "Persistence",
                    f"Cron job runs a script from a hidden/temp directory: {e['detail']}",
                    "Remove the cron entry, quarantine the referenced script, and check "
                    "/etc/cron*, /var/spool/cron for other injected jobs.",
                    "persistence_v1", 0.85,
                ))
        elif e["event_type"] == "AUTHKEYS_MODIFIED":
            alerts.append(make_alert(
                e["ts"], "Medium", e["host"], e["host"], "persistence", "T1098.004",
                "Persistence",
                f"authorized_keys file modified for user '{e['user']}'",
                "Diff the authorized_keys file against the last known-good backup and remove any "
                "unrecognized public key.",
                "persistence_v1", 0.6,
            ))
    return alerts


# ---------------------------------------------------------------------------
# 8. Large outbound transfers
# ---------------------------------------------------------------------------
def detect_large_outbound(events):
    alerts = []
    conns = [e for e in events if e["source"] == "firewall" and e["event_code"] == "ALLOW"]
    if not conns:
        return alerts
    sizes = sorted(e["bytes"] for e in conns)
    p95 = sizes[int(len(sizes) * 0.95)]
    threshold = max(p95 * 3, 400_000_000)
    for e in conns:
        if e["bytes"] >= threshold:
            hour = to_dt(e["ts"]).hour
            after_hours = hour < 6 or hour >= 21
            sev = "Critical" if after_hours else "High"
            alerts.append(make_alert(
                e["ts"], sev, e["src_ip"], e["src_ip"], "large_outbound_transfer", "T1048",
                "Exfiltration",
                f"{e['bytes']/1e6:.0f} MB transferred from {e['src_ip']} to external host {e['dst_ip']} "
                f"on port {e['dst_port']} (baseline p95 for this network is {p95/1e6:.0f} MB)"
                + (" -- outside business hours" if after_hours else ""),
                "Block the destination IP, capture a packet trace if the session is still open, "
                "and identify what data set on the source host could produce a transfer this size.",
                "exfil_v1", 0.85 if after_hours else 0.65,
            ))
    return alerts


DETECTORS = [
    detect_brute_force, detect_powershell, detect_port_scan, detect_impossible_login,
    detect_privesc, detect_new_admin, detect_persistence, detect_large_outbound,
]


def main():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(ALERTS_SCHEMA)
    conn.execute("DELETE FROM alerts")
    events = fetch_all(conn)

    all_alerts = []
    for d in DETECTORS:
        found = d(events)
        print(f"{d.__name__:28s} -> {len(found)} alert(s)")
        all_alerts.extend(found)

    all_alerts.sort(key=lambda a: a["ts"])
    cols = ["ts", "severity", "src_ip", "target_host", "attack_type", "mitre_technique",
            "mitre_tactic", "evidence", "recommended_response", "detector", "confidence"]
    conn.executemany(
        f"INSERT INTO alerts ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})",
        [tuple(a[c] for c in cols) for a in all_alerts],
    )
    conn.commit()

    with open(os.path.join(DATA_DIR, "alerts.json"), "w") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"\nTotal alerts: {len(all_alerts)}")
    conn.close()


if __name__ == "__main__":
    main()
