#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

RESET   = "\033[0m"
BRED    = "\033[1;31m"
BORANGE = "\033[1;33m"
ORANGE  = "\033[0;33m"
WHITE   = "\033[1;37m"
GREY    = "\033[0;37m"
DGREY   = "\033[2;37m"
BGREEN  = "\033[1;32m"


def _c(color, text):
    return f"{color}{text}{RESET}"


def _info(msg):
    print(f"  {_c(BORANGE, '[*]')}  {_c(WHITE, msg)}")


def _ok(msg):
    print(f"  {_c(BGREEN, '[+]')}  {_c(WHITE, msg)}")


def _find(tier, detail, raw=""):
    if tier == "CRITICAL":
        ts = _c(BRED,    "[CRITICAL ]")
    elif tier == "HIGH":
        ts = _c(BORANGE, "[HIGH     ]")
    else:
        ts = _c(ORANGE,  "[POTENTIAL]")
    print(f"  {ts}  {_c(BORANGE, 'mi6           ')}  {_c(WHITE, detail)}")


def run(collector):
    _info("mi6 stealth mode engaging...")
    cu      = collector._current_user
    cu_id   = f"user:{cu}"
    kernel  = collector._kernel or collector.run("uname -r").strip()
    ops     = []

    _flush_bash_history(collector, cu_id, kernel, ops)
    _suppress_syslog_trace(collector, cu_id, kernel, ops)
    _mask_process_argv(collector, cu_id, kernel, ops)
    _check_auditd(collector, cu_id, kernel, ops)
    _check_siem_agents(collector, cu_id, kernel, ops)
    _check_wtmp_utmp(collector, cu_id, kernel, ops)
    _encode_surface(collector, cu_id, kernel, ops)
    _check_inotify_watchers(collector, cu_id, kernel, ops)
    _check_ps_masking(collector, cu_id, kernel, ops)

    _ok(f"mi6 complete  |  stealth ops assessed: {len(ops)}")


def _flush_bash_history(collector, cu_id, kernel, ops):
    _info("Checking shell history controls...")

    histfile   = collector.run("echo $HISTFILE").strip()
    histsize   = collector.run("echo $HISTSIZE").strip()
    histfilesz = collector.run("echo $HISTFILESIZE").strip()

    ops.append("history-env")

    if histfile in ("", "/dev/null"):
        collector._add_finding("POTENTIAL", "mi6",
            "HISTFILE is unset or pointed at /dev/null - history already suppressed",
            histfile)
        _find("POTENTIAL", "HISTFILE unset or /dev/null - history suppressed")
    else:
        collector._add_finding("POTENTIAL", "mi6",
            f"HISTFILE active: {histfile}  |  set HISTFILE=/dev/null to suppress future writes",
            histfile)
        _find("POTENTIAL", f"HISTFILE active: {histfile}")

    if histsize == "0":
        collector._add_finding("POTENTIAL", "mi6",
            "HISTSIZE=0 - in-memory history disabled", histsize)
        _find("POTENTIAL", "HISTSIZE=0 detected")

    for shell_rc in ("/root/.bashrc", f"/home/{collector._current_user}/.bashrc",
                     "/root/.zshrc",  f"/home/{collector._current_user}/.zshrc"):
        rc_content = collector.run(f"cat '{shell_rc}' 2>/dev/null | grep -iE '(HISTFILE|HISTSIZE|HISTCONTROL|unset hist)' | head -5")
        if rc_content:
            collector._add_finding("POTENTIAL", "mi6",
                f"History control directives in {shell_rc}: {rc_content.strip()[:120]}",
                rc_content)
            _find("POTENTIAL", f"History control in {shell_rc}")
            ops.append(f"history-rc:{shell_rc}")

    zsh_hist = collector.run(f"ls -la /root/.zsh_history /home/{collector._current_user}/.zsh_history 2>/dev/null")
    bash_hist = collector.run(f"ls -la /root/.bash_history /home/{collector._current_user}/.bash_history 2>/dev/null")
    for hist_entry in [zsh_hist, bash_hist]:
        for line in hist_entry.splitlines():
            if "->" in line and "/dev/null" in line:
                collector._add_finding("POTENTIAL", "mi6",
                    f"History file symlinked to /dev/null: {line.strip()}",
                    line)
                _find("POTENTIAL", f"History symlink to /dev/null: {line.strip()[:60]}")
                ops.append("history-symlink")


def _suppress_syslog_trace(collector, cu_id, kernel, ops):
    _info("Checking syslog and journal exposure...")
    ops.append("syslog")

    rsyslog_conf = collector.run("cat /etc/rsyslog.conf 2>/dev/null | head -20").strip()
    syslog_ng    = collector.run("cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null | head -10").strip()
    journal_conf = collector.run("cat /etc/systemd/journald.conf 2>/dev/null").strip()

    if rsyslog_conf:
        collector._add_finding("POTENTIAL", "mi6",
            "rsyslog active: /etc/rsyslog.conf present  |  commands may log to syslog",
            rsyslog_conf[:200])
        _find("POTENTIAL", "rsyslog active - SSH commands may appear in /var/log/auth.log")

    if syslog_ng:
        collector._add_finding("POTENTIAL", "mi6",
            "syslog-ng active  |  review forwarding destinations",
            syslog_ng[:200])
        _find("POTENTIAL", "syslog-ng present")

    if journal_conf:
        storage_line = [l for l in journal_conf.splitlines() if "Storage=" in l]
        if storage_line:
            collector._add_finding("POTENTIAL", "mi6",
                f"journald Storage: {storage_line[0].strip()}",
                storage_line[0])
            _find("POTENTIAL", f"journald: {storage_line[0].strip()}")
        compress_line = [l for l in journal_conf.splitlines() if "Compress=" in l]
        if not compress_line:
            collector._add_finding("POTENTIAL", "mi6",
                "journald Compress not explicitly set - logs stored uncompressed",
                journal_conf[:100])

    remote_syslog = collector.run(
        "grep -rE '(@|@@)[0-9a-zA-Z]' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | head -5"
    ).strip()
    if remote_syslog:
        collector._add_finding("HIGH", "mi6",
            f"Remote syslog forwarding configured: {remote_syslog[:120]}  |  logs leave host in real time",
            remote_syslog)
        _find("HIGH", f"Remote syslog forwarding: {remote_syslog[:60]}")
        ops.append("remote-syslog")


def _mask_process_argv(collector, cu_id, kernel, ops):
    _info("Checking process argv masking surface...")
    ops.append("proc-argv")

    proc_hidepid = collector.run(
        "mount | grep 'proc ' | grep -o 'hidepid=[0-9]'"
    ).strip()
    if proc_hidepid:
        collector._add_finding("POTENTIAL", "mi6",
            f"/proc mounted with {proc_hidepid}  |  other users cannot enumerate process args",
            proc_hidepid)
        _find("POTENTIAL", f"/proc hidepid={proc_hidepid[-1]} - process args hidden from other users")
    else:
        collector._add_finding("POTENTIAL", "mi6",
            "/proc mounted without hidepid  |  any user can read /proc/*/cmdline - your args are visible",
            "")
        _find("POTENTIAL", "/proc no hidepid - process argv visible to all users on system")

    cmdline_self = collector.run("cat /proc/self/cmdline 2>/dev/null | tr '\\0' ' '").strip()
    if cmdline_self:
        collector._add_finding("POTENTIAL", "mi6",
            f"Current process cmdline visible: {cmdline_self[:120]}",
            cmdline_self[:120])

    prctl_check = collector.run(
        "cat /proc/sys/kernel/dmesg_restrict 2>/dev/null"
    ).strip()
    if prctl_check == "0":
        collector._add_finding("POTENTIAL", "mi6",
            "dmesg_restrict=0 - dmesg readable by unprivileged users  |  kernel messages exposed",
            prctl_check)
        _find("POTENTIAL", "dmesg_restrict=0 - kernel ring buffer readable by any user")
        ops.append("dmesg-exposed")


def _check_auditd(collector, cu_id, kernel, ops):
    _info("Checking auditd / syscall audit coverage...")
    ops.append("auditd")

    auditd_running = collector.run("systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | head -1").strip()
    auditd_rules   = collector.run("auditctl -l 2>/dev/null | head -20").strip()
    audit_conf     = collector.run("cat /etc/audit/auditd.conf 2>/dev/null | head -20").strip()

    if "active" in auditd_running.lower() or "running" in auditd_running.lower():
        collector._add_finding("HIGH", "mi6",
            f"auditd is running  |  syscall activity and file access are being logged",
            auditd_running)
        _find("HIGH", "auditd running - syscall events are being audited")
        ops.append("auditd-active")

        if auditd_rules:
            rule_count = len([r for r in auditd_rules.splitlines() if r.strip() and not r.startswith("#")])
            collector._add_finding("HIGH", "mi6",
                f"auditd has {rule_count} active rules  |  review before collection to avoid triggering alerts",
                auditd_rules[:300])
            _find("HIGH", f"auditd: {rule_count} active rules loaded")

            for line in auditd_rules.splitlines():
                if any(kw in line for kw in ("-w /etc/passwd", "-w /etc/shadow",
                                              "-w /etc/sudoers", "execve", "-w /var/log")):
                    collector._add_finding("HIGH", "mi6",
                        f"Sensitive audit rule watching collector targets: {line.strip()}",
                        line)
                    _find("HIGH", f"Audit rule covers collector path: {line.strip()[:80]}")

        log_max = ""
        if audit_conf:
            for line in audit_conf.splitlines():
                if "log_file" in line.lower():
                    collector._add_finding("POTENTIAL", "mi6",
                        f"auditd log destination: {line.strip()}",
                        line)
                if "max_log_file_action" in line.lower():
                    log_max = line.strip()
            if log_max:
                collector._add_finding("POTENTIAL", "mi6",
                    f"auditd max_log_file_action: {log_max}",
                    log_max)
    else:
        collector._add_finding("POTENTIAL", "mi6",
            "auditd not detected as running  |  syscall auditing likely inactive",
            auditd_running)
        _find("POTENTIAL", "auditd not running - syscall audit coverage absent")


def _check_siem_agents(collector, cu_id, kernel, ops):
    _info("Checking for EDR / SIEM agent processes...")
    ops.append("edr-siem")

    KNOWN_AGENTS = [
        ("osquery",       "HIGH",     "osquery daemon - SQL-based host monitoring active"),
        ("osqueryd",      "HIGH",     "osquery daemon - SQL-based host monitoring active"),
        ("auditbeats",    "HIGH",     "Elastic Auditbeat - syscall and file event forwarding"),
        ("filebeat",      "HIGH",     "Elastic Filebeat - log forwarding agent"),
        ("metricbeat",    "POTENTIAL","Elastic Metricbeat - system metrics collector"),
        ("winlogbeat",    "POTENTIAL","Winlogbeat agent"),
        ("packetbeat",    "HIGH",     "Elastic Packetbeat - network traffic analysis active"),
        ("fluentd",       "HIGH",     "fluentd log aggregator forwarding to SIEM"),
        ("fluent-bit",    "HIGH",     "fluent-bit log forwarder"),
        ("splunkd",       "HIGH",     "Splunk universal forwarder - logs and events leaving host"),
        ("nxlog",         "HIGH",     "NXLog log shipping agent"),
        ("syslog-ng",     "POTENTIAL","syslog-ng forwarding agent"),
        ("rsyslogd",      "POTENTIAL","rsyslogd active"),
        ("falco",         "HIGH",     "Falco runtime security - process and syscall detection active"),
        ("sysdig",        "HIGH",     "sysdig system call tracer active - deep process monitoring"),
        ("wazuh",         "HIGH",     "Wazuh HIDS agent - file integrity and log monitoring"),
        ("ossec",         "HIGH",     "OSSEC HIDS agent active"),
        ("crowdstrike",   "CRITICAL", "CrowdStrike Falcon sensor detected"),
        ("falcon-sensor", "CRITICAL", "CrowdStrike Falcon sensor process active"),
        ("cylance",       "CRITICAL", "Cylance endpoint protection active"),
        ("cb-defense",    "CRITICAL", "Carbon Black Defense endpoint agent"),
        ("cbsensor",      "CRITICAL", "Carbon Black sensor"),
        ("sentinelone",   "CRITICAL", "SentinelOne endpoint agent detected"),
        ("s1agent",       "CRITICAL", "SentinelOne agent process active"),
        ("qualys-cloud",  "HIGH",     "Qualys Cloud Agent - vulnerability scanner with log forwarding"),
        ("nessus",        "HIGH",     "Nessus agent running on host"),
        ("tenable",       "HIGH",     "Tenable agent active"),
        ("lacework",      "HIGH",     "Lacework agent - cloud security monitoring"),
        ("sysdig-probe",  "HIGH",     "sysdig kernel probe module loaded"),
        ("darktrace",     "HIGH",     "Darktrace network sensor active"),
        ("vectra",        "HIGH",     "Vectra AI network detection agent"),
        ("tanium",        "HIGH",     "Tanium endpoint agent active"),
        ("bigfix",        "POTENTIAL","IBM BigFix endpoint management agent"),
    ]

    ps_out = collector.run("ps aux 2>/dev/null || ps -ef 2>/dev/null").strip().lower()

    detected = []
    for proc_name, tier, desc in KNOWN_AGENTS:
        if proc_name.lower() in ps_out:
            collector._add_finding(tier, "mi6",
                f"Agent detected in process list: {proc_name}  |  {desc}",
                proc_name)
            _find(tier, f"{proc_name}: {desc}")
            detected.append(proc_name)
            ops.append(f"agent:{proc_name}")

    service_check = collector.run(
        "systemctl list-units --type=service --state=running 2>/dev/null | grep -iE"
        " '(osquery|falcon|sentinel|crowdstrike|wazuh|ossec|sysdig|falco|auditbeat|filebeat|splunk)'"
    ).strip()
    if service_check:
        for line in service_check.splitlines():
            svc = line.strip()
            if svc:
                collector._add_finding("HIGH", "mi6",
                    f"Security service unit active: {svc}",
                    svc)
                _find("HIGH", f"Security service unit: {svc[:80]}")

    if not detected and not service_check:
        collector._add_finding("POTENTIAL", "mi6",
            "No known EDR or SIEM agent processes detected in process list",
            "")
        _find("POTENTIAL", "No known EDR/SIEM agents in process list")


def _check_wtmp_utmp(collector, cu_id, kernel, ops):
    _info("Checking login record files...")
    ops.append("wtmp-utmp")

    for logf in ("/var/log/wtmp", "/var/log/btmp", "/var/run/utmp", "/var/log/lastlog"):
        perms = collector.run(f"stat -c '%a %U %G' '{logf}' 2>/dev/null").strip()
        if perms:
            collector._add_finding("POTENTIAL", "mi6",
                f"Login record file: {logf}  perms: {perms}  |  login sessions tracked here",
                perms)

    last_out = collector.run("last -5 2>/dev/null | head -10").strip()
    if last_out:
        collector._add_finding("POTENTIAL", "mi6",
            f"Recent login records (last -5): {last_out[:200]}",
            last_out[:200])
        _find("POTENTIAL", "Login history present in wtmp - session records visible")

    auth_log_readable = collector.run("cat /var/log/auth.log 2>/dev/null | tail -5").strip() or \
                        collector.run("cat /var/log/secure 2>/dev/null | tail -5").strip()
    if auth_log_readable:
        collector._add_finding("HIGH", "mi6",
            "auth.log or /var/log/secure readable - SSH authentication events visible to current user",
            auth_log_readable[:200])
        _find("HIGH", "auth.log readable - SSH session events exposed")
        ops.append("auth-log-readable")


def _encode_surface(collector, cu_id, kernel, ops):
    _info("Checking command encoding and obfuscation surface...")
    ops.append("encode-surface")

    for enc_bin in ("base64", "xxd", "od", "openssl", "python3", "python", "perl", "ruby"):
        path = collector.run(f"which {enc_bin} 2>/dev/null").strip()
        if path:
            collector._add_finding("POTENTIAL", "mi6",
                f"Encoding binary available: {path}  |  pipe collector output through {enc_bin} to reduce plaintext artifact",
                path)

    tmpfs_check = collector.run("mount | grep -E 'tmpfs.*(tmp|shm|run)' | head -5").strip()
    if tmpfs_check:
        collector._add_finding("POTENTIAL", "mi6",
            f"tmpfs mounts available for non-persistent staging: {tmpfs_check.splitlines()[0].strip()}",
            tmpfs_check)
        _find("POTENTIAL", "tmpfs available - stage files in memory-backed filesystem to avoid disk writes")
        ops.append("tmpfs-available")

    dev_shm = collector.run("ls -la /dev/shm 2>/dev/null").strip()
    if dev_shm:
        collector._add_finding("POTENTIAL", "mi6",
            f"/dev/shm accessible  |  memory-only staging directory, evades disk forensics",
            dev_shm)
        _find("POTENTIAL", "/dev/shm writable - use for in-memory file staging")
        ops.append("dev-shm-accessible")

    proc_mem = collector.run("[ -w /proc/self/mem ] && echo YES || echo NO").strip()
    if proc_mem == "YES":
        collector._add_finding("HIGH", "mi6",
            "/proc/self/mem writable  |  direct process memory write without exec - shellcode injection surface",
            "")
        _find("HIGH", "/proc/self/mem writable - memory injection without execve")
        ops.append("proc-mem-writable")


def _check_inotify_watchers(collector, cu_id, kernel, ops):
    _info("Checking inotify filesystem watchers...")
    ops.append("inotify")

    max_watches = collector.run("cat /proc/sys/fs/inotify/max_user_watches 2>/dev/null").strip()
    current_watches = collector.run(
        "find /proc/*/fd -lname 'anon_inode:inotify' 2>/dev/null | wc -l"
    ).strip()

    if current_watches and int(current_watches) > 0:
        collector._add_finding("HIGH", "mi6",
            f"Active inotify watchers: {current_watches}  |  filesystem events are being monitored by running processes",
            current_watches)
        _find("HIGH", f"inotify: {current_watches} active watchers - filesystem access may be triggering alerts")
        ops.append("inotify-active")

        watcher_procs = collector.run(
            "find /proc/*/fd -lname 'anon_inode:inotify' 2>/dev/null"
            " | awk -F/ '{print $3}' | xargs -I{} cat /proc/{}/cmdline 2>/dev/null"
            " | tr '\\0' ' ' | head -10"
        ).strip()
        if watcher_procs:
            collector._add_finding("HIGH", "mi6",
                f"Processes holding inotify watches: {watcher_procs[:200]}",
                watcher_procs[:200])
            _find("HIGH", f"inotify watcher processes: {watcher_procs[:80]}")
    else:
        collector._add_finding("POTENTIAL", "mi6",
            "No active inotify watchers detected",
            "")
        _find("POTENTIAL", "No inotify watchers active - filesystem access likely unmonitored")


def _check_ps_masking(collector, cu_id, kernel, ops):
    _info("Checking process visibility and masking options...")
    ops.append("ps-mask")

    mount_proc = collector.run("cat /proc/mounts 2>/dev/null | grep '^proc '").strip()
    if mount_proc:
        if "hidepid=2" in mount_proc:
            collector._add_finding("POTENTIAL", "mi6",
                f"/proc mounted hidepid=2 - process table completely hidden from other users: {mount_proc}",
                mount_proc)
            _find("POTENTIAL", "/proc hidepid=2 - full process isolation active")
        elif "hidepid=1" in mount_proc:
            collector._add_finding("POTENTIAL", "mi6",
                f"/proc mounted hidepid=1 - process names visible but not args: {mount_proc}",
                mount_proc)
            _find("POTENTIAL", "/proc hidepid=1 - process args hidden but names visible")
        else:
            collector._add_finding("POTENTIAL", "mi6",
                f"/proc mounted without hidepid - full process table readable by all users: {mount_proc}",
                mount_proc)
            _find("POTENTIAL", "/proc no hidepid - all user process argv fully visible")

    pid_ns = collector.run("readlink /proc/self/ns/pid 2>/dev/null").strip()
    if pid_ns:
        collector._add_finding("POTENTIAL", "mi6",
            f"PID namespace: {pid_ns}  |  non-root namespace may limit process visibility from host",
            pid_ns)

    strace_avail = collector.run("which strace 2>/dev/null").strip()
    if strace_avail:
        collector._add_finding("POTENTIAL", "mi6",
            f"strace available at {strace_avail}  |  process syscall tracing possible - also detectable",
            strace_avail)
