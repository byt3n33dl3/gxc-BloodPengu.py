#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import os

MODULE_NAME        = "avrisk"
MODULE_DESCRIPTION = "Anti-Virus Discovery!!"
MODULE_ROLE        = "RECON"

AV_SIGNATURES = [
    ("clamav",          ["clamscan","clamd","freshclam","clamav"],         ["clamav","clamav-daemon","clamav-freshclam"]),
    ("sophos",          ["sophossps","savd","savscand"],                   ["sophos-spl","sav-protect"]),
    ("eset",            ["esets_daemon","esets_scan","eset"],              ["eset"]),
    ("kaspersky",       ["kesl","kesl-control","kavscanner"],              ["kesl"]),
    ("trend",           ["ds_agent","ds_notifier","trendmicro"],          ["ds_agent"]),
    ("crowdstrike",     ["falcon-sensor","falcond","csagent"],             ["falcon-sensor"]),
    ("sentinelone",     ["sentineld","sentinelagent","s1agent"],           ["sentinelone"]),
    ("carbon_black",    ["cbdaemon","cb","cbsensor"],                     ["cb-psc-sensor"]),
    ("cylance",         ["cylancesvc","cyoptics"],                        ["cylance"]),
    ("mcafee",          ["masvc","mfetpd","nails","nailsd"],              ["mcafee-ens-tp","mcafee-msc"]),
    ("symantec",        ["sisman","sisips","rtvscand","navapsvc"],        ["symantec-endpoint-protection"]),
    ("fireeye",         ["xagt","fireeye-agent","hx"],                    ["fireeye-hx-agent"]),
    ("palo_alto",       ["traps","cortex-xdr","cyserver"],                ["cortex-xdr"]),
    ("bitdefender",     ["bdnsd","bdservicehost","bdscan"],               ["bitdefender"]),
    ("comodo",          ["cmdavd","cmdmgd","comodo"],                     ["comodo"]),
    ("f_secure",        ["fsav","fsupdate","fssm32"],                     ["f-secure-gam","f-secure-linuxsecurity"]),
    ("avg",             ["avgscan","avgd","avgdiag"],                     ["avg"]),
    ("avast",           ["avast","avastd"],                               ["avast"]),
    ("malwarebytes",    ["mbam","mbamd"],                                 ["malwarebytes"]),
    ("wazuh",           ["wazuh-agentd","ossec-agentd","wazuh"],         ["wazuh-agent"]),
    ("ossec",           ["ossec-agentd","ossec-analysisd","ossec"],      ["ossec-hids"]),
    ("auditd",          ["auditd","audispd"],                             ["auditd"]),
    ("aide",            ["aide"],                                         ["aide"]),
    ("tripwire",        ["tripwire","twadmin"],                           ["tripwire"]),
    ("rkhunter",        ["rkhunter"],                                     []),
    ("chkrootkit",      ["chkrootkit"],                                   []),
    ("lynis",           ["lynis"],                                        []),
    ("apparmor",        ["apparmor","aa-status","aad"],                   ["apparmor"]),
    ("selinux",         ["getenforce","setenforce","sestatus"],           []),
    ("seccomp",         [],                                               []),
    ("fail2ban",        ["fail2ban-client","fail2ban-server"],            ["fail2ban"]),
    ("snort",           ["snort"],                                        ["snort"]),
    ("suricata",        ["suricata"],                                     ["suricata"]),
    ("zeek",            ["zeek","bro"],                                   ["zeek"]),
]

SECURITY_PATHS = [
    "/opt/sophos-spl",
    "/opt/CrowdStrike",
    "/opt/sentinelone",
    "/opt/carbonblack",
    "/opt/cylance",
    "/Library/CS",
    "/opt/McAfee",
    "/opt/Symantec",
    "/opt/fireeye",
    "/opt/traps",
    "/opt/BitDefender",
    "/opt/f-secure",
    "/opt/eset",
    "/opt/kaspersky",
    "/var/ossec",
    "/var/lib/aide",
    "/etc/tripwire",
    "/etc/clamav",
    "/etc/apparmor",
    "/etc/apparmor.d",
    "/etc/selinux",
    "/etc/fail2ban",
]


def run(collector):
    cu_id = f"user:{collector._current_user}"

    collector.log_info("Running AVRisk...")

    detected = []

    ps_out      = collector.run("ps aux 2>/dev/null || ps -ef 2>/dev/null")
    svc_out     = collector.run("systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null")
    which_cache = {}

    for av_name, proc_names, svc_names in AV_SIGNATURES:
        found_procs = []
        found_svcs  = []
        found_paths = []
        found_bins  = []

        for proc in proc_names:
            if proc and proc in ps_out.lower():
                found_procs.append(proc)
            if proc not in which_cache:
                which_cache[proc] = collector.run(f"which {proc} 2>/dev/null").strip()
            if which_cache[proc]:
                found_bins.append(which_cache[proc])

        for svc in svc_names:
            if svc and svc in svc_out.lower():
                found_svcs.append(svc)

        for path in SECURITY_PATHS:
            if av_name.replace("_", "-") in path.lower() or av_name.replace("_", "") in path.lower():
                if collector.run(f"[ -d '{path}' ] && echo YES || echo NO").strip() == "YES":
                    found_paths.append(path)

        if found_procs or found_svcs or found_paths or found_bins:
            detected.append({
                "name":       av_name,
                "processes":  found_procs,
                "services":   found_svcs,
                "paths":      found_paths,
                "binaries":   list(set(found_bins)),
            })

    for apparmor_check in ["aa-status 2>/dev/null", "apparmor_status 2>/dev/null"]:
        aa_out = collector.run(apparmor_check)
        if aa_out and ("profiles are loaded" in aa_out or "apparmor" in aa_out.lower()):
            collector._add_finding("HIGH", MODULE_NAME,
                f"AppArmor active: {aa_out.splitlines()[0].strip()[:80]}", aa_out[:200])
            break

    se_out = collector.run("getenforce 2>/dev/null || sestatus 2>/dev/null | head -1")
    if se_out:
        mode = se_out.strip().lower()
        if "enforcing" in mode:
            collector._add_finding("HIGH", MODULE_NAME, f"SELinux active: Enforcing mode", se_out)
        elif "permissive" in mode:
            collector._add_finding("POTENTIAL", MODULE_NAME, f"SELinux present: Permissive mode (not blocking)", se_out)
        elif "disabled" not in mode and se_out.strip():
            collector._add_finding("POTENTIAL", MODULE_NAME, f"SELinux status: {se_out.strip()[:80]}", se_out)

    seccomp_out = collector.run("grep Seccomp /proc/self/status 2>/dev/null")
    if seccomp_out:
        val = seccomp_out.split(":")[-1].strip()
        if val == "2":
            collector._add_finding("HIGH", MODULE_NAME, "Seccomp: filter mode active (strict syscall filtering)", seccomp_out)
        elif val == "1":
            collector._add_finding("POTENTIAL", MODULE_NAME, "Seccomp: strict mode active", seccomp_out)

    audit_rules = collector.run("auditctl -l 2>/dev/null | head -10")
    if audit_rules and "-a" in audit_rules:
        collector._add_finding("HIGH", MODULE_NAME,
            f"Auditd active with rules loaded - activity may be logged", audit_rules[:200])
    elif collector.run("systemctl is-active auditd 2>/dev/null").strip() == "active":
        collector._add_finding("POTENTIAL", MODULE_NAME, "Auditd service is running - check rules with auditctl -l")

    inotify_watches = collector.run("find /proc/*/fd -lname 'anon_inode:inotify' 2>/dev/null | wc -l").strip()
    if inotify_watches and int(inotify_watches) > 10:
        collector._add_finding("POTENTIAL", MODULE_NAME,
            f"High inotify watch count ({inotify_watches}) - possible filesystem monitoring active", inotify_watches)

    nid_av = "network:av_summary"
    collector._add_node(nid_av, "network", "av_summary", {
        "detected_count": len(detected),
        "detected":       [d["name"] for d in detected],
    })

    for av in detected:
        av_node_id = f"binary:av_{av['name']}"
        detail_parts = []
        if av["processes"]:
            detail_parts.append(f"procs={','.join(av['processes'])}")
        if av["services"]:
            detail_parts.append(f"svcs={','.join(av['services'])}")
        if av["binaries"]:
            detail_parts.append(f"bins={','.join(av['binaries'])}")
        if av["paths"]:
            detail_parts.append(f"paths={','.join(av['paths'])}")
        detail = "  ".join(detail_parts)

        collector._add_node(av_node_id, "binary", av["name"], {
            "path":      av["binaries"][0] if av["binaries"] else "",
            "suid":      False,
            "gtfobin":   False,
            "owner":     "root",
            "av_vendor": av["name"],
            "processes": av["processes"],
            "services":  av["services"],
        })

        collector._add_finding("HIGH", MODULE_NAME,
            f"Security software detected: {av['name'].upper()}  ({detail})",
            str(av))

        collector._add_edge(cu_id, "MemberOf", av_node_id, risk="high",
                            properties={"note": f"{av['name']} detected on host"})

    log_lines = collector.run_lines(
        "find /var/log -maxdepth 2 -name '*.log' -newer /etc/passwd 2>/dev/null | head -20"
    )
    active_logs = []
    for lf in log_lines:
        size = collector.run(f"stat -c '%s' '{lf}' 2>/dev/null").strip()
        if size and size.isdigit() and int(size) > 0:
            active_logs.append(lf)
    if active_logs:
        collector._add_finding("POTENTIAL", MODULE_NAME,
            f"Active log files found ({len(active_logs)}) : review for credential or activity capture",
            "\n".join(active_logs[:10]))

    if not detected:
        collector._add_finding("POTENTIAL", MODULE_NAME,
            "No known AV/EDR detected, host may be unprotected or using unknown security software")

    collector.log_ok(f"Security products detected: {len(detected)}  |  Products: {', '.join(d['name'] for d in detected) or 'none'}")
