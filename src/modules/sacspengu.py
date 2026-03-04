#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

MODULE_NAME        = "sacspengu"
MODULE_DESCRIPTION = "Compiler and Binary Analysis suggestor"
MODULE_ROLE        = "COMPILE"

GTFOBINS_COMPILERS = [
    "gcc","g++","cc","c89","c99","make","cmake","ninja",
    "python","python3","python2","perl","ruby","php",
    "java","javac","go","cargo","rustc",
    "as","ld","ar","nm","objdump","strip","readelf",
]


def run(collector):
    log_info  = collector.log_info
    log_ok    = collector.log_ok
    log_verbose = collector.log_verbose
    cu_id     = f"user:{collector._current_user}"

    log_info("Running SACSPengu analysis...")

    found = 0
    for comp in GTFOBINS_COMPILERS:
        path = collector.run(f"which {comp} 2>/dev/null")
        if not path:
            continue
        found += 1
        nid = f"binary:{path.strip()}"
        collector._add_node(nid, "binary", path.strip(), {
            "path": path.strip(), "suid": False, "gtfobin": False, "owner": "root",
        })
        collector._add_finding("POTENTIAL", MODULE_NAME, f"Compiler/interpreter: {comp} -> {path.strip()}", path)
        if comp in ("gcc","g++","cc","make","as"):
            collector._add_edge(cu_id, "SuidBinary", nid, risk="medium",
                                properties={"path": path.strip(), "note": "compiler available"})

    ld_path = collector.run("echo $LD_LIBRARY_PATH")
    if ld_path:
        for ldir in ld_path.split(":"):
            if ldir.strip() and collector.writable(ldir.strip()):
                collector._add_finding("CRITICAL", MODULE_NAME, f"Writable LD_LIBRARY_PATH dir: {ldir}", ldir)

    for ldir in ("/usr/local/lib", "/usr/lib", "/lib", "/opt/lib"):
        if collector.writable(ldir):
            collector._add_finding("CRITICAL", MODULE_NAME, f"Writable library directory: {ldir}", ldir)

    writable_path = 0
    for pdir in collector.run("echo $PATH").split(":"):
        if pdir.strip() and collector.writable(pdir.strip()):
            writable_path += 1
            collector._add_finding("CRITICAL", MODULE_NAME, f"Writable $PATH directory: {pdir}", pdir)

    for bf in collector.run_lines(
        "find /opt /srv /home /var/www /usr/local/src /tmp -maxdepth 4"
        " \\( -name 'Makefile' -o -name 'CMakeLists.txt'"
        " -o -name 'setup.py' -o -name 'Cargo.toml' \\)"
        " 2>/dev/null | head -20"
    ):
        import os
        bdir = os.path.dirname(bf)
        if collector.writable(bdir):
            collector._add_finding("HIGH", MODULE_NAME, f"Writable build directory: {bdir}  ({os.path.basename(bf)})", bdir)
        elif collector.verbose:
            collector.log_verbose(MODULE_NAME, "build file", bf)

    for s in collector.run_lines(
        "find / -perm -4000 \\( -name '*.py' -o -name '*.pl'"
        " -o -name '*.rb' -o -name '*.sh' \\) 2>/dev/null"
    ):
        import os
        nid = f"binary:{s}"
        collector._add_node(nid, "binary", s, {
            "path": s, "suid": True, "gtfobin": True, "owner": "root",
        })
        collector._add_finding("CRITICAL", MODULE_NAME, f"SUID interpreted script: {s}", s)
        collector._add_edge(cu_id, "SuidBinary", nid, risk="critical",
                            properties={"path": s, "note": "SUID interpreted script"})
        collector._add_edge(cu_id, "SuidBinary", "user:root", risk="critical",
                            properties={"via": f"SUID script {s}"})

    caps = collector.run("getcap -r / 2>/dev/null | head -20")
    if caps:
        dangerous = ("cap_setuid","cap_setgid","cap_sys_admin","cap_net_admin","cap_dac_override","cap_fowner")
        for line in caps.splitlines():
            if not line.strip():
                continue
            import os
            cap_path = line.split()[0] if line.split() else ""
            if any(cap in line for cap in dangerous):
                cap_name = os.path.basename(cap_path)
                nid      = f"binary:{cap_path}"
                collector._add_node(nid, "binary", cap_name, {
                    "path": cap_path, "suid": False, "gtfobin": True, "owner": "root",
                })
                collector._add_finding("CRITICAL", MODULE_NAME, f"Dangerous capability: {line.strip()}", line)
                collector._add_edge(cu_id, "SuidBinary", nid, risk="critical",
                                    properties={"capability": line.strip()})
                collector._add_edge(cu_id, "SuidBinary", "user:root", risk="critical",
                                    properties={"via": f"capability {cap_name}"})
            elif collector.verbose:
                collector.log_verbose(MODULE_NAME, "capability", line.strip())

    log_ok(f"Compilers: {found}  |  Writable PATH dirs: {writable_path}  |  Capabilities scanned")
