#!/usr/bin/env python3
"""PrivateFirewall root helper (Linux) — the ONE privileged boundary.

The engine runs as the logged-in user; this helper is spawned ONCE per session
via pkexec (graphical polkit prompt — the Linux analog of the Windows UAC
prompt at launch; no terminal involved) and speaks a line-oriented JSON
protocol on stdin/stdout:

    {"id": 1, "op": "ufw", "args": {"argv": ["status", "verbose"]}}
    {"id": 1, "ok": true, "data": {"rc": 0, "out": "...", "err": ""}}

Design rules, in priority order:
  * NEVER run anything that could disable the firewall. "enable", "disable",
    "reset" and "--dry-run reset" are NOT in the verb whitelist — even a
    compromised or confused engine cannot turn ufw off through this helper.
  * Whitelisted operations only; every argument is validated here (again),
    the engine's validation is not trusted.
  * No shell. Every subprocess call is an argv exec with a timeout.

Ops: ping, ufw (whitelisted verbs), tail (whitelisted log paths),
pids (socket-inode -> process map), sysctl_ipv6, kill (ss -K one connection).
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys

# ufw verbs the helper will execute. Deliberately absent: enable, disable,
# reset, reload (the engine must never toggle the OS firewall on/off — Quick OS
# ships ufw enabled and it stays that way).
UFW_VERBS = {"status", "allow", "deny", "reject", "limit", "delete", "insert",
             "prepend", "default", "app", "--force"}
# --force may only prefix "delete" (non-interactive rule removal).
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.,:/\-]*$|^--force$")
_COMMENT = re.compile(r"^[\w .:\-\[\]()/]{1,120}$")

TAIL_PATHS = ("/var/log/ufw.log", "/var/log/kern.log", "/var/log/syslog")

_UFW = shutil.which("ufw") or "/usr/sbin/ufw"


def _run(argv, timeout=60):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        return {"rc": p.returncode,
                "out": p.stdout.decode("utf-8", "replace"),
                "err": p.stderr.decode("utf-8", "replace")}
    except subprocess.TimeoutExpired:
        return {"rc": 124, "out": "", "err": "timeout"}
    except FileNotFoundError as e:
        return {"rc": 127, "out": "", "err": str(e)}


def validate_ufw_argv(argv):
    """Raise ValueError unless argv is a safe, whitelisted ufw invocation."""
    if not isinstance(argv, list) or not argv or len(argv) > 24:
        raise ValueError("bad argv")
    head = argv[0]
    if head not in UFW_VERBS:
        raise ValueError(f"ufw verb not allowed: {head!r}")
    if head == "--force" and (len(argv) < 2 or argv[1] != "delete"):
        raise ValueError("--force only allowed with delete")
    if head == "default" and len(argv) >= 2 and argv[1] not in (
            "allow", "deny", "reject"):
        raise ValueError("bad default policy")
    comment_next = False
    for tok in argv:
        if not isinstance(tok, str) or not tok:
            raise ValueError("bad token type")
        if comment_next:
            if not _COMMENT.fullmatch(tok):
                raise ValueError("bad comment text")
            comment_next = False
            continue
        if tok == "comment":
            comment_next = True
            continue
        if not _TOKEN.fullmatch(tok):
            raise ValueError(f"bad token: {tok!r}")
    if comment_next:
        raise ValueError("comment without text")


def op_ufw(args):
    argv = args.get("argv")
    validate_ufw_argv(argv)
    return _run([_UFW, *argv])


def op_status(args):
    """verbose + numbered in one round trip (defaults AND rule numbers)."""
    return {"verbose": _run([_UFW, "status", "verbose"]),
            "numbered": _run([_UFW, "status", "numbered"])}


def op_tail(args):
    path = args.get("path", "")
    offset = int(args.get("offset", 0))
    if path not in TAIL_PATHS:
        raise ValueError("path not allowed")
    try:
        size = os.path.getsize(path)
    except OSError:
        return {"data": "", "offset": offset, "size": -1}
    if offset < 0 or offset > size:
        offset = max(0, size - 65536)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)
        data = f.read(1 << 20)
        offset = f.tell()
    return {"data": data, "offset": offset, "size": size}


def op_pids(args):
    """Map socket inodes -> [pid, comm, exe] for the requested inodes."""
    wanted = args.get("inodes")
    if not isinstance(wanted, list) or len(wanted) > 8192:
        raise ValueError("bad inodes")
    wanted = {str(i) for i in wanted if str(i).isdigit()}
    out = {}
    if not wanted:
        return out
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        hit = False
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("socket:["):
                inode = target[8:-1]
                if inode in wanted:
                    if not hit:
                        try:
                            with open(f"/proc/{pid}/comm") as f:
                                comm = f.read().strip()
                        except OSError:
                            comm = f"pid:{pid}"
                        try:
                            exe = os.readlink(f"/proc/{pid}/exe")
                        except OSError:
                            exe = ""
                        hit = True
                    out[inode] = [int(pid), comm, exe]
        if len(out) >= len(wanted):
            break
    return out


NM_IPV6_STATE = "/var/lib/quickopen/private-firewall/ipv6-profiles.json"


def _nm_ipv6(disable):
    """Keep NetworkManager in step with the sysctl (1.0.12, Quick OS laptop
    sweep 2026-08-27). With disable_ipv6=1 and a profile still at
    ipv6.method=auto, NM retried link-local configuration every ~15 s for
    days -- 14,914 "IPv6 is disabled on this device" warnings in one boot.
    Blocking: every wired/Wi-Fi profile at auto/dhcp goes to `disabled` and
    the list is remembered; unblocking restores exactly those to `auto`.
    Best effort: no nmcli (not NM-managed) is not an error."""
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return []
    touched = []
    try:
        if disable:
            out = subprocess.run([nmcli, "-t", "-f", "UUID,TYPE", "connection", "show"],
                                 capture_output=True, text=True, timeout=20).stdout
            for line in out.splitlines():
                uuid, _, ctype = line.partition(":")
                if ctype not in ("802-11-wireless", "802-3-ethernet"):
                    continue
                m = subprocess.run([nmcli, "-g", "ipv6.method", "connection", "show", uuid],
                                   capture_output=True, text=True, timeout=20).stdout.strip()
                if m not in ("auto", "dhcp", "link-local", ""):
                    continue
                r = subprocess.run([nmcli, "connection", "modify", uuid, "ipv6.method", "disabled"],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0:
                    touched.append({"uuid": uuid, "method": m or "auto"})
            os.makedirs(os.path.dirname(NM_IPV6_STATE), exist_ok=True)
            with open(NM_IPV6_STATE, "w") as f:
                json.dump(touched, f)
        else:
            try:
                with open(NM_IPV6_STATE) as f:
                    prev = json.load(f)
            except (OSError, ValueError):
                prev = []
            for ent in prev:
                r = subprocess.run([nmcli, "connection", "modify", ent["uuid"],
                                    "ipv6.method", ent.get("method") or "auto"],
                                   capture_output=True, text=True, timeout=20)
                if r.returncode == 0:
                    touched.append(ent)
            try:
                os.unlink(NM_IPV6_STATE)
            except OSError:
                pass
    except Exception:
        pass
    return touched


def op_sysctl_ipv6(args):
    disable = "1" if args.get("disable") else "0"
    wrote = []
    for key in ("all", "default"):
        path = f"/proc/sys/net/ipv6/conf/{key}/disable_ipv6"
        try:
            with open(path, "w") as f:
                f.write(disable)
            wrote.append(key)
        except OSError as e:
            return {"ok": False, "err": f"{path}: {e}"}
    nm = _nm_ipv6(disable == "1")
    return {"ok": True, "wrote": wrote, "nm_profiles": [t["uuid"] for t in nm]}


def op_kill(args):
    """Terminate ONE TCP connection with ss -K, exact 4-tuple only."""
    laddr = str(ipaddress.ip_address(args["laddr"]))
    raddr = str(ipaddress.ip_address(args["raddr"]))
    lport, rport = int(args["lport"]), int(args["rport"])
    if not (0 < lport < 65536 and 0 < rport < 65536):
        raise ValueError("bad port")
    ss = shutil.which("ss") or "/usr/bin/ss"
    return _run([ss, "-K", "src", laddr, "sport", "=", str(lport),
                 "dst", raddr, "dport", "=", str(rport)])


OPS = {"ping": lambda a: {"pong": True, "uid": os.getuid()},
       "ufw": op_ufw, "status": op_status, "tail": op_tail, "pids": op_pids,
       "sysctl_ipv6": op_sysctl_ipv6, "kill": op_kill}


def handle_line(line):
    rid = None
    try:
        req = json.loads(line)
        rid = req.get("id")
        fn = OPS.get(req.get("op"))
        if fn is None:
            return {"id": rid, "ok": False, "err": "unknown op"}
        return {"id": rid, "ok": True, "data": fn(req.get("args") or {})}
    except Exception as e:  # noqa: BLE001 — protocol boundary, report + carry on
        return {"id": rid, "ok": False, "err": f"{type(e).__name__}: {e}"}


def main():
    # refuse to run without root: nothing here works unprivileged
    if os.getuid() != 0:
        print(json.dumps({"id": None, "ok": False, "err": "not root"}),
              flush=True)
        return 1
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        print(json.dumps(handle_line(line)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
