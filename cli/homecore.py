#!/usr/bin/env python3
"""HomeCore OS — terminal control centre.

Standard library only (no pip installs). Read-only views run directly; anything
that changes the system is delegated to the audited shell scripts in
/opt/homecore/scripts and runs through sudo. User input is never passed through
a shell (subprocess argument lists only).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

CLI_DIR = os.path.dirname(os.path.realpath(__file__))
HC_ROOT = os.environ.get("HC_ROOT", "/opt/homecore")
HC_ETC = os.environ.get("HC_ETC", "/etc/homecore")
SCRIPTS = os.path.join(HC_ROOT, "scripts")
UNITS = {"ssh": "ssh", "tailscale": "tailscaled", "mdns": "avahi-daemon",
         "discover": "homecore-discover", "scan": "homecore-scan"}
SEV_COLOR = {"critical": lambda s: _c("1;31", s), "high": lambda s: _c("31", s),
             "medium": lambda s: _c("33", s), "low": lambda s: _c("36", s), "info": lambda s: _c("2", s)}


def _mod(name: str):
    """Import helper modules only when needed (faster start on a Pi 3B)."""
    if CLI_DIR not in sys.path:
        sys.path.insert(0, CLI_DIR)
    return __import__(name)


def guard_module():
    return _mod("homecore_guard")


def scan_module():
    return _mod("homecore_scan")


def safe(text, limit: int = 60) -> str:
    """Neutralise device-supplied text before printing it: strips ANSI/terminal escape
    sequences, invisible and control characters, chat-template tokens (prompt injection)."""
    return guard_module().sanitize(str(text or ""), max_len=limit)


# --------------------------------------------------------------------------- output
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def bold(s): return _c("1", s)
def dim(s): return _c("2", s)
def green(s): return _c("32", s)
def yellow(s): return _c("33", s)
def red(s): return _c("31", s)
def cyan(s): return _c("36", s)


def header(title: str) -> None:
    print("\n" + bold(cyan(f"── {title} ")) + cyan("─" * max(0, 56 - len(title))))


def kv(key: str, value: str) -> None:
    print(f"  {dim(key.ljust(20))} {value}")


def human(n: float) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


# --------------------------------------------------------------------------- process helpers
class Result:
    __slots__ = ("code", "out", "err")

    def __init__(self, code: int, out: str, err: str):
        self.code, self.out, self.err = code, out, err

    @property
    def ok(self) -> bool:
        return self.code == 0


def is_root() -> bool:
    return os.geteuid() == 0


def run(cmd: list[str], sudo: bool = False, capture: bool = True, timeout: int | None = 60) -> Result:
    if sudo and not is_root():
        cmd = ["sudo", "--", *cmd]
    try:
        p = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
        return Result(p.returncode, p.stdout or "", p.stderr or "")
    except FileNotFoundError:
        return Result(127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return Result(124, "", "timed out")
    except KeyboardInterrupt:
        return Result(130, "", "interrupted")


def script(name: str, *args: str) -> int:
    path = os.path.join(SCRIPTS, name)
    if not os.path.exists(path):
        print(red(f"Missing {path} — is HomeCore installed?"))
        return 1
    return run([path, *args], sudo=True, capture=False, timeout=None).code


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def read(path: str, default: str = "") -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return default


def read_env(path: str) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in read(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def ensure_root(argv: list[str]) -> None:
    """Re-run this command through sudo when root is needed (e.g. reading secrets/sshd -T)."""
    if not is_root():
        os.execvp("sudo", ["sudo", "--", sys.executable, "-I", os.path.realpath(__file__), *argv])


# --------------------------------------------------------------------------- system facts
def meminfo() -> dict[str, int]:
    info = {}
    for line in read("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            info[parts[0].rstrip(":")] = int(parts[1]) * 1024
    return info


def platform_desc() -> str:
    model = read("/proc/device-tree/model").replace("\x00", "").strip()
    if model:
        return model
    virt = run(["systemd-detect-virt"]).out.strip()
    return f"virtual machine ({virt})" if virt and virt != "none" else "bare metal"


def os_name() -> str:
    for line in read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip('"')
    return "unknown"


def interfaces() -> list[dict]:
    r = run(["ip", "-j", "addr", "show"])
    try:
        data = json.loads(r.out) if r.ok else []
    except ValueError:
        data = []
    out = []
    for iface in data:
        if iface.get("ifname") == "lo":
            continue
        addrs = [f"{a['local']}/{a['prefixlen']}" for a in iface.get("addr_info", [])
                 if a.get("scope") != "link"]
        out.append({"name": iface.get("ifname"), "state": iface.get("operstate", "?"),
                    "mac": iface.get("address", ""), "addrs": addrs})
    return out


def top_memory(n: int = 6) -> list[tuple[int, str]]:
    """Largest processes by resident memory, straight from /proc (no ps needed)."""
    procs = []
    for pid in filter(str.isdigit, os.listdir("/proc")):
        status = read(f"/proc/{pid}/status")
        m = re.search(r"^VmRSS:\s+(\d+) kB", status, re.M)
        name = re.search(r"^Name:\s+(.+)$", status, re.M)
        if m and name:
            procs.append((int(m.group(1)) * 1024, name.group(1)))
    agg: dict[str, int] = {}
    for rss, name in procs:
        agg[name] = agg.get(name, 0) + rss
    return sorted(((v, k) for k, v in agg.items()), reverse=True)[:n]


def _decode_addr(hexaddr: str) -> str:
    raw = bytes.fromhex(hexaddr)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1])
    return socket.inet_ntop(socket.AF_INET6, b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))


def listening_sockets() -> list[dict]:
    """Parse /proc/net/{tcp,udp}{,6} — no external tools needed."""
    inode_to_proc: dict[str, str] = {}
    if is_root():
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                comm = read(f"/proc/{pid}/comm").strip()
                for fd in os.listdir(f"/proc/{pid}/fd"):
                    link = os.readlink(f"/proc/{pid}/fd/{fd}")
                    if link.startswith("socket:["):
                        inode_to_proc[link[8:-1]] = comm
            except OSError:
                continue
    socks, seen = [], set()
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        for line in read(f"/proc/net/{proto}").splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            if proto.startswith("tcp") and f[3] != "0A":      # LISTEN
                continue
            if proto.startswith("udp") and f[3] != "07":      # unconnected
                continue
            addr_hex, port_hex = f[1].split(":")
            addr, port = _decode_addr(addr_hex), int(port_hex, 16)
            key = (proto[:3], addr, port)
            if key in seen:
                continue
            seen.add(key)
            socks.append({"proto": proto[:3], "addr": addr, "port": port,
                          "process": inode_to_proc.get(f[9], "")})
    return sorted(socks, key=lambda s: (s["proto"], s["port"]))


def is_loopback(addr: str) -> bool:
    return addr.startswith("127.") or addr == "::1"


def service_state(unit: str) -> str:
    return run(["systemctl", "is-active", unit]).out.strip() or "unknown"


def boot_time() -> str:
    r = run(["systemd-analyze", "time"], timeout=10)
    m = re.search(r"=\s*(.+?)\s*$", r.out.splitlines()[0]) if r.ok and r.out else None
    return m.group(1) if m else "?"


# --------------------------------------------------------------------------- commands: system
def cmd_status(_args) -> int:
    header("HomeCore OS " + read(os.path.join(HC_ROOT, "VERSION"), "?").strip())
    kv("Host", f"{socket.gethostname()} · {platform_desc()}")
    kv("OS", f"{os_name()} · {os.uname().release} · {os.uname().machine}")
    up = float(read("/proc/uptime", "0").split()[0] or 0)
    kv("Uptime", f"{int(up // 86400)}d {int(up % 86400 // 3600)}h {int(up % 3600 // 60)}m"
       f"  (last boot took {boot_time()})")
    kv("Load", " ".join(read("/proc/loadavg").split()[:3]) + f"  ({os.cpu_count()} CPUs)")
    m = meminfo()
    total, avail = m.get("MemTotal", 0), m.get("MemAvailable", 0)
    pct = 100 * (total - avail) / total if total else 0
    color = red if pct > 90 else yellow if pct > 75 else green
    kv("Memory", color(f"{human(total - avail)} / {human(total)} ({pct:.0f}%)"))
    swap_t, swap_f = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    kv("Swap", f"{human(swap_t - swap_f)} / {human(swap_t)} "
               f"({'zram' if 'zram' in read('/proc/swaps') else 'file/none'})")
    st = os.statvfs("/")
    kv("Disk /", f"{human((st.f_blocks - st.f_bfree) * st.f_frsize)} / {human(st.f_blocks * st.f_frsize)}")
    temp = read("/sys/class/thermal/thermal_zone0/temp").strip()
    if temp.isdigit():
        t = int(temp) / 1000
        kv("CPU temp", (red if t > 75 else yellow if t > 65 else green)(f"{t:.1f} °C"))
    if have("vcgencmd"):
        thr = run(["vcgencmd", "get_throttled"]).out.strip().split("=")[-1]
        if thr and thr != "0x0":
            kv("Throttling", red(f"{thr} — check the power supply (5V/2.5A)"))
    kv("Addresses", ", ".join(a for i in interfaces() for a in i["addrs"]) or "none")

    header("Services")
    for unit in ("ssh", "homecore-firewall", "homecore-discover.timer", "homecore-scan.timer",
                 "tailscaled", "avahi-daemon", "unattended-upgrades"):
        s = service_state(unit)
        kv(unit, green(s) if s == "active" else dim(s) if s in ("inactive", "unknown") else yellow(s))

    if is_root():
        sc = scan_module()
        inv = sc.load_inventory()
        _, rep = sc.latest_report()
        header("Network security")
        devs = inv.get("devices", {})
        kv("Known devices", f"{len(devs)} ({sum(1 for d in devs.values() if d.get('trusted'))} trusted)")
        if rep:
            summ = rep.get("summary", {})
            kv("Last scan", f"{rep['meta']['started']} ({rep['meta']['profile']})")
            kv("Findings", "  ".join(SEV_COLOR[s](f"{summ.get(s, 0)} {s}") for s in sc.SEVERITIES[:4]))
        else:
            kv("Last scan", yellow("never — run: sudo homecore scan"))
    else:
        print(dim("\n  (run with sudo to include the network-security summary)"))

    header("Top memory users")
    for rss, name in top_memory():
        kv(safe(name, 20), human(rss))
    return 0


def cmd_boot(_args) -> int:
    header("Boot time")
    r = run(["systemd-analyze", "time"], timeout=15)
    print("  " + (r.out.strip().replace("\n", "\n  ") or red(r.err.strip())))
    header("Slowest units")
    for line in run(["systemd-analyze", "blame", "--no-pager"], timeout=15).out.splitlines()[:12]:
        print("  " + line.strip())
    header("Critical chain")
    for line in run(["systemd-analyze", "critical-chain", "--no-pager"], timeout=15).out.splitlines()[2:14]:
        print("  " + line)
    print(dim("\n  Tip: anything slow you don't need → sudo systemctl disable --now <unit>"))
    return 0


# --------------------------------------------------------------------------- commands: network
def cmd_network(args) -> int:
    sub = args.sub or "show"
    if sub == "show":
        header("Interfaces")
        for i in interfaces():
            state = green(i["state"]) if i["state"] == "UP" else dim(i["state"])
            print(f"  {bold(i['name'].ljust(12))} {state:<8} {dim(i['mac'])}")
            for a in i["addrs"]:
                print(f"  {'':12} {a}")
        header("Routing & DNS")
        try:
            for rt in json.loads(run(["ip", "-j", "route", "show", "default"]).out or "[]"):
                kv("Default route", f"via {rt.get('gateway', '?')} dev {rt.get('dev', '?')}")
        except ValueError:
            pass
        dns = [ln.split()[1] for ln in read("/etc/resolv.conf").splitlines()
               if ln.startswith("nameserver") and len(ln.split()) > 1]
        kv("DNS", ", ".join(dns) or "?")
        kv("mDNS name", f"{socket.gethostname()}.local ({service_state('avahi-daemon')})")
        if have("tailscale"):
            ts = run(["tailscale", "ip", "-4"])
            kv("Tailscale", green(ts.out.strip()) if ts.ok and ts.out.strip() else yellow("not connected"))
        header("Listening ports on HomeCore")
        _print_ports()
        fw = run(["nft", "list", "table", "inet", "homecore"], sudo=True)
        kv("Firewall", green("active (default deny)") if fw.ok else red("NOT LOADED"))
        return 0
    if sub == "test":
        return _network_test()
    if sub == "neighbors":
        header("Devices in the ARP/ND cache")
        try:
            neigh = json.loads(run(["ip", "-j", "neigh"]).out or "[]")
        except ValueError:
            neigh = []
        for n in sorted(neigh, key=lambda x: x.get("dst", "")):
            mac = n.get("lladdr", "")
            if mac:
                tag = dim(" (random MAC)") if int(mac.split(":")[0], 16) & 2 else ""
                print(f"  {n.get('dst', ''):<40} {mac}  {dim(n.get('dev', ''))}{tag}")
        print(dim("\n  For a full sweep: sudo homecore discover"))
        return 0
    if sub == "ports":
        header("Listening ports on HomeCore")
        _print_ports()
        return 0
    print(red(f"Unknown network command: {sub}"))
    return 2


def _print_ports() -> None:
    known = {22: "SSH", 53: "DNS", 5353: "mDNS", 41641: "Tailscale", 68: "DHCP", 546: "DHCPv6"}
    for s in listening_sockets():
        scope = dim("local only") if is_loopback(s["addr"]) else yellow("network")
        print(f"  {s['proto']} {str(s['port']).rjust(5)}  {s['addr']:<16} {scope:<20} "
              f"{known.get(s['port'], '')} {dim(s['process'])}")
    if not is_root():
        print(dim("  (run with sudo to see process names)"))


def _network_test() -> int:
    header("Connectivity test")
    failures = 0

    def check(label: str, fn) -> None:
        nonlocal failures
        t0 = time.monotonic()
        try:
            detail = fn()
            print(f"  {green('✔')} {label:<28} {dim(detail or '')} {dim(f'{(time.monotonic() - t0) * 1000:.0f} ms')}")
        except Exception as e:  # noqa: BLE001 — report any failure
            failures += 1
            print(f"  {red('✘')} {label:<28} {red(str(e))}")

    def gateway():
        routes = json.loads(run(["ip", "-j", "route", "show", "default"]).out or "[]")
        if not routes:
            raise RuntimeError("no default route")
        gw = routes[0].get("gateway", "")
        if not run(["ping", "-c", "1", "-W", "2", gw], timeout=5).ok:
            raise RuntimeError(f"{gw} does not answer ping")
        return gw

    def dns():
        return socket.getaddrinfo("deb.debian.org", 443)[0][4][0]

    def https():
        with socket.create_connection(("deb.debian.org", 443), timeout=5):
            return "deb.debian.org:443"

    def mdns():
        return socket.getaddrinfo(socket.gethostname() + ".local", None)[0][4][0]

    check("Default gateway", gateway)
    check("DNS resolution", dns)
    check("Internet (HTTPS)", https)
    check("Local name (.local)", mdns)
    if have("tailscale"):
        def ts():
            state = json.loads(run(["tailscale", "status", "--json"], timeout=10).out or "{}").get("BackendState", "?")
            if state != "Running":
                raise RuntimeError(f"state {state} — run: sudo homecore tailscale")
            return state
        check("Tailscale", ts)
    return 1 if failures else 0


# --------------------------------------------------------------------------- commands: scanning
def _targets(args_targets: list[str] | None) -> list[str]:
    sc = scan_module()
    if args_targets:
        return sc.validate_targets(args_targets)
    nets, _ = sc.local_networks()
    if not nets:
        raise sc.ScopeError("no private IPv4 network detected — pass --target <CIDR>")
    return sc.validate_targets(nets)


def _print_findings(findings: list[dict], limit: int = 0) -> None:
    if not findings:
        print(green("  ✔ no findings"))
        return
    shown = findings[:limit] if limit else findings
    for f in shown:
        sev = SEV_COLOR.get(f["severity"], dim)(f["severity"].upper().ljust(8))
        where = " ".join(x for x in (f.get("host", ""), f.get("port", "")) if x)
        print(f"  {sev} {bold(safe(f['title'], 90))}")
        if where or f.get("detail"):
            print(f"           {safe(where, 40)}  {dim(safe(f.get('detail', ''), 80))}")
        if f.get("fix"):
            print(f"           {dim('→ ' + safe(f['fix'], 110))}")
    if limit and len(findings) > limit:
        print(dim(f"  … {len(findings) - limit} more: homecore report"))


def cmd_discover(args) -> int:
    ensure_root(["discover", *(["--target", *args.target] if args.target else []), *(["--quiet"] if args.quiet else [])])
    sc = scan_module()
    try:
        targets = _targets(args.target)
    except sc.ScopeError as e:
        print(red(f"  {e}"))
        return 2
    if not args.quiet:
        header("Device discovery")
        print(dim(f"  {', '.join(targets)}"))
    _, own = sc.local_networks()
    try:
        hosts = [h for h in sc.discover(targets) if h.ip not in own]
    except RuntimeError as e:
        print(red(f"  {e}"))
        return 1
    inv, alerts = sc.update_inventory(hosts, sc.default_gateway(), with_ports=False)
    sc.save_json(os.path.join(sc.STATE_DIR, "inventory.json"), inv)
    sc.record_alerts(alerts)
    if not args.quiet:
        print(f"  {len(hosts)} devices up")
        if alerts:
            header("Changes")
            _print_findings([a.__dict__ for a in alerts])
        _print_devices(inv, only_ips={h.ip for h in hosts})
    return 0


def cmd_scan(args) -> int:
    argv = ["scan", args.profile, *(["--target", *args.target] if args.target else []),
            *(["--cve-lookup"] if args.cve_lookup else []), *(["--quiet"] if args.quiet else [])]
    ensure_root(argv)
    sc = scan_module()
    try:
        targets = _targets(args.target)
    except sc.ScopeError as e:
        print(red(f"  {e}"))
        return 2
    if not args.quiet:
        header(f"Vulnerability scan · {args.profile}")
        print(dim("  Scan only networks you own or are authorised to test."))
        if args.cve_lookup:
            print(yellow("  --cve-lookup sends product names/versions found on your LAN to vulners.com."))
    try:
        rep = sc.full_scan(targets, args.profile, cve_lookup=args.cve_lookup, progress=not args.quiet,
                           log=(lambda *_: None) if args.quiet else (lambda m: print(dim("  " + m))))
    except RuntimeError as e:
        print(red(f"  {e}"))
        return 1
    if args.quiet:
        return 0
    _print_report(rep, limit=25)
    return 0


def _print_report(rep: dict, limit: int = 0) -> None:
    meta, summ = rep.get("meta", {}), rep.get("summary", {})
    header("Scan report")
    kv("Started", f"{meta.get('started')} · {meta.get('duration_s', '?')} s · profile {meta.get('profile')}")
    kv("Targets", ", ".join(meta.get("targets", [])))
    kv("Devices", str(len(rep.get("hosts", []))))
    kv("Findings", "  ".join(SEV_COLOR[s](f"{summ.get(s, 0)} {s}") for s in ("critical", "high", "medium", "low", "info")))
    if rep.get("alerts"):
        header("Changes since last scan")
        _print_findings(rep["alerts"])
    header("Findings (most severe first)")
    _print_findings(rep.get("findings", []), limit)
    if rep.get("path"):
        print(dim(f"\n  Full report: {rep['path']}"))


def cmd_report(args) -> int:
    ensure_root(["report", *(["--json"] if args.json else []), *(["--all"] if args.all else [])])
    path, rep = scan_module().latest_report()
    if not rep:
        print(yellow("No scan yet — run: sudo homecore scan"))
        return 1
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
        return 0
    rep["path"] = path
    _print_report(rep)
    if args.all:
        header("Devices and open ports")
        for h in rep.get("hosts", []):
            print(f"  {bold(h['ip']):<18} {dim(h.get('mac', ''))}  {safe(h.get('vendor', ''), 24)}  "
                  f"{safe(h.get('hostname', ''), 30)}")
            for p in h.get("ports", []):
                banner = " ".join(x for x in (p.get("product"), p.get("version"), p.get("extrainfo")) if x)
                print(f"      {p['proto']}/{p['port']:<6} {p.get('service', ''):<14} {dim(safe(banner, 60))}")
    return 0


def _print_devices(inv: dict, only_ips: set | None = None) -> None:
    header("Devices")
    devs = sorted(inv.get("devices", {}).items(),
                  key=lambda kv_: tuple(int(x) if x.isdigit() else 0 for x in kv_[1].get("ip", "0").split(".")))
    gw = inv.get("gateway", {}).get("ip")
    print(dim(f"  {'IP':<16} {'MAC':<18} {'VENDOR':<22} {'NAME / HOSTNAME':<26} {'PORTS':<6} LAST SEEN"))
    for key, d in devs:
        if only_ips is not None and d.get("ip") not in only_ips:
            continue
        flag = green("✔") if d.get("trusted") else yellow("?")
        name = d.get("name") or d.get("hostname", "")
        if d.get("ip") == gw:
            name = (name + " (gateway)").strip()
        ports = "-" if d.get("ports") is None else str(len(d["ports"]))
        mac = "" if key.startswith("ip:") else key
        print(f"{flag} {d.get('ip', ''):<16} {mac:<18} {safe(d.get('vendor', ''), 22):<22} "
              f"{safe(name, 26):<26} {ports:<6} {dim(d.get('last_seen', ''))}")
    print(dim("\n  ✔ trusted  ? unknown — homecore devices trust <mac|ip> [name]"))


def cmd_devices(args) -> int:
    ensure_root(["devices", *([args.sub] if args.sub else []), *args.rest])
    sc = scan_module()
    inv = sc.load_inventory()
    devs = inv.get("devices", {})
    sub = args.sub or "list"
    if sub == "list":
        if not devs:
            print(yellow("No devices yet — run: sudo homecore discover"))
            return 1
        _print_devices(inv)
        return 0
    if sub == "hardware":
        return _local_hardware()
    if not args.rest:
        print(red(f"Usage: homecore devices {sub} <mac|ip>" + (" [name]" if sub == "trust" else "")))
        return 2
    ident = args.rest[0].lower()
    key = ident if ident in devs else next((k for k, d in devs.items() if d.get("ip") == ident), None)
    if not key:
        print(red(f"Unknown device: {ident}"))
        return 1
    if sub == "trust":
        devs[key]["trusted"] = True
        if len(args.rest) > 1:
            devs[key]["name"] = safe(" ".join(args.rest[1:]), 40)
        print(green(f"  ✔ {key} marked as trusted"))
    elif sub == "untrust":
        devs[key]["trusted"] = False
        print(f"  {key} marked as unknown")
    elif sub == "forget":
        devs.pop(key)
        print(f"  {key} removed from the inventory")
    sc.save_json(os.path.join(sc.STATE_DIR, "inventory.json"), inv)
    return 0


def _usb_devices() -> list[dict]:
    base = "/sys/bus/usb/devices"
    out = []
    if not os.path.isdir(base):
        return out
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d)
        vid = read(f"{p}/idVendor").strip()
        if vid and read(f"{p}/bDeviceClass").strip() != "09":   # skip hubs
            out.append({"id": f"{vid}:{read(f'{p}/idProduct').strip()}",
                        "maker": read(f"{p}/manufacturer").strip(), "product": read(f"{p}/product").strip()})
    return out


def _local_hardware() -> int:
    header("USB devices attached to HomeCore")
    usb = _usb_devices()
    for u in usb:
        print(f"  {u['id']}  {safe(u['maker'], 30)} {safe(u['product'], 40)}")
    if not usb:
        print(dim("  none"))
    header("Wireless interfaces")
    wl = [i for i in os.listdir("/sys/class/net") if os.path.isdir(f"/sys/class/net/{i}/wireless")] \
        if os.path.isdir("/sys/class/net") else []
    print("  " + (", ".join(wl) or dim("none")))
    return 0


def cmd_alerts(args) -> int:
    ensure_root(["alerts", "-n", str(args.lines)])
    sc = scan_module()
    lines = read(os.path.join(sc.STATE_DIR, "alerts.jsonl")).splitlines()[-args.lines:]
    if not lines:
        print(green("  no alerts yet"))
        return 0
    header("Recent alerts")
    for line in lines:
        try:
            a = json.loads(line)
        except ValueError:
            continue
        print(f"  {dim(a.get('time', ''))} {SEV_COLOR.get(a.get('severity'), dim)(a.get('severity', '').upper()):<10} "
              f"{safe(a.get('title'), 70)}  {safe(a.get('host'), 30)} {safe(a.get('port'), 20)}")
    return 0


def _wifi_iface() -> str:
    if not os.path.isdir("/sys/class/net"):
        return ""
    return next((i for i in sorted(os.listdir("/sys/class/net")) if os.path.isdir(f"/sys/class/net/{i}/wireless")), "")


def cmd_wifi(args) -> int:
    ensure_root(["wifi", *(["--ssid", args.ssid] if args.ssid else [])])
    iface = _wifi_iface()
    if not iface:
        print(yellow("  No Wi-Fi interface (normal in VirtualBox). On the Pi 3B this audits nearby networks."))
        return 1
    if not have("iw"):
        print(red("  'iw' is not installed: sudo apt install iw"))
        return 1
    run(["ip", "link", "set", iface, "up"])
    r = run(["iw", "dev", iface, "scan"], timeout=30)
    if not r.ok:
        print(red(f"  scan failed: {r.err.strip()}"))
        return 1
    sc = scan_module()
    bss = sc.parse_iw_scan(r.out)
    header(f"Wi-Fi networks nearby ({len(bss)} access points, {iface})")
    print(dim(f"  {'SSID':<28} {'BSSID':<18} {'CH/MHz':<7} {'dBm':<6} {'SECURITY':<16} WPS"))
    for b in sorted(bss, key=lambda x: -(x["signal"] or -999)):
        sec = b["security"]
        col = red if sec in ("OPEN", "WEP", "WPA1") else yellow if "WPA1" in sec else green
        mark = bold("◀ connected") if b["associated"] else ""
        print(f"  {safe(b['ssid'] or '(hidden)', 28):<28} {b['bssid']:<18} {str(b['freq'] or ''):<7} "
              f"{str(b['signal'] or ''):<6} {col(sec):<16} {'yes' if b['wps'] else '-'} {mark}")
    header("Findings")
    _print_findings([f.__dict__ for f in sc.assess_wifi(bss, args.ssid or "")])
    return 0


# --------------------------------------------------------------------------- security self-audit
class Check:
    def __init__(self, status: str, name: str, detail: str = ""):
        self.status, self.name, self.detail = status, name, detail   # status: PASS/WARN/FAIL/INFO


def _audit() -> list[Check]:
    checks: list[Check] = []

    def add(status: str, name: str, detail: str = "") -> None:
        checks.append(Check(status, name, detail))

    henv = read_env(os.path.join(HC_ETC, "homecore.env"))

    t = run(["sshd", "-T"])
    if t.ok:
        cfg: dict[str, str] = {}
        for line in t.out.splitlines():
            k, _, v = line.partition(" ")
            cfg.setdefault(k, v)
        add("PASS" if cfg.get("permitrootlogin") == "no" else "FAIL", "SSH root login disabled",
            f"PermitRootLogin {cfg.get('permitrootlogin')}")
        pw = cfg.get("passwordauthentication", "?")
        add("PASS" if pw == "no" else "WARN", "SSH key-only login",
            f"PasswordAuthentication {pw}" + ("" if pw == "no" else " → ssh-copy-id, then: sudo homecore harden ssh"))
        add("PASS" if cfg.get("x11forwarding") == "no" else "WARN", "SSH X11 forwarding off")
    else:
        add("WARN", "SSH configuration", "could not run sshd -T")

    fw = run(["nft", "list", "table", "inet", "homecore"])
    add("PASS" if fw.ok and "policy drop" in fw.out else "FAIL", "Firewall loaded, default deny",
        "" if fw.ok else "run: sudo homecore firewall apply")
    if run(["systemctl", "is-enabled", "homecore-firewall"]).out.strip() != "enabled":
        add("WARN", "Firewall enabled at boot", "systemctl enable homecore-firewall")

    expected_tcp = {int(p) for p in henv.get("LAN_TCP_PORTS", "22").split() if p.isdigit()}
    expected_udp = {int(p) for p in henv.get("LAN_UDP_PORTS", "5353").split() if p.isdigit()}
    expected_udp |= {68, 546, int(henv.get("TAILSCALE_UDP_PORT", "41641") or 41641)}
    unexpected = []
    for s in listening_sockets():
        if is_loopback(s["addr"]) or s["addr"].startswith("100.") or s["addr"].startswith("fd7a:115c"):
            continue
        if s["port"] not in (expected_tcp if s["proto"] == "tcp" else expected_udp):
            unexpected.append(f"{s['proto']}/{s['port']} {s['process']}".strip())
    add("PASS" if not unexpected else "INFO", "Unexpected listening ports",
        ", ".join(unexpected[:8]) + (" (blocked by firewall unless listed in homecore.env)" if unexpected else "none"))

    sysctls = {"net.ipv4.conf.all.rp_filter": "1", "net.ipv4.tcp_syncookies": "1",
               "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1",
               "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.ip_forward": "0"}
    bad = [k for k, v in sysctls.items() if read("/proc/sys/" + k.replace(".", "/")).strip() not in ("", v)]
    add("PASS" if not bad else "WARN", "Kernel/network sysctl hardening", ", ".join(bad))

    add("PASS" if 'Unattended-Upgrade "1"' in read("/etc/apt/apt.conf.d/20auto-upgrades") else "WARN",
        "Automatic security updates")
    if os.path.exists("/run/reboot-required"):
        add("WARN", "Reboot pending", "installed updates need a reboot")

    sc = scan_module()
    for path in (sc.STATE_DIR, os.path.join(HC_ROOT, "backups")):
        try:
            mode = os.stat(path).st_mode & 0o777
            add("PASS" if mode & 0o077 == 0 else "FAIL", f"Permissions {path}", oct(mode))
        except OSError:
            pass
    add("PASS" if service_state("homecore-discover.timer") == "active" else "WARN",
        "Periodic device discovery (timer)", "sudo systemctl enable --now homecore-discover.timer")

    empty = [ln.split(":")[0] for ln in read("/etc/shadow").splitlines()
             if ln.count(":") >= 2 and ln.split(":")[1] == ""]
    add("PASS" if not empty else "FAIL", "No accounts with empty passwords", ", ".join(empty))
    if any(ln.startswith("pi:") for ln in read("/etc/passwd").splitlines()):
        add("WARN", "Default 'pi' user exists", "remove it if unused: sudo deluser --remove-home pi")

    j = run(["journalctl", "--since", "-24h", "-q", "--no-pager", "-o", "cat",
             "-u", "ssh", "-u", "sshd", "-g", "Failed password|Invalid user|authentication failure"], timeout=30)
    fails = len(j.out.splitlines()) if j.ok else 0
    add("PASS" if fails < 10 else "WARN", "Failed SSH logins (24 h)", str(fails))
    k = run(["journalctl", "-k", "--since", "-24h", "-q", "--no-pager", "-o", "cat", "-g", "homecore-ssh-flood"],
            timeout=30)
    if k.ok and k.out.strip():
        add("WARN", "SSH flood attempts rate-limited (24 h)", str(len(k.out.splitlines())))

    ntp = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).out.strip()
    add("PASS" if ntp == "yes" else "WARN", "Clock synchronised (NTP)", ntp)

    if have("tailscale"):
        try:
            data = json.loads(run(["tailscale", "status", "--json"], timeout=10).out or "{}")
        except ValueError:
            data = {}
        state = data.get("BackendState", "?")
        add("PASS" if state == "Running" else "INFO", "Tailscale connected", state)
    return checks


def cmd_security(args) -> int:
    ensure_root(["security", *(["--json"] if args.json else [])])
    checks = _audit()
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        header("HomeCore self-audit")
        icon = {"PASS": green("✔ PASS"), "WARN": yellow("! WARN"), "FAIL": red("✘ FAIL"), "INFO": cyan("i INFO")}
        for c in checks:
            print(f"  {icon[c.status]}  {c.name:<44} {dim(c.detail)}")
        n = {s: sum(c.status == s for c in checks) for s in icon}
        print(f"\n  {n['PASS']} passed · {n['WARN']} warnings · {n['FAIL']} failed")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


# --------------------------------------------------------------------------- prompt-injection guard
def _print_reports(reports, as_json: bool, show_all: bool = False) -> int:
    guard = guard_module()
    reports = [r for r in reports if show_all or r.score > 0]
    if as_json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        colors = {"block": red, "review": yellow, "low": dim, "clean": green}
        for r in sorted(reports, key=lambda x: -x.score):
            print(f"  {colors[r.level](r.level.upper().ljust(6))} score {r.score:<3} {bold(safe(r.source or r.context, 60))}")
            print(f"         {dim(repr(guard.sanitize(r.text, max_len=100)))}")
            for f in r.findings:
                print(f"         · {f.description}" + (dim(f"  [{safe(f.excerpt, 60)}]") if f.excerpt else ""))
        if not reports:
            print(green("  ✔ nothing suspicious found"))
    worst = max((r.score for r in reports), default=0)
    return 2 if worst >= guard.LEVEL_BLOCK else 1 if worst >= guard.LEVEL_REVIEW else 0


def report_strings(rep: dict) -> list[tuple[str, str, str]]:
    """Attacker-controlled strings in a scan report: (source, context, text)."""
    out = []
    for h in rep.get("hosts", []):
        ip = h.get("ip", "?")
        if h.get("hostname"):
            out.append((f"{ip} hostname", "name", h["hostname"]))
        for p in h.get("ports", []):
            src = f"{ip} {p.get('proto')}/{p.get('port')}"
            banner = " ".join(x for x in (p.get("product"), p.get("version"), p.get("extrainfo")) if x)
            if banner:
                out.append((f"{src} banner", "name", banner))
            for sid in ("http-title", "upnp-info", "snmp-info", "ssl-cert"):
                if p.get("scripts", {}).get(sid):
                    out.append((f"{src} {sid}", "text", p["scripts"][sid]))
    for d in rep.get("ssdp", []):
        if d.get("server"):
            out.append((f"{d.get('ip')} SSDP server", "name", d["server"]))
    return out


def cmd_guard(args) -> int:
    guard = guard_module()
    sub = args.sub
    text = " ".join(args.text) if args.text else ""
    if sub in ("check", "sanitize", "wrap") and (not text or text == "-"):
        text = sys.stdin.read()
    if sub == "check":
        return _print_reports([guard.scan_text(text, args.context, source="input")], args.json, show_all=True)
    if sub == "sanitize":
        print(guard.sanitize(text, max_len=args.max_len, strict=args.strict))
        return 0
    if sub == "wrap":
        print(guard.wrap_untrusted(text))
        return 0
    if sub == "report":
        ensure_root(["guard", "report", *(["--json"] if args.json else [])])
        path, rep = scan_module().latest_report()
        if not rep:
            print(yellow("No scan yet — run: sudo homecore scan"))
            return 1
        strings = report_strings(rep)
        if not args.json:
            header("Prompt-injection scan · strings from devices in the last report")
            print(dim(f"  {len(strings)} hostnames, banners, titles and UPnP names from {path}"))
        return _print_reports([guard.scan_text(t, ctx, src) for src, ctx, t in strings], args.json)
    print(red("Usage: homecore guard check|sanitize|wrap|report"))
    return 2


# --------------------------------------------------------------------------- misc commands
def cmd_firewall(args) -> int:
    sub = args.sub or "status"
    if sub == "apply":
        return script("firewall.sh", "apply", "--safe")
    return script("firewall.sh", sub)


def cmd_logs(args) -> int:
    svc = args.service or "scan"
    cmd = ["journalctl", "--no-pager", "-n", str(args.lines)]
    if svc == "firewall":
        cmd += ["-k", "-g", "homecore-"]
    elif svc in ("scan", "alerts"):
        cmd += ["-t", "homecore", "-u", "homecore-discover", "-u", "homecore-scan"]
    elif svc in UNITS:
        cmd += ["-u", UNITS[svc]]
    elif svc != "system":
        print(red(f"Unknown log '{svc}'. Use: scan, firewall, {', '.join(sorted(UNITS))}, system"))
        return 2
    if args.follow:
        cmd.append("-f")
    return run(cmd, sudo=True, capture=False, timeout=None).code


def cmd_version(_args) -> int:
    print("HomeCore OS " + read(os.path.join(HC_ROOT, "VERSION"), "unknown").strip())
    return 0


# --------------------------------------------------------------------------- interactive menu
MENU = [
    ("Status overview", ["status"]),
    ("Discover devices on the LAN", ["discover"]),
    ("Vulnerability scan (quick)", ["scan", "quick"]),
    ("Vulnerability scan (standard)", ["scan", "standard"]),
    ("Last scan report", ["report"]),
    ("Known devices", ["devices"]),
    ("Recent alerts", ["alerts"]),
    ("Wi-Fi security audit", ["wifi"]),
    ("Network info", ["network"]),
    ("Connectivity test", ["network", "test"]),
    ("HomeCore self-audit", ["security"]),
    ("Prompt-injection check of scan data", ["guard", "report"]),
    ("Firewall rules", ["firewall", "status"]),
    ("Boot time report", ["boot"]),
    ("Backup now", ["backup"]),
    ("Update the system", ["update"]),
]
NEEDS_ROOT = {"discover", "scan", "report", "devices", "alerts", "wifi", "security"}


def cmd_menu(_args) -> int:
    while True:
        header("HomeCore OS")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"  {bold(str(i).rjust(2))}  {label}")
        print(f"  {bold(' q')}  Quit")
        try:
            choice = input(cyan("\n  homecore › ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice in ("q", "quit", "exit", ""):
            return 0
        if not (choice.isdigit() and 1 <= int(choice) <= len(MENU)):
            print(red("  invalid choice"))
            continue
        argv = MENU[int(choice) - 1][1]
        try:
            if (argv[0] in NEEDS_ROOT or argv[:2] == ["guard", "report"]) and not is_root():
                # needs root: run as a child through sudo, keep the menu alive
                run([sys.executable, "-I", os.path.realpath(__file__), *argv], sudo=True, capture=False, timeout=None)
            else:
                main(argv)
        except KeyboardInterrupt:
            print()
        try:
            input(dim("\n  press Enter to continue"))
        except (EOFError, KeyboardInterrupt):
            return 0


# --------------------------------------------------------------------------- argument parsing
WRAPPERS = {
    "backup": ("backup.sh", "back up settings, inventory and reports [--dest DIR]"),
    "restore": ("restore.sh", "restore a backup archive"),
    "update": ("update.sh", "update the system (backup first)"),
    "tailscale": ("install-tailscale.sh", "install/connect Tailscale VPN (optional)"),
    "harden": ("harden.sh", "re-apply hardening: all|ssh|kernel|journald|updates"),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="homecore", description="HomeCore OS — home network security appliance.")
    sp = p.add_subparsers(dest="cmd")

    sp.add_parser("menu", help="interactive menu (default)").set_defaults(fn=cmd_menu)
    sp.add_parser("status", help="system, memory, services, security summary").set_defaults(fn=cmd_status)
    sp.add_parser("boot", help="boot-time report (slowest units)").set_defaults(fn=cmd_boot)

    d = sp.add_parser("discover", help="find devices on the LAN, update inventory, alert on changes")
    d.add_argument("--target", nargs="+", help="private CIDR(s)/IP(s); default: local LAN")
    d.add_argument("--quiet", action="store_true")
    d.set_defaults(fn=cmd_discover)

    s = sp.add_parser("scan", help="vulnerability scan: quick | standard | deep")
    s.add_argument("profile", nargs="?", default="standard", choices=["quick", "standard", "deep"])
    s.add_argument("--target", nargs="+", help="private CIDR(s)/IP(s); default: local LAN")
    s.add_argument("--cve-lookup", action="store_true", help="match versions to CVEs via vulners.com (online)")
    s.add_argument("--quiet", action="store_true")
    s.set_defaults(fn=cmd_scan)

    r = sp.add_parser("report", help="show the last scan report")
    r.add_argument("--json", action="store_true")
    r.add_argument("--all", action="store_true", help="also list every device and open port")
    r.set_defaults(fn=cmd_report)

    dv = sp.add_parser("devices", help="inventory: list | trust | untrust | forget | hardware")
    dv.add_argument("sub", nargs="?", choices=["list", "trust", "untrust", "forget", "hardware"])
    dv.add_argument("rest", nargs="*", help="mac|ip [name]")
    dv.set_defaults(fn=cmd_devices)

    a = sp.add_parser("alerts", help="recent alerts (new devices, new ports, ARP anomalies)")
    a.add_argument("-n", "--lines", type=int, default=30)
    a.set_defaults(fn=cmd_alerts)

    w = sp.add_parser("wifi", help="Wi-Fi security audit (encryption, WPS, evil twins)")
    w.add_argument("--ssid", help="your network name (when HomeCore is on Ethernet)")
    w.set_defaults(fn=cmd_wifi)

    n = sp.add_parser("network", help="HomeCore's interfaces, routes, ports; ARP cache; connectivity test")
    n.add_argument("sub", nargs="?", choices=["show", "test", "neighbors", "ports"])
    n.set_defaults(fn=cmd_network)

    sec = sp.add_parser("security", help="self-audit of HomeCore's own hardening")
    sec.add_argument("--json", action="store_true")
    sec.set_defaults(fn=cmd_security)

    g = sp.add_parser("guard", help="prompt-injection scanner: check | sanitize | wrap | report")
    g.add_argument("sub", choices=["check", "sanitize", "wrap", "report"])
    g.add_argument("text", nargs="*", help="text to check (or stdin)")
    g.add_argument("--context", choices=["name", "text"], default="text")
    g.add_argument("--json", action="store_true")
    g.add_argument("--strict", action="store_true", help="sanitize: keep only plain name characters")
    g.add_argument("--max-len", type=int, default=None)
    g.set_defaults(fn=cmd_guard)

    f = sp.add_parser("firewall", help="show or apply HomeCore's own firewall")
    f.add_argument("sub", nargs="?", choices=["status", "apply", "render", "detect", "disable"])
    f.set_defaults(fn=cmd_firewall)

    lg = sp.add_parser("logs", help="logs: scan, firewall, ssh, tailscale, mdns, system")
    lg.add_argument("service", nargs="?")
    lg.add_argument("-n", "--lines", type=int, default=100)
    lg.add_argument("-f", "--follow", action="store_true")
    lg.set_defaults(fn=cmd_logs)

    for name, (_scr, helptext) in WRAPPERS.items():
        sp.add_parser(name, help=helptext, add_help=False)

    sp.add_parser("version", help="show version").set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in WRAPPERS:
        return script(WRAPPERS[argv[0]][0], *argv[1:])
    args = build_parser().parse_args(argv)
    if not getattr(args, "fn", None):
        return cmd_menu(args)
    return args.fn(args) or 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
