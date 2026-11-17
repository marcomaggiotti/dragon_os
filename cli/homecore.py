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
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import homecore_guard as guard  # noqa: E402

HC_ROOT = os.environ.get("HC_ROOT", "/opt/homecore")
HC_ETC = "/etc/homecore"
SCRIPTS = os.path.join(HC_ROOT, "scripts")
CONTAINERS = ("homecore-mosquitto", "homecore-homeassistant", "homecore-zigbee2mqtt")
SERVICES = {"ha": "homecore-homeassistant", "homeassistant": "homecore-homeassistant",
            "mqtt": "homecore-mosquitto", "mosquitto": "homecore-mosquitto",
            "zigbee": "homecore-zigbee2mqtt", "zigbee2mqtt": "homecore-zigbee2mqtt"}

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
@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def is_root() -> bool:
    return os.geteuid() == 0


def run(cmd: list[str], sudo: bool = False, capture: bool = True, timeout: int | None = 60,
        env: dict | None = None) -> Result:
    if sudo and not is_root():
        cmd = ["sudo", "--", *cmd]
    try:
        p = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout,
                           env={**os.environ, **env} if env else None)
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


def mqtt_cli(tool: str, *args: str, timeout: int = 15) -> Result:
    """Run mosquitto_sub/pub inside the broker container with the 'hc-cli' account.
    Credentials come from an options file mounted at /cli (never on the command line)."""
    return run(["docker", "exec", "-e", "XDG_CONFIG_HOME=/cli", "homecore-mosquitto", tool, *args],
               sudo=True, timeout=timeout)


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
        lines = read(f"/proc/net/{proto}").splitlines()[1:]
        for line in lines:
            f = line.split()
            if len(f) < 10:
                continue
            state = f[3]
            if proto.startswith("tcp") and state != "0A":      # LISTEN
                continue
            if proto.startswith("udp") and state != "07":      # unconnected
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


def container_states() -> dict[str, str]:
    r = run(["docker", "ps", "-a", "--filter", "name=homecore-", "--format", "{{.Names}}\t{{.Status}}"], sudo=True)
    states = {}
    for line in r.out.splitlines():
        if "\t" in line:
            name, status = line.split("\t", 1)
            states[name] = status
    return states


def service_state(unit: str) -> str:
    return run(["systemctl", "is-active", unit]).out.strip() or "unknown"


# --------------------------------------------------------------------------- commands
def cmd_status(_args) -> int:
    header("HomeCore OS " + read(os.path.join(HC_ROOT, "VERSION"), "?").strip())
    kv("Host", f"{socket.gethostname()} · {platform_desc()}")
    kv("OS", f"{os_name()} · {os.uname().release} · {os.uname().machine}")
    up = float(read("/proc/uptime", "0").split()[0] or 0)
    kv("Uptime", f"{int(up // 86400)}d {int(up % 86400 // 3600)}h {int(up % 3600 // 60)}m")
    kv("Load", " ".join(read("/proc/loadavg").split()[:3]) + f"  ({os.cpu_count()} CPUs)")
    m = meminfo()
    total, avail = m.get("MemTotal", 0), m.get("MemAvailable", 0)
    pct = 100 * (total - avail) / total if total else 0
    color = red if pct > 90 else yellow if pct > 75 else green
    kv("Memory", color(f"{human(total - avail)} / {human(total)} ({pct:.0f}%)"))
    swap_t, swap_f = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    zram = "zram" if "zram" in read("/proc/swaps") else "file/none"
    kv("Swap", f"{human(swap_t - swap_f)} / {human(swap_t)} ({zram})")
    st = os.statvfs("/")
    used = (st.f_blocks - st.f_bfree) * st.f_frsize
    kv("Disk /", f"{human(used)} / {human(st.f_blocks * st.f_frsize)}")
    temp = read("/sys/class/thermal/thermal_zone0/temp").strip()
    if temp.isdigit():
        t = int(temp) / 1000
        kv("CPU temp", (red if t > 75 else yellow if t > 65 else green)(f"{t:.1f} °C"))
    if have("vcgencmd"):
        thr = run(["vcgencmd", "get_throttled"]).out.strip().split("=")[-1]
        if thr and thr != "0x0":
            kv("Throttling", red(f"{thr} — check the power supply (5V/2.5A)"))
    ips = [a for i in interfaces() for a in i["addrs"]]
    kv("Addresses", ", ".join(ips) or "none")

    header("Services")
    for unit in ("docker", "ssh", "homecore-firewall", "tailscaled", "bluetooth", "unattended-upgrades"):
        s = service_state(unit)
        kv(unit, green(s) if s == "active" else dim(s) if s in ("inactive", "unknown") else yellow(s))

    header("Containers")
    states = container_states()
    if not states:
        print("  " + yellow("No containers yet — run: sudo homecore setup"))
    for name in CONTAINERS:
        if name in states:
            s = states[name]
            kv(name.replace("homecore-", ""), green(s) if s.startswith("Up") else red(s))
    stats = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
                sudo=True, timeout=20)
    for line in stats.out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].startswith("homecore-"):
            kv("  " + parts[0].replace("homecore-", ""), dim(f"cpu {parts[1]}  mem {parts[2]}"))
    return 0


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
        r = run(["ip", "-j", "route", "show", "default"])
        try:
            for rt in json.loads(r.out or "[]"):
                kv("Default route", f"via {rt.get('gateway', '?')} dev {rt.get('dev', '?')}")
        except ValueError:
            pass
        dns = [ln.split()[1] for ln in read("/etc/resolv.conf").splitlines() if ln.startswith("nameserver")]
        kv("DNS", ", ".join(dns) or "?")
        kv("mDNS name", f"{socket.gethostname()}.local ({service_state('avahi-daemon')})")
        if have("nmcli"):
            wifi = run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY", "dev", "wifi"]).out
            for line in wifi.splitlines():
                if line.startswith("yes:"):
                    _, ssid, signal, sec = (line.split(":") + ["", "", ""])[:4]
                    kv("Wi-Fi", f"{ssid}  signal {signal}%  {sec}")
        if have("tailscale"):
            ts = run(["tailscale", "ip", "-4"])
            kv("Tailscale", green(ts.out.strip()) if ts.ok and ts.out.strip() else yellow("not connected"))
        header("Listening ports")
        _print_ports()
        fw = run(["nft", "list", "table", "inet", "homecore"], sudo=True)
        kv("Firewall", green("active (default deny)") if fw.ok else red("NOT LOADED"))
        return 0
    if sub == "test":
        return _network_test()
    if sub == "neighbors":
        header("Devices seen on the LAN (ARP/ND cache)")
        r = run(["ip", "-j", "neigh"])
        try:
            neigh = json.loads(r.out or "[]")
        except ValueError:
            neigh = []
        for n in sorted(neigh, key=lambda x: x.get("dst", "")):
            mac = n.get("lladdr", "")
            if not mac:
                continue
            first = int(mac.split(":")[0], 16)
            tag = dim(" (random MAC)") if first & 2 else ""
            print(f"  {n.get('dst', ''):<40} {mac}  {dim(n.get('dev', ''))} {dim(','.join(n.get('state', [])))}{tag}")
        print(dim("\n  Tip: devices appear here after they talk to HomeCore; ping the subnet to refresh."))
        return 0
    if sub == "ports":
        header("Listening ports")
        _print_ports()
        return 0
    print(red(f"Unknown network command: {sub}"))
    return 2


def _print_ports() -> None:
    known = {22: "SSH", 53: "DNS", 1883: "MQTT", 5353: "mDNS", 8080: "Zigbee2MQTT UI",
             8123: "Home Assistant", 41641: "Tailscale", 68: "DHCP", 546: "DHCPv6"}
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
        r = run(["ip", "-j", "route", "show", "default"])
        routes = json.loads(r.out or "[]")
        if not routes:
            raise RuntimeError("no default route")
        gw = routes[0].get("gateway", "")
        p = run(["ping", "-c", "1", "-W", "2", gw], timeout=5)
        if not p.ok:
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
            r = run(["tailscale", "status", "--json"], timeout=10)
            state = json.loads(r.out or "{}").get("BackendState", "?")
            if state != "Running":
                raise RuntimeError(f"state {state} — run: sudo homecore tailscale")
            return state
        check("Tailscale", ts)
    return 1 if failures else 0


def cmd_bluetooth(args) -> int:
    header("Bluetooth")
    adapters = sorted(os.listdir("/sys/class/bluetooth")) if os.path.isdir("/sys/class/bluetooth") else []
    kv("Adapters", ", ".join(a for a in adapters if ":" not in a) or yellow("none detected"))
    kv("bluetoothd", service_state("bluetooth"))
    if os.path.isdir("/sys/class/rfkill"):
        for rf in sorted(os.listdir("/sys/class/rfkill")):
            base = f"/sys/class/rfkill/{rf}"
            if read(f"{base}/type").strip() == "bluetooth":
                soft, hard = read(f"{base}/soft").strip(), read(f"{base}/hard").strip()
                blocked = red("blocked") if "1" in (soft, hard) else green("unblocked")
                kv("rfkill", f"{read(f'{base}/name').strip()} {blocked}")
    if not have("bluetoothctl"):
        print(yellow("  BlueZ is not installed (installed with --no-bluetooth?)."))
        return 1
    if not adapters:
        print(dim("  In VirtualBox, pass a USB Bluetooth dongle through: Devices → USB."))
        return 1
    if args.sub == "scan":
        secs = str(max(5, min(args.seconds, 60)))
        print(dim(f"  Scanning for {secs} s…"))
        run(["bluetoothctl", "--timeout", secs, "scan", "on"], timeout=int(secs) + 10)
    print(run(["bluetoothctl", "show"]).out.strip())
    devs = run(["bluetoothctl", "devices"]).out.strip()
    header("Known / discovered devices")
    print(devs or dim("  none — try: homecore bluetooth scan"))
    return 0


def cmd_mqtt(args) -> int:
    sub = args.sub or "users"
    if sub == "users":
        return script("mqtt-user.sh", "list")
    if sub == "add":
        if not args.name:
            print(red("Usage: homecore mqtt add <user> [--role device|admin|readonly|zigbee|cli]"))
            return 2
        return script("mqtt-user.sh", "add", args.name, args.role)
    if sub == "remove":
        if not args.name:
            print(red("Usage: homecore mqtt remove <user>"))
            return 2
        return script("mqtt-user.sh", "remove", args.name)
    if sub == "listen":
        topic = args.name or "#"
        print(dim(f"Listening on '{topic}' for {args.seconds} s (Ctrl-C to stop)…"))
        r = run(["docker", "exec", "-e", "XDG_CONFIG_HOME=/cli", "homecore-mosquitto", "mosquitto_sub",
                 "-v", "-t", topic, "-W", str(args.seconds)], sudo=True, capture=False, timeout=args.seconds + 10)
        return 0 if r.code in (0, 27) else r.code   # 27 = mosquitto_sub timeout
    print(red(f"Unknown mqtt command: {sub}"))
    return 2


def _usb_devices() -> list[dict]:
    base = "/sys/bus/usb/devices"
    out = []
    if not os.path.isdir(base):
        return out
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d)
        vid = read(f"{p}/idVendor").strip()
        if not vid or read(f"{p}/bDeviceClass").strip() == "09":   # skip hubs
            continue
        out.append({"id": f"{vid}:{read(f'{p}/idProduct').strip()}",
                    "maker": read(f"{p}/manufacturer").strip(), "product": read(f"{p}/product").strip()})
    return out


def cmd_devices(_args) -> int:
    header("USB devices")
    usb = _usb_devices()
    for u in usb:
        print(f"  {u['id']}  {u['maker']} {u['product']}")
    if not usb:
        print(dim("  none"))
    header("Serial ports (Zigbee coordinators)")
    byid = "/dev/serial/by-id"
    if os.path.isdir(byid):
        for name in sorted(os.listdir(byid)):
            print(f"  {name}\n    → {os.path.realpath(os.path.join(byid, name))}")
    else:
        print(dim("  none — plug in the Zigbee dongle (VirtualBox: Devices → USB)"))
    env = read_env(os.path.join(HC_ROOT, ".env")) if is_root() or os.access(os.path.join(HC_ROOT, ".env"), os.R_OK) else {}
    if env.get("ZIGBEE_DEVICE"):
        kv("Zigbee2MQTT", f"{env['ZIGBEE_DEVICE']} ({env.get('ZIGBEE_ADAPTER', '?')})")

    header("Bluetooth adapters")
    bt = [a for a in os.listdir("/sys/class/bluetooth") if ":" not in a] if os.path.isdir("/sys/class/bluetooth") else []
    print("  " + (", ".join(bt) or dim("none")))

    if "homecore-zigbee2mqtt" in container_states():
        header("Zigbee devices")
        r = mqtt_cli("mosquitto_sub", "-t", "zigbee2mqtt/bridge/devices", "-C", "1", "-W", "5")
        try:
            devices = json.loads(r.out.strip() or "[]")
        except ValueError:
            devices = []
        for dev in devices:
            if dev.get("type") == "Coordinator":
                continue
            d = dev.get("definition") or {}
            name = guard.sanitize(str(dev.get("friendly_name", "?")), max_len=40)
            print(f"  {name:<32} {d.get('vendor', '')} {d.get('model', '')} "
                  f"{dim(dev.get('power_source', '') or '')}")
        if not devices:
            print(dim("  none paired yet — homecore zigbee pair"))
    return 0


def cmd_zigbee(args) -> int:
    sub = args.sub or "detect"
    if sub == "detect":
        return script("zigbee.sh", "detect")
    if sub == "enable":
        return script("zigbee.sh", "enable", *[a for a in (args.device, args.adapter) if a])
    if sub == "disable":
        return script("zigbee.sh", "disable")
    if sub == "pair":
        secs = max(30, min(args.seconds, 254))
        r = mqtt_cli("mosquitto_pub", "-t", "zigbee2mqtt/bridge/request/permit_join",
                     "-m", json.dumps({"time": secs}))
        if r.ok:
            print(green(f"Pairing open for {secs} s — put the device in pairing mode now."))
        else:
            print(red(f"Could not open pairing: {r.err.strip()}"))
        return r.code
    print(red(f"Unknown zigbee command: {sub}"))
    return 2


# --------------------------------------------------------------------------- security audit
@dataclass
class Check:
    status: str   # PASS / WARN / FAIL / INFO
    name: str
    detail: str = ""


def _audit() -> list[Check]:
    checks: list[Check] = []
    add = lambda s, n, d="": checks.append(Check(s, n, d))  # noqa: E731
    henv = read_env(os.path.join(HC_ETC, "homecore.env"))

    # SSH
    t = run(["sshd", "-T"])
    if t.ok:
        cfg = {}
        for line in t.out.splitlines():
            k, _, v = line.partition(" ")
            cfg.setdefault(k, v)
        add("PASS" if cfg.get("permitrootlogin") == "no" else "FAIL", "SSH root login disabled",
            f"PermitRootLogin {cfg.get('permitrootlogin')}")
        add("PASS" if cfg.get("passwordauthentication") == "no" else "WARN", "SSH key-only login",
            "PasswordAuthentication " + cfg.get("passwordauthentication", "?") +
            ("" if cfg.get("passwordauthentication") == "no" else " → ssh-copy-id, then: sudo homecore harden ssh"))
        add("PASS" if cfg.get("x11forwarding") == "no" else "WARN", "SSH X11 forwarding off")
    else:
        add("WARN", "SSH configuration", "could not run sshd -T")

    # Firewall
    fw = run(["nft", "list", "table", "inet", "homecore"])
    if fw.ok and "policy drop" in fw.out:
        add("PASS", "Firewall loaded, default deny")
    else:
        add("FAIL", "Firewall loaded, default deny", "run: sudo homecore firewall apply")
    if run(["systemctl", "is-enabled", "homecore-firewall"]).out.strip() != "enabled":
        add("WARN", "Firewall enabled at boot", "systemctl enable homecore-firewall")

    # Network exposure
    expected_tcp = {int(p) for p in henv.get("LAN_TCP_PORTS", "22 8123 1883 8080").split() if p.isdigit()}
    expected_udp = {int(p) for p in henv.get("LAN_UDP_PORTS", "5353").split() if p.isdigit()}
    expected_udp |= {68, 546, int(henv.get("TAILSCALE_UDP_PORT", "41641") or 41641)}
    unexpected = []
    for s in listening_sockets():
        if is_loopback(s["addr"]) or s["addr"].startswith("100.") or s["addr"].startswith("fd7a:115c"):
            continue
        allowed = expected_tcp if s["proto"] == "tcp" else expected_udp
        if s["port"] not in allowed:
            unexpected.append(f"{s['proto']}/{s['port']} {s['process']}".strip())
    add("PASS" if not unexpected else "INFO", "Unexpected listening ports",
        ", ".join(unexpected[:8]) + (" (blocked by firewall unless listed in homecore.env)" if unexpected else "none"))

    # Kernel hardening
    sysctls = {"net.ipv4.conf.all.rp_filter": "1", "net.ipv4.tcp_syncookies": "1",
               "kernel.kptr_restrict": "2", "kernel.dmesg_restrict": "1",
               "net.ipv4.conf.all.accept_redirects": "0", "net.ipv4.ip_forward": "0"}
    bad = [k for k, v in sysctls.items()
           if read("/proc/sys/" + k.replace(".", "/")).strip() not in ("", v)]
    add("PASS" if not bad else "WARN", "Kernel/network sysctl hardening", ", ".join(bad) or "")

    # Updates
    au = read("/etc/apt/apt.conf.d/20auto-upgrades")
    add("PASS" if 'Unattended-Upgrade "1"' in au else "WARN", "Automatic security updates")
    if os.path.exists("/run/reboot-required"):
        add("WARN", "Reboot pending", "installed updates need a reboot")

    # MQTT broker
    conf = read(os.path.join(HC_ROOT, "config/mosquitto/mosquitto.conf"))
    add("PASS" if re.search(r"^allow_anonymous\s+false", conf, re.M) else "FAIL", "MQTT requires authentication")
    acl = read(os.path.join(HC_ROOT, "config/mosquitto/acl"))
    add("PASS" if "user " in acl else "WARN", "MQTT per-user ACL", "" if acl else "run: sudo homecore setup")

    # Secrets & permissions
    for path, want in ((os.path.join(HC_ROOT, "secrets"), 0o700), (os.path.join(HC_ROOT, ".env"), 0o600),
                       (os.path.join(HC_ROOT, "backups"), 0o700)):
        try:
            mode = os.stat(path).st_mode & 0o777
            add("PASS" if mode & 0o077 == 0 else "FAIL", f"Permissions {path}", oct(mode))
        except OSError:
            pass

    # Docker
    r = run(["docker", "ps", "-q", "--filter", "name=homecore-"])
    ids = r.out.split()
    if ids:
        ins = run(["docker", "inspect", "--format",
                   "{{.Name}} {{.HostConfig.Privileged}} {{range .Mounts}}{{.Source}} {{end}}", *ids])
        priv, sock = [], []
        for ln in ins.out.splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[1] == "true":
                priv.append(parts[0].lstrip("/"))
            if any(m.endswith("docker.sock") for m in parts[2:]):
                sock.append(parts[0].lstrip("/"))
        add("PASS" if not priv else "FAIL", "No privileged containers", ", ".join(priv))
        add("PASS" if not sock else "FAIL", "Docker socket not exposed to containers", ", ".join(sock))
    dgrp = [ln for ln in read("/etc/group").splitlines() if ln.startswith("docker:")]
    members = dgrp[0].split(":")[3] if dgrp else ""
    add("PASS" if not members else "WARN", "'docker' group is empty (it equals root)", members)

    # Accounts
    shadow = read("/etc/shadow")
    empty = [ln.split(":")[0] for ln in shadow.splitlines() if ln.count(":") >= 2 and ln.split(":")[1] == ""]
    add("PASS" if not empty else "FAIL", "No accounts with empty passwords", ", ".join(empty))
    if any(ln.startswith("pi:") for ln in read("/etc/passwd").splitlines()):
        add("WARN", "Default 'pi' user exists", "remove it if unused: sudo deluser --remove-home pi")

    # Intrusion signals (last 24h)
    j = run(["journalctl", "--since", "-24h", "-q", "--no-pager", "-o", "cat",
             "-u", "ssh", "-u", "sshd", "-g", "Failed password|Invalid user|authentication failure"], timeout=30)
    fails = len(j.out.splitlines()) if j.ok else 0
    add("PASS" if fails < 10 else "WARN", "Failed SSH logins (24 h)", str(fails))
    k = run(["journalctl", "-k", "--since", "-24h", "-q", "--no-pager", "-o", "cat", "-g", "homecore-ssh-flood"], timeout=30)
    floods = len(k.out.splitlines()) if k.ok else 0
    if floods:
        add("WARN", "SSH flood attempts rate-limited (24 h)", str(floods))
    bans = read(os.path.join(HC_ROOT, "config/homeassistant/ip_bans.yaml"))
    banned = len(re.findall(r"^\S+:", bans, re.M))
    add("PASS" if banned == 0 else "INFO", "Home Assistant banned IPs", str(banned))

    # Home Assistant HTTP
    ha = read(os.path.join(HC_ROOT, "config/homeassistant/configuration.yaml"))
    add("PASS" if re.search(r"^\s*ip_ban_enabled:\s*true", ha, re.M) else "WARN", "Home Assistant login ban enabled")

    # Time (TLS, logs and tokens depend on it)
    ntp = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).out.strip()
    add("PASS" if ntp == "yes" else "WARN", "Clock synchronised (NTP)", ntp)

    # Tailscale
    if have("tailscale"):
        st = run(["tailscale", "status", "--json"], timeout=10)
        try:
            data = json.loads(st.out or "{}")
        except ValueError:
            data = {}
        state = data.get("BackendState", "?")
        add("PASS" if state == "Running" else "INFO", "Tailscale connected", state)
        if (data.get("Self") or {}).get("KeyExpiry") is None and state == "Running":
            add("INFO", "Tailscale key expiry disabled", "fine only if the device is physically secure")

    # Prompt-injection tripwire on Home Assistant names
    reports, scanned = guard.scan_ha_storage(os.path.join(HC_ROOT, "config/homeassistant/.storage"))
    flagged = [r for r in reports if r.flagged]
    if scanned:
        add("PASS" if not flagged else "WARN", "No prompt-injection text in HA names",
            f"{len(flagged)} suspicious → homecore guard ha" if flagged else f"{len(scanned)} registries scanned")
    return checks


def cmd_security(args) -> int:
    ensure_root(["security", *(["--json"] if args.json else [])])
    checks = _audit()
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        header("Security audit")
        icon = {"PASS": green("✔ PASS"), "WARN": yellow("! WARN"), "FAIL": red("✘ FAIL"), "INFO": cyan("i INFO")}
        for c in checks:
            print(f"  {icon[c.status]}  {c.name:<44} {dim(c.detail)}")
        n = {s: sum(c.status == s for c in checks) for s in icon}
        print(f"\n  {n['PASS']} passed · {n['WARN']} warnings · {n['FAIL']} failed")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


# --------------------------------------------------------------------------- prompt-injection guard
def _print_reports(reports: list[guard.Report], as_json: bool, show_all: bool = False) -> int:
    reports = [r for r in reports if show_all or r.score > 0]
    if as_json:
        print(json.dumps([r.to_dict() for r in reports], indent=2, ensure_ascii=False))
    else:
        colors = {"block": red, "review": yellow, "low": dim, "clean": green}
        for r in sorted(reports, key=lambda x: -x.score):
            print(f"  {colors[r.level](r.level.upper().ljust(6))} score {r.score:<3} {bold(r.source or r.context)}")
            print(f"         {dim(repr(guard.sanitize(r.text, max_len=100)))}")
            for f in r.findings:
                print(f"         · {f.description}" + (dim(f"  [{f.excerpt}]") if f.excerpt else ""))
        if not reports:
            print(green("  ✔ nothing suspicious found"))
    worst = max((r.score for r in reports), default=0)
    return 2 if worst >= guard.LEVEL_BLOCK else 1 if worst >= guard.LEVEL_REVIEW else 0


def cmd_guard(args) -> int:
    sub = args.sub
    text = " ".join(args.text) if args.text else ""
    if sub in ("check", "sanitize", "wrap") and (not text or text == "-"):
        text = sys.stdin.read()
    if sub == "check":
        r = guard.scan_text(text, args.context, source="input")
        return _print_reports([r], args.json, show_all=True)
    if sub == "sanitize":
        print(guard.sanitize(text, max_len=args.max_len, strict=args.strict))
        return 0
    if sub == "wrap":
        print(guard.wrap_untrusted(text))
        return 0
    if sub == "ha":
        ensure_root(["guard", "ha", *(["--json"] if args.json else [])])
        path = os.path.join(HC_ROOT, "config/homeassistant/.storage")
        reports, scanned = guard.scan_ha_storage(path)
        if not args.json:
            header("Prompt-injection scan · Home Assistant names")
            print(dim(f"  scanned: {', '.join(scanned) or 'nothing (has Home Assistant been onboarded?)'}"))
        return _print_reports(reports, args.json)
    if sub == "mqtt":
        if not args.json:
            header("Prompt-injection scan · retained MQTT discovery & Zigbee data")
        lines = []
        for topic in ("homeassistant/#", "zigbee2mqtt/bridge/devices", "zigbee2mqtt/bridge/groups"):
            r = mqtt_cli("mosquitto_sub", "-v", "-t", topic, "--retained-only", "-W", str(args.seconds),
                         timeout=args.seconds + 10)
            if r.code not in (0, 27):
                print(red(f"  mosquitto_sub failed: {r.err.strip() or r.code} (is the stack running?)"))
                return 3
            lines.extend(r.out.splitlines())
        if not args.json:
            print(dim(f"  scanned {len(lines)} retained messages"))
        return _print_reports(guard.scan_mqtt_lines(lines), args.json)
    print(red("Usage: homecore guard check|sanitize|wrap|ha|mqtt"))
    return 2


# --------------------------------------------------------------------------- misc commands
def cmd_firewall(args) -> int:
    sub = args.sub or "status"
    if sub == "status":
        return script("firewall.sh", "status")
    if sub == "apply":
        return script("firewall.sh", "apply", "--safe")
    if sub in ("render", "detect", "disable"):
        return script("firewall.sh", sub)
    print(red(f"Unknown firewall command: {sub}"))
    return 2


def cmd_logs(args) -> int:
    svc = args.service or "ha"
    if svc in ("system", "ssh", "firewall", "docker", "tailscale"):
        unit = {"system": None, "ssh": "ssh", "firewall": None, "docker": "docker", "tailscale": "tailscaled"}[svc]
        cmd = ["journalctl", "--no-pager", "-n", str(args.lines)]
        if svc == "firewall":
            cmd += ["-k", "-g", "homecore-"]
        elif unit:
            cmd += ["-u", unit]
        if args.follow:
            cmd.append("-f")
        return run(cmd, sudo=True, capture=False, timeout=None).code
    name = SERVICES.get(svc)
    if not name:
        print(red(f"Unknown service '{svc}'. Use: ha, mqtt, zigbee, system, ssh, firewall, docker, tailscale"))
        return 2
    cmd = ["docker", "logs", "--tail", str(args.lines), *(["-f"] if args.follow else []), name]
    return run(cmd, sudo=True, capture=False, timeout=None).code


def _compose(*args: str) -> int:
    return run(["docker", "compose", "--project-directory", HC_ROOT, "-f",
                os.path.join(HC_ROOT, "docker-compose.yml"), *args], sudo=True, capture=False, timeout=None).code


def cmd_stack(args) -> int:
    svc = [SERVICES[args.service]] if args.service in SERVICES else []
    svc = [s.replace("homecore-", "") for s in svc]
    return {"start": lambda: _compose("up", "-d", *svc), "stop": lambda: _compose("stop", *svc),
            "restart": lambda: _compose("restart", *svc)}[args.cmd]()


def cmd_version(_args) -> int:
    print("HomeCore OS " + read(os.path.join(HC_ROOT, "VERSION"), "unknown").strip())
    return 0


# --------------------------------------------------------------------------- interactive menu
MENU = [
    ("Status overview", ["status"]),
    ("Network", ["network"]),
    ("Network connectivity test", ["network", "test"]),
    ("Devices on the LAN", ["network", "neighbors"]),
    ("Bluetooth (scan)", ["bluetooth", "scan"]),
    ("Hardware & Zigbee devices", ["devices"]),
    ("MQTT users", ["mqtt", "users"]),
    ("Security audit", ["security"]),
    ("Prompt-injection scan (Home Assistant)", ["guard", "ha"]),
    ("Prompt-injection scan (MQTT)", ["guard", "mqtt"]),
    ("Firewall rules", ["firewall", "status"]),
    ("Home Assistant logs", ["logs", "ha"]),
    ("Backup now", ["backup"]),
    ("Update everything", ["update"]),
    ("Restart the stack", ["restart"]),
]


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
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            argv = MENU[int(choice) - 1][1]
            if argv[0] in ("security",) or argv[:2] == ["guard", "ha"]:
                run([sys.executable, "-I", os.path.realpath(__file__), *argv], sudo=True, capture=False, timeout=None)
            else:
                try:
                    main(argv)
                except KeyboardInterrupt:
                    print()
            try:
                input(dim("\n  press Enter to continue"))
            except (EOFError, KeyboardInterrupt):
                return 0
        else:
            print(red("  invalid choice"))


# --------------------------------------------------------------------------- argument parsing
WRAPPERS = {
    "setup": ("setup.sh", "first start: MQTT accounts + start the stack"),
    "backup": ("backup.sh", "back up configuration, data and secrets [--full] [--dest DIR]"),
    "restore": ("restore.sh", "restore a backup archive"),
    "update": ("update.sh", "update OS packages and containers [--os-only|--containers-only]"),
    "tailscale": ("install-tailscale.sh", "install/connect Tailscale VPN"),
    "harden": ("harden.sh", "re-apply hardening: all|ssh|kernel|journald|updates"),
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="homecore", description="HomeCore OS control centre.")
    sp = p.add_subparsers(dest="cmd")

    sp.add_parser("menu", help="interactive menu (default)").set_defaults(fn=cmd_menu)
    sp.add_parser("status", help="system, services and containers").set_defaults(fn=cmd_status)

    n = sp.add_parser("network", help="interfaces, routes, ports, LAN devices, tests")
    n.add_argument("sub", nargs="?", choices=["show", "test", "neighbors", "ports"])
    n.set_defaults(fn=cmd_network)

    b = sp.add_parser("bluetooth", help="Bluetooth adapter and devices")
    b.add_argument("sub", nargs="?", choices=["show", "scan"])
    b.add_argument("--seconds", type=int, default=10)
    b.set_defaults(fn=cmd_bluetooth)

    m = sp.add_parser("mqtt", help="MQTT users and live traffic")
    m.add_argument("sub", nargs="?", choices=["users", "add", "remove", "listen"])
    m.add_argument("name", nargs="?", help="user name (add/remove) or topic (listen)")
    m.add_argument("--role", default="device", choices=["device", "admin", "readonly", "zigbee", "cli"])
    m.add_argument("--seconds", type=int, default=30)
    m.set_defaults(fn=cmd_mqtt)

    sp.add_parser("devices", help="USB, serial, Bluetooth and Zigbee devices").set_defaults(fn=cmd_devices)

    z = sp.add_parser("zigbee", help="Zigbee coordinator: detect, enable, disable, pair")
    z.add_argument("sub", nargs="?", choices=["detect", "enable", "disable", "pair"])
    z.add_argument("device", nargs="?")
    z.add_argument("adapter", nargs="?", choices=["zstack", "ember", "deconz", "zigate", "zboss"])
    z.add_argument("--seconds", type=int, default=120)
    z.set_defaults(fn=cmd_zigbee)

    s = sp.add_parser("security", help="security audit")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_security)

    g = sp.add_parser("guard", help="prompt-injection scanner")
    g.add_argument("sub", choices=["check", "sanitize", "wrap", "ha", "mqtt"])
    g.add_argument("text", nargs="*", help="text to check (or stdin)")
    g.add_argument("--context", choices=["name", "text"], default="text")
    g.add_argument("--json", action="store_true")
    g.add_argument("--strict", action="store_true", help="sanitize: keep only plain name characters")
    g.add_argument("--max-len", type=int, default=None)
    g.add_argument("--seconds", type=int, default=3, help="mqtt: seconds to wait for retained messages")
    g.set_defaults(fn=cmd_guard)

    f = sp.add_parser("firewall", help="show or apply firewall rules")
    f.add_argument("sub", nargs="?", choices=["status", "apply", "render", "detect", "disable"])
    f.set_defaults(fn=cmd_firewall)

    lg = sp.add_parser("logs", help="logs: ha, mqtt, zigbee, system, ssh, firewall, docker, tailscale")
    lg.add_argument("service", nargs="?")
    lg.add_argument("-n", "--lines", type=int, default=100)
    lg.add_argument("-f", "--follow", action="store_true")
    lg.set_defaults(fn=cmd_logs)

    for name, helptext in (("start", "start the stack"), ("stop", "stop the stack"), ("restart", "restart the stack")):
        x = sp.add_parser(name, help=helptext)
        x.add_argument("service", nargs="?", choices=sorted(SERVICES))
        x.set_defaults(fn=cmd_stack)

    # Thin wrappers around the scripts: listed here for --help, dispatched in main()
    # so that options such as `backup --full` pass through untouched.
    for name, (_scr, helptext) in WRAPPERS.items():
        sp.add_parser(name, help=helptext, add_help=False)

    sp.add_parser("version", help="show version").set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in WRAPPERS:
        return script(WRAPPERS[argv[0]][0], *argv[1:])
    parser = build_parser()
    args = parser.parse_args(argv)
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
