"""HomeCore Scan — local-network discovery and vulnerability assessment.

Engine: nmap (SYN/ARP scans, service detection, *safe* NSE scripts) plus a few
tiny native checks (anonymous MQTT, UPnP/SSDP). Results are turned into
findings with a severity and a fix, an inventory of devices is kept, and
changes (new device, new open port, gateway MAC change) become alerts.

Scope: only private address space (RFC 1918, link-local, ULA) is accepted —
scan only networks you own or are authorised to test.

Pure standard library. Every string that comes from a scanned device (hostnames,
banners, page titles, SSIDs) is attacker-controlled: callers must pass it through
homecore_guard.sanitize() before printing it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field

STATE_DIR = os.environ.get("HC_STATE", "/var/lib/homecore")
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_PREFIX_V4 = 20          # largest network scanned in one go: /20 = 4096 addresses

# NSE scripts used by the standard profile: all in nmap's "safe" category.
SAFE_SCRIPTS = ("ftp-anon,smb-protocols,vnc-info,sshv1,ssh2-enum-algos,http-title,ssl-cert,"
                "redis-info,mongodb-info,memcached-info,rdp-enum-encryption,docker-version")

# High-risk ports that nmap's "top 1000" list misses: MQTT, Docker API, ADB, databases,
# Xiongmai/Dahua cameras, MikroTik, TR-069, Kubernetes, UPnP control, CoAP-over-TCP.
IOT_PORTS = ("1883,8883,2375,2376,5555,6379,7547,8291,8554,9200,10250,11211,27017,"
             "34567,37777,49152,49153,5683,1900,8009,8060,9000,9999")

PROFILES = {
    "quick": {
        "desc": "top 100 TCP ports, no service detection (~1-3 min for a /24 on a Pi 3B)",
        "tcp": ["-sS", "--top-ports", "100", "-T4", "--open", "--max-retries", "2"],
        "udp": None, "network": False,
    },
    "standard": {
        "desc": "top 1000 TCP + key UDP ports, service versions, safe checks (~5-15 min)",
        "tcp": ["-sS", "-sV", "--version-light", "--top-ports", "1000", "-T4", "--open",
                "--max-retries", "2", "--script", SAFE_SCRIPTS],
        "udp": ["-sU", "-p", "69,161,1900", "--open", "-T4", "--max-retries", "1",
                "--script", "snmp-info,upnp-info"],
        "network": True,
    },
    "deep": {
        "desc": "top 5000 TCP + UDP, TLS ciphers, nmap 'vuln and safe' scripts (30-90 min)",
        "tcp": ["-sS", "-sV", "--top-ports", "5000", "-T3", "--open", "--max-retries", "2",
                "--script", SAFE_SCRIPTS + ",ssl-enum-ciphers,(vuln and safe)"],
        "udp": ["-sU", "--top-ports", "30", "--open", "-T4", "--max-retries", "1",
                "--script", "snmp-info,upnp-info"],
        "network": True,
    },
}


# --------------------------------------------------------------------------- data model
@dataclass
class Port:
    proto: str
    port: int
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.proto}/{self.port}"

    @property
    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extrainfo) if x)


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list = field(default_factory=list)
    scripts: dict = field(default_factory=dict)

    def port(self, proto: str, number: int) -> Port | None:
        return next((p for p in self.ports if p.proto == proto and p.port == number), None)


@dataclass
class Finding:
    severity: str
    title: str
    host: str = ""
    port: str = ""
    detail: str = ""
    fix: str = ""
    rule: str = ""

    def key(self) -> tuple:
        return (SEV_RANK.get(self.severity, 9), self.host, self.port, self.title)


# --------------------------------------------------------------------------- scope
class ScopeError(ValueError):
    pass


def _allowed_net(net) -> bool:
    return (net.is_private or net.is_link_local) and not (net.is_loopback or net.is_multicast
                                                          or net.is_unspecified)


def validate_targets(targets: list[str]) -> list[str]:
    """Accept only IPs/CIDRs inside private address space and of a sane size."""
    out = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t.strip(), strict=False)
        except ValueError as e:
            raise ScopeError(f"'{t}' is not an IP address or CIDR network (hostnames are not accepted)") from e
        if not _allowed_net(net):
            raise ScopeError(f"{net} is not private address space — HomeCore only scans your own LAN")
        if net.version == 4 and net.prefixlen < MAX_PREFIX_V4:
            raise ScopeError(f"{net} is too large for one scan (max /{MAX_PREFIX_V4}); split it up")
        if net.version == 6 and net.num_addresses > 1:
            raise ScopeError(f"{net}: IPv6 networks can't be swept; give single IPv6 addresses")
        out.append(str(net) if net.num_addresses > 1 else str(net.network_address))
    if not out:
        raise ScopeError("no targets")
    return out


def _ip_json(args: list[str]) -> list:
    try:
        r = subprocess.run(["ip", "-j", *args], capture_output=True, text=True, timeout=10)
        return json.loads(r.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


SKIP_IFACES = ("lo", "docker", "br-", "veth", "tailscale", "virbr", "wg")


def local_networks() -> tuple[list[str], set[str]]:
    """LAN networks of this machine (IPv4) and its own addresses."""
    nets, own = [], set()
    for iface in _ip_json(["addr", "show"]):
        name = iface.get("ifname", "")
        for a in iface.get("addr_info", []):
            own.add(a.get("local", ""))
            if name.startswith(SKIP_IFACES) or a.get("family") != "inet" or a.get("scope") != "global":
                continue
            prefix = a["prefixlen"] if a["prefixlen"] >= MAX_PREFIX_V4 else 24
            net = ipaddress.ip_interface(f"{a['local']}/{prefix}").network
            if _allowed_net(net) and str(net) not in nets:
                nets.append(str(net))
    return nets, own


def default_gateway() -> str:
    routes = _ip_json(["route", "show", "default"])
    return routes[0].get("gateway", "") if routes else ""


# --------------------------------------------------------------------------- nmap
def nmap_version() -> str:
    try:
        out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout
        return out.splitlines()[0] if out else "?"
    except OSError:
        return "not installed"


def run_nmap(args: list[str], targets: list[str], progress: bool = False, timeout: int = 6 * 3600) -> ET.Element:
    ensure_state_dir()
    os.makedirs(os.path.join(STATE_DIR, "tmp"), mode=0o700, exist_ok=True)
    xml_path = os.path.join(STATE_DIR, "tmp", f"nmap-{os.getpid()}-{time.time_ns()}.xml")
    cmd = ["nmap", *args, "-oX", xml_path]
    if progress:
        cmd += ["--stats-every", "30s"]
    cmd += ["--", *targets]
    try:
        r = subprocess.run(cmd, stdout=None if progress else subprocess.DEVNULL, stderr=subprocess.PIPE,
                           text=True, timeout=timeout, check=False)
        try:
            return ET.parse(xml_path).getroot()
        except (OSError, ET.ParseError) as e:
            raise RuntimeError(f"nmap failed: {(r.stderr or str(e)).strip()[:300]}") from e
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def _script_outputs(elem) -> dict:
    return {s.get("id", ""): s.get("output", "") for s in elem.findall("script")}


def parse_nmap_xml(root: ET.Element) -> tuple[list[Host], dict]:
    """Return (hosts that are up, pre/post-scan script outputs)."""
    hosts = []
    for h in root.findall("host"):
        status = h.find("status")
        if status is not None and status.get("state") != "up":
            continue
        host = Host(ip="")
        for addr in h.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = addr.get("addr", "").lower()
                host.vendor = addr.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None:
            host.hostname = hn.get("name", "")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            sv = svc.attrib if svc is not None else {}
            host.ports.append(Port(proto=p.get("protocol", "tcp"), port=int(p.get("portid", "0")),
                                   service=sv.get("name", ""), product=sv.get("product", ""),
                                   version=sv.get("version", ""), extrainfo=sv.get("extrainfo", ""),
                                   tunnel=sv.get("tunnel", ""), scripts=_script_outputs(p)))
        hs = h.find("hostscript")
        if hs is not None:
            host.scripts = _script_outputs(hs)
        if host.ip:
            hosts.append(host)
    extra = {}
    for tag in ("prescript", "postscript"):
        e = root.find(tag)
        if e is not None:
            extra.update(_script_outputs(e))
    return hosts, extra


def merge_hosts(base: list[Host], more: list[Host]) -> list[Host]:
    by_ip = {h.ip: h for h in base}
    for h in more:
        if h.ip in by_ip:
            tgt = by_ip[h.ip]
            tgt.mac = tgt.mac or h.mac
            tgt.vendor = tgt.vendor or h.vendor
            tgt.hostname = tgt.hostname or h.hostname
            tgt.ports.extend(p for p in h.ports if not tgt.port(p.proto, p.port))
            tgt.scripts.update(h.scripts)
        else:
            by_ip[h.ip] = h
            base.append(h)
    return base


# --------------------------------------------------------------------------- native checks
def mqtt_anonymous(ip: str, port: int = 1883, timeout: float = 3.0) -> bool | None:
    """True if the broker accepts a CONNECT without credentials. Only connects and
    disconnects — nothing is subscribed or published."""
    client_id = b"homecore-audit"
    var = b"\x00\x04MQTT\x04\x02\x00\x3c"
    payload = len(client_id).to_bytes(2, "big") + client_id
    body = var + payload
    packet = b"\x10" + bytes([len(body)]) + body
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(packet)
            resp = s.recv(4)
            try:
                s.sendall(b"\xe0\x00")
            except OSError:
                pass
    except OSError:
        return None
    if len(resp) >= 4 and resp[0] == 0x20:
        return resp[3] == 0
    return None


def ssdp_discover(wait: float = 3.0) -> list[dict]:
    """UPnP/SSDP M-SEARCH on the LAN. Returns responders with their headers."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    found: dict[str, dict] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        sock.sendto(msg, ("239.255.255.250", 1900))
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                data, (ip, _) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            headers = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                k, _, v = line.partition(":")
                if k:
                    headers[k.strip().lower()] = v.strip()
            entry = found.setdefault(ip, {"ip": ip, "server": headers.get("server", ""), "types": set()})
            if headers.get("st"):
                entry["types"].add(headers["st"])
    except OSError:
        pass
    finally:
        sock.close()
    return [{**v, "types": sorted(v["types"])} for v in found.values()]


# --------------------------------------------------------------------------- assessment rules
# (ports, nmap service names, severity, title, fix)
SERVICE_RULES = [
    ({2375}, {"docker"}, "critical", "Docker API without TLS (full remote control of the host)",
     "Never expose the Docker socket over TCP; bind it to localhost or use TLS on 2376."),
    ({5555}, {"adb", "freeciv"}, "critical", "Android Debug Bridge (ADB) exposed",
     "Disable network debugging on the device (TV boxes, phones)."),
    ({23, 2323}, {"telnet"}, "high", "Telnet enabled — logins travel in cleartext",
     "Disable Telnet in the device settings; use SSH or the vendor app. Common botnet (Mirai) target."),
    ({69}, {"tftp"}, "high", "TFTP enabled — file transfer without authentication",
     "Disable TFTP unless it is needed for network boot."),
    ({6379}, {"redis"}, "high", "Redis database exposed on the network",
     "Bind Redis to 127.0.0.1 and set a password (requirepass)."),
    ({27017}, {"mongodb", "mongod"}, "high", "MongoDB exposed on the network",
     "Bind MongoDB to localhost and enable authentication."),
    ({11211}, {"memcache", "memcached"}, "high", "Memcached exposed on the network",
     "Bind memcached to localhost (-l 127.0.0.1)."),
    ({9200}, {"elasticsearch"}, "high", "Elasticsearch exposed on the network",
     "Enable security (authentication/TLS) and bind to localhost."),
    ({21}, {"ftp"}, "medium", "FTP enabled — credentials travel in cleartext",
     "Disable FTP or replace it with SFTP/FTPS."),
    ({3389}, {"ms-wbt-server"}, "medium", "Remote Desktop (RDP) exposed",
     "Allow RDP only where needed, require NLA, keep Windows patched."),
    ({5900, 5901, 5902}, {"vnc"}, "medium", "VNC remote desktop exposed",
     "Disable VNC or protect it with a strong password and restrict access."),
    ({1883}, {"mqtt"}, "medium", "MQTT broker without TLS",
     "Require authentication and prefer MQTT over TLS (8883)."),
    ({554, 8554}, {"rtsp"}, "medium", "RTSP video stream service (likely a camera)",
     "Set a strong camera password, update firmware, keep cameras on an isolated network."),
    ({161}, {"snmp"}, "medium", "SNMP enabled",
     "Disable SNMP or use SNMPv3 with authentication."),
    ({3306}, {"mysql"}, "medium", "MySQL/MariaDB exposed on the network",
     "Bind the database to localhost unless remote access is required."),
    ({5432}, {"postgresql"}, "medium", "PostgreSQL exposed on the network",
     "Bind the database to localhost unless remote access is required."),
    ({445, 139}, {"microsoft-ds", "netbios-ssn"}, "low", "Windows file sharing (SMB) exposed",
     "Share only what you need, require passwords, disable SMBv1."),
    ({1900}, {"upnp"}, "low", "UPnP/SSDP service enabled",
     "Disable UPnP on devices that don't need it."),
    ({9100}, {"jetdirect"}, "low", "Raw printing port (9100) open",
     "Restrict printer access to trusted hosts; update printer firmware."),
]

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8088, 8888}
HTTPS_PORTS = {443, 8443, 4443, 9443}
WEAK_SSH = ("diffie-hellman-group1-sha1", "ssh-dss", "arcfour", "-cbc", "hmac-md5", "3des")


def _first_line(text: str, limit: int = 160) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:limit]
    return ""


def assess_host(host: Host, check_mqtt: bool = True) -> list[Finding]:
    f: list[Finding] = []

    def add(sev, title, port="", detail="", fix="", rule=""):
        f.append(Finding(sev, title, host.ip, port, detail, fix, rule))

    for p in host.ports:
        for ports, names, sev, title, fix in SERVICE_RULES:
            if p.port in ports or (p.service and p.service in names):
                add(sev, title, p.label, p.banner, fix, "service")
                break
        s = p.scripts
        if "Anonymous FTP login allowed" in s.get("ftp-anon", ""):
            add("high", "Anonymous FTP login allowed", p.label, "", "Disable anonymous FTP.", "ftp-anon")
        smb = s.get("smb-protocols", "")
        if "SMBv1" in smb or "NT LM 0.12" in smb:
            add("high", "SMBv1 enabled (exploited by WannaCry/EternalBlue-class worms)", p.label, "",
                "Disable SMBv1 on the device or NAS.", "smb-protocols")
        vnc = s.get("vnc-info", "")
        if re.search(r"Security types:[\s\S]*?\bNone\b", vnc):
            add("critical", "VNC without password", p.label, "", "Set a VNC password or disable VNC.", "vnc-info")
        if "Server supports SSHv1" in s.get("sshv1", ""):
            add("high", "SSH protocol version 1 supported", p.label, "", "Disable SSHv1.", "sshv1")
        algos = s.get("ssh2-enum-algos", "")
        weak = sorted({w.strip("-") for w in WEAK_SSH if w in algos})
        if weak:
            add("medium", "SSH server offers weak algorithms", p.label, ", ".join(weak),
                "Update the device firmware or disable legacy algorithms.", "ssh2-enum-algos")
        for script in ("redis-info", "mongodb-info", "memcached-info"):
            out = s.get(script, "")
            if out and not re.search(r"auth|denied|unauthori[sz]ed|ERROR", out, re.I):
                add("critical", f"{script.split('-')[0].capitalize()} answers without authentication",
                    p.label, _first_line(out), "Enable authentication and bind to localhost.", script)
        if s.get("docker-version"):
            add("critical", "Docker API answers without authentication", p.label, "",
                "Disable the TCP Docker API.", "docker-version")
        if s.get("snmp-info"):
            add("high", "SNMP answers to the default 'public' community", p.label, _first_line(s["snmp-info"]),
                "Change the community string or disable SNMP (use SNMPv3).", "snmp-info")
        upnp = s.get("upnp-info", "")
        if "InternetGatewayDevice" in upnp or "WANIPConnection" in upnp:
            add("medium", "UPnP IGD enabled — any LAN device can open ports on your router", p.label, "",
                "Disable UPnP in the router unless a console/app really needs it.", "upnp-info")
        rdp = s.get("rdp-enum-encryption", "")
        if rdp and "CredSSP (NLA): SUCCESS" not in rdp:
            add("medium", "RDP without Network Level Authentication", p.label, "",
                "Require NLA for Remote Desktop.", "rdp-enum-encryption")
        tls = s.get("ssl-enum-ciphers", "")
        m = re.search(r"least strength:\s*([A-F])", tls)
        if m and m.group(1) in "CDEF":
            add("medium", f"Weak TLS configuration (grade {m.group(1)})", p.label, "",
                "Update the firmware; disable old TLS versions and ciphers.", "ssl-enum-ciphers")
        if re.search(r"\b(SSLv3|TLSv1\.0):", tls):
            add("medium", "Obsolete SSLv3/TLS 1.0 enabled", p.label, "", "Disable SSLv3 and TLS 1.0.", "ssl-enum-ciphers")
        cert = s.get("ssl-cert", "")
        m = re.search(r"Not valid after:\s*(\d{4}-\d{2}-\d{2})", cert)
        if m and m.group(1) < time.strftime("%Y-%m-%d"):
            add("low", "Expired TLS certificate", p.label, f"expired {m.group(1)}", "Renew the certificate.", "ssl-cert")
        f.extend(_vuln_script_findings(host.ip, p.label, s))
        f.extend(_vulners_findings(host.ip, p, s.get("vulners", "")))
        if check_mqtt and (p.port == 1883 or p.service == "mqtt") and p.proto == "tcp":
            if mqtt_anonymous(host.ip, p.port):
                add("critical", "MQTT broker accepts anonymous clients (anyone can read and control devices)",
                    p.label, "", "Set allow_anonymous false and create per-device accounts.", "mqtt-anon")

    tcp = {p.port for p in host.ports if p.proto == "tcp"}
    tls_ports = {p.port for p in host.ports if p.tunnel == "ssl" or p.service in ("https", "ssl/http")}
    http = sorted(tcp & HTTP_PORTS)
    if http and not (tcp & HTTPS_PORTS or tls_ports):
        add("low", "Web interface only over HTTP (no HTTPS)", f"tcp/{http[0]}", "",
            "Passwords typed into this interface travel in cleartext on the LAN.", "http-only")
    f.extend(_vuln_script_findings(host.ip, "", host.scripts))
    return f


def _vuln_script_findings(ip: str, port: str, scripts: dict) -> list[Finding]:
    out = []
    for sid, text in scripts.items():
        if sid == "vulners" or not re.search(r"State:\s+(LIKELY )?VULNERABLE", text):
            continue
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        title = next((lines[i + 1] for i, ln in enumerate(lines[:-1]) if ln.startswith("VULNERABLE")), sid)
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text)))
        out.append(Finding("high", title[:120], ip, port, ", ".join(cves[:5]),
                           "Patch or update the affected device/firmware.", sid))
    return out


def _vulners_findings(ip: str, p: Port, text: str) -> list[Finding]:
    if not text:
        return []
    scored = []
    for cve, score in re.findall(r"(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)", text):
        scored.append((float(score), cve))
    if not scored:
        return []
    scored.sort(reverse=True)
    top = scored[0][0]
    sev = "critical" if top >= 9 else "high" if top >= 7 else "medium" if top >= 4 else "low"
    worst = ", ".join(f"{c} ({s:g})" for s, c in scored[:4])
    return [Finding(sev, f"{p.banner or p.service}: {len(scored)} known CVEs (max CVSS {top:g})", ip, p.label,
                    worst, "Update this software/firmware to the latest version.", "vulners")]


def assess_network(hosts: list[Host], extra_scripts: dict, ssdp: list[dict], gateway: str) -> list[Finding]:
    f: list[Finding] = []
    dhcp = extra_scripts.get("broadcast-dhcp-discover", "")
    servers = sorted(set(re.findall(r"Server Identifier:\s*([0-9a-fA-F.:]+)", dhcp)))
    if len(servers) > 1:
        f.append(Finding("high", "Multiple DHCP servers on the network (possible rogue DHCP)", "", "",
                         ", ".join(servers), "Find and remove the unexpected DHCP server.", "dhcp"))
    for dev in ssdp:
        if any("InternetGatewayDevice" in t or "WANIPConnection" in t for t in dev["types"]):
            f.append(Finding("medium", "UPnP IGD enabled — any LAN device can open ports on your router",
                             dev["ip"], "udp/1900", dev.get("server", "")[:80],
                             "Disable UPnP in the router unless a console/app really needs it.", "ssdp-igd"))
    macs: dict[str, list[str]] = {}
    for h in hosts:
        if h.mac:
            macs.setdefault(h.mac, []).append(h.ip)
    for mac, ips in macs.items():
        if len(ips) > 1:
            sev = "high" if gateway in ips else "medium"
            f.append(Finding(sev, "One MAC address answers for several IPs (possible ARP spoofing)", ", ".join(ips),
                             "", mac, "Check which device owns this MAC; if it claims the gateway IP, "
                             "someone may be intercepting traffic.", "arp-dup"))
    return f


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in sorted(findings, key=Finding.key):
        k = (f.host, f.title)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# --------------------------------------------------------------------------- inventory & alerts
def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _path(*parts: str) -> str:
    return os.path.join(STATE_DIR, *parts)


def load_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path: str, data) -> None:
    ensure_state_dir()
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, ensure_ascii=False, default=list)
    os.replace(tmp, path)


def load_inventory() -> dict:
    return load_json(_path("inventory.json"), {"version": 1, "gateway": {}, "devices": {}})


def device_key(h: Host) -> str:
    return h.mac or f"ip:{h.ip}"


def update_inventory(hosts: list[Host], gateway: str, with_ports: bool, inv: dict | None = None) -> tuple[dict, list[Finding]]:
    """Merge a scan into the inventory and return alerts for meaningful changes."""
    inv = inv if inv is not None else load_inventory()
    devices = inv.setdefault("devices", {})
    baseline = not devices
    alerts: list[Finding] = []
    now = _now()
    ip_owner = {d.get("ip"): k for k, d in devices.items()}

    for h in hosts:
        k = device_key(h)
        known = devices.get(k)
        if h.ip == gateway and h.mac:
            old = inv.get("gateway", {})
            if old.get("ip") == gateway and old.get("mac") and old["mac"] != h.mac:
                alerts.append(Finding("critical", "Gateway MAC address changed — possible ARP spoofing / "
                                      "man-in-the-middle", h.ip, "", f"{old['mac']} → {h.mac}",
                                      "If you did not replace the router, investigate immediately.", "gw-mac"))
            inv["gateway"] = {"ip": gateway, "mac": h.mac}
        prev_key = ip_owner.get(h.ip)
        if prev_key and prev_key != k and h.mac and not prev_key.startswith("ip:") and h.ip != gateway:
            alerts.append(Finding("low", "IP address now used by a different device", h.ip, "",
                                  f"{prev_key} → {k}", "Normal with DHCP; suspicious if it repeats.", "ip-mac"))
        if known is None:
            known = devices[k] = {"ip": h.ip, "mac": h.mac, "vendor": h.vendor, "hostname": h.hostname,
                                  "first_seen": now, "trusted": False, "name": "", "ports": None}
            if not baseline:
                alerts.append(Finding("medium", "New device on the network", h.ip, "",
                                      " ".join(x for x in (h.mac, h.vendor, h.hostname) if x),
                                      "Identify it; mark it trusted with: homecore devices trust "
                                      f"{h.mac or h.ip}", "new-device"))
        known.update({"ip": h.ip, "last_seen": now})
        for attr in ("vendor", "hostname"):
            if getattr(h, attr):
                known[attr] = getattr(h, attr)
        if with_ports:
            ports = sorted(p.label for p in h.ports)
            if known.get("ports") is not None and not baseline:
                new = sorted(set(ports) - set(known["ports"]))
                if new:
                    alerts.append(Finding("medium", "New open port(s) on a known device", h.ip, ", ".join(new),
                                          known.get("name") or known.get("hostname", ""),
                                          "Check whether a service was enabled or the device was compromised.",
                                          "new-port"))
            known["ports"] = ports
    inv["updated"] = now
    if baseline and hosts:
        alerts.append(Finding("info", f"Baseline inventory created ({len(hosts)} devices)", "", "", "",
                              "Mark your own devices as trusted: homecore devices trust <mac>", "baseline"))
    return inv, alerts


def record_alerts(alerts: list[Finding]) -> None:
    if not alerts:
        return
    ensure_state_dir()
    fd = os.open(_path("alerts.jsonl"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps({"time": _now(), **asdict(a)}, ensure_ascii=False) + "\n")
    try:
        import syslog
        syslog.openlog("homecore", 0, syslog.LOG_DAEMON)
        for a in alerts:
            prio = syslog.LOG_WARNING if SEV_RANK[a.severity] <= 2 else syslog.LOG_NOTICE
            syslog.syslog(prio, f"[{a.severity}] {a.title} {a.host} {a.port}".strip())
    except (ImportError, OSError):
        pass


def save_report(report: dict, keep: int = 20) -> str:
    d = _path("reports")
    os.makedirs(d, mode=0o700, exist_ok=True)
    ms = int(time.time() * 1000) % 1000
    stem = f"scan-{time.strftime('%Y%m%d-%H%M%S')}-{ms:03d}"
    path, n = os.path.join(d, f"{stem}.json"), 1
    while os.path.exists(path):                      # never overwrite an earlier report
        path, n = os.path.join(d, f"{stem}-{n}.json"), n + 1
    save_json(path, report)
    for name in _report_files(d)[:-keep]:
        os.unlink(os.path.join(d, name))
    return path


def _report_files(d: str) -> list[str]:
    """Report file names, oldest first."""
    names = [f for f in os.listdir(d) if f.startswith("scan-") and f.endswith(".json")]
    return sorted(names, key=lambda f: (os.stat(os.path.join(d, f)).st_mtime_ns, f))


def latest_report() -> tuple[str, dict] | tuple[None, None]:
    d = _path("reports")
    try:
        files = _report_files(d)
    except OSError:
        return None, None
    if not files:
        return None, None
    path = os.path.join(d, files[-1])
    return path, load_json(path, {})


# --------------------------------------------------------------------------- orchestration
def discover(targets: list[str], progress: bool = False) -> list[Host]:
    """Host discovery (ARP on the local segment, ping elsewhere); MAC + vendor from nmap."""
    root = run_nmap(["-sn", "-T4", "--max-retries", "2"], targets, progress=progress, timeout=1800)
    return parse_nmap_xml(root)[0]


def _replace_ports(args: list[str], ports: str) -> list[str]:
    """Same nmap options, but scan an explicit port list instead of --top-ports N."""
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--top-ports":
            skip = True
            out += ["-p", ports]
            continue
        out.append(a)
    return out


def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)


def full_scan(targets: list[str], profile: str = "standard", cve_lookup: bool = False,
              progress: bool = False, log=print) -> dict:
    prof = PROFILES[profile]
    started = time.time()
    _, own = local_networks()
    gateway = default_gateway()

    log(f"[1/4] Discovering devices in {', '.join(targets)} …")
    hosts = [h for h in discover(targets) if h.ip not in own]
    live = [h.ip for h in hosts]
    log(f"      {len(live)} devices up")

    extra: dict = {}
    if live:
        tcp_args = list(prof["tcp"])
        if cve_lookup:
            i = tcp_args.index("--script")
            tcp_args[i + 1] += ",vulners"
            if "-sV" not in tcp_args:
                tcp_args.insert(0, "-sV")
        log(f"[2/4] Port & service scan ({profile}: {prof['desc']}) …")
        tcp_hosts, extra = parse_nmap_xml(run_nmap(tcp_args, live, progress=progress))
        merge_hosts(hosts, tcp_hosts)
        iot_args = _replace_ports(tcp_args, IOT_PORTS)
        merge_hosts(hosts, parse_nmap_xml(run_nmap(iot_args, live, progress=progress))[0])
        if prof["udp"]:
            log("[3/4] UDP checks (TFTP, SNMP, UPnP) …")
            merge_hosts(hosts, parse_nmap_xml(run_nmap(prof["udp"], live, progress=progress))[0])
    ssdp = []
    if prof["network"]:
        log("[4/4] Network checks (rogue DHCP, UPnP, ARP anomalies) …")
        _, net_extra = parse_nmap_xml(run_nmap(["--script", "broadcast-dhcp-discover", "-sn", "-n"],
                                               [gateway or targets[0].split("/")[0]], timeout=120))
        extra.update(net_extra)
        ssdp = ssdp_discover()

    findings: list[Finding] = []
    for h in hosts:
        findings.extend(assess_host(h))
    findings.extend(assess_network(hosts, extra, ssdp, gateway))
    findings = dedupe(findings)
    inv, alerts = update_inventory(hosts, gateway, with_ports=True)
    save_json(_path("inventory.json"), inv)
    record_alerts(alerts)
    findings.sort(key=Finding.key)

    report = {
        "meta": {"profile": profile, "targets": targets, "gateway": gateway, "started": _now(),
                 "duration_s": round(time.time() - started), "nmap": nmap_version(), "cve_lookup": cve_lookup},
        "summary": {s: sum(f.severity == s for f in findings) for s in SEVERITIES},
        "hosts": [asdict(h) for h in hosts],
        "ssdp": ssdp,
        "findings": [asdict(f) for f in findings],
        "alerts": [asdict(a) for a in alerts],
    }
    report["path"] = save_report(report)
    return report


# --------------------------------------------------------------------------- Wi-Fi
def parse_iw_scan(text: str) -> list[dict]:
    bss_list, cur, section = [], None, ""
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^BSS ([0-9a-f:]{17})", raw)
        if m:
            cur = {"bssid": m.group(1), "associated": "associated" in raw, "ssid": "", "signal": None,
                   "freq": None, "rsn": False, "wpa": False, "privacy": False, "wps": False,
                   "akm": [], "pairwise": [], "mfp": ""}
            bss_list.append(cur)
            section = ""
            continue
        if cur is None:
            continue
        if line.startswith("SSID:"):
            cur["ssid"] = line[5:].strip()
        elif line.startswith("signal:"):
            cur["signal"] = float(re.findall(r"-?\d+(?:\.\d+)?", line)[0])
        elif line.startswith("freq:"):
            cur["freq"] = int(float(line.split()[1]))
        elif line.startswith("capability:"):
            cur["privacy"] = "Privacy" in line
        elif line.startswith("RSN:"):
            cur["rsn"], section = True, "rsn"
        elif line.startswith("WPA:"):
            cur["wpa"], section = True, "wpa"
        elif line.startswith("WPS:"):
            cur["wps"], section = True, "wps"
        elif "Authentication suites:" in line and section == "rsn":
            cur["akm"] = line.split(":", 1)[1].split()
        elif "Pairwise ciphers:" in line and section in ("rsn", "wpa"):
            cur["pairwise"] = sorted(set(cur["pairwise"]) | set(line.split(":", 1)[1].split()))
        elif "Capabilities:" in line and section == "rsn":
            cur["mfp"] = "required" if "MFP-required" in line else "capable" if "MFP-capable" in line else ""
    for b in bss_list:
        b["security"] = wifi_security(b)
    return bss_list


def wifi_security(b: dict) -> str:
    if b["rsn"]:
        akm = set(b["akm"])
        if "OWE" in akm:
            label = "OWE"
        elif "SAE" in akm and "PSK" in akm:
            label = "WPA2/WPA3"
        elif "SAE" in akm:
            label = "WPA3"
        elif "802.1X" in akm or "IEEE" in " ".join(akm):
            label = "WPA2-Enterprise"
        else:
            label = "WPA2"
        return label + ("+WPA1" if b["wpa"] else "")
    if b["wpa"]:
        return "WPA1"
    return "WEP" if b["privacy"] else "OPEN"


_SEC_STRENGTH = {"OPEN": 0, "WEP": 1, "WPA1": 2, "WPA2+WPA1": 3, "OWE": 3, "WPA2": 4, "WPA2/WPA3": 5,
                 "WPA2-Enterprise": 5, "WPA3": 6}


def assess_wifi(bss_list: list[dict], my_ssid: str = "") -> list[Finding]:
    f: list[Finding] = []
    # "Mine" = the access point(s) we are associated with; if we are not on Wi-Fi
    # (e.g. Ethernet), every BSS broadcasting the given SSID.
    mine = [b for b in bss_list if b["associated"]] or \
        [b for b in bss_list if my_ssid and b["ssid"] == my_ssid]
    my_ssid = my_ssid or (mine[0]["ssid"] if mine else "")
    for b in mine:
        sec, where = b["security"], f"{b['ssid']} ({b['bssid']})"
        if sec in ("OPEN", "WEP"):
            f.append(Finding("critical", f"Your Wi-Fi uses {sec}", where, "", "",
                             "Switch the router to WPA2-AES or WPA3.", "wifi-weak"))
        elif "WPA1" in sec or "TKIP" in b["pairwise"]:
            f.append(Finding("high", "Your Wi-Fi allows WPA1/TKIP", where, "", sec,
                             "Use WPA2-AES (CCMP) only, or WPA3.", "wifi-tkip"))
        elif sec == "WPA2" and b["mfp"] != "required":
            f.append(Finding("low", "Your Wi-Fi is WPA2-only (no WPA3/PMF)", where, "", "",
                             "Enable WPA2/WPA3 transition mode if all your devices support it.", "wifi-wpa2"))
        if b["wps"]:
            f.append(Finding("medium", "WPS is enabled on your Wi-Fi", where, "", "",
                             "Disable WPS in the router (PIN brute-force / Pixie-Dust attacks).", "wifi-wps"))
    if my_ssid and mine:
        best = max(_SEC_STRENGTH.get(b["security"], 0) for b in mine)
        my_bssids = {b["bssid"] for b in mine}
        for b in bss_list:
            if b["ssid"] == my_ssid and b["bssid"] not in my_bssids and _SEC_STRENGTH.get(b["security"], 0) < best:
                f.append(Finding("high", "Possible evil twin: your network name with weaker security",
                                 f"{b['ssid']} ({b['bssid']})", "", f"{b['security']}, {b['signal']} dBm",
                                 "Don't connect to it; find the device broadcasting it.", "wifi-twin"))
    return sorted(f, key=Finding.key)
