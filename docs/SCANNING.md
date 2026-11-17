# Discovering devices and vulnerabilities on your LAN

> **Only scan networks you own or are explicitly authorised to test.** HomeCore
> refuses public IP addresses and networks larger than /20, and it uses only
> nmap's *safe* checks. Even so, a scan of someone else's network can be
> illegal.

## What runs automatically

| Timer | What it does | Pi 3B cost |
|---|---|---|
| `homecore-discover.timer` (every 30 min) | ARP sweep of the LAN, updates the device inventory, alerts on changes | ~10–20 s, < 40 MB RAM |
| `homecore-scan.timer` (Sundays 02:30) | `standard` vulnerability scan of every live device | 5–15 min for a typical home |

Alerts go to the journal (`homecore logs scan`) and `/var/lib/homecore/alerts.jsonl`.
Read them with `homecore alerts`.

## Commands

```bash
sudo homecore discover
```

Finds every device on the LAN: IP, MAC, vendor (from nmap's OUI database) and
hostname. The first run creates a **baseline**. After that you get alerts for:

| Alert | Severity | Meaning |
|---|---|---|
| New device on the network | medium | a MAC never seen before |
| New open port(s) on a known device | medium | a service appeared: new feature, or compromise |
| Gateway MAC address changed | **critical** | classic ARP spoofing / man-in-the-middle sign |
| One MAC answers for several IPs | medium/high | possible ARP spoofing (high if it includes the gateway) |
| IP now used by a different device | low | normal with DHCP; suspicious if it repeats |

```bash
sudo homecore scan
```

The default `standard` profile:

| Profile | What it covers | Typical time (/24, Pi 3B) |
|---|---|---|
| `quick` | top 100 TCP ports + high-risk IoT ports | 1–3 min |
| `standard` | top 1000 TCP + IoT ports, service versions, safe NSE checks, UDP 69/161/1900, rogue-DHCP and UPnP checks | 5–15 min |
| `deep` | top 5000 TCP + top 30 UDP, TLS cipher grading, nmap `vuln and safe` scripts | 30–90 min |

Options: `--target 192.168.1.0/24 10.0.0.7` (private ranges only),
`--cve-lookup` (see below), `--quiet`.

```bash
sudo homecore report --all
```

Shows the last report with every device and open port. Add `--json` for
machine-readable output.

```bash
sudo homecore devices
```

Shows the inventory. `✔` marks trusted devices and `?` unknown ones.

```bash
sudo homecore devices trust aa:bb:cc:dd:ee:ff "Living-room TV"
```

```bash
sudo homecore devices forget 192.168.1.77
```

```bash
sudo homecore wifi
```

Runs a Wi-Fi audit on the Raspberry Pi; VirtualBox has no Wi-Fi interface.
When HomeCore is on Ethernet, add `--ssid YourNetwork`.

## What gets flagged

**Insecure or exposed services**

| Finding | Severity |
|---|---|
| Docker API (2375), Android ADB (5555) exposed | critical |
| VNC without password; Redis/MongoDB/Memcached answering without auth; MQTT broker accepting anonymous clients | critical |
| Telnet; TFTP; anonymous FTP; SMBv1; SSHv1; SNMP with community `public`; exposed Redis/MongoDB/Memcached/Elasticsearch | high |
| Results of nmap `vuln` scripts that report *VULNERABLE* (e.g. MS17-010) | high |
| FTP, RDP (and RDP without NLA), VNC, MQTT without TLS, RTSP cameras, SNMP, exposed SQL databases | medium |
| Weak SSH algorithms; TLS grade C–F; SSLv3/TLS 1.0 | medium |
| UPnP IGD on the router ("any LAN device can open ports to the internet") | medium |
| Multiple DHCP servers (rogue DHCP) | high |
| Web interface only over HTTP; SMB/UPnP/raw printing exposed; expired TLS certificate | low |

Each finding comes with a concrete fix.

**IoT ports nmap's top-1000 list misses** are always added: 1883/8883 MQTT,
2375/2376 Docker, 5555 ADB, 6379 Redis, 7547 TR-069, 8291 MikroTik, 8554 RTSP,
9200 Elasticsearch, 10250 Kubelet, 11211 Memcached, 27017 MongoDB, 34567/37777
(Xiongmai/Dahua cameras: frequent botnet targets), 49152/49153 UPnP and others.

## CVE matching (optional, online)

```bash
sudo homecore scan --cve-lookup
```

This adds nmap's `vulners` script. Product names and versions found on your LAN
(e.g. `vsftpd 2.3.4`) are **sent to vulners.com**, which returns known CVEs with
CVSS scores. Findings are rated by the highest score: ≥ 9 critical, ≥ 7 high,
≥ 4 medium. It is off by default because it shares information about your
network with a third party.

## Is it safe for my devices?

The `standard` profile uses only scripts in nmap's **safe** category: no
brute-forcing, no exploitation, no denial-of-service checks. It also uses
conservative retries. The anonymous-MQTT probe only connects and disconnects.
Some very cheap IoT devices still misbehave when port-scanned (for example a
camera rebooting). If one does, exclude it with `--target` lists or run `quick`.

`deep` uses timing `-T3` and `vuln and safe` scripts. Run it when you are at home
and can power-cycle a device if needed.

## Making sense of the results

1. **Critical and high first.** Most fixes are a setting in the device's app or
   web UI (disable Telnet/UPnP/WPS, set a password) or a firmware update.
2. **Unknown devices.** Identify each `?` device (vendor + hostname usually
   tell you), then `trust` it. From then on, an alert really means something new.
3. **Cameras and cheap IoT** belong on a guest/IoT Wi-Fi network that cannot
   reach your PCs. Most routers offer this.
4. **Re-scan after fixing:** `sudo homecore scan quick --target <ip>`.

## Feeding reports to an AI assistant

Scan reports contain text written by the scanned devices: hostnames, banners,
page titles, UPnP names, SSIDs. Treat it as untrusted. Before pasting a report
into a chatbot, run:

```bash
sudo homecore guard report
```

See [PROMPT-INJECTION.md](PROMPT-INJECTION.md).

## Where the data lives

`/var/lib/homecore/` (0700, root):

* `inventory.json`
* `alerts.jsonl`
* `reports/scan-*.json` (last 20 kept)

All of it is included in `homecore backup`.
