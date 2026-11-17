"""Tests for cli/homecore_scan.py — run: python3 -m unittest discover -s tests"""

import os
import socket
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cli"))
import homecore_scan as sc  # noqa: E402

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS -sV">
<prescript><script id="broadcast-dhcp-discover" output="&#xa;  Response 1 of 2: &#xa;    Server Identifier: 192.168.1.1&#xa;  Response 2 of 2: &#xa;    Server Identifier: 192.168.1.66&#xa;"/></prescript>
<host><status state="up"/>
 <address addr="192.168.1.20" addrtype="ipv4"/><address addr="AA:BB:CC:00:00:20" addrtype="mac" vendor="Hikvision"/>
 <hostnames><hostname name="cam-garden" type="PTR"/></hostnames>
 <ports>
  <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="BusyBox telnetd"/></port>
  <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
    <script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>
    <script id="vulners" output="&#xa;  cpe:/a:vsftpd:vsftpd:2.3.4: &#xa;    &#9;CVE-2011-2523&#9;9.8&#9;https://vulners.com/cve/CVE-2011-2523&#xa;    &#9;CVE-2015-1419&#9;5.0&#9;https://vulners.com/cve/CVE-2015-1419"/></port>
  <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Hikvision-Webs"/>
    <script id="http-title" output="Login"/></port>
  <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/>
    <script id="smb-protocols" output="&#xa;  dialects: &#xa;    NT LM 0.12 (SMBv1) [dangerous, but default]&#xa;    2:1:0"/></port>
  <port protocol="tcp" portid="5900"><state state="open"/><service name="vnc"/>
    <script id="vnc-info" output="&#xa;  Protocol version: 3.8&#xa;  Security types: &#xa;    None (1)"/></port>
  <port protocol="tcp" portid="8443"><state state="closed"/><service name="https-alt"/></port>
 </ports>
 <hostscript><script id="smb-vuln-ms17-010" output="&#xa;  VULNERABLE:&#xa;  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)&#xa;    State: VULNERABLE&#xa;    IDs:  CVE:CVE-2017-0143"/></hostscript>
</host>
<host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/><address addr="11:22:33:44:55:66" addrtype="mac" vendor="AVM"/>
 <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port></ports></host>
<host><status state="down"/><address addr="192.168.1.99" addrtype="ipv4"/></host>
</nmaprun>"""

IW_SCAN = """BSS 11:11:11:11:11:11(on wlan0) -- associated
\tfreq: 2437
\tsignal: -41.00 dBm
\tSSID: CasaMaggi
\tRSN:\t * Version: 1
\t\t * Group cipher: CCMP
\t\t * Pairwise ciphers: CCMP TKIP
\t\t * Authentication suites: PSK
\t\t * Capabilities: 1-PTKSA-RC 1-GTKSA-RC (0x0000)
\tWPS:\t * Version: 1.0
\tcapability: ESS Privacy ShortSlotTime (0x0411)
BSS 22:22:22:22:22:22(on wlan0)
\tfreq: 2412
\tsignal: -60.00 dBm
\tSSID: CasaMaggi
\tcapability: ESS ShortSlotTime (0x0401)
BSS 33:33:33:33:33:33(on wlan0)
\tfreq: 5180
\tsignal: -70.00 dBm
\tSSID: Neighbour
\tRSN:\t * Version: 1
\t\t * Pairwise ciphers: CCMP
\t\t * Authentication suites: SAE
\t\t * Capabilities: MFP-required (0x00c0)
\tcapability: ESS Privacy (0x0011)
"""


class ScopeTests(unittest.TestCase):
    def test_private_targets_accepted(self):
        self.assertEqual(sc.validate_targets(["192.168.1.0/24", "10.0.0.5", "fe80::1"]),
                         ["192.168.1.0/24", "10.0.0.5", "fe80::1"])

    def test_public_and_oversized_targets_refused(self):
        for bad in (["8.8.8.8"], ["192.168.0.0/16"], ["example.com"], ["fd00::/64"], ["127.0.0.1"], []):
            with self.subTest(bad=bad), self.assertRaises(sc.ScopeError):
                sc.validate_targets(bad)

    def test_replace_ports(self):
        self.assertEqual(sc._replace_ports(["-sS", "--top-ports", "100", "-T4"], "1883"),
                         ["-sS", "-p", "1883", "-T4"])


class ParseAndAssessTests(unittest.TestCase):
    def setUp(self):
        self.hosts, self.extra = sc.parse_nmap_xml(ET.fromstring(NMAP_XML))

    def test_parse(self):
        self.assertEqual([h.ip for h in self.hosts], ["192.168.1.20", "192.168.1.1"])
        cam = self.hosts[0]
        self.assertEqual((cam.mac, cam.vendor, cam.hostname), ("aa:bb:cc:00:00:20", "Hikvision", "cam-garden"))
        self.assertEqual(sorted(p.port for p in cam.ports), [21, 23, 80, 445, 5900])   # closed 8443 dropped
        self.assertIn("broadcast-dhcp-discover", self.extra)

    def test_host_findings(self):
        findings = sc.assess_host(self.hosts[0], check_mqtt=False)
        titles = {f.title: f.severity for f in findings}
        self.assertEqual(titles["Telnet enabled — logins travel in cleartext"], "high")
        self.assertEqual(titles["Anonymous FTP login allowed"], "high")
        self.assertEqual(titles["VNC without password"], "critical")
        self.assertIn("SMBv1 enabled (exploited by WannaCry/EternalBlue-class worms)", titles)
        self.assertIn("Web interface only over HTTP (no HTTPS)", titles)
        vuln = [f for f in findings if f.rule == "smb-vuln-ms17-010"]
        self.assertEqual(vuln[0].detail, "CVE-2017-0143")
        cve = [f for f in findings if f.rule == "vulners"][0]
        self.assertEqual(cve.severity, "critical")
        self.assertIn("CVE-2011-2523", cve.detail)

    def test_router_with_https_is_clean(self):
        self.assertEqual(sc.assess_host(self.hosts[1], check_mqtt=False), [])

    def test_network_findings(self):
        dup = sc.Host("192.168.1.50", mac="11:22:33:44:55:66")
        f = sc.assess_network(self.hosts + [dup], self.extra, [], gateway="192.168.1.1")
        rules = {x.rule: x for x in f}
        self.assertIn("192.168.1.66", rules["dhcp"].detail)
        self.assertEqual(rules["arp-dup"].severity, "high")     # it claims the gateway's MAC

    def test_ssdp_igd(self):
        f = sc.assess_network([], {}, [{"ip": "192.168.1.1", "server": "Linux UPnP/1.0",
                                        "types": ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]}], "")
        self.assertEqual(f[0].rule, "ssdp-igd")


class InventoryTests(unittest.TestCase):
    def test_baseline_then_changes(self):
        gw = "192.168.1.1"
        inv, alerts = sc.update_inventory([sc.Host(gw, mac="11:11:11:11:11:11"),
                                           sc.Host("192.168.1.20", mac="aa:aa:aa:aa:aa:aa",
                                                   ports=[sc.Port("tcp", 80)])], gw, True, inv={})
        self.assertEqual([a.rule for a in alerts], ["baseline"])
        # new device, new port, gateway MAC change
        _, alerts = sc.update_inventory([sc.Host(gw, mac="66:66:66:66:66:66"),
                                         sc.Host("192.168.1.20", mac="aa:aa:aa:aa:aa:aa",
                                                 ports=[sc.Port("tcp", 80), sc.Port("tcp", 23)]),
                                         sc.Host("192.168.1.77", mac="bb:bb:bb:bb:bb:bb")], gw, True, inv=inv)
        rules = {a.rule: a for a in alerts}
        self.assertEqual(rules["gw-mac"].severity, "critical")
        self.assertEqual(rules["new-port"].port, "tcp/23")
        self.assertIn("new-device", rules)

    def test_save_and_reports(self):
        with tempfile.TemporaryDirectory() as d:
            old = sc.STATE_DIR
            sc.STATE_DIR = os.path.join(d, "state")
            try:
                for i in range(3):
                    sc.save_report({"n": i}, keep=2)
                path, rep = sc.latest_report()
                self.assertEqual(len(os.listdir(os.path.join(sc.STATE_DIR, "reports"))), 2)
                self.assertEqual(os.stat(sc.STATE_DIR).st_mode & 0o777, 0o700)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            finally:
                sc.STATE_DIR = old


class WifiTests(unittest.TestCase):
    def test_parse_and_assess(self):
        bss = sc.parse_iw_scan(IW_SCAN)
        self.assertEqual([b["security"] for b in bss], ["WPA2", "OPEN", "WPA3"])
        rules = {f.rule for f in sc.assess_wifi(bss)}
        self.assertEqual(rules, {"wifi-tkip", "wifi-wps", "wifi-twin"})

    def test_ethernet_mode_with_ssid(self):
        bss = [b for b in sc.parse_iw_scan(IW_SCAN)]
        for b in bss:
            b["associated"] = False
        rules = {f.rule for f in sc.assess_wifi(bss, my_ssid="Neighbour")}
        self.assertEqual(rules, set())      # WPA3 + PMF required: nothing to report


class MqttProbeTests(unittest.TestCase):
    def _fake_broker(self, return_code: int) -> int:
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            conn.recv(64)
            conn.sendall(bytes([0x20, 0x02, 0x00, return_code]))
            conn.close()
            srv.close()
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]

    def test_anonymous_accepted(self):
        self.assertTrue(sc.mqtt_anonymous("127.0.0.1", self._fake_broker(0)))

    def test_anonymous_refused(self):
        self.assertFalse(sc.mqtt_anonymous("127.0.0.1", self._fake_broker(5)))

    def test_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertIsNone(sc.mqtt_anonymous("127.0.0.1", port, timeout=1))


if __name__ == "__main__":
    unittest.main()
