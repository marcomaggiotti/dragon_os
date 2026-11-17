# HomeCore OS — Networking

## Ports

| Port | Proto | Service | Reachable from |
|---|---|---|---|
| 22 | TCP | OpenSSH (keys only, rate-limited) | LAN, Tailscale, `ADMIN4` |
| 8123 | TCP | Home Assistant | LAN, Tailscale |
| 1883 | TCP | Mosquitto MQTT (auth + ACL) | LAN, Tailscale |
| 8080 | TCP | Zigbee2MQTT UI (token) | LAN, Tailscale |
| 5353 | UDP | mDNS (`homecore.local`, device discovery) | LAN |
| 41641 | UDP | Tailscale WireGuard | anywhere (encrypted, authenticated) |

Everything else inbound is dropped and rate-logged (`homecore logs firewall`).
Outbound traffic is allowed (updates, cloud integrations, NTP).

## Configuring the firewall

Edit `/etc/homecore/homecore.env`:

```bash
LAN4="192.168.1.0/24"          # empty = auto-detect from interfaces
LAN6=""                        # global/ULA prefixes; fe80::/10 is always allowed
ADMIN4="192.168.1.10"          # workstations that can always SSH in
LAN_TCP_PORTS="22 8123 1883 8080"
LAN_UDP_PORTS="5353"
TS_TCP_PORTS="22 8123 1883 8080"
SSH_RATE="8/minute"
```

Then:

```bash
sudo homecore firewall apply
```

`apply` validates the ruleset with `nft -c` first. It then asks you to open a
**new** SSH session and type `keep` within 120 s. If you don't, the previous
rules are restored automatically, so a typo can't lock you out. The firewall
uses its own table (`inet homecore`) and leaves Tailscale's rules alone.

Common additions:

| Need | Change |
|---|---|
| HomeKit Bridge | add `21063` to `LAN_TCP_PORTS` and `5353` stays |
| MQTT over TLS | add `8883` (see SECURITY.md) |
| Close the Zigbee UI on the LAN | remove `8080` from `LAN_TCP_PORTS` (keep it in `TS_TCP_PORTS`) |
| SSH only over Tailscale | remove `22` from `LAN_TCP_PORTS` (keep `ADMIN4` empty) |

## Commands

```bash
homecore network
```

Shows interfaces, addresses, default route, DNS, Wi-Fi signal, Tailscale IP,
listening ports and whether the firewall is loaded.

```bash
homecore network test
```

Tests the gateway, DNS, HTTPS to the internet, `.local` resolution and the
Tailscale state.

```bash
homecore network neighbors
```

Lists LAN devices from the ARP/ND cache and marks randomised MACs.

```bash
homecore network ports
```

Lists listening sockets, with process names when run with sudo.

## Recommended home network layout

```
Internet ── Router ──┬── Trusted LAN (PCs, phones) ── 192.168.1.0/24
                     │        └── HomeCore (DHCP reservation e.g. 192.168.1.5)
                     └── IoT SSID/VLAN (plugs, cameras, ESP devices) ── 192.168.20.0/24
```

* Give HomeCore a **DHCP reservation** on the router (or a static address) so
  devices and bookmarks keep working.
* If your router supports it, put cloud-dependent IoT gadgets on a **separate
  SSID or VLAN**. Allow them to reach HomeCore only on 1883 (and the ports of
  the integrations that need it) and block them from your PCs.
  Add the IoT prefix to `LAN4` and remove `22`/`8080` for it. To do that, change
  the `from_lan` chain, or keep IoT out of `LAN4` and allow only MQTT with a
  custom rule.
* **Never port-forward** 8123/1883/22 on the router. Use Tailscale.
* Zigbee devices don't use IP at all. They talk to the USB coordinator, which
  is one of the reasons Zigbee is a good choice for security-sensitive sensors.

## Wi-Fi on the Raspberry Pi

Ethernet is preferred for a hub. If you use Wi-Fi:

* HomeCore disables Wi-Fi power saving (`/etc/NetworkManager/conf.d/homecore-wifi.conf`),
  which otherwise causes drop-outs on Pis.
* Configure Wi-Fi with `sudo nmtui` (text UI) or `sudo nmcli dev wifi connect <SSID> --ask`.
* The Pi 3B has only 2.4 GHz Wi-Fi, which shares the band with Zigbee. Put the
  Zigbee channel (Zigbee2MQTT: 15, 20 or 25) away from your Wi-Fi channel
  (1/6/11), and use a **USB extension cable** for the coordinator to keep it away
  from the Pi's USB 3/Wi-Fi noise.

## Remote access with Tailscale

```bash
sudo homecore tailscale
```

This opens a login URL. Once the machine is authorised, open
`http://homecore:8123` (MagicDNS) or `http://<100.x.y.z>:8123` from any device
on your tailnet. In the Tailscale admin console:

* tag the machine `tag:homecore` and restrict access with ACLs, e.g. only your
  user may reach `tag:homecore:22,8123`;
* leave key expiry on unless the Pi is physically secure.

### Optional: HTTPS with `tailscale serve`

```bash
sudo tailscale serve --bg 8123
```

This gives `https://homecore.<tailnet>.ts.net` with a valid certificate (enable
HTTPS in the Tailscale admin console first). Then uncomment the two
`use_x_forwarded_for` / `trusted_proxies` lines in
`/opt/homecore/config/homeassistant/configuration.yaml` and run `homecore restart ha`.
Do **not** use `tailscale funnel`: that publishes the site to the internet.
