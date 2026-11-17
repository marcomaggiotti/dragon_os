# HomeCore OS — Hardware notes

## Raspberry Pi 3B (1 GB RAM)

| | Budget | How HomeCore saves it |
|---|---|---|
| OS + SSH + Docker | ~150 MB | Lite image, no GUI (`multi-user.target`), no recommends, unneeded services disabled |
| Mosquitto | ~5 MB (limit 48 MB) | |
| Home Assistant | 300–500 MB (limit 640 MB) | lean `configuration.yaml` instead of `default_config` |
| Zigbee2MQTT | ~100 MB (limit 256 MB) | only started when a coordinator is configured |
| Swap | zram (compressed RAM) | no swap file on the SD card |
| GPU | 16 MB | `gpu_mem=16`, audio/camera/display probing off |

Tips:

* Use a **good 5 V / 2.5 A power supply**. `homecore status` warns when the
  firmware reports under-voltage/throttling.
* Use an A1/A2-rated microSD card from a known brand. HomeCore reduces writes
  (journal capped, HA recorder commits every 30 s and keeps 5 days, Mosquitto
  saves every 30 min), but SD cards still wear out. **Back up to USB/NAS.**
* Add integrations one at a time and watch `homecore status` memory.
* Booting from a USB SSD (Pi 3B supports USB boot after enabling it once) is
  far more reliable than microSD.

## Zigbee coordinator

The Pi has no Zigbee radio. You need a USB coordinator:

| Stick | Chip | `ZIGBEE_ADAPTER` | Notes |
|---|---|---|---|
| Sonoff ZBDongle-P | TI CC2652P | `zstack` | very mature support |
| Sonoff ZBDongle-E | SiLabs EFR32MG21 | `ember` | flash a recent EmberZNet firmware |
| Home Assistant Connect ZBT-1 (SkyConnect) | SiLabs EFR32MG21 | `ember` | |
| ConBee II / III | Dresden Elektronik | `deconz` | |

```bash
homecore zigbee detect
```

```bash
sudo homecore zigbee enable
```

```bash
homecore zigbee pair
```

`enable` guesses the adapter type from the USB id. If it guesses wrong, set it
explicitly, e.g. `sudo homecore zigbee enable /dev/serial/by-id/usb-… ember`.
Always use the `/dev/serial/by-id/…` path, not `/dev/ttyUSB0`, because the
numbering can change between boots.

Plug the stick in with a **USB extension cable** (0.5–1 m). The Pi's USB ports
and 2.4 GHz Wi-Fi interfere with Zigbee.

## Bluetooth

The Pi 3B's built-in Bluetooth (BCM43438) works with BlueZ and is passed to
Home Assistant over D-Bus (no privileged container). It shares its antenna with
Wi-Fi. With many BLE devices, a USB Bluetooth adapter or ESPHome Bluetooth
proxies work better.

```bash
homecore bluetooth
```

```bash
homecore bluetooth scan --seconds 20
```

## Wi-Fi / DIY devices

* Wi-Fi devices with a local API (Shelly, ESPHome, Tasmota, …) are added
  directly in Home Assistant. They need no extra containers.
* ESPHome nodes can use the native API (recommended, encrypted) or MQTT
  (`homecore mqtt add <node-name>`). The ESPHome *dashboard/compiler* is heavy.
  Run it on your PC (`pip install esphome`) instead of on the Pi 3B.
