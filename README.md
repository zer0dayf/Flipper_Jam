<div align="center">

# ⚡ JamFlipper

**Flipper Zero + ESP32 WiFi Attack Companion**

[![Platform](https://img.shields.io/badge/Platform-Flipper%20Zero-orange)](https://flipperzero.one)
[![Firmware](https://img.shields.io/badge/Firmware-Momentum-blue)](https://github.com/Next-Flip/Momentum-Firmware)
[![ESP32](https://img.shields.io/badge/ESP32-WiFi%20Dev%20Board-green)](https://shop.flipperzero.one/products/wifi-devboard)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

*A WiFi security research tool for educational purposes*

[English](#english) · [Türkçe](#türkçe)

</div>

---

> ⚠️ **LEGAL NOTICE:** This tool is intended **only for use on networks you own** or have **explicit written permission** to test. Attacking networks without authorization is illegal and punishable by law. The developer assumes no liability.

---

<a name="english"></a>

## 🇬🇧 English

### What is JamFlipper?

JamFlipper is an open-source WiFi security research tool that pairs a **Flipper Zero** with an **ESP32 WiFi Dev Board** to perform various WiFi attack and auditing scenarios.

The Flipper Zero acts as the **command & control interface** (display + buttons), while the ESP32 Dev Board handles the **radio layer** (deauth frames, beacon spam, captive portal, etc.).

```
┌─────────────────┐   UART (GPIO)   ┌──────────────────────┐
│   Flipper Zero  │ ◄─────────────► │  ESP32 WiFi Dev Board│
│  (UI / Control) │                 │  (WiFi Radio Layer)  │
└─────────────────┘                 └──────────────────────┘
```

### Features

| Mode | Description |
|------|-------------|
| 🔇 **Complete Jam** | Floods all nearby channels with deauth frames |
| 📡 **Beacon Spam** | Broadcasts a list of fake SSIDs (customizable) |
| 🎯 **Targeted Deauth** | Disconnects a specific client from a selected AP |
| 🕵️ **Evil Twin** | Opens a rogue AP with a captive portal |
| 🍎 **Phishing Portals** | Brand-themed login pages (Instagram, Facebook, Google, Netflix) |
| 🔍 **WiFi Sniff** | Scans nearby networks and lists MAC addresses |

### Requirements

**Hardware**
- Flipper Zero running Momentum firmware 011+
- ESP32 WiFi Dev Board (official Flipper accessory or compatible ESP32-S2)

**Software**
- Python 3.8+
- `ufbt` (Flipper app builder)
- Arduino IDE 2.x **or** `arduino-cli`
- ESP32 Arduino Core 3.x

---

### Installation

#### Step 1 — Flash the ESP32 WiFi Dev Board

`jam_flipper_esp32.cpp` is the ESP32 firmware source code. Flash it with one of the methods below.

**Method A — Arduino IDE**

1. Download Arduino IDE 2.x from https://www.arduino.cc/en/software

2. Add the ESP32 board package:
   - `File → Preferences → Additional Boards Manager URLs`:
     ```
     https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
     ```
   - `Tools → Board → Boards Manager` → search **esp32 by Espressif Systems** → install version **3.x**

3. Open the firmware:
   - Create a new sketch folder (e.g. `jam_flipper_esp32/`)
   - Copy `jam_flipper_esp32.cpp` and `jam_flipper_types.h` into it
   - Rename `jam_flipper_esp32.cpp` → `jam_flipper_esp32.ino`

4. Set board settings:
   - `Tools → Board → ESP32 Arduino → ESP32S2 Dev Module`
   - `Tools → Upload Speed → 921600`
   - `Tools → Port → (your ESP32 port)`

5. Click **Upload** (`Ctrl+U`)

**Method B — arduino-cli (command line)**

```bash
# Install ESP32 core
arduino-cli core update-index \
  --additional-urls https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
arduino-cli core install esp32:esp32

# Compile
arduino-cli compile --fqbn esp32:esp32:esp32s2 jam_flipper_esp32/

# Upload (replace /dev/ttyUSB0 with your port)
arduino-cli upload --fqbn esp32:esp32:esp32s2 \
  -p /dev/ttyUSB0 jam_flipper_esp32/
```

> **Port reference:** Linux → `/dev/ttyUSB0` or `/dev/ttyACM0` · macOS → `/dev/cu.usbmodem*` · Windows → `COM3`

**Connect to Flipper Zero**

After flashing, plug the ESP32 Dev Board into the Flipper Zero's top GPIO connector. JamFlipper communicates over UART.

---

#### Step 2 — Build and Install the Flipper FAP

**Install ufbt**

```bash
pip install ufbt
```

**Pull Momentum SDK** (required for Momentum firmware)

```bash
python3 -m ufbt update \
  --index-url=https://up.momentum-fw.dev/firmware/directory.json \
  --channel=release
```

**Generate the app icon**

```bash
mkdir -p flipper_app/images

python3 - << 'EOF'
import struct, zlib

def chunk(name, data):
    c = name.encode() + data
    return struct.pack('>I', len(data)) + c + struct.pack('>I', zlib.crc32(c) & 0xffffffff)

def make_png(pixels):
    w, h = len(pixels[0]), len(pixels)
    raw = b''
    for row in pixels:
        byte, bits, rowb = 0, 0, b''
        for px in row:
            byte = (byte << 1) | px
            bits += 1
            if bits == 8:
                rowb += bytes([byte]); byte = 0; bits = 0
        if bits: rowb += bytes([byte << (8 - bits)])
        raw += b'\x00' + rowb
    ihdr = chunk('IHDR', struct.pack('>IIBBBBB', w, h, 1, 0, 0, 0, 0))
    idat = chunk('IDAT', zlib.compress(raw))
    iend = chunk('IEND', b'')
    return b'\x89PNG\r\n\x1a\n' + ihdr + idat + iend

pixels = [
    [0,1,1,1,0,1,1,1,0,0],
    [1,0,0,0,1,0,0,0,1,0],
    [0,1,1,0,0,1,1,0,0,0],
    [0,0,1,0,0,0,1,0,0,0],
    [0,0,0,1,1,0,0,0,0,0],
    [0,0,1,1,0,0,0,0,0,0],
    [0,1,1,1,0,0,0,0,0,0],
    [0,0,1,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0],
    [0,0,0,0,0,0,0,0,0,0],
]
with open('flipper_app/images/icon_10x10.png', 'wb') as f:
    f.write(make_png(pixels))
print('Icon created!')
EOF
```

**Build the FAP**

```bash
cd flipper_app
python3 -m ufbt build
```

The compiled `jam_flipper.fap` will be in `flipper_app/dist/`.

**Install on Flipper Zero**

```bash
# Option A — launch directly (Flipper connected via USB)
python3 -m ufbt launch

# Option B — copy manually via qFlipper
# Drag flipper_app/dist/jam_flipper.fap to SD Card/apps/GPIO/
```

---

### Usage

1. Open `Apps → GPIO → JamFlipper` on your Flipper Zero
2. Select an attack mode from the main menu
3. Scan and select a target AP (if required)
4. Press **OK** to start · Press **BACK** to stop

### Repository Structure

```
JamFlipper/
├── README.md                    # This file
├── .gitignore
├── LICENSE
├── custom_ssids.txt             # Custom SSID list for Beacon Spam
├── jam_flipper_esp32.cpp        # ← ESP32 firmware (flash this to the Dev Board)
├── jam_flipper_types.h          # Shared type definitions (ESP32 ↔ Flipper protocol)
│
└── flipper_app/                 # Flipper Zero FAP application
    ├── application.fam          # App manifest (name, version, icon)
    ├── jam_flipper_app.c        # Main app entry & state machine
    ├── jam_flipper_app_i.h      # Global state struct & enums
    ├── jam_flipper_uart.c/h     # UART communication layer
    ├── images/
    │   └── icon_10x10.png       # App icon (1-bit, 10×10 px)
    └── scenes/
        ├── jam_flipper_scene_start.c         # Main menu
        ├── jam_flipper_scene_config.c        # Mode configuration screens
        ├── jam_flipper_scene_target_select.c # AP scan & selection
        ├── jam_flipper_scene_client_select.c # Client selection
        ├── jam_flipper_scene_console_output.c# Live log output
        └── jam_flipper_scene_wifi_pass.c     # WiFi password input
```

### UART Protocol

Flipper and ESP32 communicate via text-based commands over GPIO UART:

| Direction | Format | Example |
|-----------|--------|---------|
| Flipper → ESP32 | `CMD:<cmd>\|param:val` | `CMD:DEAUTH\|CH:6\|MAC:AA:BB:CC:DD:EE:FF` |
| ESP32 → Flipper | `STATUS:<state>` / `LOG:<msg>` | `STATUS:PORTAL\|Active` |

---

<a name="türkçe"></a>

## 🇹🇷 Türkçe

### Nedir?

JamFlipper, Flipper Zero ile ESP32 WiFi Dev Board'u kullanarak çeşitli WiFi güvenlik testi senaryoları gerçekleştiren açık kaynaklı bir araştırma aracıdır.

Flipper Zero **komuta merkezi** (ekran + butonlar), ESP32 ise **radyo katmanını** yönetir (deauth, beacon spam, captive portal).

### Gereksinimler

- Flipper Zero (Momentum firmware 011+)
- ESP32 WiFi Dev Board
- Python 3.8+, `ufbt`, Arduino IDE 2.x veya `arduino-cli`

### Kurulum

#### ESP32 Flash Etme

`jam_flipper_esp32.cpp` dosyasını Arduino IDE veya `arduino-cli` ile ESP32'ye yükle.

Board ayarı: `Tools → Board → ESP32S2 Dev Module`

#### Flipper FAP Derleme

```bash
# Momentum SDK'yı çek
python3 -m ufbt update \
  --index-url=https://up.momentum-fw.dev/firmware/directory.json \
  --channel=release

# Derle
cd flipper_app
python3 -m ufbt build

# Yükle
python3 -m ufbt launch
```

### Kullanım

`Apps → GPIO → JamFlipper` → mod seç → hedef seç → **OK** ile başlat, **BACK** ile durdur.

---

<div align="center">
<sub>⚡ Built for security research and education · Use responsibly</sub>
</div>
