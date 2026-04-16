<div align="center">

# ⚡ JamFlipper

**Flipper Zero + ESP32 WiFi Security Research Tool**

[![Platform](https://img.shields.io/badge/Platform-Flipper%20Zero-orange)](https://flipperzero.one)
[![Firmware](https://img.shields.io/badge/Firmware-Momentum%20011+-blue)](https://github.com/Next-Flip/Momentum-Firmware)
[![ESP32](https://img.shields.io/badge/ESP32-WiFi%20Dev%20Board-green)](https://shop.flipperzero.one/products/wifi-devboard)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

[English](#english) · [Türkçe](#türkçe)

</div>

---

> ⚠️ **Legal Notice / Yasal Uyarı:** For educational and authorized testing only. Using this tool on networks without permission is illegal. / Yalnızca eğitim ve izinli testler için. İzinsiz kullanım yasadışıdır.

---

<a name="english"></a>

## 🇬🇧 English

### Overview

JamFlipper pairs a **Flipper Zero** with an **ESP32 WiFi Dev Board** over UART to conduct WiFi security assessments. The Flipper Zero handles all UI and controls; the ESP32 executes the radio operations.

```
┌─────────────────┐   UART (GPIO)   ┌──────────────────────┐
│   Flipper Zero  │ ◄─────────────► │  ESP32 WiFi Dev Board│
│   UI / Control  │                 │    WiFi Radio Layer   │
└─────────────────┘                 └──────────────────────┘
```

---

### Attack Modes

#### Core Modes

| Mode | Description |
|------|-------------|
| 🔍 **WiFi Scan** | Scans nearby access points, lists SSID / BSSID / channel / RSSI. Optional PCAP capture saved to SD card. |
| 🔇 **Complete Jam** | Floods all channels with deauthentication frames, disconnecting every nearby client. |
| 🎯 **WiFi Jam** | Targeted deauth against a single selected AP. |
| 👥 **Listed Deauth** | Deauths multiple selected APs from the scan list simultaneously. |
| 📡 **Beacon Spam** | Broadcasts up to 20 fake SSIDs continuously. Supports a custom SSID list from `custom_ssids.txt`. |
| 🕵️ **WiFi Sniff** | Passive monitor-mode capture of raw 802.11 frames, saved as `.pcap` to SD card. |
| 👿 **Evil Twin** | Clones a target AP's SSID (with optional MAC clone and lookalike suffix). Runs a captive portal that captures the real WiFi password when the victim reconnects. |

#### Beacon Portal Modes *(no deauth — standalone rogue AP)*

These modes open a rogue access point broadcasting a chosen SSID and serve a phishing captive portal. Credentials are saved to the Flipper SD card.

| Mode | Portal Theme |
|------|-------------|
| **G-Login Beacon** | Google account login page |
| **Instagram Beacon** | Instagram login page |
| **Facebook Beacon** | Facebook login page |
| **Telegram Beacon** | Telegram login page |
| **Starbucks Beacon** | Starbucks Free WiFi portal |
| **McDonald's Beacon** | McDonald's Free WiFi portal |
| **Public Wi-Fi Beacon** | Generic public hotspot portal |
| **School Beacon** | School/campus login portal |

#### Targeted Portal Modes *(deauth + rogue AP)*

Same portal themes as above, but first **deauthenticates clients from the real AP**, then brings up the rogue AP. The victim's device reconnects automatically to the cloned network.

| Mode | Action |
|------|--------|
| **Target G-Login** | Deauth target → Google phishing portal |
| **Target Instagram** | Deauth target → Instagram phishing portal |
| **Target Facebook** | Deauth target → Facebook phishing portal |
| **Target Telegram** | Deauth target → Telegram phishing portal |
| **Target Starbucks** | Deauth target → Starbucks portal |
| **Target McDonald's** | Deauth target → McDonald's portal |
| **Target Public Wi-Fi** | Deauth target → Generic portal |
| **Target School** | Deauth target → School portal |

---

### Captive Portal Engine

The ESP32 runs a full captive portal stack designed to trigger the login popup on all major platforms:

- **DHCP Option 114 (RFC 8910)** — advertises the portal URI directly via DHCP, bypassing DNS entirely
- **DNS wildcard** — all DNS queries resolve to `192.168.4.1`
- **Platform-specific HTTP handlers** — `/generate_204` (Android), `/hotspot-detect.html` (iOS/macOS), `/ncsi.txt` (Windows), connectivity check endpoints (Linux NetworkManager)
- **lwIP Layer-3 packet hook** — blocks DNS-over-TLS (TCP/UDP port 853) to force plain DNS fallback on Android Private DNS, and blocks QUIC (UDP 443) to prevent Chrome's QUIC PROTOCOL ERROR

---

### Captured Data

All credentials and captures are saved to **SD card** at `/apps_data/jam_flipper/`:

| File | Contents |
|------|----------|
| `passwords.txt` | Evil Twin — captured WiFi passwords |
| `glogin_creds.txt` | Google login credentials |
| `iglogin_creds.txt` | Instagram credentials |
| `fblogin_creds.txt` | Facebook credentials |
| `tgmlogin_creds.txt` | Telegram credentials |
| `cap_YYYYMMDD_HHMMSS.pcap` | Raw 802.11 packet captures |

---

### Requirements

**Hardware**
- Flipper Zero running **Momentum firmware 011+**
- **ESP32 WiFi Dev Board** (official Flipper accessory or compatible ESP32-S2)

**Software**
- Python 3.8+
- `ufbt` — Flipper app builder
- Arduino IDE 2.x **or** `arduino-cli`
- ESP32 Arduino Core **3.x**

---

### Installation

#### 1. Flash the ESP32 WiFi Dev Board

`jam_flipper_esp32.cpp` is the ESP32 firmware. Flash it using Arduino IDE or arduino-cli.

**Arduino IDE**

1. Download Arduino IDE 2.x → https://www.arduino.cc/en/software

2. Add ESP32 board support:  
   `File → Preferences → Additional Boards Manager URLs`:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
   Then `Tools → Boards Manager` → install **esp32 by Espressif Systems 3.x**

3. Create a sketch folder (e.g. `jam_flipper_esp32/`), copy `jam_flipper_esp32.cpp` and `jam_flipper_types.h` into it, rename the `.cpp` file to `.ino`.

4. Select board:  
   `Tools → Board → ESP32 Arduino → ESP32S2 Dev Module`

5. Select port and click **Upload** (`Ctrl+U`)

**arduino-cli**

```bash
# Add ESP32 core
arduino-cli core update-index \
  --additional-urls https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
arduino-cli core install esp32:esp32

# Compile & upload (replace port)
arduino-cli compile --fqbn esp32:esp32:esp32s2 jam_flipper_esp32/
arduino-cli upload  --fqbn esp32:esp32:esp32s2 -p /dev/ttyUSB0 jam_flipper_esp32/
```

> **Port:** Linux `/dev/ttyUSB0` · macOS `/dev/cu.usbmodem*` · Windows `COM3`

After flashing, plug the ESP32 Dev Board into the Flipper Zero's top GPIO connector.

---

#### 2. Install the Flipper App (FAP)

**Install ufbt**
```bash
pip install ufbt
```

**Pull Momentum SDK**
```bash
python3 -m ufbt update \
  --index-url=https://up.momentum-fw.dev/firmware/directory.json \
  --channel=release
```

**Build**
```bash
cd flipper_app
python3 -m ufbt build
```

The compiled `.fap` will be in `flipper_app/dist/`.

**Install to Flipper**
```bash
# With Flipper connected via USB:
python3 -m ufbt launch

# Or drag flipper_app/dist/jam_flipper.fap to
# SD Card → apps → GPIO via qFlipper
```

---

### Usage

1. On Flipper Zero: `Apps → GPIO → JamFlipper`
2. Select a mode from the main menu
3. For targeted modes: scan APs → select target → (optionally) select client
4. Press **OK** to start · **BACK** to stop
5. Live output shown on the console screen; credentials auto-saved to SD card

---

### Repository Structure

```
Flipper_Jam/
├── README.md
├── .gitignore
├── LICENSE
├── custom_ssids.txt          # Custom SSID list for Beacon Spam
├── jam_flipper_esp32.cpp     # ESP32 firmware source (flash this)
├── jam_flipper_types.h       # Shared type definitions
│
└── flipper_app/              # Flipper Zero FAP
    ├── application.fam       # App manifest
    ├── jam_flipper_app.c
    ├── jam_flipper_app_i.h
    ├── jam_flipper_uart.c/h
    ├── images/
    │   └── icon_10x10.png
    └── scenes/
```

---

<a name="türkçe"></a>

## 🇹🇷 Türkçe

### Ne Yapar?

JamFlipper, Flipper Zero ile ESP32 WiFi Dev Board'u GPIO üzerinden UART ile eşleştirerek çeşitli WiFi güvenlik testleri yapmanı sağlar. Flipper Zero tüm arayüzü yönetir, ESP32 radyo katmanını çalıştırır.

---

### Saldırı Modları

#### Temel Modlar

| Mod | Açıklama |
|-----|----------|
| 🔍 **WiFi Scan** | Yakın AP'leri tarar, SSID / BSSID / kanal / RSSI listeler. İsteğe bağlı PCAP kaydı SD karta aktarılır. |
| 🔇 **Complete Jam** | Tüm kanallara deauth paketi göndererek yakındaki tüm cihazları ağdan düşürür. |
| 🎯 **WiFi Jam** | Seçilen tek bir AP'ye hedefli deauth uygular. |
| 👥 **Listed Deauth** | Listeden seçilen birden fazla AP'ye aynı anda deauth gönderir. |
| 📡 **Beacon Spam** | 20'ye kadar sahte SSID yayınlar. `custom_ssids.txt` ile özelleştirilebilir. |
| 🕵️ **WiFi Sniff** | Ham 802.11 frame'leri pasif olarak yakalar, SD karta `.pcap` olarak kaydeder. |
| 👿 **Evil Twin** | Hedef AP'nin SSID'sini (ve isteğe bağlı MAC adresini) klonlar. Captive portal üzerinden gerçek WiFi şifresini yakalar. |

#### Beacon Portal Modları *(deauth yok — bağımsız sahte AP)*

Seçilen SSID ile sahte bir AP açar ve phishing captive portal sunar. Girilen bilgiler SD karta kaydedilir.

| Mod | Portal Teması |
|-----|--------------|
| **G-Login Beacon** | Google hesap giriş sayfası |
| **Instagram Beacon** | Instagram giriş sayfası |
| **Facebook Beacon** | Facebook giriş sayfası |
| **Telegram Beacon** | Telegram giriş sayfası |
| **Starbucks Beacon** | Starbucks Free WiFi portalı |
| **McDonald's Beacon** | McDonald's Free WiFi portalı |
| **Public Wi-Fi Beacon** | Genel halka açık hotspot portalı |
| **School Beacon** | Okul / kampüs giriş portalı |

#### Targeted Portal Modları *(deauth + sahte AP)*

Yukarıdaki portal temalarının hedefli versiyonu. Önce gerçek AP'den istemcileri deauth eder, ardından sahte AP'yi açar. Kurban otomatik olarak klonlanan ağa bağlanır.

| Mod | İşlem |
|-----|-------|
| **Target G-Login** | Deauth → Google phishing portalı |
| **Target Instagram** | Deauth → Instagram phishing portalı |
| **Target Facebook** | Deauth → Facebook phishing portalı |
| **Target Telegram** | Deauth → Telegram phishing portalı |
| **Target Starbucks** | Deauth → Starbucks portalı |
| **Target McDonald's** | Deauth → McDonald's portalı |
| **Target Public Wi-Fi** | Deauth → Genel portal |
| **Target School** | Deauth → Okul portalı |

---

### Captive Portal Motoru

Tüm büyük işletim sistemlerinde (Android, iOS, Windows, Linux) captive portal popup'ını tetiklemek için çok katmanlı bir yaklaşım kullanılır:

- **DHCP Option 114 (RFC 8910)** — Portal URI'sini DHCP üzerinden direkt iletir, DNS'e gerek kalmaz
- **DNS wildcard** — Tüm DNS sorguları `192.168.4.1`'e yönlendirilir
- **Platform bazlı HTTP handler'lar** — Android `/generate_204`, iOS `/hotspot-detect.html`, Windows `/ncsi.txt`, Linux NetworkManager endpoint'leri
- **lwIP Layer-3 paket hook** — DNS-over-TLS (port 853) ve QUIC (UDP 443) bloke edilerek Samsung gibi modern Android cihazlarda portal tespiti zorlanır

---

### Yakalanan Veriler

Tüm bilgiler SD karta `/apps_data/jam_flipper/` klasörüne kaydedilir:

| Dosya | İçerik |
|-------|--------|
| `passwords.txt` | Evil Twin ile yakalanan WiFi şifreleri |
| `glogin_creds.txt` | Google kullanıcı adı/şifreleri |
| `iglogin_creds.txt` | Instagram kullanıcı adı/şifreleri |
| `fblogin_creds.txt` | Facebook kullanıcı adı/şifreleri |
| `tgmlogin_creds.txt` | Telegram kullanıcı adı/şifreleri |
| `cap_YYYYMMDD_HHMMSS.pcap` | Ham 802.11 paket yakaları |

---

### Gereksinimler

- Flipper Zero — Momentum firmware 011+
- ESP32 WiFi Dev Board (Flipper resmi aksesuarı veya uyumlu ESP32-S2)
- Python 3.8+, `ufbt`, Arduino IDE 2.x veya `arduino-cli`, ESP32 Arduino Core 3.x

---

### Kurulum

#### 1. ESP32 WiFi Dev Board Flashlama

`jam_flipper_esp32.cpp` ESP32 firmware kaynak kodudur.

**Arduino IDE ile:**

1. Arduino IDE 2.x indir → https://www.arduino.cc/en/software
2. `File → Preferences → Additional Boards Manager URLs` ekle:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. `Tools → Boards Manager` → **esp32 by Espressif Systems 3.x** yükle
4. `jam_flipper_esp32.cpp` ve `jam_flipper_types.h` dosyalarını aynı sketch klasörüne koy, `.cpp` uzantısını `.ino` yap
5. `Tools → Board → ESP32S2 Dev Module` seç
6. Port seç → **Upload** (`Ctrl+U`)

**arduino-cli ile:**
```bash
arduino-cli core install esp32:esp32
arduino-cli compile --fqbn esp32:esp32:esp32s2 jam_flipper_esp32/
arduino-cli upload  --fqbn esp32:esp32:esp32s2 -p /dev/ttyUSB0 jam_flipper_esp32/
```

Flash tamamlandıktan sonra ESP32 Dev Board'u Flipper Zero'nun üst GPIO konektörüne tak.

---

#### 2. Flipper Uygulamasını Yükleme (FAP)

```bash
# ufbt yükle
pip install ufbt

# Momentum SDK'yı çek
python3 -m ufbt update \
  --index-url=https://up.momentum-fw.dev/firmware/directory.json \
  --channel=release

# Derle
cd flipper_app
python3 -m ufbt build

# Flipper'a yükle (USB bağlıyken)
python3 -m ufbt launch
```

Veya `flipper_app/dist/jam_flipper.fap` dosyasını qFlipper ile `SD Card → apps → GPIO` klasörüne kopyala.

---

### Kullanım

1. Flipper Zero'da `Apps → GPIO → JamFlipper`
2. Ana menüden mod seç
3. Hedefli modlarda: AP tara → hedef AP seç → (isteğe bağlı) istemci seç
4. **OK** ile başlat · **BACK** ile durdur
5. Canlı çıktı konsol ekranında görünür, bilgiler otomatik SD karta kaydedilir

---

<div align="center">
<sub>⚡ Built for security research and education · Use responsibly</sub>
</div>
