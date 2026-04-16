#pragma once
/*
 * JamFlipper — Tip Tanımları
 * 
 * Arduino IDE .ino dosyalarında auto-prototype üretimi
 * struct tanımlarından ÖNCE gerçekleşir. Bu yüzden struct'lar
 * ayrı bir .h dosyasında olmalı.
 */

#include <stdint.h>
#include <stdbool.h>

// ─── Donanım Yapılandırması ──────────────────────────────────
#define FLIPPER_TX_PIN    17       // ESP TX → Flipper RX (IO17)
#define FLIPPER_RX_PIN    18       // ESP RX ← Flipper TX (IO18)
#define UART_BAUD         115200
#define CMD_BUF_SIZE      256
#define MAX_APS           64
#define DEAUTH_FRAME_SIZE 26
#define BEACON_FRAME_SIZE 128
#define MAX_CUSTOM_SSIDS  16
#define PORTAL_SSID_MAX   33

// ─── Tip Tanımları ────────────────────────────────────────────
struct ClientRecord {
    uint8_t mac[6];
    bool    selected;
};

struct APRecord {
    uint8_t bssid[6];
    char    ssid[33];
    uint8_t channel;
    int8_t  rssi;
    bool    selected;  // Listed Deauth için seçili mi?
    
    // Ağda yakalanan cihazların (Client) listesi
    ClientRecord clients[8]; 
    uint8_t      client_count;
};

// PCAP Record Header (16 byte)
struct PCAPRecordHeader {
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
};

typedef enum {
    MODE_IDLE = 0,
    MODE_SCAN,
    MODE_WIFI_JAM,
    MODE_BEACON_SPAM,
    MODE_COMPLETE_JAM,
    MODE_LISTED_DEAUTH,
    MODE_CAPTIVE_PORTAL,
    MODE_SNIFF,                // Bağlı ağı tüm trafik ile snifle
    MODE_TARGET_SNIFF,         // Bağlı ağda sadece belirtilen MAC'i snifle
    MODE_EVIL_TWIN,            // Şifreli ağ: deauth + Evil Twin + WPA şifre toplama
    // ── Beacon Portal Modları (deauth YOK, sadece portal yayını) ──
    MODE_G_LOGIN,              // Açık beacon + Google Login phishing portal
    MODE_IG_LOGIN,             // Instagram Login beacon portal
    MODE_FB_LOGIN,             // Facebook Login beacon portal
    MODE_TGM_LOGIN,            // Telegram Login beacon portal
    MODE_SB_LOGIN,             // Starbucks Free WiFi beacon portal
    MODE_MC_LOGIN,             // McDonald's Free WiFi beacon portal
    MODE_PUB_LOGIN,            // Generic Public WiFi beacon portal
    MODE_SCH_LOGIN,            // School/Campus WiFi beacon portal
    // ── Targeted Portal Modları (deauth + portal, MAC klonlama YOK) ──
    MODE_TARGET_G_LOGIN,       // Hedef SSID deauth + Google Login portal
    MODE_TARGET_IG_LOGIN,      // Hedef SSID deauth + Instagram Login portal
    MODE_TARGET_FB_LOGIN,      // Hedef SSID deauth + Facebook Login portal
    MODE_TARGET_TGM_LOGIN,     // Hedef SSID deauth + Telegram Login portal
    MODE_TARGET_SB_LOGIN,      // Hedef SSID deauth + Starbucks portal
    MODE_TARGET_MC_LOGIN,      // Hedef SSID deauth + McDonald's portal
    MODE_TARGET_PUB_LOGIN,     // Hedef SSID deauth + Public WiFi portal
    MODE_TARGET_SCH_LOGIN,     // Hedef SSID deauth + School portal
} AttackMode;
