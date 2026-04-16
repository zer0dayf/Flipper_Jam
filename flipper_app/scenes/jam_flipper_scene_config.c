#include "../jam_flipper_app_i.h"

/* ────────────────────────────────────────────────────────────
 * Config Sahnesi — Dinamik Ayar Ekranı
 *
 * active_mode'a göre farklı VariableItemList oluşturur.
 * Her modun START butonuna basılınca ESP32'ye komut gönderir
 * ve ConsoleOutput sahnesine geçer.
 * ──────────────────────────────────────────────────────────── */

/* ── Değer etiketleri ────────────────────────────────────── */
static const char* AGGR_LABELS[]     = {"Low", "Mid", "High"};
static const char* SCAN_LABELS[]     = {"Basic", "Logged(PCAP)"};
static const char* NAMETYPE_LABELS[] = {"Random", "Custom", "Top 20"};
static const char* MSG_LABELS[]      = {"Update Req.", "Free Wi-Fi", "Maintenance", "Login Err."};
static const char* BAUD_LABELS[]     = {"115200", "230400", "921600"};
static const char* HOP_LABELS[]      = {"50ms", "100ms", "200ms"};
static const char* PORTAL_LABELS[]   = {"Off", "On"};
static const char* YESNO_LABELS[]    = {"No", "Yes"};

/* ── Değer değişim callback'leri ─────────────────────────── */
static void cb_aggression(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->aggression = idx;
    variable_item_set_current_value_text(item, AGGR_LABELS[idx]);
}

static void cb_scan_type(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->scan_type = idx;
    variable_item_set_current_value_text(item, SCAN_LABELS[idx]);
}

static void cb_hop_speed(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->hop_speed = idx;
    variable_item_set_current_value_text(item, HOP_LABELS[idx]);
}

static void cb_name_type(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->beacon_name_type = idx;
    variable_item_set_current_value_text(item, NAMETYPE_LABELS[idx]);
}



static void cb_portal_msg(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->portal_msg = idx;
    variable_item_set_current_value_text(item, MSG_LABELS[idx]);
}

static void cb_baud_rate(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->baud_rate = idx;
    variable_item_set_current_value_text(item, BAUD_LABELS[idx]);
}

static void cb_portal_toggle(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->portal_enabled = idx;
    variable_item_set_current_value_text(item, PORTAL_LABELS[idx]);
}

static void cb_clone_mac(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->clone_mac = idx;
    variable_item_set_current_value_text(item, YESNO_LABELS[idx]);
}

static const char* const LOOKALIKE_LABELS[] = {"Clone", "Lookalike"};

static void cb_ssid_lookalike(VariableItem* item) {
    JamFlipperApp* app = variable_item_get_context(item);
    uint8_t idx = variable_item_get_current_value_index(item);
    app->ssid_lookalike = idx;
    variable_item_set_current_value_text(item, LOOKALIKE_LABELS[idx]);
}

/* ── Enter callback — START butonuna basıldığında ────────── */
static void config_enter_callback(void* context, uint32_t index) {
    JamFlipperApp* app = context;
    char cmd[64];

    switch(app->active_mode) {
    case JamFlipperMenuIndexScanning:
        /* Son satır: >>> START SCAN <<< (index=2) */
        if(index == 2) {
            /* Yeni tarama — eski AP listesini temizle */
            app->scanned_ap_count = 0;
            app->line_idx = 0;

            /* Önceki PCAP dosyasını kapat */
            jf_pcap_close(app);

            furi_string_reset(app->text_box_store);

            /* PCAP modu: dosyayı aç */
            if(app->scan_type == 1) {
                if(jf_pcap_open(app)) {
                    furi_string_set_str(app->text_box_store,
                        "PCAP Scan starting...\n"
                        "Saving to: ");
                    furi_string_cat_str(app->text_box_store, app->pcap_path);
                    furi_string_cat_str(app->text_box_store, "\n");
                } else {
                    furi_string_set_str(app->text_box_store,
                        "ERROR: Could not create PCAP file!\n"
                        "Check SD card.\n");
                }
            } else {
                furi_string_set_str(app->text_box_store, "Starting scan...\n");
            }

            snprintf(cmd, sizeof(cmd), "CMD:SCAN,TYPE:%d", (int)app->scan_type);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexCompleteJam:
        /* Son satır: >>> START ATTACK <<< (index=6) */
        if(index == 6) {
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Complete Jam starting...\n");

            /* Custom SSID listesi yükle ve gönder (SSID List = Custom ise) */
            if(app->ssid_list == 1) {
                /* SD karttan custom_ssids.txt dosyasını oku */
                File* f = storage_file_alloc(app->storage);
                if(storage_file_open(f, JAM_FLIPPER_APP_FOLDER "/custom_ssids.txt",
                                     FSAM_READ, FSOM_OPEN_EXISTING)) {
                    char ssid_buf[256];
                    char cmd_buf[256];
                    int pos = 0;
                    int cmd_pos = snprintf(cmd_buf, sizeof(cmd_buf), "CMD:CSSID,");
                    bool first = true;

                    uint16_t bytes_read;
                    while((bytes_read = storage_file_read(f, ssid_buf + pos, 1)) > 0) {
                        if(ssid_buf[pos] == '\n' || ssid_buf[pos] == '\r') {
                            if(pos > 0) {
                                ssid_buf[pos] = '\0';
                                if(!first && cmd_pos < (int)sizeof(cmd_buf) - 34) {
                                    cmd_buf[cmd_pos++] = '\t';
                                }
                                int copy_len = pos;
                                if(cmd_pos + copy_len >= (int)sizeof(cmd_buf) - 1) break;
                                memcpy(cmd_buf + cmd_pos, ssid_buf, copy_len);
                                cmd_pos += copy_len;
                                first = false;
                            }
                            pos = 0;
                        } else {
                            pos++;
                            if(pos >= 32) pos = 32; /* SSID max 32 char */
                        }
                    }
                    /* Son satır (newline olmadan) */
                    if(pos > 0) {
                        ssid_buf[pos] = '\0';
                        if(!first && cmd_pos < (int)sizeof(cmd_buf) - 34) {
                            cmd_buf[cmd_pos++] = '\t';
                        }
                        if(cmd_pos + pos < (int)sizeof(cmd_buf) - 1) {
                            memcpy(cmd_buf + cmd_pos, ssid_buf, pos);
                            cmd_pos += pos;
                        }
                    }
                    cmd_buf[cmd_pos] = '\0';

                    if(!first) {
                        jf_uart_send_str(app, cmd_buf);
                        furi_delay_ms(20);
                        furi_string_cat_str(app->text_box_store, "Custom SSIDs loaded\n");
                    } else {
                        furi_string_cat_str(app->text_box_store, "custom_ssids.txt empty!\n");
                    }
                    storage_file_close(f);
                } else {
                    furi_string_cat_str(app->text_box_store,
                        "No custom_ssids.txt found.\n"
                        "Create: " JAM_FLIPPER_APP_FOLDER "/custom_ssids.txt\n"
                        "Using Top20 fallback.\n");
                }
                storage_file_free(f);
            }

            char cmd[64];
            snprintf(cmd, sizeof(cmd), "CMD:CJAM,AGR:%d,HOP:%d,SSID:%d,MSG:%d,PORTAL:%d",
                     (int)app->aggression, (int)app->hop_speed,
                     (int)app->beacon_name_type,
                     (int)app->portal_msg, (int)app->portal_enabled
                     );
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexWifiJam:
        /* Son satır: >>> START ATTACK <<< (index=3) */
        if(index == 3) {
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "WiFi Jam starting...\n");
            snprintf(cmd, sizeof(cmd), "CMD:WJ,AGR:%d,HOP:%d",
                     (int)app->aggression, (int)app->hop_speed);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexListedDeauth:
        /* index=2: Select Targets → TargetSelect sahnesine git */
        if(index == 2) {
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);

        /* index=3: START ATTACK → seçili hedeflere deauth */
        } else if(index == 3) {
            /* Seçili hedef var mı kontrol et */
            int sel_count = 0;
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) sel_count++;
            }
            if(sel_count == 0) {
                /* Seçili hedef yok — uyar */
                furi_string_reset(app->text_box_store);
                furi_string_set_str(app->text_box_store,
                    "No targets selected!\nUse Select Targets first.\n");
                scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
            } else {
                furi_string_reset(app->text_box_store);
                furi_string_set_str(app->text_box_store, "Listed Deauth starting...\n");

                /* İlk önce Client seçim komutlarını UART ile tek tek bildir (CMD:SCLI,AP_ID,C1,C2...) */
                for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                    if(app->scanned_aps[i].selected && app->scanned_aps[i].client_count > 0) {
                        char cli_buf[64];
                        int cli_pos = snprintf(cli_buf, sizeof(cli_buf), "CMD:SCLI,%d", i);
                        bool has_selected_client = false;
                        for(uint8_t c = 0; c < app->scanned_aps[i].client_count; c++) {
                            if(app->scanned_aps[i].clients[c].selected) {
                                if(cli_pos < (int)sizeof(cli_buf) - 4) {
                                    cli_buf[cli_pos++] = ',';
                                }
                                cli_pos += snprintf(cli_buf + cli_pos, sizeof(cli_buf) - cli_pos, "%d", c);
                                has_selected_client = true;
                            }
                        }
                        // Sadece hedeflenmiş cihaz varsa komutu gönder
                        if(has_selected_client) {
                            jf_uart_send_str(app, cli_buf);
                            // ESP32'in buffer'ı dolmadan komutu parse etmesi için şuanlık Flipper delay koyalım (10ms)
                            furi_delay_ms(10);
                        }
                    }
                }

                /* Seçili hedef indekslerini gönder: CMD:LDEAUTH,AGR:N,SEL:0,3,5 */
                char sel_buf[256];
                int pos = snprintf(sel_buf, sizeof(sel_buf),
                                   "CMD:LDEAUTH,AGR:%d,SEL:", (int)app->aggression);
                bool first = true;
                for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                    if(app->scanned_aps[i].selected) {
                        if(!first && pos < (int)sizeof(sel_buf) - 4) {
                            sel_buf[pos++] = ',';
                        }
                        pos += snprintf(sel_buf + pos, sizeof(sel_buf) - pos, "%d", i);
                        first = false;
                    }
                }
                jf_uart_send_str(app, sel_buf);
                app->attack_running = true;
                scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
            }
        }
        break;

    case JamFlipperMenuIndexBeaconSpam:
        /* Son satır: >>> START SPAM <<< (index=4) */
        if(index == 4) {
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Beacon Spam starting...\n");

            /* Custom SSID listesi yükle ve gönder (Name Type = Custom ise) */
            if(app->beacon_name_type == 1) {
                /* SD karttan custom_ssids.txt dosyasını oku */
                File* f = storage_file_alloc(app->storage);
                if(storage_file_open(f, JAM_FLIPPER_APP_FOLDER "/custom_ssids.txt",
                                     FSAM_READ, FSOM_OPEN_EXISTING)) {
                    char ssid_buf[256];
                    char cmd_buf[256];
                    int pos = 0;
                    int cmd_pos = snprintf(cmd_buf, sizeof(cmd_buf), "CMD:CSSID,");
                    bool first = true;

                    uint16_t bytes_read;
                    while((bytes_read = storage_file_read(f, ssid_buf + pos, 1)) > 0) {
                        if(ssid_buf[pos] == '\n' || ssid_buf[pos] == '\r') {
                            if(pos > 0) {
                                ssid_buf[pos] = '\0';
                                if(!first && cmd_pos < (int)sizeof(cmd_buf) - 34) {
                                    cmd_buf[cmd_pos++] = '\t';
                                }
                                int copy_len = pos;
                                if(cmd_pos + copy_len >= (int)sizeof(cmd_buf) - 1) break;
                                memcpy(cmd_buf + cmd_pos, ssid_buf, copy_len);
                                cmd_pos += copy_len;
                                first = false;
                            }
                            pos = 0;
                        } else {
                            pos++;
                            if(pos >= 32) pos = 32;
                        }
                    }
                    if(pos > 0) {
                        ssid_buf[pos] = '\0';
                        if(!first && cmd_pos < (int)sizeof(cmd_buf) - 34) {
                            cmd_buf[cmd_pos++] = '\t';
                        }
                        if(cmd_pos + pos < (int)sizeof(cmd_buf) - 1) {
                            memcpy(cmd_buf + cmd_pos, ssid_buf, pos);
                            cmd_pos += pos;
                        }
                    }
                    cmd_buf[cmd_pos] = '\0';

                    if(!first) {
                        jf_uart_send_str(app, cmd_buf);
                        furi_delay_ms(20);
                        furi_string_cat_str(app->text_box_store, "Custom SSIDs loaded\n");
                    } else {
                        furi_string_cat_str(app->text_box_store, "custom_ssids.txt empty!\n");
                    }
                    storage_file_close(f);
                } else {
                    furi_string_cat_str(app->text_box_store,
                        "No custom_ssids.txt found.\n"
                        "Create: " JAM_FLIPPER_APP_FOLDER "/custom_ssids.txt\n"
                        "Using Random fallback.\n");
                }
                storage_file_free(f);
            }

            char cmd[64];
            snprintf(cmd, sizeof(cmd), "CMD:BSPAM,TYPE:%d,PORTAL:%d,MSG:%d",
                     (int)app->beacon_name_type,
                     (int)app->portal_enabled,
                     (int)app->portal_msg);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexSettings:
        /* Son satır: >>> REBOOT ESP32 <<< (index=2) */
        if(index == 2) {
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Rebooting ESP32...\n");
            jf_uart_send_str(app, "CMD:REBOOT");
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    /* ── Wi-Fi Sniff ───────────────────────────────────────── */
    case JamFlipperMenuIndexWifiSniff:
        if(index == 1) {
            /* Select AP → TargetSelect sahnesi */
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);
        } else if(index == 2) {
            /* Enter Password → WifiPass sahnesi */
            app->text_input_mode = JamFlipperTextInputModeWifiPass;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneWifiPass);
        } else if(index == 3) {
            /* >>> START SNIFF <<< */
            /* Seçili AP'yi bul */
            const char* ssid = "";
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) {
                    ssid = app->scanned_aps[i].ssid;
                    break;
                }
            }
            if(ssid[0] == '\0') {
                furi_string_reset(app->text_box_store);
                furi_string_set_str(app->text_box_store,
                    "No AP selected!\nUse Select AP first.\n");
                scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
                break;
            }
            char cmd[128];
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "WiFi Sniff starting...\n");
            /* PCAP dosyasini ac */
            if(jf_pcap_open(app)) {
                furi_string_cat_str(app->text_box_store, "PCAP: ");
                furi_string_cat_str(app->text_box_store, app->pcap_path);
                furi_string_cat_str(app->text_box_store, "\n");
            }
            snprintf(cmd, sizeof(cmd), "CMD:SNIFF,SSID:%s,PASS:%s", ssid, app->wifi_pass);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexEvilTwin:
        if(index == 1) {
            /* Select Target AP → hedef AP listesi */
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);
        } else if(index == 4) {
            const char* ssid = ""; const char* bssid = ""; uint8_t channel = 6;
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) {
                    ssid = app->scanned_aps[i].ssid;
                    bssid = app->scanned_aps[i].bssid_str;
                    channel = app->scanned_aps[i].channel;
                    break;
                }
            }
            if(!ssid[0]) return;
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Evil Twin starting...\n");
            snprintf(cmd, sizeof(cmd), "CMD:EVILTWIN,SSID:%s,CH:%d,BSSID:%s,CLONE:%d,SUFFIX:%d",
                     ssid, channel, bssid, (int)app->clone_mac, (int)app->ssid_lookalike);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    /* ── Beacon Portal Modülleri ───────────────────────── */
    case JamFlipperMenuIndexGLogin:
    case JamFlipperMenuIndexIgLogin:
    case JamFlipperMenuIndexFbLogin:
    case JamFlipperMenuIndexTgmLogin:
    case JamFlipperMenuIndexSbLogin:
    case JamFlipperMenuIndexMcLogin:
    case JamFlipperMenuIndexPubLogin:
    case JamFlipperMenuIndexSchLogin:
        if(index == 1) {
            app->text_input_mode = JamFlipperTextInputModeSsid;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneWifiPass);
        } else if(index == 2) {
            const char* prefix = (app->active_mode == JamFlipperMenuIndexGLogin)  ? "GLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexIgLogin) ? "IGLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexFbLogin) ? "FBLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexTgmLogin)? "TGMLOGIN":
                                 (app->active_mode == JamFlipperMenuIndexSbLogin) ? "SBLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexMcLogin) ? "MCLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexPubLogin)? "PUBLOGIN" : "SCHLOGIN";
            const char* def_ssid = (app->active_mode == JamFlipperMenuIndexIgLogin) ? "Instagram_WiFi" :
                                   (app->active_mode == JamFlipperMenuIndexFbLogin) ? "Facebook_WiFi" :
                                   (app->active_mode == JamFlipperMenuIndexTgmLogin)? "Telegram_WiFi" :
                                   (app->active_mode == JamFlipperMenuIndexSbLogin) ? "Starbucks_WiFi" :
                                   (app->active_mode == JamFlipperMenuIndexMcLogin) ? "McDonalds_Free" :
                                   (app->active_mode == JamFlipperMenuIndexPubLogin)? "Free_Public_WiFi" : "School_Guest";
            if(app->active_mode == JamFlipperMenuIndexGLogin) def_ssid = "Free_WiFi";

            const char* ssid = app->evil_ssid[0] ? app->evil_ssid : def_ssid;
            furi_string_reset(app->text_box_store);
            furi_string_printf(app->text_box_store, "%s starting...\nSSID: %s\n", prefix, ssid);
            snprintf(cmd, sizeof(cmd), "CMD:%s,SSID:%s", prefix, ssid);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexTargetGLogin:
        if(index == 1) {
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);
        } else if(index == 4) {
            const char* ssid = ""; const char* bssid = ""; uint8_t channel = 6;
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) { ssid = app->scanned_aps[i].ssid; bssid = app->scanned_aps[i].bssid_str; channel = app->scanned_aps[i].channel; break; }
            }
            if(!ssid[0]) return;
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Target G-Login starting...\n");
            snprintf(cmd, sizeof(cmd), "CMD:TGLOGIN,SSID:%s,CH:%d,BSSID:%s,CLONE:%d,SUFFIX:%d",
                     ssid, channel, bssid, (int)app->clone_mac, (int)app->ssid_lookalike);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    /* ── Targeted Portal Modülleri ─────────────────────── */
    case JamFlipperMenuIndexTargetIgLogin:
    case JamFlipperMenuIndexTargetFbLogin:
    case JamFlipperMenuIndexTargetTgmLogin:
    case JamFlipperMenuIndexTargetSbLogin:
    case JamFlipperMenuIndexTargetMcLogin:
    case JamFlipperMenuIndexTargetPubLogin:
        if(index == 1) {
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);
        } else if(index == 4) {
            const char* ssid = "";
            const char* bssid = "";
            uint8_t channel = 6;
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) {
                    ssid = app->scanned_aps[i].ssid;
                    bssid = app->scanned_aps[i].bssid_str;
                    channel = app->scanned_aps[i].channel;
                    break;
                }
            }
            if(!ssid[0]) return;
            
            const char* prefix = (app->active_mode == JamFlipperMenuIndexTargetIgLogin)  ? "TIGLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexTargetFbLogin)  ? "TFBLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexTargetTgmLogin) ? "TTGMLOGIN":
                                 (app->active_mode == JamFlipperMenuIndexTargetSbLogin)  ? "TSBLOGIN" :
                                 (app->active_mode == JamFlipperMenuIndexTargetMcLogin)  ? "TMCLOGIN" : "TPUBLOGIN";
            
            furi_string_reset(app->text_box_store);
            furi_string_printf(app->text_box_store, "Target %s starting...\nSSID: %s\n", prefix, ssid);
            
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "CMD:%s,SSID:%s,CH:%d,BSSID:%s,CLONE:%d,SUFFIX:%d",
                     prefix, ssid, channel, bssid, (int)app->clone_mac, (int)app->ssid_lookalike);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    /* ── Target School ───────────────────────────────────── */
    case JamFlipperMenuIndexTargetSchLogin:
        if(index == 1) {
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneTargetSelect);
        } else if(index == 4) {
            const char* ssid = "";
            const char* bssid = "";
            uint8_t channel = 6;
            for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
                if(app->scanned_aps[i].selected) {
                    ssid = app->scanned_aps[i].ssid;
                    bssid = app->scanned_aps[i].bssid_str;
                    channel = app->scanned_aps[i].channel;
                    break;
                }
            }
            if(ssid[0] == '\0') {
                furi_string_reset(app->text_box_store);
                furi_string_set_str(app->text_box_store, "No AP selected!\n");
                scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
                break;
            }
            char cmd[128];
            furi_string_reset(app->text_box_store);
            furi_string_set_str(app->text_box_store, "Target School starting...\n");
            snprintf(cmd, sizeof(cmd), "CMD:TSCHLOGIN,SSID:%s,CH:%d,BSSID:%s,CLONE:%d,SUFFIX:%d",
                     ssid, channel, bssid, (int)app->clone_mac, (int)app->ssid_lookalike);
            jf_uart_send_str(app, cmd);
            app->attack_running = true;
            scene_manager_next_scene(app->scene_manager, JamFlipperSceneConsoleOutput);
        }
        break;

    case JamFlipperMenuIndexSepBeacon:
    case JamFlipperMenuIndexSepTargeted:
    case JamFlipperMenuIndexSepSettings:
    default:
        break;
    }
}

/* ── on_enter — Dinamik menü oluşturucu ──────────────────── */
void jam_flipper_scene_config_on_enter(void* context) {
    JamFlipperApp* app = context;
    VariableItemList* vil = app->var_item_list;
    VariableItem* item;

    variable_item_list_reset(vil);

    switch(app->active_mode) {
    case JamFlipperMenuIndexScanning:
        variable_item_list_add(vil, "--- SCAN MODE ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Type", 2, cb_scan_type, app);
        variable_item_set_current_value_index(item, app->scan_type);
        variable_item_set_current_value_text(item, SCAN_LABELS[app->scan_type]);
        variable_item_list_add(vil, ">>> START SCAN <<<", 0, NULL, NULL);
        break;

    case JamFlipperMenuIndexCompleteJam:
        variable_item_list_add(vil, "--- COMPLETE JAM ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Aggression", 3, cb_aggression, app);
        variable_item_set_current_value_index(item, app->aggression);
        variable_item_set_current_value_text(item, AGGR_LABELS[app->aggression]);

        item = variable_item_list_add(vil, "Hop Speed", 3, cb_hop_speed, app);
        variable_item_set_current_value_index(item, app->hop_speed);
        variable_item_set_current_value_text(item, HOP_LABELS[app->hop_speed]);

        item = variable_item_list_add(vil, "Name Type", 3, cb_name_type, app);
        variable_item_set_current_value_index(item, app->beacon_name_type);
        variable_item_set_current_value_text(item, NAMETYPE_LABELS[app->beacon_name_type]);

        item = variable_item_list_add(vil, "Portal Msg", 4, cb_portal_msg, app);
        variable_item_set_current_value_index(item, app->portal_msg);
        variable_item_set_current_value_text(item, MSG_LABELS[app->portal_msg]);

        item = variable_item_list_add(vil, "Captive Portal", 2, cb_portal_toggle, app);
        variable_item_set_current_value_index(item, app->portal_enabled);
        variable_item_set_current_value_text(item, PORTAL_LABELS[app->portal_enabled]);

        variable_item_list_add(vil, ">>> START ATTACK <<<", 0, NULL, NULL);
        break;

    case JamFlipperMenuIndexWifiJam:
        variable_item_list_add(vil, "--- WI-FI JAM ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Aggression", 3, cb_aggression, app);
        variable_item_set_current_value_index(item, app->aggression);
        variable_item_set_current_value_text(item, AGGR_LABELS[app->aggression]);

        item = variable_item_list_add(vil, "Hop Speed", 3, cb_hop_speed, app);
        variable_item_set_current_value_index(item, app->hop_speed);
        variable_item_set_current_value_text(item, HOP_LABELS[app->hop_speed]);

        variable_item_list_add(vil, ">>> START ATTACK <<<", 0, NULL, NULL);
        break;

    case JamFlipperMenuIndexListedDeauth: {
        variable_item_list_add(vil, "--- LISTED DEAUTH ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Target Aggr.", 3, cb_aggression, app);
        variable_item_set_current_value_index(item, app->aggression);
        variable_item_set_current_value_text(item, AGGR_LABELS[app->aggression]);

        /* Kaç AP taranmış, kaçı seçili göster */
        char sel_label[48];
        int sel_count = 0;
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            if(app->scanned_aps[i].selected) sel_count++;
        }
        if(app->scanned_ap_count > 0) {
            snprintf(sel_label, sizeof(sel_label), "Select Targets [%d/%d] >",
                     sel_count, app->scanned_ap_count);
        } else {
            snprintf(sel_label, sizeof(sel_label), "Select Targets [scan first] >");
        }
        variable_item_list_add(vil, sel_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START ATTACK <<<", 0, NULL, NULL);
        break;
    }

    case JamFlipperMenuIndexBeaconSpam:
        variable_item_list_add(vil, "--- BEACON SPAM ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Name Type", 3, cb_name_type, app);
        variable_item_set_current_value_index(item, app->beacon_name_type);
        variable_item_set_current_value_text(item, NAMETYPE_LABELS[app->beacon_name_type]);

        item = variable_item_list_add(vil, "Portal Msg", 4, cb_portal_msg, app);
        variable_item_set_current_value_index(item, app->portal_msg);
        variable_item_set_current_value_text(item, MSG_LABELS[app->portal_msg]);

        item = variable_item_list_add(vil, "Captive Portal", 2, cb_portal_toggle, app);
        variable_item_set_current_value_index(item, app->portal_enabled);
        variable_item_set_current_value_text(item, PORTAL_LABELS[app->portal_enabled]);

        variable_item_list_add(vil, ">>> START SPAM <<<", 0, NULL, NULL);
        break;

    case JamFlipperMenuIndexSettings:
        variable_item_list_add(vil, "--- GLOBAL SETTINGS ---", 0, NULL, NULL);
        item = variable_item_list_add(vil, "Baud Rate", 3, cb_baud_rate, app);
        variable_item_set_current_value_index(item, app->baud_rate);
        variable_item_set_current_value_text(item, BAUD_LABELS[app->baud_rate]);

        variable_item_list_add(vil, ">>> REBOOT ESP32 <<<", 0, NULL, NULL);
        break;

    /* ── Wi-Fi Sniff ekranı ──────────────────────────────── */
    case JamFlipperMenuIndexWifiSniff: {
        variable_item_list_add(vil, "--- WI-FI SNIFF ---", 0, NULL, NULL);

        /* AP seçim durumu */
        char ap_label[48];
        const char* sel_ssid = NULL;
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            if(app->scanned_aps[i].selected) { sel_ssid = app->scanned_aps[i].ssid; break; }
        }
        if(sel_ssid && sel_ssid[0]) {
            snprintf(ap_label, sizeof(ap_label), "AP: %.20s >", sel_ssid);
        } else {
            snprintf(ap_label, sizeof(ap_label), "Select AP [scan 1st] >");
        }
        variable_item_list_add(vil, ap_label, 0, NULL, NULL);

        /* Şifre göstergesi */
        char pass_label[32];
        snprintf(pass_label, sizeof(pass_label), "WiFi Pass: %s",
                 app->wifi_pass[0] ? "(set) >" : "(none) >");
        variable_item_list_add(vil, pass_label, 0, NULL, NULL);

        variable_item_list_add(vil, ">>> START SNIFF <<<", 0, NULL, NULL);
        break;
    }

    /* ── Evil Twin Saldırı ekranı ────────────────────────── */
    case JamFlipperMenuIndexEvilTwin: {
        variable_item_list_add(vil, "--- EVIL TWIN ---", 0, NULL, NULL);

        /* Hedef AP seçim durumu */
        char et_ap_label[48];
        const char* et_ssid = NULL;
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            if(app->scanned_aps[i].selected) { et_ssid = app->scanned_aps[i].ssid; break; }
        }
        if(et_ssid && et_ssid[0]) {
            snprintf(et_ap_label, sizeof(et_ap_label), "Target: %.18s >", et_ssid);
        } else {
            snprintf(et_ap_label, sizeof(et_ap_label), "Select Target AP >");
        }
        variable_item_list_add(vil, et_ap_label, 0, NULL, NULL);

        /* Clone MAC toggle */
        item = variable_item_list_add(vil, "Clone MAC", 2, cb_clone_mac, app);
        variable_item_set_current_value_index(item, app->clone_mac);
        variable_item_set_current_value_text(item, YESNO_LABELS[app->clone_mac]);

        /* SSID Mode toggle (Lookalike / Clone) */
        item = variable_item_list_add(vil, "SSID Mode", 2, cb_ssid_lookalike, app);
        variable_item_set_current_value_index(item, app->ssid_lookalike);
        variable_item_set_current_value_text(item, LOOKALIKE_LABELS[app->ssid_lookalike]);

        variable_item_list_add(vil, ">>> START EVIL TWIN <<<", 0, NULL, NULL);
        break;
    }

    /* ── G-Login Beacon ekranı ───────────────────────────── */
    case JamFlipperMenuIndexGLogin: {
        variable_item_list_add(vil, "--- G-LOGIN BEACON ---", 0, NULL, NULL);

        /* Tıklanabilir SSID göstergesi */
        char gl_ssid_label[48];
        snprintf(gl_ssid_label, sizeof(gl_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Free_WiFi");
        variable_item_list_add(vil, gl_ssid_label, 0, NULL, NULL);

        variable_item_list_add(vil, ">>> START G-LOGIN <<<", 0, NULL, NULL);
        break;
    }

    /* ── Targeted G-Login ekranı ─────────────────────────── */
    case JamFlipperMenuIndexTargetGLogin: {
        variable_item_list_add(vil, "--- TARGET G-LOGIN ---", 0, NULL, NULL);

        /* Hedef AP */
        char tgl_ap_label[48];
        const char* tgl_ssid = NULL;
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            if(app->scanned_aps[i].selected) { tgl_ssid = app->scanned_aps[i].ssid; break; }
        }
        if(tgl_ssid && tgl_ssid[0]) {
            snprintf(tgl_ap_label, sizeof(tgl_ap_label), "Target: %.18s >", tgl_ssid);
        } else {
            snprintf(tgl_ap_label, sizeof(tgl_ap_label), "Select Target AP >");
        }
        variable_item_list_add(vil, tgl_ap_label, 0, NULL, NULL);

        /* Clone MAC toggle */
        item = variable_item_list_add(vil, "Clone MAC", 2, cb_clone_mac, app);
        variable_item_set_current_value_index(item, app->clone_mac);
        variable_item_set_current_value_text(item, YESNO_LABELS[app->clone_mac]);

        /* SSID Mode toggle (Lookalike / Clone) */
        item = variable_item_list_add(vil, "SSID Mode", 2, cb_ssid_lookalike, app);
        variable_item_set_current_value_index(item, app->ssid_lookalike);
        variable_item_set_current_value_text(item, LOOKALIKE_LABELS[app->ssid_lookalike]);

        variable_item_list_add(vil, ">>> START T-GLOGIN <<<", 0, NULL, NULL);
        break;
    }

    /* ── Instagram Beacon ekranı ─────────────────────────── */
    case JamFlipperMenuIndexIgLogin: {
        variable_item_list_add(vil, "--- INSTAGRAM BEACON ---", 0, NULL, NULL);
        char ig_ssid_label[48];
        snprintf(ig_ssid_label, sizeof(ig_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Instagram_WiFi");
        variable_item_list_add(vil, ig_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── Facebook Beacon ekranı ──────────────────────────── */
    case JamFlipperMenuIndexFbLogin: {
        variable_item_list_add(vil, "--- FACEBOOK BEACON ---", 0, NULL, NULL);
        char fb_ssid_label[48];
        snprintf(fb_ssid_label, sizeof(fb_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Facebook_WiFi");
        variable_item_list_add(vil, fb_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── Telegram Beacon ekranı ──────────────────────────── */
    case JamFlipperMenuIndexTgmLogin: {
        variable_item_list_add(vil, "--- TELEGRAM BEACON ---", 0, NULL, NULL);
        char tgm_ssid_label[48];
        snprintf(tgm_ssid_label, sizeof(tgm_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Telegram_WiFi");
        variable_item_list_add(vil, tgm_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── Starbucks Beacon ekranı ─────────────────────────── */
    case JamFlipperMenuIndexSbLogin: {
        variable_item_list_add(vil, "--- STARBUCKS PORTAL ---", 0, NULL, NULL);
        char sb_ssid_label[48];
        snprintf(sb_ssid_label, sizeof(sb_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Starbucks_WiFi");
        variable_item_list_add(vil, sb_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── McDonald's Beacon ekranı ────────────────────────── */
    case JamFlipperMenuIndexMcLogin: {
        variable_item_list_add(vil, "--- MCDONALD'S PORTAL ---", 0, NULL, NULL);
        char mc_ssid_label[48];
        snprintf(mc_ssid_label, sizeof(mc_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "McDonalds_Free");
        variable_item_list_add(vil, mc_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── Public Wi-Fi Beacon ekranı ──────────────────────── */
    case JamFlipperMenuIndexPubLogin: {
        variable_item_list_add(vil, "--- PUBLIC WI-FI ---", 0, NULL, NULL);
        char pub_ssid_label[48];
        snprintf(pub_ssid_label, sizeof(pub_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "Free_Public_WiFi");
        variable_item_list_add(vil, pub_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── School Login Beacon ekranı ──────────────────────── */
    case JamFlipperMenuIndexSchLogin: {
        variable_item_list_add(vil, "--- SCHOOL LOGIN ---", 0, NULL, NULL);
        char sch_ssid_label[48];
        snprintf(sch_ssid_label, sizeof(sch_ssid_label), "SSID: %s >",
                 app->evil_ssid[0] ? app->evil_ssid : "School_Guest");
        variable_item_list_add(vil, sch_ssid_label, 0, NULL, NULL);
        variable_item_list_add(vil, ">>> START BEACON <<<", 0, NULL, NULL);
        break;
    }
    /* ── Targeted ekranlar (AP seçım göstergesi + START) ───── */
    case JamFlipperMenuIndexTargetIgLogin:
    case JamFlipperMenuIndexTargetFbLogin:
    case JamFlipperMenuIndexTargetTgmLogin:
    case JamFlipperMenuIndexTargetSbLogin:
    case JamFlipperMenuIndexTargetMcLogin:
    case JamFlipperMenuIndexTargetPubLogin:
    case JamFlipperMenuIndexTargetSchLogin: {
        const char* title = (app->active_mode == JamFlipperMenuIndexTargetIgLogin)  ? "--- TARGET INSTAGRAM ---" :
                            (app->active_mode == JamFlipperMenuIndexTargetFbLogin)  ? "--- TARGET FACEBOOK ---" :
                            (app->active_mode == JamFlipperMenuIndexTargetTgmLogin) ? "--- TARGET TELEGRAM ---" :
                            (app->active_mode == JamFlipperMenuIndexTargetSbLogin)  ? "--- TARGET STARBUCKS ---" :
                            (app->active_mode == JamFlipperMenuIndexTargetMcLogin)  ? "--- TARGET MCDONALD'S ---" :
                            (app->active_mode == JamFlipperMenuIndexTargetPubLogin) ? "--- TARGET PUB.WIFI ---" : "--- TARGET SCHOOL ---";
        variable_item_list_add(vil, title, 0, NULL, NULL);

        char t_ap_label[48];
        const char* t_ssid = NULL;
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            if(app->scanned_aps[i].selected) { t_ssid = app->scanned_aps[i].ssid; break; }
        }
        snprintf(t_ap_label, sizeof(t_ap_label), (t_ssid && t_ssid[0]) ? "Target: %.18s >" : "Select Target AP >", t_ssid ? t_ssid : "");
        variable_item_list_add(vil, t_ap_label, 0, NULL, NULL);

        item = variable_item_list_add(vil, "Clone MAC", 2, cb_clone_mac, app);
        variable_item_set_current_value_index(item, app->clone_mac);
        variable_item_set_current_value_text(item, YESNO_LABELS[app->clone_mac]);

        item = variable_item_list_add(vil, "SSID Mode", 2, cb_ssid_lookalike, app);
        variable_item_set_current_value_index(item, app->ssid_lookalike);
        variable_item_set_current_value_text(item, LOOKALIKE_LABELS[app->ssid_lookalike]);

        variable_item_list_add(vil, ">>> START TARGET <<<", 0, NULL, NULL);
        break;
    }

    default:
        break;
    }

    variable_item_list_set_selected_item(vil, 0);
    variable_item_list_set_enter_callback(vil, config_enter_callback, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewVarItemList);
}

/* ── on_event ────────────────────────────────────────────── */
bool jam_flipper_scene_config_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

/* ── on_exit ─────────────────────────────────────────────── */
void jam_flipper_scene_config_on_exit(void* context) {
    JamFlipperApp* app = context;
    variable_item_list_reset(app->var_item_list);
}
