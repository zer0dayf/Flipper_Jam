#include "jam_flipper_app_i.h"

/* ════════════════════════════════════════════════════════════
 * SceneManager event callback'leri
 * ════════════════════════════════════════════════════════════ */

static bool jam_flipper_custom_event_callback(void* context, uint32_t event) {
    furi_assert(context);
    JamFlipperApp* app = context;
    return scene_manager_handle_custom_event(app->scene_manager, event);
}

static bool jam_flipper_back_event_callback(void* context) {
    furi_assert(context);
    JamFlipperApp* app = context;
    
    /* Eğer saldırı devam ediyorsa, İLK "Geri" tuş basışında sadece durdur emri gönder ve sahnede kal. */
    if(app->attack_running) {
        jf_uart_send_str(app, "CMD:STOP");
        app->attack_running = false;
        
        furi_string_cat_printf(app->text_box_store, 
            "\n\n[!] STOP SIGNAL SENT...\n    Press BACK again to exit.\n");
        if(app->text_box) {
            text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
        }
        
        /* Olayı yuttuğumuzu belirt -> Önceki menüye geçmeyi engeller! */
        return true;
    }

    /* İkinci basışta (veya saldırı yokken) normal şekilde menüden çık */
    return scene_manager_handle_back_event(app->scene_manager);
}

static void jam_flipper_tick_event_callback(void* context) {
    furi_assert(context);
    JamFlipperApp* app = context;
    scene_manager_handle_tick_event(app->scene_manager);
}

/* ════════════════════════════════════════════════════════════
 * RX Data Callback — ESP'den gelen veriyi text_box_store'a yaz
 * ════════════════════════════════════════════════════════════ */

static void jam_flipper_uart_handle_rx_data(uint8_t* buf, size_t len, void* context) {
    JamFlipperApp* app = (JamFlipperApp*)context;
    furi_assert(app);

    /* Her byte'ı işle */
    for(size_t i = 0; i < len; i++) {
        char c = (char)buf[i];

        /* Satır sonu — tam satırı ayrıştır */
        if(c == '\n' || c == '\r') {
            if(app->line_idx > 0) {
                app->line_buf[app->line_idx] = '\0';
                /* AP: satırlarını yakala ve depola */
                jf_parse_line(app, app->line_buf);
                app->line_idx = 0;
            }
        } else if(app->line_idx < JAM_FLIPPER_LINE_BUF_SIZE - 1) {
            app->line_buf[app->line_idx++] = c;
        }
    }

    /* Görsel çıktı için text_box_store'a ekle */
    furi_string_cat_printf(app->text_box_store, "%.*s", (int)len, (const char*)buf);

    /* Buffer dolunca en eski yarısını sil */
    if(furi_string_size(app->text_box_store) >= JAM_FLIPPER_TEXT_BOX_STORE_SIZE) {
        furi_string_right(
            app->text_box_store,
            furi_string_size(app->text_box_store) / 2);
    }

    /* Custom event gönder — aktif sahne GUI thread'inde güncellesin */
    view_dispatcher_send_custom_event(
        app->view_dispatcher, JamFlipperCustomEventUartRxDone);
}

/* ════════════════════════════════════════════════════════════
 * Uygulama Başlatma
 * ════════════════════════════════════════════════════════════ */

static JamFlipperApp* jam_flipper_app_alloc(void) {
    JamFlipperApp* app = malloc(sizeof(JamFlipperApp));
    memset(app, 0, sizeof(JamFlipperApp));

    /* Varsayılan değerler */
    app->aggression       = 0; // Low
    app->hop_speed        = 0; // 50ms
    app->scan_type        = 0; // Basic
    app->beacon_name_type = 0; // Random
    app->beacon_interval  = 0; // 10s
    app->ssid_list        = 0; // Top 20
    app->portal_msg       = 0; // Update Req.
    app->baud_rate        = 0; // 115200
    app->clone_mac        = 0; // No
    app->attack_running   = false;
    app->wifi_pass[0]     = '\0';
    app->evil_ssid[0]     = '\0';
    app->evil_bssid[0]    = '\0';
    app->evil_channel     = 6;
    app->sniff_target_mac[0] = '\0';

    app->gui     = furi_record_open(RECORD_GUI);
    app->storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(app->storage, "/ext/apps_data");
    storage_common_mkdir(app->storage, JAM_FLIPPER_APP_FOLDER);

    /* --- STORAGE TEST --- */
    File* test_f = storage_file_alloc(app->storage);
    if(storage_file_open(test_f, "/ext/TEST_JAM.txt", FSAM_READ_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_write(test_f, "SD CARD WORKS!\n", 15);
        storage_file_close(test_f);
    }
    storage_file_free(test_f);
    /* -------------------- */

    /* ── View Dispatcher ────────────────────────────────────── */
    app->view_dispatcher = view_dispatcher_alloc();
    app->scene_manager   = scene_manager_alloc(&jam_flipper_scene_handlers, app);

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(
        app->view_dispatcher, jam_flipper_custom_event_callback);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher, jam_flipper_back_event_callback);
    view_dispatcher_set_tick_event_callback(
        app->view_dispatcher, jam_flipper_tick_event_callback, 250);
    view_dispatcher_attach_to_gui(
        app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    /* ── Submenu (ana menü) ────────────────────────────────── */
    app->submenu = submenu_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher,
        JamFlipperAppViewSubmenu,
        submenu_get_view(app->submenu));

    /* ── Variable Item List (ayar ekranları) ────────────────── */
    app->var_item_list = variable_item_list_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher,
        JamFlipperAppViewVarItemList,
        variable_item_list_get_view(app->var_item_list));

    /* ── TextBox (konsol çıkışı) ─────────────────────────────── */
    app->text_box       = text_box_alloc();
    app->text_box_store = furi_string_alloc();
    furi_string_reserve(app->text_box_store, JAM_FLIPPER_TEXT_BOX_STORE_SIZE);
    view_dispatcher_add_view(
        app->view_dispatcher,
        JamFlipperAppViewConsoleOutput,
        text_box_get_view(app->text_box));

    /* ── Widget ─────────────────────────────────────────────── */
    app->widget = widget_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher,
        JamFlipperAppViewWidget,
        widget_get_view(app->widget));

    /* ── TextInput (WiFi şifresi / metin girişi) ─────────────── */
    app->text_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher,
        JamFlipperAppViewTextInput,
        text_input_get_view(app->text_input));

    /* ── İlk sahne ──────────────────────────────────────────── */
    scene_manager_next_scene(app->scene_manager, JamFlipperSceneStart);

    return app;
}

/* ════════════════════════════════════════════════════════════
 * Uygulama Temizleme
 * ════════════════════════════════════════════════════════════ */

static void jam_flipper_app_free(JamFlipperApp* app) {
    furi_assert(app);

    /* View'leri kaldır */
    view_dispatcher_remove_view(app->view_dispatcher, JamFlipperAppViewSubmenu);
    view_dispatcher_remove_view(app->view_dispatcher, JamFlipperAppViewVarItemList);
    view_dispatcher_remove_view(app->view_dispatcher, JamFlipperAppViewConsoleOutput);
    view_dispatcher_remove_view(app->view_dispatcher, JamFlipperAppViewWidget);
    view_dispatcher_remove_view(app->view_dispatcher, JamFlipperAppViewTextInput);

    /* Modüller */
    submenu_free(app->submenu);
    variable_item_list_free(app->var_item_list);
    text_box_free(app->text_box);
    furi_string_free(app->text_box_store);
    widget_free(app->widget);
    text_input_free(app->text_input);

    /* Dispatcher / SceneManager */
    view_dispatcher_free(app->view_dispatcher);
    scene_manager_free(app->scene_manager);

    /* UART */
    if(app->uart) jam_flipper_uart_free(app->uart);

    /* PCAP dosyasını kapat (eğer açıksa) */
    jf_pcap_close(app);

    /* Record'lar */
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_GUI);

    free(app);
}

/* ════════════════════════════════════════════════════════════
 * Uygulama Giriş Noktası
 * ════════════════════════════════════════════════════════════ */

int32_t jam_flipper_app(void* p) {
    UNUSED(p);

    /* Expansion protokolünü devre dışı bırak (UART çakışması önlenir) */
    Expansion* expansion = furi_record_open(RECORD_EXPANSION);
    expansion_disable(expansion);

    /* OTG gücü aç (Wi-Fi devboard için gerekli) */
    uint8_t attempts = 0;
    bool otg_was_enabled = furi_hal_power_is_otg_enabled();
    while(!furi_hal_power_is_otg_enabled() && attempts++ < 5) {
        furi_hal_power_enable_otg();
        furi_delay_ms(10);
    }
    furi_delay_ms(200); /* ESP'nin boot olması için bekle */

    /* Uygulamayı başlat */
    JamFlipperApp* app = jam_flipper_app_alloc();

    /* UART'ı başlat ve RX callback'i bağla */
    app->uart = jam_flipper_uart_init(app);
    jam_flipper_uart_set_handle_rx_data_cb(app->uart, jam_flipper_uart_handle_rx_data);

    /* Ana event döngüsü */
    view_dispatcher_run(app->view_dispatcher);

    /* Temizle */
    jam_flipper_app_free(app);

    /* OTG durumunu önceki haline geri al */
    if(furi_hal_power_is_otg_enabled() && !otg_was_enabled) {
        furi_hal_power_disable_otg();
    }

    /* Expansion'ı tekrar aç */
    expansion_enable(expansion);
    furi_record_close(RECORD_EXPANSION);

    return 0;
}
