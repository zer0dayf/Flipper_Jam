#include "../jam_flipper_app_i.h"

/*
 * ConsoleOutput sahnesi — canlı log ekranı.
 * Geri tuşuna basınca saldırıyı durdurur ve önceki sahneye döner.
 */

/* ── on_enter ────────────────────────────────────────────── */
void jam_flipper_scene_console_output_on_enter(void* context) {
    JamFlipperApp* app = context;

    text_box_reset(app->text_box);
    text_box_set_font(app->text_box, TextBoxFontText);
    text_box_set_focus(app->text_box, TextBoxFocusEnd);

    /* Önceden hazırlanmış mesajı göster */
    if(furi_string_size(app->text_box_store) > 0) {
        text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewConsoleOutput);
}

/* ── on_event ────────────────────────────────────────────── */
bool jam_flipper_scene_console_output_on_event(void* context, SceneManagerEvent event) {
    JamFlipperApp* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == JamFlipperCustomEventUartRxDone) {
            /* GUI thread'inde TextBox'u güncelle */
            text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeTick) {
        /* Periyodik yenile (scroll) */
        text_box_set_text(app->text_box, furi_string_get_cstr(app->text_box_store));
        consumed = true;
    }

    return consumed;
}

/* ── on_exit ─────────────────────────────────────────────── */
void jam_flipper_scene_console_output_on_exit(void* context) {
    JamFlipperApp* app = context;

    /* Ekrandan çıkınca saldırıyı durdur */
    if(app->attack_running) {
        jf_uart_send_str(app, "CMD:STOP");
        app->attack_running = false;
    }

    /* PCAP dosyasını kapat ve sonucu logla */
    if(app->pcap_active) {
        uint32_t count = app->pcap_frame_count;
        jf_pcap_close(app);
        
        /* Sonuç mesajını ekle (bir sonraki girişte görülebilir veya UART RX ile gelebilir) */
        furi_string_cat_printf(app->text_box_store, 
            "\n--- PCAP Finished ---\n"
            "Saved %lu frames.\n", count);
    }

    text_box_reset(app->text_box);
}
