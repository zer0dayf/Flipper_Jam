#include "../jam_flipper_app_i.h"

/* ────────────────────────────────────────────────────────────
 * WifiPass / SSID Input Sahnesi — TextInput ile metin alır
 *
 * app->text_input_mode değişkeni hangi buffer'a yazılacağını belirtir:
 *   JamFlipperTextInputModeWifiPass → app->wifi_pass[]
 *   JamFlipperTextInputModeSsid    → app->evil_ssid[]
 *
 * Tamamlanınca Config sahnesine geri döner.
 * ──────────────────────────────────────────────────────────── */

/* ── Tamamlanma callback'i ──────────────────────────────── */
static void wifi_pass_input_done(void* ctx) {
    JamFlipperApp* app = (JamFlipperApp*)ctx;
    /* Hangi modu kullanıyoruz? Buna göre event gönder */
    if(app->text_input_mode == JamFlipperTextInputModeSsid) {
        view_dispatcher_send_custom_event(
            app->view_dispatcher,
            JamFlipperCustomEventSsidDone);
    } else {
        view_dispatcher_send_custom_event(
            app->view_dispatcher,
            JamFlipperCustomEventWifiPassDone);
    }
}

/* ── on_enter ────────────────────────────────────────────── */
void jam_flipper_scene_wifi_pass_on_enter(void* context) {
    JamFlipperApp* app = context;

    text_input_reset(app->text_input);

    if(app->text_input_mode == JamFlipperTextInputModeSsid) {
        text_input_set_header_text(app->text_input, "G-Login SSID");
        text_input_set_result_callback(
            app->text_input,
            wifi_pass_input_done,
            app,
            app->evil_ssid,
            sizeof(app->evil_ssid),
            false
        );
    } else {
        text_input_set_header_text(app->text_input, "WiFi Password");
        text_input_set_result_callback(
            app->text_input,
            wifi_pass_input_done,
            app,
            app->wifi_pass,
            sizeof(app->wifi_pass),
            false
        );
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewTextInput);
}

/* ── on_event ────────────────────────────────────────────── */
bool jam_flipper_scene_wifi_pass_on_event(void* context, SceneManagerEvent event) {
    JamFlipperApp* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == JamFlipperCustomEventWifiPassDone ||
           event.event == JamFlipperCustomEventSsidDone) {
            /* Şifre veya SSID girildi — Config sahnesine geri dön */
            scene_manager_previous_scene(app->scene_manager);
            consumed = true;
        }
    }

    return consumed;
}

/* ── on_exit ─────────────────────────────────────────────── */
void jam_flipper_scene_wifi_pass_on_exit(void* context) {
    JamFlipperApp* app = context;
    text_input_reset(app->text_input);
}
