#include "../jam_flipper_app_i.h"

/* ── Submenu callback ────────────────────────────────────── */
static void start_menu_callback(void* context, uint32_t index) {
    JamFlipperApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, index);
}

/* ── on_enter ────────────────────────────────────────────── */
void jam_flipper_scene_start_on_enter(void* context) {
    JamFlipperApp* app = context;

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "JamFlipper V2.1");

    /* ── Temel Saldırı Modları ─────────────────────── */
    submenu_add_item(app->submenu, "0) Scanning",        JamFlipperMenuIndexScanning,      start_menu_callback, app);
    submenu_add_item(app->submenu, "1) Complete Jam",    JamFlipperMenuIndexCompleteJam,   start_menu_callback, app);
    submenu_add_item(app->submenu, "2) Wi-Fi Jam",       JamFlipperMenuIndexWifiJam,       start_menu_callback, app);
    submenu_add_item(app->submenu, "3) Listed Deauth",   JamFlipperMenuIndexListedDeauth,  start_menu_callback, app);
    submenu_add_item(app->submenu, "4) Beacon Spam",     JamFlipperMenuIndexBeaconSpam,    start_menu_callback, app);
    submenu_add_item(app->submenu, "5) Wi-Fi Sniff",     JamFlipperMenuIndexWifiSniff,     start_menu_callback, app);
    submenu_add_item(app->submenu, "6) Evil Twin",       JamFlipperMenuIndexEvilTwin,      start_menu_callback, app);

    /* ── Separator: Beacon Portals ─────────────────── */
    submenu_add_item(app->submenu, "-- BEACON PORTALS --", JamFlipperMenuIndexSepBeacon,  start_menu_callback, app);

    /* ── Beacon Portal Modları (deauth YOK) ─────────── */
    submenu_add_item(app->submenu, "8) G-Login Beacon",    JamFlipperMenuIndexGLogin,      start_menu_callback, app);
    submenu_add_item(app->submenu, "9) Instagram Beacon",  JamFlipperMenuIndexIgLogin,     start_menu_callback, app);
    submenu_add_item(app->submenu, "10) Facebook Beacon",  JamFlipperMenuIndexFbLogin,     start_menu_callback, app);
    submenu_add_item(app->submenu, "11) Telegram Beacon",  JamFlipperMenuIndexTgmLogin,    start_menu_callback, app);
    submenu_add_item(app->submenu, "12) Starbucks Login",  JamFlipperMenuIndexSbLogin,     start_menu_callback, app);
    submenu_add_item(app->submenu, "13) McDonald's Login", JamFlipperMenuIndexMcLogin,     start_menu_callback, app);
    submenu_add_item(app->submenu, "14) Public Wi-Fi",     JamFlipperMenuIndexPubLogin,    start_menu_callback, app);
    submenu_add_item(app->submenu, "15) School Login",     JamFlipperMenuIndexSchLogin,    start_menu_callback, app);

    /* ── Separator: Targeted Portals ───────────────── */
    submenu_add_item(app->submenu, "-- TARGETED PORTALS --", JamFlipperMenuIndexSepTargeted, start_menu_callback, app);

    /* ── Targeted Portal Modları (deauth + portal) ─── */
    submenu_add_item(app->submenu, "16) Target G-Login",   JamFlipperMenuIndexTargetGLogin,    start_menu_callback, app);
    submenu_add_item(app->submenu, "17) Target Instagram",  JamFlipperMenuIndexTargetIgLogin,   start_menu_callback, app);
    submenu_add_item(app->submenu, "18) Target Facebook",   JamFlipperMenuIndexTargetFbLogin,   start_menu_callback, app);
    submenu_add_item(app->submenu, "19) Target Telegram",   JamFlipperMenuIndexTargetTgmLogin,  start_menu_callback, app);
    submenu_add_item(app->submenu, "20) Target Starbucks",  JamFlipperMenuIndexTargetSbLogin,   start_menu_callback, app);
    submenu_add_item(app->submenu, "21) Target McDonald's", JamFlipperMenuIndexTargetMcLogin,   start_menu_callback, app);
    submenu_add_item(app->submenu, "22) Target Pub.WiFi",   JamFlipperMenuIndexTargetPubLogin,  start_menu_callback, app);
    submenu_add_item(app->submenu, "23) Target School",     JamFlipperMenuIndexTargetSchLogin,  start_menu_callback, app);

    /* ── Separator: Settings ───────────────────────── */
    submenu_add_item(app->submenu, "-- SETTINGS --",  JamFlipperMenuIndexSepSettings, start_menu_callback, app);
    submenu_add_item(app->submenu, "24) Settings",    JamFlipperMenuIndexSettings,    start_menu_callback, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewSubmenu);
}

/* ── on_event ────────────────────────────────────────────── */
bool jam_flipper_scene_start_on_event(void* context, SceneManagerEvent event) {
    JamFlipperApp* app = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        uint32_t idx = event.event;

        /* Separator itemleri — navigasyon YOK, sadece tüket */
        if(idx == JamFlipperMenuIndexSepBeacon   ||
           idx == JamFlipperMenuIndexSepTargeted ||
           idx == JamFlipperMenuIndexSepSettings) {
            consumed = true;
            return consumed;
        }

        app->active_mode = (JamFlipperMenuIndex)idx;
        scene_manager_next_scene(app->scene_manager, JamFlipperSceneConfig);
        consumed = true;
    }

    return consumed;
}

/* ── on_exit ─────────────────────────────────────────────── */
void jam_flipper_scene_start_on_exit(void* context) {
    JamFlipperApp* app = context;
    submenu_reset(app->submenu);
}
