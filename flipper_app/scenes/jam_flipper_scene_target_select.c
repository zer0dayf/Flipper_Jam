#include "../jam_flipper_app_i.h"

/* ────────────────────────────────────────────────────────────
 * TargetSelect Sahnesi
 *
 * Scan sonucunda bulunan AP'leri VariableItemList (No/Yes)
 * olarak gösterir. Kullanıcı her AP için toggle yapar.
 *
 * Layout:
 *   [0]     "--- N APs Found ---"   (başlık)
 *   [1..N]  AP satırları            (No/Yes toggle)
 *   [N+1]   ">>> SELECT ALL <<<"    (enter callback)
 *   [N+2]   ">>> DESELECT ALL <<<"  (enter callback)
 *
 * Toggle problem çözümü:
 *   VariableItem callback'i hangi AP'ye ait olduğunu bilmiyor
 *   çünkü context hep app. Ancak VariableItemList'te item'lar
 *   sıralı ekleniyor ve her toggle sırayla tetikleniyor.
 *   Çözüm: on_exit'te SEÇİMLERİ GÜNCELLEME YAPIYORUZ.
 *   variable_item_list API'sinde item'a index ile ulaşamıyoruz
 *   ama on_exit çağrıldığında toggle durumları zaten kaybolacak.
 *
 *   GERÇEK ÇÖZÜM: Her AP'nin VariableItem pointer'ını saklayıp
 *   on_exit'te her birinin current_value_index'ini okumak.
 * ──────────────────────────────────────────────────────────── */

static const char* SEL_LABELS[] = {"No", "Yes"};

/* AP item pointer'larını saklıyoruz */
static VariableItem* s_ap_items[JAM_FLIPPER_MAX_APS];

/* ── Toggle callback ─────────────────────────────────────── */
static void cb_target_toggle(VariableItem* item) {
    uint8_t val = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, SEL_LABELS[val]);
}

/* ── Enter callback — Select All / Deselect All / View Clients ──────────── */
static void target_select_enter_cb(void* context, uint32_t index) {
    JamFlipperApp* app = context;

    if(app->scanned_ap_count == 0) return;

    if(index > 0 && index <= app->scanned_ap_count) {
        // Bir AP'ye OK tıklandı. İlgili AP'nin istemci listesi ekranına git.
        app->active_ap_index = index - 1; // Başlık 0. index olduğu için 1 eksiltiyoruz.
        
        // Önce mevcut toggles durumlarını kaydedelim
        jam_flipper_scene_target_select_on_exit(app);

        scene_manager_next_scene(app->scene_manager, JamFlipperSceneClientSelect);
    }
}

/* ── on_enter ────────────────────────────────────────────── */
void jam_flipper_scene_target_select_on_enter(void* context) {
    JamFlipperApp* app = context;
    VariableItemList* vil = app->var_item_list;

    variable_item_list_reset(vil);
    memset(s_ap_items, 0, sizeof(s_ap_items));

    if(app->scanned_ap_count == 0) {
        variable_item_list_add(vil, "No APs found!", 0, NULL, NULL);
        variable_item_list_add(vil, "Run Scan first.", 0, NULL, NULL);
    } else {
        /* Başlık */
        char header[40];
        snprintf(header, sizeof(header), "--- %d APs Found ---", app->scanned_ap_count);
        variable_item_list_add(vil, header, 0, NULL, NULL);

        /* Her AP için bir satır */
        for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
            JamFlipperAP* ap = &app->scanned_aps[i];

            char label[64];
            if(ap->ssid[0] != '\0') {
                snprintf(label, sizeof(label), "%s (%d Cli)", ap->ssid, ap->client_count);
            } else {
                snprintf(label, sizeof(label), "%s (%d Cli)", ap->bssid_str, ap->client_count);
            }

            VariableItem* item = variable_item_list_add(
                vil, label, 2, cb_target_toggle, app);
            variable_item_set_current_value_index(item, ap->selected ? 1 : 0);
            variable_item_set_current_value_text(item, SEL_LABELS[ap->selected ? 1 : 0]);

            /* Pointer'ı sakla — on_exit'te okuyacağız */
            s_ap_items[i] = item;
        }
    }

    variable_item_list_set_selected_item(vil, app->scanned_ap_count > 0 ? 1 : 0);
    variable_item_list_set_enter_callback(vil, target_select_enter_cb, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewVarItemList);
}

/* ── on_event ────────────────────────────────────────────── */
bool jam_flipper_scene_target_select_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

/* ── on_exit — Toggle değerlerini kaydet ─────────────────── */
void jam_flipper_scene_target_select_on_exit(void* context) {
    JamFlipperApp* app = context;

    /* Her AP'nin VariableItem pointer'ından seçim durumunu oku */
    for(uint8_t i = 0; i < app->scanned_ap_count; i++) {
        if(s_ap_items[i] != NULL) {
            uint8_t val = variable_item_get_current_value_index(s_ap_items[i]);
            app->scanned_aps[i].selected = (val == 1);
        }
    }

    memset(s_ap_items, 0, sizeof(s_ap_items));
    variable_item_list_reset(app->var_item_list);
}
