#include "../jam_flipper_app_i.h"

static const char* SEL_LABELS[] = {"No", "Yes"};
static VariableItem* s_cli_items[8];

static void cb_client_toggle(VariableItem* item) {
    uint8_t val = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, SEL_LABELS[val]);
}

static void client_select_enter_cb(void* context, uint32_t index) {
    JamFlipperApp* app = context;
    JamFlipperAP* ap = &app->scanned_aps[app->active_ap_index];
    UNUSED(index);

    if(ap->client_count == 0) return;
}

void jam_flipper_scene_client_select_on_enter(void* context) {
    JamFlipperApp* app = context;
    VariableItemList* vil = app->var_item_list;

    variable_item_list_reset(vil);
    memset(s_cli_items, 0, sizeof(s_cli_items));

    JamFlipperAP* ap = &app->scanned_aps[app->active_ap_index];

    if(ap->client_count == 0) {
        variable_item_list_add(vil, "No Clients Found", 0, NULL, NULL);
    } else {
        char header[40];
        snprintf(header, sizeof(header), "--- %d Clients ---", ap->client_count);
        variable_item_list_add(vil, header, 0, NULL, NULL);

        for(uint8_t i = 0; i < ap->client_count; i++) {
            JamFlipperClient* cli = &ap->clients[i];

            char label[32];
            snprintf(label, sizeof(label), "%s", cli->mac_str);

            VariableItem* item = variable_item_list_add(
                vil, label, 2, cb_client_toggle, app);
            variable_item_set_current_value_index(item, cli->selected ? 1 : 0);
            variable_item_set_current_value_text(item, SEL_LABELS[cli->selected ? 1 : 0]);

            s_cli_items[i] = item;
        }
    }

    variable_item_list_set_selected_item(vil, ap->client_count > 0 ? 1 : 0);
    variable_item_list_set_enter_callback(vil, client_select_enter_cb, app);

    view_dispatcher_switch_to_view(app->view_dispatcher, JamFlipperAppViewVarItemList);
}

bool jam_flipper_scene_client_select_on_event(void* context, SceneManagerEvent event) {
    UNUSED(context);
    UNUSED(event);
    return false;
}

void jam_flipper_scene_client_select_on_exit(void* context) {
    JamFlipperApp* app = context;
    JamFlipperAP* ap = &app->scanned_aps[app->active_ap_index];

    for(uint8_t i = 0; i < ap->client_count; i++) {
        if(s_cli_items[i] != NULL) {
            uint8_t val = variable_item_get_current_value_index(s_cli_items[i]);
            ap->clients[i].selected = (val == 1);
        }
    }

    memset(s_cli_items, 0, sizeof(s_cli_items));
    variable_item_list_reset(app->var_item_list);
}
