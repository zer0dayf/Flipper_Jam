#pragma once

#include <gui/scene_manager.h>

/* ── Scene ID Enum ─────────────────────────────────────────── */
typedef enum {
#define ADD_SCENE(prefix, name, id) JamFlipperScene##id,
#include "jam_flipper_scene_config.h"
#undef ADD_SCENE
    JamFlipperSceneNum,
} JamFlipperScene;

/* ── Handler tablosu (jam_flipper_scene.c'de tanımlanır) ───── */
extern const SceneManagerHandlers jam_flipper_scene_handlers;

/* ── Her sahne için callback prototipleri ─────────────────── */
#define ADD_SCENE(prefix, name, id)                                        \
    void prefix##_scene_##name##_on_enter(void*);                          \
    bool prefix##_scene_##name##_on_event(void*, SceneManagerEvent);       \
    void prefix##_scene_##name##_on_exit(void*);
#include "jam_flipper_scene_config.h"
#undef ADD_SCENE
