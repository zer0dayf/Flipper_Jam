#include "jam_flipper_scene.h"

/* ── On-enter callback dizisi ─────────────────────────────── */
static void (*const jam_flipper_on_enter_handlers[])(void*) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_enter,
#include "jam_flipper_scene_config.h"
#undef ADD_SCENE
};

/* ── On-event callback dizisi ────────────────────────────── */
static bool (*const jam_flipper_on_event_handlers[])(void*, SceneManagerEvent) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_event,
#include "jam_flipper_scene_config.h"
#undef ADD_SCENE
};

/* ── On-exit callback dizisi ─────────────────────────────── */
static void (*const jam_flipper_on_exit_handlers[])(void*) = {
#define ADD_SCENE(prefix, name, id) prefix##_scene_##name##_on_exit,
#include "jam_flipper_scene_config.h"
#undef ADD_SCENE
};

/* ── SceneManager handler tablosu ────────────────────────── */
const SceneManagerHandlers jam_flipper_scene_handlers = {
    .on_enter_handlers  = jam_flipper_on_enter_handlers,
    .on_event_handlers  = jam_flipper_on_event_handlers,
    .on_exit_handlers   = jam_flipper_on_exit_handlers,
    .scene_num          = JamFlipperSceneNum,
};
