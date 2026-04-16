#pragma once

typedef enum {
    JamFlipperCustomEventUartRxDone,
    JamFlipperCustomEventWifiPassDone,  // WiFi şifresi tamamlandı
    JamFlipperCustomEventSsidDone,      // SSID girişi tamamlandı
} JamFlipperCustomEvent;

/* TextInput sahnesi hangi amaçla açıldı? */
typedef enum {
    JamFlipperTextInputModeWifiPass = 0,  // wifi_pass[] buffer'ına yaz
    JamFlipperTextInputModeSsid,          // evil_ssid[] buffer'ına yaz
} JamFlipperTextInputMode;
