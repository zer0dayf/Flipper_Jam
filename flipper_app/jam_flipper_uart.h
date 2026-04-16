#pragma once

#include <stdint.h>
#include <stddef.h>
#include "jam_flipper_app.h"

#define RX_BUF_SIZE 512

typedef struct JamFlipperUart JamFlipperUart;

/**
 * UART modülünü başlatır.
 * @param app  Ana uygulama context'i
 * @return     Ayrılmış JamFlipperUart handle'ı
 */
JamFlipperUart* jam_flipper_uart_init(JamFlipperApp* app);

/**
 * UART modülünü serbest bırakır ve thread'i durdurur.
 */
void jam_flipper_uart_free(JamFlipperUart* uart);

/**
 * ESP'ye veri gönderir.
 * @param uart  UART handle
 * @param data  Gönderilecek byte dizisi
 * @param len   Byte sayısı
 */
void jam_flipper_uart_tx(JamFlipperUart* uart, uint8_t* data, size_t len);

/**
 * RX verisi geldiğinde çağrılacak callback'i ayarlar.
 * @param uart              UART handle
 * @param handle_rx_data_cb Callback fonksiyonu (buf, len, context)
 */
void jam_flipper_uart_set_handle_rx_data_cb(
    JamFlipperUart* uart,
    void (*handle_rx_data_cb)(uint8_t* buf, size_t len, void* context));
