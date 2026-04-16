#include "jam_flipper_app_i.h"
#include "jam_flipper_uart.h"

/* ── Dahili Yapı ─────────────────────────────────────────── */
/*
 * UART Kanal Seçimi:
 *   FuriHalSerialIdUsart   → Flipper GPIO Pin 13 (TX) / Pin 14 (RX)
 *   FuriHalSerialIdLpuart1 → Flipper GPIO Pin 15 (TX) / Pin 16 (RX)
 *
 * ESP32 kodundaki pin eşleşmesine göre (Pin 15/16) LPUART kullanılıyor.
 * Eğer ESP32 Pin 13/14'e bağlıysa FuriHalSerialIdUsart olarak değiştir.
 */
#define UART_CH  (FuriHalSerialIdLpuart)
#define BAUDRATE (115200)

struct JamFlipperUart {
    JamFlipperApp*        app;
    FuriThread*           rx_thread;
    FuriStreamBuffer*     rx_stream;
    FuriHalSerialHandle*  serial_handle;
    uint8_t               rx_buf[RX_BUF_SIZE + 1];
    void (*handle_rx_data_cb)(uint8_t* buf, size_t len, void* context);
};

typedef enum {
    WorkerEvtStop   = (1 << 0),
    WorkerEvtRxDone = (1 << 1),
} WorkerEvtFlags;

#define WORKER_ALL_RX_EVENTS (WorkerEvtStop | WorkerEvtRxDone)

/* ── Public API ──────────────────────────────────────────── */
void jam_flipper_uart_set_handle_rx_data_cb(
    JamFlipperUart* uart,
    void (*handle_rx_data_cb)(uint8_t* buf, size_t len, void* context)) {
    furi_assert(uart);
    uart->handle_rx_data_cb = handle_rx_data_cb;
}

/* ── IRQ Callback (ISR bağlamında çalışır) ───────────────── */
static void jam_flipper_uart_on_irq_cb(
    FuriHalSerialHandle* handle,
    FuriHalSerialRxEvent event,
    void* context) {
    JamFlipperUart* uart = (JamFlipperUart*)context;

    if(event == FuriHalSerialRxEventData) {
        uint8_t data = furi_hal_serial_async_rx(handle);
        furi_stream_buffer_send(uart->rx_stream, &data, 1, 0);
        furi_thread_flags_set(furi_thread_get_id(uart->rx_thread), WorkerEvtRxDone);
    }
}

/* ── RX Worker Thread ────────────────────────────────────── */
static int32_t uart_worker(void* context) {
    JamFlipperUart* uart = (JamFlipperUart*)context;

    while(1) {
        uint32_t events = furi_thread_flags_wait(
            WORKER_ALL_RX_EVENTS, FuriFlagWaitAny, FuriWaitForever);
        furi_check((events & FuriFlagError) == 0);

        if(events & WorkerEvtStop) break;

        if(events & WorkerEvtRxDone) {
            size_t len = furi_stream_buffer_receive(
                uart->rx_stream, uart->rx_buf, RX_BUF_SIZE, 0);
            if(len > 0 && uart->handle_rx_data_cb) {
                uart->handle_rx_data_cb(uart->rx_buf, len, uart->app);
            }
        }
    }

    furi_stream_buffer_free(uart->rx_stream);
    return 0;
}

/* ── TX ──────────────────────────────────────────────────── */
void jam_flipper_uart_tx(JamFlipperUart* uart, uint8_t* data, size_t len) {
    furi_hal_serial_tx(uart->serial_handle, data, len);
}

/* ── Init ────────────────────────────────────────────────── */
JamFlipperUart* jam_flipper_uart_init(JamFlipperApp* app) {
    JamFlipperUart* uart = malloc(sizeof(JamFlipperUart));
    memset(uart, 0, sizeof(JamFlipperUart));
    uart->app = app;

    /* Stream buffer: RX_BUF_SIZE * 4 byte, trigger at 1 */
    uart->rx_stream = furi_stream_buffer_alloc(RX_BUF_SIZE * 4, 1);

    /* Worker thread */
    uart->rx_thread = furi_thread_alloc();
    furi_thread_set_name(uart->rx_thread, "JamFlipperUartRx");
    furi_thread_set_stack_size(uart->rx_thread, 2048);
    furi_thread_set_context(uart->rx_thread, uart);
    furi_thread_set_callback(uart->rx_thread, uart_worker);
    furi_thread_start(uart->rx_thread);

    /* Seri port */
    uart->serial_handle = furi_hal_serial_control_acquire(UART_CH);
    furi_check(uart->serial_handle);
    furi_hal_serial_init(uart->serial_handle, BAUDRATE);
    furi_hal_serial_async_rx_start(
        uart->serial_handle, jam_flipper_uart_on_irq_cb, uart, false);

    return uart;
}

/* ── Free ────────────────────────────────────────────────── */
void jam_flipper_uart_free(JamFlipperUart* uart) {
    furi_assert(uart);

    /* Worker'ı durdur */
    furi_thread_flags_set(furi_thread_get_id(uart->rx_thread), WorkerEvtStop);
    furi_thread_join(uart->rx_thread);
    furi_thread_free(uart->rx_thread);

    /* Seri portu kapat */
    furi_hal_serial_deinit(uart->serial_handle);
    furi_hal_serial_control_release(uart->serial_handle);

    free(uart);
}
