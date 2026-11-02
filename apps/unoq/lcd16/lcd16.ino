// BUBBLE-BLUE status on a SainSmart 16x2 keypad shield (HD44780).
//
// Parallel pins: RS=8 EN=9 D4=4 D5=5 D6=6 D7=7, backlight=10, keys on A0.
// Bit-banged with conservative delays: LiquidCrystal on the UNO Q STM32 is
// fast enough to slip the 4-bit nibble sync, which prints as katakana junk.
//
// Same Router Bridge contract as apps/unoq/panel/panel.ino:
//   Linux -> sketch   panel_status / panel_message / panel_presets
//   sketch -> Linux   panel_preset(0|1)

#include <Arduino_RouterBridge.h>
#include <zephyr/kernel.h>

static const uint8_t COLS = 16;
static const uint8_t ROWS = 2;
static const uint8_t PIN_RS = 8;
static const uint8_t PIN_EN = 9;
static const uint8_t PIN_D4 = 4;
static const uint8_t PIN_D5 = 5;
static const uint8_t PIN_D6 = 6;
static const uint8_t PIN_D7 = 7;
static const uint8_t PIN_BL = 10;

static struct k_mutex state_mutex;
static char st_line0[COLS + 1] = "BUBBLE-BLUE     ";
static char st_line1[COLS + 1] = "waiting Linux   ";
static bool dirty = true;
static uint32_t last_push_ms = 0;
static const uint32_t LINK_TIMEOUT_MS = 10000;
static bool linked = false;

static int32_t st_peers = 0;
static bool st_relay = false;
static char st_msg[COLS + 1] = "";

static void copy_pad(char *dst, const char *src) {
  size_t n = 0;
  if (src) {
    while (n < COLS && src[n]) {
      unsigned char c = (unsigned char)src[n];
      dst[n] = (c >= 32 && c < 127) ? (char)c : ' ';
      n++;
    }
  }
  while (n < COLS) dst[n++] = ' ';
  dst[COLS] = '\0';
}

static void hd_pulse() {
  digitalWrite(PIN_EN, LOW);
  k_busy_wait(50);
  digitalWrite(PIN_EN, HIGH);
  k_busy_wait(50);
  digitalWrite(PIN_EN, LOW);
  k_busy_wait(100);
}

static void hd_nibble(uint8_t nibble) {
  digitalWrite(PIN_D4, (nibble >> 0) & 1);
  digitalWrite(PIN_D5, (nibble >> 1) & 1);
  digitalWrite(PIN_D6, (nibble >> 2) & 1);
  digitalWrite(PIN_D7, (nibble >> 3) & 1);
  hd_pulse();
}

static void hd_byte(uint8_t value, bool data) {
  digitalWrite(PIN_RS, data ? HIGH : LOW);
  hd_nibble(value >> 4);
  hd_nibble(value & 0x0F);
  if (!data && (value == 0x01 || value == 0x02)) {
    k_msleep(3);
  } else {
    k_busy_wait(50);
  }
}

static void hd_cmd(uint8_t cmd) { hd_byte(cmd, false); }
static void hd_data(uint8_t value) { hd_byte(value, true); }

static void hd_begin() {
  pinMode(PIN_RS, OUTPUT);
  pinMode(PIN_EN, OUTPUT);
  pinMode(PIN_D4, OUTPUT);
  pinMode(PIN_D5, OUTPUT);
  pinMode(PIN_D6, OUTPUT);
  pinMode(PIN_D7, OUTPUT);
  pinMode(PIN_BL, OUTPUT);
  digitalWrite(PIN_RS, LOW);
  digitalWrite(PIN_EN, LOW);
  digitalWrite(PIN_BL, HIGH);
  k_msleep(50);

  // HD44780 reset: three 8-bit function-set nibbles, then 4-bit.
  hd_nibble(0x03);
  k_msleep(5);
  hd_nibble(0x03);
  k_msleep(5);
  hd_nibble(0x03);
  k_msleep(1);
  hd_nibble(0x02);
  k_msleep(1);

  hd_cmd(0x28);  // 4-bit, 2 lines, 5x8
  hd_cmd(0x08);  // display off
  hd_cmd(0x01);  // clear
  hd_cmd(0x06);  // entry mode
  hd_cmd(0x0C);  // display on, cursor off
}

static void hd_line(uint8_t row, const char *text) {
  hd_cmd(row == 0 ? 0x80 : 0xC0);
  for (uint8_t i = 0; i < COLS; i++) {
    char c = text[i];
    hd_data((c >= 32 && c < 127) ? (uint8_t)c : (uint8_t)' ');
  }
}

static void lcd_write() {
  hd_line(0, st_line0);
  hd_line(1, st_line1);
}

static void refresh_lines() {
  char l0[COLS + 1];
  char l1[COLS + 1];
  if (!linked) {
    copy_pad(l0, "BUBBLE-BLUE");
    copy_pad(l1, st_msg[0] ? st_msg : "waiting Linux");
  } else {
    char buf[24];
    snprintf(buf, sizeof(buf), "BB %dP %s", (int)st_peers, st_relay ? "RELAY" : "LEAF");
    copy_pad(l0, buf);
    copy_pad(l1, st_msg[0] ? st_msg : "no message yet");
  }
  if (strcmp(st_line0, l0) != 0 || strcmp(st_line1, l1) != 0) {
    memcpy(st_line0, l0, COLS + 1);
    memcpy(st_line1, l1, COLS + 1);
    dirty = true;
  }
}

bool on_status(String local, int peers, bool relay, int epoch) {
  (void)local;
  (void)epoch;
  k_mutex_lock(&state_mutex, K_FOREVER);
  st_peers = peers;
  st_relay = relay;
  linked = true;
  last_push_ms = millis();
  refresh_lines();
  k_mutex_unlock(&state_mutex);
  return true;
}

void on_message(String sender, String text) {
  (void)sender;
  const char *raw = text.c_str();
  if (raw && (unsigned char)raw[0] < 32) {
    return;
  }
  k_mutex_lock(&state_mutex, K_FOREVER);
  copy_pad(st_msg, raw);
  last_push_ms = millis();
  linked = true;
  refresh_lines();
  k_mutex_unlock(&state_mutex);
}

void on_presets(String label0, String label1) {
  (void)label0;
  (void)label1;
}

static int8_t read_key() {
  int v = analogRead(A0);
  if (v < 200) return 1;     // Right
  if (v < 1600) return -1;   // Up / Down
  if (v < 3200) return 0;    // Select / Left
  return -1;
}

void setup() {
  k_mutex_init(&state_mutex);
  analogReadResolution(12);
  hd_begin();
  copy_pad(st_line0, "BUBBLE-BLUE");
  copy_pad(st_line1, "hello world");
  lcd_write();

  Bridge.begin();
  Bridge.provide("panel_status", on_status);
  Bridge.provide("panel_message", on_message);
  Bridge.provide("panel_presets", on_presets);
}

void loop() {
  k_mutex_lock(&state_mutex, K_FOREVER);
  if (linked && millis() - last_push_ms > LINK_TIMEOUT_MS) {
    linked = false;
    refresh_lines();
  }
  bool draw = dirty;
  dirty = false;
  k_mutex_unlock(&state_mutex);
  if (draw) lcd_write();

  static int8_t last = -1;
  int8_t key = read_key();
  if (key >= 0 && last < 0) {
    Bridge.notify("panel_preset", (int)key);
  }
  last = key;
  delay(40);
}
