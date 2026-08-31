// Bubble-Blue status panel for the Arduino UNO Q + Adafruit 1651 shield.
//
// The mesh lives on the Linux side of the board: this sketch owns nothing but
// the screen and the touch controller. Linux pushes what to display and the
// panel calls back when a preset button is tapped, so the two presets shown
// here are always the ones Linux will actually send.
//
// RPC contract (see apps/unoq_panel.py for the other end):
//
//   Linux -> panel   panel_status(local, peers, relay, epoch) -> touch_ok
//                    panel_message(sender, text)
//                    panel_presets(label0, label1)
//   panel -> Linux   panel_preset(index)
//                    panel_touch_raw(x, y)   diagnostics, see CALIBRATION
//
// panel_status answers with the touch verdict rather than announcing it: a
// notification at boot would be shouted into the void, since Linux starts long
// after the MCU and the panel process can restart at any time. Riding the
// heartbeat means whoever is listening always has the current answer.
//
// Text arrives pre-truncated and transliterated to ASCII: the built-in GFX font
// has no accents, and doing it on the Linux side keeps this sketch free of
// string juggling it has no RAM budget for.

#include <Arduino_RouterBridge.h>
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <Adafruit_TSC2007.h>
#include <zephyr/kernel.h>

// ---------------------------------------------------------------- hardware

// Fixed by the shield: the display is on hardware SPI with these two control
// lines, the touch controller sits on I2C at 0x48.
static const uint8_t TFT_DC = 9;
static const uint8_t TFT_CS = 10;
static const uint8_t TSC_ADDR = 0x48;

Adafruit_ILI9341 tft(TFT_CS, TFT_DC);
Adafruit_TSC2007 ts;
static bool touch_ok = false;

// The controller may be absent at boot and turn up later — a cold I²C bus, or a
// shield reseated on a running board. Latching the failure would mean the
// buttons stay dead until someone presses reset, so keep probing. begin() frees
// its previous interface before allocating a new one, so this does not leak.
static const uint32_t TOUCH_PROBE_MS = 5000;
static uint32_t last_touch_probe_ms = 0;
static bool touch_probed_once = false;

// CALIBRATION. These are Adafruit's nominal values for the TSC2007; panels
// vary. panel_touch_raw() notifies every press, so if the buttons respond in
// the wrong place, read the raw pairs off the Linux log and adjust here.
static const uint16_t TS_MINX = 300, TS_MAXX = 3800;
static const uint16_t TS_MINY = 185, TS_MAXY = 3700;
static const uint16_t TS_MIN_PRESSURE = 200;

// ------------------------------------------------------------------ layout

// Landscape. Everything below is expressed against these two numbers.
static const int16_t W = 320;
static const int16_t H = 240;

static const int16_t HEADER_H = 28;
static const int16_t STATUS_Y = HEADER_H;
static const int16_t STATUS_H = 34;
static const int16_t MSG_Y = STATUS_Y + STATUS_H;
static const int16_t MSG_H = 108;
static const int16_t BTN_Y = MSG_Y + MSG_H;
static const int16_t BTN_H = H - BTN_Y - 4;
static const int16_t BTN_W = (W - 18) / 2;
static const int16_t BTN0_X = 6;
static const int16_t BTN1_X = BTN0_X + BTN_W + 6;

static const uint16_t COL_BG = ILI9341_BLACK;
static const uint16_t COL_HEADER = 0x001F;  // deep blue
static const uint16_t COL_TEXT = ILI9341_WHITE;
static const uint16_t COL_DIM = 0x8410;  // grey
static const uint16_t COL_OK = 0x07E0;   // green
static const uint16_t COL_WARN = 0xFD20;  // orange
static const uint16_t COL_BTN = 0x0210;   // dark green
static const uint16_t COL_BTN_ON = 0x05E0;
static const uint16_t COL_BTN_OFF = 0x2104;  // grey: touch is gone, button is inert

// Message body: 25 characters per line at text size 2, three lines.
static const uint8_t MSG_COLS = 25;
static const uint8_t MSG_ROWS = 3;

// ------------------------------------------------------------------- state

// Written by the Bridge thread, read by loop(). Small enough that copying it
// under the mutex costs nothing, which is cheaper than reasoning about which
// half-written string loop() might otherwise pick up.
static struct k_mutex state_mutex;

static char st_local[20] = "";
static char st_msg_from[20] = "";
static char st_msg_text[MSG_COLS * MSG_ROWS + 1] = "";
static char st_label[2][14] = {"", ""};
static int32_t st_peers = 0;
static int32_t st_epoch = 0;
static bool st_relay = false;
static bool st_linked = false;

static bool dirty_header = true;
static bool dirty_status = true;
static bool dirty_msg = true;
static bool dirty_btn = true;

// Linux pushes on a heartbeat, so silence means the link died rather than that
// nothing changed. Without this the panel would happily show stale numbers.
static const uint32_t LINK_TIMEOUT_MS = 10000;
static uint32_t last_push_ms = 0;

static int8_t pressed_btn = -1;

static void copy_str(char *dst, size_t cap, const char *src) {
  if (src == nullptr) {
    dst[0] = '\0';
    return;
  }
  strncpy(dst, src, cap - 1);
  dst[cap - 1] = '\0';
}

// ------------------------------------------------------------- RPC handlers

bool on_status(String local, int peers, bool relay, int epoch) {
  k_mutex_lock(&state_mutex, K_FOREVER);
  if (strcmp(st_local, local.c_str()) != 0) {
    copy_str(st_local, sizeof(st_local), local.c_str());
    dirty_header = true;
  }
  if (st_peers != peers || st_epoch != epoch || st_relay != relay || !st_linked) {
    st_peers = peers;
    st_epoch = epoch;
    st_relay = relay;
    dirty_status = true;
    dirty_header = true;
  }
  st_linked = true;
  last_push_ms = millis();
  k_mutex_unlock(&state_mutex);
  return touch_ok;
}

void on_message(String sender, String text) {
  k_mutex_lock(&state_mutex, K_FOREVER);
  copy_str(st_msg_from, sizeof(st_msg_from), sender.c_str());
  copy_str(st_msg_text, sizeof(st_msg_text), text.c_str());
  dirty_msg = true;
  last_push_ms = millis();
  k_mutex_unlock(&state_mutex);
}

void on_presets(String label0, String label1) {
  k_mutex_lock(&state_mutex, K_FOREVER);
  copy_str(st_label[0], sizeof(st_label[0]), label0.c_str());
  copy_str(st_label[1], sizeof(st_label[1]), label1.c_str());
  dirty_btn = true;
  last_push_ms = millis();
  k_mutex_unlock(&state_mutex);
}

// ------------------------------------------------------------------ drawing

static void draw_header(const char *local, bool relay, bool linked) {
  tft.fillRect(0, 0, W, HEADER_H, COL_HEADER);
  tft.setTextSize(2);
  tft.setTextColor(COL_TEXT);
  tft.setCursor(6, 7);
  tft.print("BUBBLE-BLUE");

  // The role badge is the one thing worth reading from across the room.
  const char *badge = linked ? (relay ? "RELAI" : "FEUILLE") : "----";
  int16_t badge_w = strlen(badge) * 12 + 8;
  tft.setTextColor(linked ? (relay ? COL_OK : COL_DIM) : COL_WARN);
  tft.setCursor(W - badge_w, 7);
  tft.print(badge);
  (void)local;
}

static void draw_status(const char *local, int32_t peers, int32_t epoch, bool linked) {
  tft.fillRect(0, STATUS_Y, W, STATUS_H, COL_BG);
  tft.setTextSize(1);

  if (!linked) {
    tft.setTextColor(COL_WARN);
    tft.setCursor(6, STATUS_Y + 6);
    tft.print("LIEN LINUX PERDU - meshd ou unoq_panel.py est arrete");
    return;
  }

  // The address matters less than knowing the buttons are dead, so the warning
  // takes its line when the touch controller is missing.
  tft.setCursor(6, STATUS_Y + 4);
  if (touch_ok) {
    tft.setTextColor(COL_DIM);
    tft.print(local);
  } else {
    tft.setTextColor(COL_WARN);
    tft.print("TACTILE HS - envoyer depuis Linux (--tap)");
  }

  tft.setTextSize(2);
  tft.setTextColor(peers > 0 ? COL_OK : COL_WARN);
  tft.setCursor(6, STATUS_Y + 16);
  tft.print("PAIRS ");
  tft.print(peers);

  tft.setTextColor(COL_DIM);
  tft.setCursor(W / 2 + 20, STATUS_Y + 16);
  tft.print("EPOQUE ");
  tft.print(epoch);
}

// Wrap on spaces, falling back to a hard cut for a word longer than a line.
static void draw_message(const char *from, const char *text) {
  tft.fillRect(0, MSG_Y, W, MSG_H, COL_BG);
  tft.drawFastHLine(0, MSG_Y, W, COL_DIM);

  tft.setTextSize(1);
  tft.setTextColor(COL_DIM);
  tft.setCursor(6, MSG_Y + 6);
  if (text[0] == '\0') {
    tft.print("DERNIER MESSAGE");
    tft.setTextSize(2);
    tft.setTextColor(COL_DIM);
    tft.setCursor(6, MSG_Y + 34);
    tft.print("(aucun)");
    return;
  }
  tft.print("DERNIER MESSAGE - ");
  tft.print(from);

  tft.setTextSize(2);
  tft.setTextColor(COL_TEXT);

  size_t len = strlen(text);
  size_t pos = 0;
  for (uint8_t row = 0; row < MSG_ROWS && pos < len; row++) {
    size_t take = len - pos;
    if (take > MSG_COLS) {
      take = MSG_COLS;
      size_t brk = take;
      while (brk > 0 && text[pos + brk] != ' ') brk--;
      if (brk > 0) take = brk;
    }
    char line[MSG_COLS + 1];
    memcpy(line, text + pos, take);
    line[take] = '\0';
    tft.setCursor(6, MSG_Y + 24 + row * 22);
    tft.print(line);
    pos += take;
    while (pos < len && text[pos] == ' ') pos++;
  }
}

static void draw_button(uint8_t idx, const char *label, bool active) {
  int16_t x = idx == 0 ? BTN0_X : BTN1_X;
  uint16_t fill = touch_ok ? (active ? COL_BTN_ON : COL_BTN) : COL_BTN_OFF;
  tft.fillRoundRect(x, BTN_Y, BTN_W, BTN_H, 6, fill);
  tft.drawRoundRect(x, BTN_Y, BTN_W, BTN_H, 6, touch_ok ? COL_OK : COL_DIM);

  if (label[0] == '\0') label = "...";
  tft.setTextSize(2);
  tft.setTextColor(touch_ok ? COL_TEXT : COL_DIM);
  int16_t tw = strlen(label) * 12;
  if (tw > BTN_W - 8) tw = BTN_W - 8;
  tft.setCursor(x + (BTN_W - tw) / 2, BTN_Y + (BTN_H - 16) / 2);
  tft.print(label);
}

// ------------------------------------------------------------------- touch

// Left half sends preset 0, right half preset 1. Splitting the row in two
// keeps the panel usable even if the calibration above is off: the worst a
// mirrored axis can do is swap the two buttons, not miss them.
static int8_t hit_test(int16_t sx, int16_t sy) {
  if (sy < BTN_Y - 8) return -1;
  return sx < W / 2 ? 0 : 1;
}

// Retry until the controller answers. Linux reads the outcome from the reply to
// panel_status, so nothing is announced here.
static void probe_touch() {
  if (touch_ok) return;
  if (touch_probed_once && millis() - last_touch_probe_ms < TOUCH_PROBE_MS) return;
  touch_probed_once = true;
  last_touch_probe_ms = millis();

  if (!ts.begin(TSC_ADDR, &Wire)) return;

  touch_ok = true;
  k_mutex_lock(&state_mutex, K_FOREVER);
  dirty_status = dirty_btn = true;
  k_mutex_unlock(&state_mutex);
}

static void poll_touch() {
  uint16_t x, y, z1, z2;
  static bool was_down = false;

  bool down = touch_ok && ts.read_touch(&x, &y, &z1, &z2) && z1 > TS_MIN_PRESSURE;
  if (!down) {
    if (was_down && pressed_btn >= 0) {
      pressed_btn = -1;
      dirty_btn = true;
    }
    was_down = false;
    return;
  }
  if (was_down) return;  // act on the press edge only
  was_down = true;

  Bridge.notify("panel_touch_raw", (int)x, (int)y);

  int16_t sx = map(x, TS_MINX, TS_MAXX, 0, W);
  int16_t sy = map(y, TS_MINY, TS_MAXY, 0, H);
  int8_t hit = hit_test(sx, sy);
  if (hit < 0) return;

  pressed_btn = hit;
  dirty_btn = true;
  Bridge.notify("panel_preset", (int)hit);
}

// -------------------------------------------------------------------- main

void setup() {
  k_mutex_init(&state_mutex);

  tft.begin();
  tft.setRotation(1);
  tft.fillScreen(COL_BG);
  tft.setTextWrap(false);

  Bridge.begin();
  Bridge.provide("panel_status", on_status);
  Bridge.provide("panel_message", on_message);
  Bridge.provide("panel_presets", on_presets);

  // After Bridge.begin() so the first verdict can be reported, not just drawn.
  probe_touch();
}

void loop() {
  probe_touch();
  poll_touch();

  char local[20], from[20], text[sizeof(st_msg_text)], label[2][14];
  int32_t peers, epoch;
  bool relay, linked;
  bool h, s, m, b;

  k_mutex_lock(&state_mutex, K_FOREVER);
  if (st_linked && millis() - last_push_ms > LINK_TIMEOUT_MS) {
    st_linked = false;
    dirty_status = true;
    dirty_header = true;
  }
  h = dirty_header; s = dirty_status; m = dirty_msg; b = dirty_btn;
  dirty_header = dirty_status = dirty_msg = dirty_btn = false;
  copy_str(local, sizeof(local), st_local);
  copy_str(from, sizeof(from), st_msg_from);
  copy_str(text, sizeof(text), st_msg_text);
  copy_str(label[0], sizeof(label[0]), st_label[0]);
  copy_str(label[1], sizeof(label[1]), st_label[1]);
  peers = st_peers; epoch = st_epoch; relay = st_relay; linked = st_linked;
  k_mutex_unlock(&state_mutex);

  if (h) draw_header(local, relay, linked);
  if (s) draw_status(local, peers, epoch, linked);
  if (m) draw_message(from, text);
  if (b) {
    draw_button(0, label[0], pressed_btn == 0);
    draw_button(1, label[1], pressed_btn == 1);
  }

  delay(20);
}
