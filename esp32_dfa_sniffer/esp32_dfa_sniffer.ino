#include <WiFi.h>
#include <esp_wifi.h>

/**
 * DFA-Based SYN Flood Detector (Standalone Sniffer Version)
 * For B.Tech Mini Project: Network Security Gateway
 */

// --- DFA Configuration ---
enum DFA_State { q0_NORMAL, q1_SYN_1, q2_SYN_2, q3_ALERT };
DFA_State currentState = q0_NORMAL;

// --- Hardware Pins ---
const int ALERT_LED = 2; // Internal LED on most ESP32 Dev Kits

// --- Forward Declarations ---
void triggerAlert();
void processPacket(bool isSYN, bool isACK, bool isRST);
String stateToShortName(DFA_State s);

/**
 * CALLBACK FUNCTION: wifi_promiscuous_cb
 * This function is called by the ESP32 hardware every time a WiFi packet is
 * heard in the air.
 */
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  static unsigned long totalFramesHeard = 0;
  totalFramesHeard++;

  // Periodic JSON heartbeat for dashboard health check
  if (totalFramesHeard % 100 == 0) {
    Serial.println("{\"h\":" + String(totalFramesHeard) + "}");
  }

  wifi_promiscuous_pkt_t *sniffer_packet = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload =
      sniffer_packet->rx_ctrl.sig_mode ? sniffer_packet->payload : NULL;

  if (!payload)
    return;

  // Most standard WiFi Data packets have the IP header around offset 32-34
  // We look for the IPv4 signature (0x45) to find the start of the IP packet
  int ipHeaderOffset = -1;
  for (int i = 0; i < 64; i++) {
    if (payload[i] == 0x45 && (payload[i + 9] == 0x06)) { // IPv4 + TCP Protocol
      ipHeaderOffset = i;
      break;
    }
  }

  if (ipHeaderOffset != -1) {
    uint8_t ipHeaderLen = (payload[ipHeaderOffset] & 0x0F) * 4;
    uint16_t tcpHeaderOffset = ipHeaderOffset + ipHeaderLen;
    uint8_t tcpFlags = payload[tcpHeaderOffset + 13];

    bool isSYN = (tcpFlags & 0x02);
    bool isACK = (tcpFlags & 0x10);
    bool isRST = (tcpFlags & 0x04);

    processPacket(isSYN, isACK, isRST);
  }
}

void triggerAlert() { digitalWrite(ALERT_LED, HIGH); }

void processPacket(bool isSYN, bool isACK, bool isRST) {
  static unsigned long totalPacketsAnalyzed = 0;
  static unsigned long totalSynsDetected = 0;

  if (isSYN && !isACK) {
    totalPacketsAnalyzed++;
    totalSynsDetected++;

    Serial.print("{\"p\":");
    Serial.print(totalPacketsAnalyzed);
    Serial.print(",\"s\":");
    Serial.print(totalSynsDetected);
    Serial.print(",\"st\":\"");

    if (currentState == q0_NORMAL)
      currentState = q1_SYN_1;
    else if (currentState == q1_SYN_1)
      currentState = q2_SYN_2;
    else if (currentState == q2_SYN_2) {
      currentState = q3_ALERT;
      triggerAlert();
    }
    Serial.println(stateToShortName(currentState) + "\"}");
  } else if (isACK || isRST) {
    if (currentState != q0_NORMAL) {
      currentState = q0_NORMAL;
      Serial.println("{\"p\":" + String(totalPacketsAnalyzed) +
                     ",\"s\":" + String(totalSynsDetected) + ",\"st\":\"q0\"}");
      digitalWrite(ALERT_LED, LOW);
    }
  }
}

String stateToShortName(DFA_State s) {
  if (s == q1_SYN_1)
    return "q1";
  if (s == q2_SYN_2)
    return "q2";
  if (s == q3_ALERT)
    return "q3";
  return "q0";
}

void setup() {
  Serial.begin(115200);
  pinMode(ALERT_LED, OUTPUT);
  digitalWrite(ALERT_LED, LOW);

  Serial.println("\n--- ESP32 DFA Network Pattern Sniffer ---");
  Serial.println("Starting in 3 seconds...");
  delay(3000);

  // Initialize WiFi for Promiscuous Mode
  WiFi.disconnect();
  esp_wifi_stop();
  esp_wifi_deinit();

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);

  Serial.println("[INFO] Radio Started. Listening for any traffic...");
}

void loop() {
  // 1. WiFi Channel Hopping
  static uint8_t channel = 1;
  static unsigned long lastHop = 0;
  if (millis() - lastHop > 2000) {
    lastHop = millis();
    channel = (channel % 13) + 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    Serial.println("{\"ch\":" + String(channel) + "}");
  }

  // 2. Demo Fail-Safe: Process Serial Commands
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd == "SYN")
      processPacket(true, false, false);
    else if (cmd == "ACK" || cmd == "RST")
      processPacket(false, true, false);
  }

  delay(10);
}
