#include "esp_wifi.h"
#include <WiFi.h>

// --- Hardware Settings ---
#define ALERT_LED 2 // Standard internal blue LED on ESP32 Dev Module

// --- DFA State Definitions ---
enum DFA_State {
  q0_NORMAL, // Start State / Normal State
  q1_SYN_1,  // Received first SYN
  q2_SYN_2,  // Received second consecutive SYN
  q3_ALERT   // Received third SYN - ALERT STATE!
};

// Global Variable to hold the current state of our machine
DFA_State currentState = q0_NORMAL;

// --- TCP Flag Definitions ---
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

// --- Promiscuous Callback Function ---
// This function is called by the ESP32 hardware every time a WiFi packet is
// heard in the air.
void wifi_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {

  // We only care about Data frames or Management frames that might contain IP
  // payload. For simplicity in this mini-project, we cast the raw buffer.
  wifi_promiscuous_pkt_t *sniffer_packet = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload =
      sniffer_packet->rx_ctrl.sig_mode ? sniffer_packet->payload : NULL;
  uint16_t length = sniffer_packet->rx_ctrl.sig_len;

  if (payload == NULL || length < 54) {
    return; // Packet is too short to contain a full TCP/IP header
  }

  // --- VERY BASIC TCP HEADER PARSING ---
  // Note: True parsing requires checking 802.11 header lengths (QoS vs
  // Non-QoS), LLC headers, etc. For demonstration, we assume a standard
  // unencrypted frame where IP payload starts around offset 32. We locate the
  // Protocol field in IPv4 (Offset 9 in IP header) Let's assume IP header
  // starts at payload[32].
  int ipHeaderOffset = 32;

  // Check if it's an IPv4 packet (Version == 4)
  if ((payload[ipHeaderOffset] >> 4) == 4) {
    uint8_t protocol =
        payload[ipHeaderOffset + 9]; // Protocol is 9th byte of IP head

    // Check if Protocol is TCP (TCP == 6)
    if (protocol == 6) {
      // Calculate IP header length (bottom 4 bits of the first byte * 4)
      uint8_t ipHeaderLen = (payload[ipHeaderOffset] & 0x0F) * 4;

      int tcpHeaderOffset = ipHeaderOffset + ipHeaderLen;

      if (tcpHeaderOffset + 13 < length) {
        // TCP Flags are located at the 13th byte of the TCP header
        uint8_t tcpFlags = payload[tcpHeaderOffset + 13];

        bool isSYN = (tcpFlags & TCP_SYN) != 0;
        bool isACK = (tcpFlags & TCP_ACK) != 0;
        bool isRST = (tcpFlags & TCP_RST) != 0;

        // --- Statistics Variables ---
        static unsigned long totalPacketsAnalyzed = 0;
        static unsigned long totalSynsDetected = 0;
        totalPacketsAnalyzed++;

        // --- DFA STATE TRANSITION LOGIC ---
        // This is the core 'Automata Theory' implementation.

        if (isSYN && !isACK) {
          totalSynsDetected++;
          Serial.print("{\"p\":");
          Serial.print(totalPacketsAnalyzed);
          Serial.print(",\"s\":");
          Serial.print(totalSynsDetected);
          Serial.print(",\"st\":\"");

          if (currentState == q0_NORMAL) {
            currentState = q1_SYN_1;
            Serial.print("q1");
          } else if (currentState == q1_SYN_1) {
            currentState = q2_SYN_2;
            Serial.print("q2");
          } else if (currentState == q2_SYN_2) {
            currentState = q3_ALERT;
            Serial.print("q3");
            triggerAlert();
          }
          Serial.println("\"}");
        } else if (isACK || isRST) {
          if (currentState != q0_NORMAL) {
            currentState = q0_NORMAL;
            Serial.print("{\"p\":");
            Serial.print(totalPacketsAnalyzed);
            Serial.print(",\"s\":");
            Serial.print(totalSynsDetected);
            Serial.println(",\"st\":\"q0\"}");
            digitalWrite(ALERT_LED, LOW);
          }
        }
      }
    }
  }
}

// --- Alert Function ---
void triggerAlert() {
  Serial.println("============================================");
  Serial.println("🚨 SUSPICIOUS PATTERN DETECTED! 🚨");
  Serial.println("🚨 POSSIBLE SYN FLOOD ATTACK! 🚨");
  Serial.println("============================================");

  // Turn on the LED to indicate danger
  digitalWrite(ALERT_LED, HIGH);

  // Remain in q3 (Alert State) until an ACK or RST resets it, or we could auto
  // reset. For this project, we wait for a reset flag to clear the alert.
}

void setup() {
  Serial.begin(115200);
  pinMode(ALERT_LED, OUTPUT);
  digitalWrite(ALERT_LED, LOW);

  Serial.println("\n--- ESP32 DFA Network Pattern Sniffer ---");
  Serial.println("Starting in 3 seconds...");
  delay(3000);

  // Initialize WiFi
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Set WiFi to Promiscuous Mode
  esp_wifi_set_promiscuous(true);

  // Register the callback function to receive packets
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous_cb);

  Serial.println("[INFO] Promiscuous Mode Enabled.");
  Serial.println("[INFO] DFA Initialized at State: q0 (Normal)");
  Serial.println("[INFO] Listening for WiFi Packets...");
}

void loop() {
  // The main loop is basically empty.
  // Everything happens asynchronously in the wifi_promiscuous_cb function!
  // This proves the efficiency of the DFA engine processing packets on the fly.

  delay(10); // Yield to watchdogs
}
