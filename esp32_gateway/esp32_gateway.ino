/*
 * Project: Network Packet Pattern Detector - ESP32 Gateway
 * Description: Receives NRF24L01 packets, runs DFA detection, and streams to WiFi Dashboard.
 */

#include <WiFi.h>
#include <SPI.h>
#include <nRF24L01.h>
#include <RF24.h>
#include <WebSocketsServer.h>

// --- Configuration ---
const char* ssid = "YOUR_WIFI_SSID";     // <--- CHANGE THIS
const char* password = "YOUR_WIFI_PASSWORD"; // <--- CHANGE THIS

#define CE_PIN   4
#define CSN_PIN  5
#define ALERT_LED 2

// --- DFA State Definitions ---
enum DFA_State { q0_NORMAL, q1_SYN_1, q2_SYN_2, q3_ALERT };
DFA_State currentState = q0_NORMAL;

// Statistics
unsigned long totalPackets = 0;
unsigned long totalSyns = 0;

// Hardware Objects
RF24 radio(CE_PIN, CSN_PIN);
WebSocketsServer webSocket = WebSocketsServer(81);
const byte address[6] = "00001";

// Packet Structure
struct Packet {
  char type[4]; // "SYN", "ACK", "RST"
};

void setup() {
  Serial.begin(115200);
  pinMode(ALERT_LED, OUTPUT);
  digitalWrite(ALERT_LED, LOW);

  // 1. Connect to WiFi
  Serial.print("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi Connected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());

  // 2. Start WebSocket Server
  webSocket.begin();
  webSocket.onEvent(webSocketEvent);

  // 3. Initialize NRF24
  if (!radio.begin()) {
    Serial.println("NRF24 Hardware not found!");
    while (1);
  }
  radio.openReadingPipe(0, address);
  radio.setPALevel(RF24_PA_MIN);
  radio.startListening();

  Serial.println("Gateway Ready. Listening for NRF24 packets...");
}

void loop() {
  webSocket.loop();

  if (radio.available()) {
    Packet incomingPacket;
    radio.read(&incomingPacket, sizeof(incomingPacket));
    totalPackets++;

    processDFA(incomingPacket.type);
    broadcastStatus();
  }
}

void processDFA(const char* type) {
  String flag = String(type);
  flag.trim();

  if (flag == "SYN") {
    totalSyns++;
    if (currentState == q0_NORMAL) currentState = q1_SYN_1;
    else if (currentState == q1_SYN_1) currentState = q2_SYN_2;
    else if (currentState == q2_SYN_2) currentState = q3_ALERT;
  } 
  else if (flag == "ACK" || flag == "RST") {
    currentState = q0_NORMAL;
    digitalWrite(ALERT_LED, LOW);
  }

  if (currentState == q3_ALERT) {
    digitalWrite(ALERT_LED, HIGH);
  }
}

void broadcastStatus() {
  String json = "{";
  json += "\"packets\":" + String(totalPackets) + ",";
  json += "\"syns\":" + String(totalSyns) + ",";
  json += "\"state\":\"" + String(stateToString(currentState)) + "\",";
  json += "\"alert\":" + String(currentState == q3_ALERT ? "true" : "false");
  json += "}";
  
  webSocket.broadcastTXT(json);
  Serial.println("Broadcast: " + json);
}

const char* stateToString(DFA_State s) {
  switch(s) {
    case q0_NORMAL: return "q0 (Normal)";
    case q1_SYN_1: return "q1 (1st SYN)";
    case q2_SYN_2: return "q2 (2nd SYN)";
    case q3_ALERT: return "q3 (ALERT)";
    default: return "Unknown";
  }
}

void webSocketEvent(uint8_t num, WStype_t type, uint8_t * payload, size_t length) {
  if (type == WStype_CONNECTED) {
    Serial.printf("[%u] Dashboard Connected\n", num);
    broadcastStatus(); // Send current state immediately
  }
}
