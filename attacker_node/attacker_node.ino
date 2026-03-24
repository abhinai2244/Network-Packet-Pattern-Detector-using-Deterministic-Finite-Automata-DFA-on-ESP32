/*
 * Project: Network Packet Pattern Detector - NRF24 Attacker Node
 * Description: Sends SYN packets over NRF24 to test DFA detection.
 */

#include <RF24.h>
#include <SPI.h>
#include <nRF24L01.h>


#define CE_PIN 9
#define CSN_PIN 10

RF24 radio(CE_PIN, CSN_PIN);
const byte address[6] = "00001";

struct Packet {
  char type[4]; // "SYN", "ACK", "RST"
};

void setup() {
  Serial.begin(9600);
  if (!radio.begin()) {
    Serial.println("NRF24 Hardware not found!");
    while (1)
      ;
  }
  radio.openWritingPipe(address);
  radio.setPALevel(RF24_PA_MIN);
  radio.stopListening();

  Serial.println("Attacker Node Ready. Press 'S' for SYN Burst.");
}

void loop() {
  if (Serial.available()) {
    char input = Serial.read();

    if (input == 's' || input == 'S') {
      sendPacket("SYN");
      delay(500);
      sendPacket("SYN");
      delay(500);
      sendPacket("SYN");
      Serial.println("SYN Flood Burst Sent!");
    } else if (input == 'a' || input == 'A') {
      sendPacket("ACK");
      Serial.println("ACK Sent (Connection Clear)");
    }
  }
}

void sendPacket(const char *type) {
  Packet p;
  strncpy(p.type, type, 4);
  radio.write(&p, sizeof(p));
}
