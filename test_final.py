import serial
import time
import subprocess

# 1. Start reading serial from COM9
ser = serial.Serial('COM9', 115200, timeout=1)
print("[TEST] Connected to COM9. Reading initial output...")

# Wait for init
time.sleep(4) 
for _ in range(5):
    print(f"> {ser.readline().decode('ascii', errors='replace').strip()}")

# 2. Run the Attack Script in the background
print("[TEST] Running SYN Flood Attack...")
subprocess.run(['python', 'c:/Users/abhin/Downloads/NET-DFA/esp32_dfa_sniffer/syn_flood_test.py'], capture_output=True)

# 3. Check for DFA transitions or Heard Frames
print("[TEST] Attack finished. Checking ESP32 logs for 5 seconds...")
start_time = time.time()
while time.time() - start_time < 5:
    line = ser.readline().decode('ascii', errors='replace').strip()
    if line:
        print(f"> {line}")

ser.close()
