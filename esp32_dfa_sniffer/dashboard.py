import serial
import time
import re
import tkinter as tk
from tkinter import ttk

# --- Configuration ---
# CHANGE THIS TO YOUR ACTUAL ESP32 COM PORT (e.g., 'COM3' on Windows, '/dev/ttyUSB0' on Linux/Mac)
SERIAL_PORT = 'COM7' 
BAUD_RATE = 115200

class DFADashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("DFA Packet Sniffer Dashboard")
        self.root.geometry("600x400")
        self.root.configure(bg="#1e1e1e")

        # Define Colors
        self.bg_color = "#1e1e1e"
        self.text_color = "#ffffff"
        self.accent_color = "#00bfa5"
        self.alert_color = "#ff5252"

        # Initialize State Variables
        self.total_packets = 0
        self.total_syns = 0
        self.current_state = "q0 (NORMAL)"
        self.alert_status = "SAFE"

        self.setup_ui()
        self.init_serial()
        self.update_data()

    def setup_ui(self):
        # Header
        header = tk.Label(self.root, text="Network Packet Pattern Detector", font=("Helvetica", 18, "bold"), bg=self.bg_color, fg=self.accent_color)
        header.pack(pady=20)

        # Main Info Frame
        info_frame = tk.Frame(self.root, bg=self.bg_color)
        info_frame.pack(pady=10)

        # Statistics Labels
        self.lbl_packets = tk.Label(info_frame, text=f"Total Packets Analyzed: {self.total_packets}", font=("Helvetica", 14), bg=self.bg_color, fg=self.text_color)
        self.lbl_packets.grid(row=0, column=0, padx=20, pady=10, sticky="w")

        self.lbl_syns = tk.Label(info_frame, text=f"Total SYN Packets: {self.total_syns}", font=("Helvetica", 14), bg=self.bg_color, fg=self.text_color)
        self.lbl_syns.grid(row=1, column=0, padx=20, pady=10, sticky="w")

        # DFA State Labels
        self.lbl_state = tk.Label(info_frame, text=f"Current DFA State: {self.current_state}", font=("Helvetica", 14, "bold"), bg=self.bg_color, fg="#ffd54f")
        self.lbl_state.grid(row=0, column=1, padx=20, pady=10, sticky="w")

        # Alert Box
        self.lbl_alert = tk.Label(self.root, text=self.alert_status, font=("Helvetica", 24, "bold"), bg="#4caf50", fg="white", width=20, pady=10)
        self.lbl_alert.pack(pady=30)

        # Log Text Box
        self.log_text = tk.Text(self.root, height=8, width=70, bg="#2d2d2d", fg=self.text_color, font=("Consolas", 10))
        self.log_text.pack(pady=10)

    def init_serial(self):
        try:
            self.ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
            self.log_message(f"Connected to ESP32 on {SERIAL_PORT}")
        except Exception as e:
            self.log_message(f"Connection Error: {e}")
            self.log_message(f"Please update SERIAL_PORT = '{SERIAL_PORT}' in the script.")
            self.ser = None

    def log_message(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def update_data(self):
        if self.ser and self.ser.in_waiting > 0:
            try:
                line = self.ser.readline().decode('utf-8').strip()
                if line:
                    self.process_serial_line(line)
            except Exception as e:
                pass # Ignore decode errors

        # Schedule the next update
        self.root.after(50, self.update_data)

    def process_serial_line(self, line):
        # Update Log
        if "SNIFF" not in line and "DFA Transition" not in line:
             self.log_message(line)

        # Parse Statistics
        if "Total SYNs so far:" in line:
             # Example: [SNIFF] TCP SYN Captured! | Total SYNs so far: 5 | Total Packets: 120
             match = re.search(r"Total SYNs so far: (\d+) \| Total Packets: (\d+)", line)
             if match:
                 self.total_syns = int(match.group(1))
                 self.total_packets = int(match.group(2))
                 self.lbl_syns.config(text=f"Total SYN Packets: {self.total_syns}")
                 self.lbl_packets.config(text=f"Total Packets Analyzed: {self.total_packets}")

        # Parse DFA State
        if "[DFA Transition]" in line:
            if "q0 -> q1" in line:
                self.current_state = "q1 (1st SYN)"
            elif "q1 -> q2" in line:
                self.current_state = "q2 (2nd SYN)"
            elif "q2 -> q3" in line:
                self.current_state = "q3 (ALERT)"
            elif "Reset to q0" in line:
                self.current_state = "q0 (NORMAL)"
                self.lbl_alert.config(text="SAFE", bg="#4caf50") # Green

            self.lbl_state.config(text=f"Current DFA State: {self.current_state}")

        # Parse Alerts
        if "SUSPICIOUS PATTERN DETECTED" in line:
            self.lbl_alert.config(text="!!! SYN FLOOD ALERT !!!", bg=self.alert_color)

if __name__ == "__main__":
    root = tk.Tk()
    app = DFADashboard(root)
    root.mainloop()
