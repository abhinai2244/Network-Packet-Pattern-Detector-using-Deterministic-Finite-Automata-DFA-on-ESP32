import streamlit as st
import serial
import time
import re

# --- PAGE CONFIG ---
st.set_page_config(page_title="DFA Packet Sniffer", page_icon="🛡️", layout="wide")

# --- CUSTOM CSS FOR STYLING ---
st.markdown("""
    <style>
    .big-font {
        font-size:30px !important;
        font-weight: bold;
    }
    .stMetric {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 2px 2px 5px rgba(0,0,0,0.1);
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Packet Pattern Detector (DFA)")
st.markdown("Real-time intrusion detection monitoring dashboard powered by ESP32.")

# --- SIDEBAR CONFIGURATION ---
st.sidebar.header("⚙️ Connection Settings")
port = st.sidebar.text_input("ESP32 COM Port", value="COM7")
baud = st.sidebar.number_input("Baud Rate", value=115200, step=100)
connect_btn = st.sidebar.toggle("Connect to ESP32", value=False)

# --- LAYOUT PLACEHOLDERS ---
# Using placeholders allows us to update the UI continuously without refreshing the whole page.
col1, col2, col3 = st.columns(3)
metrics_packets = col1.empty()
metrics_syn = col2.empty()
metrics_state = col3.empty()

st.markdown("### System Alert Status")
alert_placeholder = st.empty()

st.markdown("### Raw Serial Logs")
log_placeholder = st.empty()

# --- STATE MANAGEMENT ---
if 'total_packets' not in st.session_state: st.session_state.total_packets = 0
if 'total_syns' not in st.session_state: st.session_state.total_syns = 0
if 'dfa_state' not in st.session_state: st.session_state.dfa_state = "q0 (NORMAL)"
if 'alert_status' not in st.session_state: st.session_state.alert_status = "SAFE"
if 'logs' not in st.session_state: st.session_state.logs = ["Waiting for data..."]

def update_ui():
    """Updates the Streamlit UI elements with the current session state."""
    metrics_packets.metric("Total Packets Analyzed", st.session_state.total_packets)
    metrics_syn.metric("Total SYN Packets Detected", st.session_state.total_syns)
    
    # Color-code the DFA state
    state_color = "green" if "q0" in st.session_state.dfa_state else "orange"
    if "q3" in st.session_state.dfa_state: state_color = "red"
    
    metrics_state.markdown(f"<div class='stMetric'><p>Current DFA State</p><p style='color:{state_color}; font-size: 24px; font-weight: bold;'>{st.session_state.dfa_state}</p></div>", unsafe_allow_html=True)
    
    # Update Alert Banner
    if st.session_state.alert_status == "SAFE":
        alert_placeholder.success("✅ SYSTEM SECURE - NO THREATS DETECTED")
    else:
        alert_placeholder.error("🚨 WARNING: SYN FLOOD ATTACK DETECTED! 🚨")
        
    # Update Logs
    log_text = "\n".join(st.session_state.logs[-15:]) # Keep last 15 lines
    log_placeholder.code(log_text, language="text")


# --- MAIN EVENT LOOP ---
if connect_btn:
    try:
        # Open serial connection
        ser = serial.Serial(port, baud, timeout=0.1)
        st.session_state.logs.append(f"✅ Connected to {port} at {baud} baud")
        update_ui()
        
        # Infinite reading loop while connected
        while connect_btn:
            if ser.in_waiting > 0:
                try:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        needs_ui_update = False
                        
                        # --- DATA PARSING ---
                        if "Total SYNs so far:" in line:
                            match = re.search(r"Total SYNs so far: (\d+) \| Total Packets: (\d+)", line)
                            if match:
                                st.session_state.total_syns = int(match.group(1))
                                st.session_state.total_packets = int(match.group(2))
                                needs_ui_update = True
                                
                        elif "[DFA Transition]" in line:
                            if "q0 -> q1" in line: st.session_state.dfa_state = "q1 (1st SYN)"
                            elif "q1 -> q2" in line: st.session_state.dfa_state = "q2 (2nd SYN)"
                            elif "q2 -> q3" in line: st.session_state.dfa_state = "q3 (ALERT)"
                            elif "Reset to q0" in line:
                                st.session_state.dfa_state = "q0 (NORMAL)"
                                st.session_state.alert_status = "SAFE"
                            needs_ui_update = True
                                
                        elif "SUSPICIOUS PATTERN DETECTED" in line:
                            st.session_state.alert_status = "ALERT"
                            needs_ui_update = True
                        
                        # Only log non-spammy lines to the visual console
                        if "SNIFF" not in line and "DFA Transition" not in line and "====" not in line:
                            if "🚨" not in line: # Prevent duplicate emojis in logs
                                st.session_state.logs.append(line)
                            needs_ui_update = True
                            
                        # Keep log buffer from growing too large
                        if len(st.session_state.logs) > 30:
                            st.session_state.logs.pop(0)

                        if needs_ui_update:
                            update_ui()
                            
                except Exception as parse_e:
                    pass # Ignore decoding glitches during live streaming

            # Small sleep to prevent CPU hogging while reading serial
            time.sleep(0.01) 
            
    except serial.SerialException as e:
        alert_placeholder.error(f"❌ Connection Error: Could not open {port}. Is the ESP32 plugged in and not open in Arduino IDE?")
    except Exception as e:
        alert_placeholder.error(f"❌ Unexpected Error: {e}")
        
else:
    # If not connected, just draw the UI once
    update_ui()
