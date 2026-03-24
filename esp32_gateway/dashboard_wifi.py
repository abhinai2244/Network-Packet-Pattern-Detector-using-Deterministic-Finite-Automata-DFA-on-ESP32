import streamlit as st
import websocket
import json
import threading
import time

# --- PAGE CONFIG ---
st.set_page_config(page_title="WiFi DFA Dashboard", page_icon="🌐", layout="wide")

st.markdown("""
    <style>
    .metric-card {
        background-color: #262730;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #464855;
    }
    .status-safe { color: #00ff00; font-weight: bold; }
    .status-alert { color: #ff0000; font-weight: bold; }
    </style>
""", unsafe_allow_html=True)

st.title("🌐 Multi-Protocol DFA Gateway Dashboard")

# --- SIDEBAR ---
st.sidebar.header("📡 Gateway Settings")
esp_ip = st.sidebar.text_input("ESP32 IP Address", value="192.168.1.100")
connect_btn = st.sidebar.button("Connect Dashboard")

# --- SESSION STATE ---
if 'ws_data' not in st.session_state:
    st.session_state.ws_data = {"packets": 0, "syns": 0, "state": "Unknown", "alert": False}

# --- LAYOUT ---
col1, col2, col3 = st.columns(3)
m_packets = col1.empty()
m_syns = col2.empty()
m_state = col3.empty()

m_alert = st.empty()

# --- WEBSOCKET HANDLER ---
def on_message(ws, message):
    data = json.loads(message)
    st.session_state.ws_data = data
    # Trigger a refresh (Streamlit trick)
    st.rerun()

def run_ws(ip):
    ws_url = f"ws://{ip}:81"
    ws = websocket.WebSocketApp(ws_url, on_message=on_message)
    ws.run_forever()

if connect_btn:
    st.sidebar.success(f"Attempting to connect to {esp_ip}...")
    thread = threading.Thread(target=run_ws, args=(esp_ip,), daemon=True)
    thread.start()

# --- UPDATE UI ---
data = st.session_state.ws_data
m_packets.metric("Packets Received (NRF24)", data['packets'])
m_syns.metric("SYN Flags Detected", data['syns'])

state_style = "status-alert" if data['alert'] else "status-safe"
m_state.markdown(f"### DFA State: <span class='{state_style}'>{data['state']}</span>", unsafe_allow_html=True)

if data['alert']:
    m_alert.error("🚨 ATTACK DETECTED: SYN FLOOD IDENTIFIED OVER NRF24! 🚨")
else:
    m_alert.success("✅ SYSTEM SECURE - MONITORING NRF24 TRAFFIC")

st.info("Note: The ESP32 Gateway receives packets via NRF24, processes the DFA, and streams this data via WiFi to your laptop.")
