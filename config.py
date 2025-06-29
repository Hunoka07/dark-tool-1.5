import threading

# --- System Configuration ---
VERSION = "1.5"
EXPECTED_FILENAME = "dark_tool.py"
INTERFACE = "wlan0"  # wlan0 for most Android, eth0 for ethernet
DEFAULT_THREADS = 200

# --- Resource URLs ---
PROXY_URL = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
USER_AGENT_URL = "https://raw.githubusercontent.com/datasets/top-user-agents/main/user-agents.json"
# Backup proxy list
PROXY_URL_2 = "https://raw.githubusercontent.com/proxy4free/proxy-list/main/http.txt"


# --- Global State ---
attack_stats = {
    "l7_requests": 0, "l4_packets": 0, "errors": 0,
    "bytes_sent": 0, "start_time": 0,
    "threat_intelligence": "Awaiting target analysis...",
    "active_threads": 0
}
stop_event = threading.Event()

proxies = []
user_agents = []
