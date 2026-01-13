# File: device_profiler.py
import socket
import json
import time
import os
import argparse

# Assume config.json is in the same directory as this script
base_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(base_dir, 'config.json')

try:
    with open(config_path, 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"❌ FATAL: config.json not found at {config_path}.")
    exit(1)

HOST = config['profile_listener_ip']
PORT = config['profile_listener_port']

# Simulate the profile of a device that just connected
# In a real scenario, this would be dynamically generated (e.g., from nmap)
device_profile = {
    "ip_address": "127.0.0.1", # This will be dynamically set by mqttlive
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os_guess": "Linux 4.x",
    "open_ports": [22, 1883]
}

# Allow IP to be passed as a command-line argument
parser = argparse.ArgumentParser(description="Device Profiler for AI Decision Server.")
parser.add_argument('--ip', type=str, required=True, help='IP address of the device to profile.')
parser.add_argument('--host-ip', type=str, required=True, help="IP address of the AI server to connect to.")
args = parser.parse_args()

# Overwrite HOST from config with the one from the command line
HOST = args.host_ip

if args.ip:
    device_profile["ip_address"] = args.ip
else:
    # This case is now handled by 'required=True' in argparse
    print("❌ Error: Device IP not provided. Use --ip argument.")
    exit(1)

print(f"--- Device Profiler: Sending device profile for {device_profile['ip_address']} to AI server at {HOST}:{PORT}...")

# Retry logic: Wait for AI server to be ready
max_retries = 10
retry_delay = 2  # seconds
for attempt in range(1, max_retries + 1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # 2 second timeout
            s.connect((HOST, PORT))
            s.sendall(json.dumps(device_profile).encode())
        print("✔️  Profile sent successfully.")
        break
    except ConnectionRefusedError:
        if attempt < max_retries:
            print(f"⏳ AI server not ready yet, retrying in {retry_delay} seconds... (attempt {attempt}/{max_retries})")
            time.sleep(retry_delay)
        else:
            print(f"❌ Connection refused after {max_retries} attempts. Is the AI Decision Server running and listening on {HOST}:{PORT}?")
    except socket.timeout:
        if attempt < max_retries:
            print(f"⏳ Connection timeout, retrying in {retry_delay} seconds... (attempt {attempt}/{max_retries})")
            time.sleep(retry_delay)
        else:
            print(f"❌ Connection timeout after {max_retries} attempts.")
    except Exception as e:
        print(f"❌ Error sending profile: {e}")
        break
