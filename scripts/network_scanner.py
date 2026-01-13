import socket
from concurrent.futures import ThreadPoolExecutor

# Scan a single IP to see if port 1883 (MQTT) is open
def scan_port(ip, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except:
        return False

# Actively scan a /24 subnet to find MQTT devices
def find_mqtt_clients(network_prefix='192.168.1.', port=1883):
    ip_range = [f"{network_prefix}{i}" for i in range(1, 255)]
    active_clients = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda ip: (ip, scan_port(ip, port)), ip_range)

    for ip, is_open in results:
        if is_open:
            active_clients.append(ip)

    return active_clients
