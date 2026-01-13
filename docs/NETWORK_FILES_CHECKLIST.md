# Network Configuration Files Checklist

## ✅ All Network-Related Files Verified

### Configuration Files
- [x] **config/mosquitto_network.conf** - MQTT broker network configuration
- [x] **config/mqtt_final.lua** - MQTT rules and configuration
- [x] **config/enhanced_ai_inspector.lua** - AI inspector with socket IPC paths
- [x] **ml-models/config.json** - ML config with IPC socket path (/tmp/ai_socket.sock)

### Network Setup Scripts
- [x] **installer/setup_nfqueue_rules.sh** - NFQueue/iptables setup for inline mode

### Scripts Using Sockets/Network
- [x] **scripts/snort_mqtt_enhanced.py** - Uses Unix socket (/tmp/ai_socket.sock)
- [x] **scripts/network_scanner.py** - Network scanning with sockets
- [x] **scripts/system_monitor.py** - System monitoring with socket support

### Socket Paths Configured
- **IPC Socket**: /tmp/ai_socket.sock (configured in config.json and enhanced_ai_inspector.lua)
- **MQTT Broker**: 127.0.0.1:1883 (default, configurable via mosquitto_network.conf)
- **Profile Listener**: 127.0.0.1:9998 (configured in config.json)

### Network Interfaces
- Ethernet interfaces only (eth*, en*, ens*, enp*, eno*)
- Inline mode requires cable Ethernet (configured in snort_mqtt_enhanced.py)

## Verification
All network configuration files, socket paths, and network-related scripts have been copied to the migration package.
