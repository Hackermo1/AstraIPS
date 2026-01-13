#!/bin/bash

# Snort Live Capture Function
# Automatically detects network interface and provides flexible options

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use PROJECT_DIR environment variable or detect from script location
# MUST set this FIRST before any checks
if [ -z "$PROJECT_DIR" ]; then
    PROJECT_DIR="$SCRIPT_DIR"
fi
export PROJECT_DIR

# Find Snort binary - check system install first, then local build
SNORT_BIN=$(which snort 2>/dev/null || echo "")
if [ -z "$SNORT_BIN" ]; then
    for path in /usr/local/bin/snort /usr/bin/snort "$PROJECT_DIR/snort-install/bin/snort"; do
        if [ -x "$path" ]; then
            SNORT_BIN="$path"
            break
        fi
    done
fi

CONFIG_DIR="$PROJECT_DIR/config"
CONFIG_FILE="$CONFIG_DIR/snort.lua"

# Export LD_LIBRARY_PATH to ensure Snort finds its libraries (for local builds)
if [ -d "$PROJECT_DIR/snort-install/lib" ]; then
    export LD_LIBRARY_PATH="$PROJECT_DIR/snort-install/lib:$LD_LIBRARY_PATH"
fi
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"

# Function to detect the active network interface
detect_interface() {
    local interface=""
    local interfaces=()
    
    # Get all available interfaces with their status
    while IFS= read -r line; do
        local iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        local status=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
        
        # Skip loopback
        if [ "$iface" != "lo" ] && [ -n "$iface" ]; then
            interfaces+=("$iface:$status")
        fi
    done < <(ip link show | grep -E "^[0-9]+:" | grep -v "lo:")
    
    # Prioritize interfaces by type and status
    # 1. Wireless interfaces that are UP
    for iface_info in "${interfaces[@]}"; do
        local iface=$(echo "$iface_info" | cut -d: -f1)
        local status=$(echo "$iface_info" | cut -d: -f2)
        
        if [[ "$iface" =~ ^(wlan|wlp|wifi|wl) ]] && [ "$status" = "UP" ]; then
            interface="$iface"
            break
        fi
    done
    
    # 2. Ethernet interfaces that are UP
    if [ -z "$interface" ]; then
        for iface_info in "${interfaces[@]}"; do
            local iface=$(echo "$iface_info" | cut -d: -f1)
            local status=$(echo "$iface_info" | cut -d: -f2)
            
            if [[ "$iface" =~ ^(eth|enp|ens|en) ]] && [ "$status" = "UP" ]; then
                interface="$iface"
                break
            fi
        done
    fi
    
    # 3. Any interface that is UP
    if [ -z "$interface" ]; then
        for iface_info in "${interfaces[@]}"; do
            local iface=$(echo "$iface_info" | cut -d: -f1)
            local status=$(echo "$iface_info" | cut -d: -f2)
            
            if [ "$status" = "UP" ]; then
                interface="$iface"
                break
            fi
        done
    fi
    
    # 4. Any available interface (even if DOWN)
    if [ -z "$interface" ]; then
        for iface_info in "${interfaces[@]}"; do
            local iface=$(echo "$iface_info" | cut -d: -f1)
            interface="$iface"
            break
        done
    fi
    
    # 5. Fallback to any
    if [ -z "$interface" ]; then
        interface="any"
    fi
    
    echo "$interface"
}

# Function to show available interfaces
show_interfaces() {
    echo "📡 Available network interfaces:"
    echo ""
    
    local interfaces=()
    local up_interfaces=()
    local down_interfaces=()
    
    # Get all interfaces with their status
    while IFS= read -r line; do
        local iface=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        local status=$(ip link show "$iface" 2>/dev/null | grep -o "state [A-Z]*" | cut -d' ' -f2)
        local mtu=$(ip link show "$iface" 2>/dev/null | grep -o "mtu [0-9]*" | cut -d' ' -f2)
        local mac=$(ip link show "$iface" 2>/dev/null | grep -o "link/ether [a-f0-9:]*" | cut -d' ' -f2)
        local ip_addr=$(ip addr show "$iface" 2>/dev/null | grep -o "inet [0-9.]*/[0-9]*" | cut -d' ' -f2 | head -1)
        
        if [ -n "$iface" ] && [ "$iface" != "lo" ]; then
            local interface_info="$iface:$status:$mtu:$mac:$ip_addr"
            interfaces+=("$interface_info")
            
            if [ "$status" = "UP" ]; then
                up_interfaces+=("$interface_info")
            else
                down_interfaces+=("$interface_info")
            fi
        fi
    done < <(ip link show | grep -E "^[0-9]+:")
    
    # Show UP interfaces first
    if [ ${#up_interfaces[@]} -gt 0 ]; then
        echo "🟢 Active Interfaces:"
        for iface_info in "${up_interfaces[@]}"; do
            local iface=$(echo "$iface_info" | cut -d: -f1)
            local status=$(echo "$iface_info" | cut -d: -f2)
            local mtu=$(echo "$iface_info" | cut -d: -f3)
            local mac=$(echo "$iface_info" | cut -d: -f4)
            local ip_addr=$(echo "$iface_info" | cut -d: -f5)
            
            echo "  ✅ $iface"
            echo "     Status: $status | MTU: $mtu"
            if [ -n "$mac" ]; then
                echo "     MAC: $mac"
            fi
            if [ -n "$ip_addr" ]; then
                echo "     IP: $ip_addr"
            fi
            echo ""
        done
    fi
    
    # Show DOWN interfaces
    if [ ${#down_interfaces[@]} -gt 0 ]; then
        echo "🔴 Inactive Interfaces:"
        for iface_info in "${down_interfaces[@]}"; do
            local iface=$(echo "$iface_info" | cut -d: -f1)
            local status=$(echo "$iface_info" | cut -d: -f2)
            local mtu=$(echo "$iface_info" | cut -d: -f3)
            
            echo "  ❌ $iface ($status, MTU: $mtu)"
        done
        echo ""
    fi
    
    # Show detected interface
    local detected=$(detect_interface)
    echo "🎯 Auto-detected interface: $detected"
    echo ""
    echo "💡 Usage examples:"
    echo "   snortlive                    # Use auto-detected interface ($detected)"
    echo "   snortlive -i $detected       # Explicitly use $detected"
    echo "   snortlive -i any             # Monitor all interfaces"
}

# Main snortlive function
snortlive() {
    # Default options
    local interface=""
    local alert_mode="alert_fast"
    local log_dir="./logs"
    local packet_count=""
    local filter=""
    local output_format=""
    local verbose=false
    local show_help=false
    local config_file="$CONFIG_FILE"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                interface="$2"
                shift 2
                ;;
            -c|--config)
                config_file="$2"
                shift 2
                ;;
            -A|--alert-mode)
                alert_mode="$2"
                shift 2
                ;;
            -l|--log-dir)
                log_dir="$2"
                shift 2
                ;;
            -n|--count)
                packet_count="$2"
                shift 2
                ;;
            -f|--filter)
                filter="$2"
                shift 2
                ;;
            -L|--output-format)
                output_format="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -d|--dump)
                output_format="dump"
                shift
                ;;
            -p|--pcap)
                output_format="pcap"
                shift
                ;;
            --mqtt)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                shift
                ;;
            --mqtt-lo)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                interface="lo"
                shift
                ;;
            --mqtt-full)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                shift
                ;;
            --mqtt-full-lo)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                interface="lo"
                shift
                ;;
            --mqtt-config)
                config_file="$2"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                shift 2
                ;;
            --mqtt-config-lo)
                config_file="$2"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                interface="lo"
                shift 2
                ;;
            --mqtt-interface)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                interface="$2"
                shift 2
                ;;
            --mqtt-full-interface)
                config_file="$CONFIG_DIR/mqtt_final.lua"
                # BPF filter removed - causes hang on wireless interfaces
                # Snort rules already filter for MQTT ports (1883/8883)
                filter=""
                interface="$2"
                shift 2
                ;;
            --list-interfaces)
                show_interfaces
                return 0
                ;;
            -h|--help)
                show_help=true
                shift
                ;;
            *)
                echo "❌ Unknown option: $1"
                echo "Use -h or --help for usage information"
                return 1
                ;;
        esac
    done
    
    # Show help if requested
    if [ "$show_help" = true ]; then
        echo "🚀 Snort Live Capture Function"
        echo "   Advanced network packet capture and analysis tool"
        echo ""
        echo "Usage: snortlive [OPTIONS]"
        echo ""
        echo "📡 Interface Options:"
        echo "  -i, --interface INTERFACE    Network interface to monitor"
        echo "                              (auto-detected if not specified)"
        echo "  --list-interfaces           Show all available network interfaces"
        echo ""
        echo "⚙️  Configuration Options:"
        echo "  -c, --config FILE           Custom configuration file (default: config/snort.lua)"
        echo ""
        echo "🔌 MQTT Options:"
        echo "  --mqtt                      Use MQTT unified configuration (auto-detect interface)"
        echo "  --mqtt-lo                   Use MQTT unified configuration on loopback (lo) interface"
        echo "  --mqtt-full                 Use MQTT full configuration (auto-detect interface)"
        echo "  --mqtt-full-lo              Use MQTT full configuration on loopback (lo) interface"
        echo "  --mqtt-interface IFACE      Use MQTT unified configuration on specified interface"
        echo "  --mqtt-full-interface IFACE Use MQTT full configuration on specified interface"
        echo "  --mqtt-config FILE          Use custom MQTT configuration file (auto-detect interface)"
        echo "  --mqtt-config-lo FILE       Use custom MQTT configuration file on loopback (lo) interface"
        echo ""
        echo "📊 Capture Options:"
        echo "  -n, --count NUM             Number of packets to capture (default: unlimited)"
        echo "  -f, --filter FILTER         BPF filter expression for packet filtering"
        echo "  -t, --timeout SECONDS       Capture timeout in seconds"
        echo ""
        echo "📄 Output Options:"
        echo "  -L, --output-format FORMAT  Output format: dump, pcap, csv, json, unified2"
        echo "  -d, --dump                  Dump packets to console (same as -L dump)"
        echo "  -p, --pcap                  Capture to pcap file (same as -L pcap)"
        echo "  -l, --log-dir DIR           Log directory (default: ./logs)"
        echo "  -o, --output FILE           Output file name"
        echo ""
        echo "🚨 Alert Options:"
        echo "  -A, --alert-mode MODE       Alert mode: alert_fast, alert_full, alert_syslog, none"
        echo "  -s, --snaplen LEN           Packet snap length (default: 1514)"
        echo "  -k, --checksum-mode MODE    Checksum mode: none, all, noip, notcp, noudp, noicmp"
        echo ""
        echo "🔧 Advanced Options:"
        echo "  -v, --verbose               Verbose output"
        echo "  -q, --quiet                 Quiet mode (minimal output)"
        echo "  -D, --daemon                Run as daemon"
        echo "  -P, --pidfile FILE          PID file for daemon mode"
        echo "  -T, --test-mode             Test mode (validate config and exit)"
        echo "  -V, --version               Show version information"
        echo ""
        echo "📋 Filter Examples:"
        echo "  'tcp port 80'               HTTP traffic"
        echo "  'tcp port 443'              HTTPS traffic"
        echo "  'udp port 53'               DNS queries"
        echo "  'host 192.168.1.1'          Traffic to/from specific IP"
        echo "  'net 192.168.1.0/24'        Traffic to/from subnet"
        echo "  'tcp and port 22'           SSH traffic"
        echo "  'icmp'                      ICMP packets"
        echo "  'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0'  TCP flags"
        echo ""
        echo "🎯 Quick Examples:"
        echo "  snortlive                                    # Auto-detect interface, basic monitoring"
        echo "  snortlive -i wlp3s0                         # Monitor specific interface"
        echo "  snortlive -n 100 -d                         # Capture 100 packets and dump to console"
        echo "  snortlive -f 'tcp port 80' -p               # Capture HTTP traffic to pcap"
        echo "  snortlive -A alert_full -v                  # Full alerts with verbose output"
        echo "  snortlive --list-interfaces                 # Show available interfaces"
        echo "  snortlive -f 'host 8.8.8.8' -n 50 -d        # Capture 50 packets to/from Google DNS"
        echo "  snortlive -f 'tcp port 443' -p -n 1000      # Capture 1000 HTTPS packets to pcap"
        echo ""
        echo "🔌 MQTT Examples:"
        echo "  snortlive --mqtt                            # Monitor MQTT traffic with unified config (auto-detect)"
        echo "  snortlive --mqtt-lo                         # Monitor MQTT on loopback interface (localhost)"
        echo "  snortlive --mqtt-interface eth0             # Monitor MQTT on eth0 interface"
        echo "  snortlive --mqtt-interface wlan0            # Monitor MQTT on wlan0 interface"
        echo "  snortlive --mqtt-full-interface any         # Monitor MQTT on any interface with full config"
        echo "  snortlive --mqtt-full -i wlp3s0             # Monitor MQTT with full config on wlp3s0"
        echo "  snortlive --mqtt-full-lo                    # Monitor MQTT with full config on loopback"
        echo "  snortlive --mqtt-config custom.lua          # Use custom MQTT configuration (auto-detect)"
        echo "  snortlive --mqtt-config-lo custom.lua       # Use custom MQTT config on loopback"
        echo "  snortlive --mqtt -n 100 -d                  # Capture 100 MQTT packets and dump to console"
        echo "  snortlive --mqtt-lo -n 50 -d                # Capture 50 MQTT packets on loopback and dump"
        echo "  snortlive --mqtt-interface eth0 -n 50 -d    # Capture 50 MQTT packets on eth0 and dump"
        echo "  snortlive --mqtt-full -f 'tcp port 1883'    # Monitor MQTT on port 1883 only"
        echo ""
        echo "🧪 Quick Test Commands:"
        echo "  # Test with loopback (no external traffic needed):"
        echo "  snortlive --mqtt-lo -n 10 -d                # MQTT on loopback, 10 packets, dump to console"
        echo "  snortlive -i lo -n 10 -d                    # Basic monitoring on loopback"
        echo ""
        echo "  # Generate test traffic (run in another terminal):"
        echo "  ping 127.0.0.1                             # Generate ICMP traffic"
        echo "  curl http://127.0.0.1                      # Generate HTTP traffic"
        echo "  mosquitto_pub -h localhost -t test -m hello # Generate MQTT traffic"
        echo ""
        echo "🔍 Current System Info:"
        local detected=$(detect_interface)
        echo "  Auto-detected interface: $detected"
        echo "  Available interfaces: $(ip link show | grep -E "^[0-9]+:" | grep -v "lo" | wc -l) (use --list-interfaces to see details)"
        return 0
    fi
    
    # Check if Snort binary exists
    if [ ! -f "$SNORT_BIN" ]; then
        echo "❌ Error: Snort binary not found at $SNORT_BIN"
        echo "   Please run ./build_snort.sh first to build Snort 3"
        return 1
    fi
    
    # Check if config file exists
    if [ ! -f "$config_file" ]; then
        echo "❌ Error: Configuration file not found at $config_file"
        return 1
    fi
    
    # Auto-detect interface if not specified
    if [ -z "$interface" ]; then
        # If no arguments provided, show interfaces and let user choose
        if [ $# -eq 0 ]; then
            show_interfaces
            echo ""
            echo "🎯 Quick Start Options:"
            echo ""
            echo "📡 Interface Selection:"
            echo "  snortlive -i lo -n 10 -d                    # Test on loopback (localhost)"
            echo "  snortlive -i $(detect_interface) -n 10 -d   # Test on detected interface ($(detect_interface))"
            echo "  snortlive -i any -n 10 -d                   # Test on all interfaces"
            echo ""
        echo "🔌 MQTT Testing:"
        echo "  snortlive --mqtt-lo -n 10 -d                # MQTT test on loopback"
        echo "  snortlive --mqtt -n 10 -d                   # MQTT test on detected interface"
        echo "  snortlive --mqtt-interface eth0 -n 10 -d    # MQTT test on eth0 interface"
        echo "  snortlive --mqtt-interface wlan0 -n 10 -d   # MQTT test on wlan0 interface"
            echo ""
            echo "🌐 Live Monitoring:"
            echo "  snortlive -i $(detect_interface)            # Live monitoring on detected interface"
            echo "  snortlive --mqtt-lo                         # Live MQTT monitoring on loopback"
            echo "  snortlive --mqtt-interface eth0             # Live MQTT monitoring on eth0"
            echo "  snortlive --mqtt-interface wlan0            # Live MQTT monitoring on wlan0"
            echo ""
            echo "📋 Other Options:"
            echo "  snortlive --list-interfaces                 # Show detailed interface info"
            echo "  snortlive --help                           # Show full help"
            echo ""
            echo "💡 Tip: Generate traffic in another terminal to see alerts!"
            echo "     ping 127.0.0.1                          # ICMP traffic"
            echo "     curl http://127.0.0.1                   # HTTP traffic"
            echo "     mosquitto_pub -h localhost -t test -m hello  # MQTT traffic"
            echo ""
            return 0
        fi
        interface=$(detect_interface)
    fi
    
    # Create log directory if it doesn't exist (with proper permissions)
    mkdir -p "$log_dir"
    # Ensure directory is writable (Snort needs to create alert files)
    chmod 755 "$log_dir" 2>/dev/null || sudo chmod 755 "$log_dir" 2>/dev/null
    
    # Fix wireless interface issues (GRO/LRO offloading causes Snort to hang)
    if [ "$interface" != "lo" ] && [ -n "$interface" ]; then
        echo "🔧 Configuring interface $interface for packet capture..."
        # Enable promiscuous mode (required for packet capture)
        sudo ip link set "$interface" promisc on 2>/dev/null && echo "   ✅ Promiscuous mode enabled" || echo "   ⚠️  Could not enable promiscuous mode"
        
        # Disable hardware offloading (GRO/LRO cause Snort to hang on wireless interfaces)
        if command -v ethtool >/dev/null 2>&1; then
            sudo ethtool -K "$interface" gro off lro off 2>/dev/null && echo "   ✅ Hardware offloading disabled (GRO/LRO)" || echo "   ⚠️  Could not disable offloading (ethtool may not support this interface)"
        else
            echo "   ⚠️  ethtool not found - install with: sudo apt install ethtool"
        fi
    fi
    
    # Display information
    echo "🚀 Starting Snort Live Capture..."
    echo "📡 Interface: $interface"
    echo "📊 Alert Mode: $alert_mode"
    echo "📁 Log Directory: $log_dir"
    echo "⚙️  Config: $config_file"
    if [ -n "$packet_count" ]; then
        echo "📦 Packet Count: $packet_count"
    fi
    if [ -n "$filter" ]; then
        echo "🔍 Filter: $filter"
    fi
    if [ -n "$output_format" ]; then
        echo "📄 Output Format: $output_format"
    fi
    echo ""
    
    # Ensure PROJECT_DIR is set (should already be set at top of script, but double-check)
    if [ -z "$PROJECT_DIR" ]; then
        PROJECT_DIR="$SCRIPT_DIR"
        export PROJECT_DIR
    fi
    export CONFIG_DIR="${CONFIG_DIR:-$PROJECT_DIR/config}"
    
    # Build Snort command - Auto-detect IDS vs IPS based on interface
    # Use pcap DAQ for IDS mode (passive monitoring) - afpacket is for IPS mode (inline)
    # Use unbuffered output to prevent log truncation
    
    local daq_type="pcap"  # Default: IDS mode
    local snort_mode="IDS"  # Default: passive monitoring
    
    # DEBUG: Log detection process
    echo "🐛 DEBUG: Interface=$interface, PROJECT_DIR=$PROJECT_DIR" >&2
    echo "🐛 DEBUG: Checking afpacket at: $PROJECT_DIR/snort-install/lib/daq/daq_afpacket.so" >&2
    
    # Auto-detect mode based on interface type
    if [ "$interface" = "lo" ] || [ "$interface" = "any" ]; then
        # Loopback or any = IDS mode (passive, can't block)
        daq_type="pcap"
        snort_mode="IDS"
        echo "🛡️  Interface: $interface → IDS Mode (passive monitoring - no blocking)" >&2
    else
        # Physical interface (eth0, wlan0, etc.) = IPS mode (inline, can block)
        # Check if afpacket DAQ exists (it's daq_afpacket.so, not libdaq_afpacket.so)
        afpacket_path1="$PROJECT_DIR/snort-install/lib/daq/daq_afpacket.so"
        afpacket_path2="$PROJECT_DIR/snort-install/lib/daq/libdaq_afpacket.so"
        afpacket_path3="/usr/local/lib/daq/daq_afpacket.so"
        
        if [ -f "$afpacket_path1" ]; then
            echo "🐛 DEBUG: Found afpacket at: $afpacket_path1" >&2
            daq_type="afpacket"
            snort_mode="IPS"
            echo "🛡️  Interface: $interface → IPS Mode (inline monitoring - can block/drop packets)" >&2
            echo "   ⚠️  IPS mode requires interface to be in promiscuous mode" >&2
        elif [ -f "$afpacket_path2" ]; then
            echo "🐛 DEBUG: Found afpacket at: $afpacket_path2" >&2
            daq_type="afpacket"
            snort_mode="IPS"
            echo "🛡️  Interface: $interface → IPS Mode (inline monitoring - can block/drop packets)" >&2
            echo "   ⚠️  IPS mode requires interface to be in promiscuous mode" >&2
        elif [ -f "$afpacket_path3" ]; then
            echo "🐛 DEBUG: Found afpacket at: $afpacket_path3" >&2
            daq_type="afpacket"
            snort_mode="IPS"
            echo "🛡️  Interface: $interface → IPS Mode (inline monitoring - can block/drop packets)" >&2
            echo "   ⚠️  IPS mode requires interface to be in promiscuous mode" >&2
        else
            # Fallback: physical interface but afpacket not available = IDS mode
            echo "🐛 DEBUG: afpacket NOT FOUND at any path!" >&2
            echo "🐛 DEBUG: Checked: $afpacket_path1" >&2
            echo "🐛 DEBUG: Checked: $afpacket_path2" >&2
            echo "🐛 DEBUG: Checked: $afpacket_path3" >&2
            daq_type="pcap"
            snort_mode="IDS"
            echo "🛡️  Interface: $interface → IDS Mode (afpacket DAQ not found, using passive mode)" >&2
            echo "   💡 To enable IPS: Install afpacket DAQ or use loopback for IDS mode" >&2
        fi
    fi
    
    echo "🛡️  Snort Mode: $snort_mode (DAQ: $daq_type)" >&2  # Output to stderr so it shows in mqttlive output
    echo "🐛 DEBUG: Final daq_type=$daq_type, snort_mode=$snort_mode" >&2
    
    # For true inline IPS on single interface, use NFQUEUE (works with iptables)
    # For afpacket inline mode, interface must be specified as a pair (eth0:eth0 for single interface)
    # For pcap passive mode, use single interface (eth0)
    
    # For IPS mode, prefer NFQUEUE if SNORT_DAQ_MODE=inline is set, otherwise use afpacket
    if [ "$daq_type" = "afpacket" ] && [ "$snort_mode" = "IPS" ]; then
        # Check if SNORT_DAQ_MODE is explicitly set to inline
        if [ "$SNORT_DAQ_MODE" = "inline" ]; then
            # Check if nfq DAQ exists
            if [ -f "$PROJECT_DIR/snort-install/lib/daq/daq_nfq.so" ] || [ -f "/usr/local/lib/daq/daq_nfq.so" ]; then
                # Use NFQUEUE for true inline IPS on single interface
                daq_type="nfq"
                daq_interface=""  # NFQUEUE doesn't use -i option
                echo "🐛 DEBUG: SNORT_DAQ_MODE=inline detected, using NFQUEUE DAQ for inline IPS" >&2
                echo "✅ NFQUEUE inline mode: Packets will be BLOCKED" >&2
                echo "⚠️  IMPORTANT: Ensure iptables NFQUEUE rules are set:" >&2
                echo "   sudo iptables -I FORWARD -j NFQUEUE --queue-num 0" >&2
                echo "   sudo iptables -I INPUT -j NFQUEUE --queue-num 0" >&2
                echo "   sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0" >&2
            else
                # NFQUEUE not available, use afpacket with interface pair
                daq_interface="$interface:$interface"
                echo "🐛 DEBUG: NFQUEUE not available, using afpacket interface pair: $daq_interface" >&2
                echo "⚠️  Note: afpacket inline mode requires interface pair" >&2
            fi
        else
            # SNORT_DAQ_MODE not set to inline, use afpacket (may be passive)
            daq_interface="$interface:$interface"
            echo "🐛 DEBUG: SNORT_DAQ_MODE not set to 'inline', using afpacket" >&2
            echo "⚠️  To enable true inline blocking, set: export SNORT_DAQ_MODE=inline" >&2
            echo "⚠️  Current SNORT_DAQ_MODE: ${SNORT_DAQ_MODE:-not set}" >&2
        fi
    else
        # Passive mode: use single interface
        daq_interface="$interface"
        echo "🐛 DEBUG: IDS passive mode - using single interface: $daq_interface" >&2
    fi
    
    # Build Snort command
    if [ "$daq_type" = "nfq" ]; then
        # NFQUEUE uses --daq nfq without -i option (it gets packets from iptables)
        # CRITICAL: For true inline blocking, must add these DAQ variables:
        #   -Q flag → REQUIRED for inline mode (tells Snort to operate inline)
        #   --daq-mode inline  → REQUIRED for inline blocking (not passive!)
        #   --daq-var fail_open=no  → Do NOT let bad packets pass on error (prevents bypass on queue full)
        # Export SNORT_DAQ_MODE so Lua config knows we're in inline mode
        local snort_cmd="stdbuf -oL -eL sudo env PROJECT_DIR=\"$PROJECT_DIR\" CONFIG_DIR=\"$CONFIG_DIR\" SNORT_DAQ_MODE=\"inline\" $SNORT_BIN -c \"$config_file\" -A $alert_mode -k none -l \"$log_dir\" -v -Q --daq nfq --daq-mode inline --daq-var queue=0 --daq-var fail_open=no"
        echo "🐛 DEBUG: NFQUEUE command: -Q flag added for inline mode" >&2
        echo "🐛 DEBUG: NFQUEUE command: -Q --daq nfq --daq-mode inline --daq-var queue=0 --daq-var fail_open=no" >&2
        echo "✅ Real inline IPS mode: malicious packets will be DROPPED" >&2
        echo "⚠️  CRITICAL: If log shows 'passive', Snort is NOT blocking!" >&2
    elif [ "$daq_type" = "afpacket" ] && [ "$snort_mode" = "IPS" ]; then
        # Afpacket inline mode - export SNORT_DAQ_MODE
        local snort_cmd="stdbuf -oL -eL sudo env PROJECT_DIR=\"$PROJECT_DIR\" CONFIG_DIR=\"$CONFIG_DIR\" SNORT_DAQ_MODE=\"inline\" $SNORT_BIN -c \"$config_file\" -i $daq_interface -A $alert_mode -k none -l \"$log_dir\" -v --daq $daq_type"
    else
        # IDS mode (passive) - no SNORT_DAQ_MODE export
        local snort_cmd="stdbuf -oL -eL sudo env PROJECT_DIR=\"$PROJECT_DIR\" CONFIG_DIR=\"$CONFIG_DIR\" $SNORT_BIN -c \"$config_file\" -i $daq_interface -A $alert_mode -k none -l \"$log_dir\" -v --daq $daq_type"
    fi
    echo "🐛 DEBUG: Snort command will use: --daq $daq_type $([ "$daq_type" != "nfq" ] && echo "-i $daq_interface" || echo "--daq-mode inline")" >&2
    
    # Handle PCAP output specifically
    if [ "$output_format" = "pcap" ]; then
        # If log_dir ends with /alerts, we want pcaps in ../pcap
        if [[ "$log_dir" == *"/alerts" ]]; then
            PCAP_DIR="$(dirname "$log_dir")/pcap"
        else
            PCAP_DIR="$log_dir/pcap"
        fi
        
        mkdir -p "$PCAP_DIR"
        chmod 777 "$PCAP_DIR" 2>/dev/null || sudo chmod 777 "$PCAP_DIR" 2>/dev/null
        
        # Add pcap logging option to Snort command
        # Use log_pcap inspector in config file instead of command line option
        # PCAP_DIR is set for reference, but pcap logging is handled by config file
        echo "📦 PCAP directory: $PCAP_DIR (configured in Lua config)"
    fi
    
    # Add packet count if specified
    if [ -n "$packet_count" ]; then
        snort_cmd="$snort_cmd -n $packet_count"
    fi
    
    # Add filter if specified
    if [ -n "$filter" ]; then
        snort_cmd="$snort_cmd --bpf '$filter'"
    fi
    
    # Add output format if specified
    if [ -n "$output_format" ]; then
        snort_cmd="$snort_cmd -L $output_format"
    fi
    
    # Display information
    echo "🚀 Starting Snort Live Capture..."
    echo "📡 Interface: $interface"
    echo "📊 Alert Mode: $alert_mode"
    echo "📁 Log Directory: $log_dir"
    echo "⚙️  Config: $config_file"
    if [ -n "$packet_count" ]; then
        echo "📦 Packet Count: $packet_count"
    fi
    if [ -n "$filter" ]; then
        echo "🔍 Filter: $filter"
    fi
    if [ -n "$output_format" ]; then
        echo "📄 Output Format: $output_format"
    fi
    echo ""
    
    # Run Snort - output goes to log file, and we'll tail it separately
    eval "$snort_cmd" > "$log_dir/snort_console.log" 2>&1
}

# If script is run directly (not sourced), call snortlive function
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    snortlive "$@"
fi