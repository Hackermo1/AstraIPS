# AstraIPS Setup Summary

## Components

| Component | Port | Purpose |
|-----------|------|---------|
| MQTT Router | 1889 | Intercepts MQTT traffic |
| AI Server | 9998 | ML-based threat detection |
| Snort3 | NFQUEUE | Inline packet inspection |

## Network Flow

```
External Device (1883) → iptables NAT → MQTT Router (1889) → NFQUEUE → Snort IPS
                                                                          ↓
                                                                    ALLOW or DROP
```

## iptables Rules (Auto-configured)

```bash
# NAT: Redirect 1883 to 1889
iptables -t nat -A PREROUTING -p tcp --dport 1883 -j REDIRECT --to-port 1889

# NFQUEUE: Send to Snort for inspection
iptables -I INPUT -p tcp --dport 1889 -j NFQUEUE --queue-num 0
```

## Verification Commands

```bash
# Check Snort is running
pgrep -a snort

# Check ports
ss -tlnp | grep -E "1889|9998"

# Check iptables
sudo iptables -t nat -L -n
sudo iptables -L -n | grep NFQUEUE

# Check logs
tail -f logs/logs/snort.log
```

## Cleanup (automatic on Ctrl+C)

```bash
# If needed manually:
sudo ./installer/kill_all_processes.sh
```
