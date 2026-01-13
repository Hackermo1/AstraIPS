# AstraIPS - Raspberry Pi IPS Mode

## Overview

This folder contains Pi-optimized versions of AstraIPS scripts.

**Note**: The main AstraIPS scripts now auto-detect paths and work on Raspberry Pi without modification. These files are kept for reference.

## Quick Start on Pi

```bash
# Use the main scripts (recommended)
cd ~/AstraIPS
sudo ./installer/install.sh
sudo ./mqttlive
```

## IPS Mode Requirements

1. **Snort3** with NFQ DAQ module
2. **libdaq** v3.0.23+ built with NFQ support
3. **iptables** for packet redirection
4. Root privileges for packet capture

## How IPS Mode Works

```
Device → Port 1883 → iptables NAT → Port 1889 → NFQUEUE → Snort IPS → ALLOW/DROP
```

## Verification

```bash
# Check Snort has NFQ support
snort --daq-list | grep nfq

# Check iptables rules are active
sudo iptables -t nat -L -n | grep 1889
sudo iptables -L -n | grep NFQUEUE
```
