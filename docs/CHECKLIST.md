# AstraIPS Installation Checklist

## Pre-Installation Checklist

- [ ] Verify system meets requirements (Linux, 4GB+ RAM, 10GB disk)
- [ ] Ensure internet connection for package downloads
- [ ] Backup existing Snort3 installation (if any)
- [ ] Review INSTALLER_GUIDE.md

## Package Installation Checklist

- [ ] Install build dependencies (cmake, g++, etc.)
- [ ] Install Python 3.8+ and pip
- [ ] Install Python development headers
- [ ] Install network libraries (libpcap, libnetfilter-queue)
- [ ] Install LuaJIT development libraries
- [ ] Install OpenSSL development libraries
- [ ] Install PCRE2 development libraries

## Snort3 Installation Checklist

- [ ] Clone Snort3 source (v3.1.0.0+)
- [ ] Clone libdaq source (v3.0.23)
- [ ] Build and install libdaq FIRST
- [ ] Verify libdaq installation (daq-config --version)
- [ ] Build Snort3 with --enable-ips --enable-inline
- [ ] Install Snort3
- [ ] Verify Snort3 installation (snort --version)
- [ ] Verify DAQ modules (snort --daq-list)

## Project Setup Checklist

- [ ] Run installer script (./installer/install.sh)
- [ ] Verify project directory structure created
- [ ] Verify all files copied correctly
- [ ] Set file permissions (chmod +x scripts/*.py)
- [ ] Update configuration paths
- [ ] Set environment variables
- [ ] Initialize database

## Python Dependencies Checklist

- [ ] Install pandas
- [ ] Install numpy
- [ ] Install tensorflow
- [ ] Install keras
- [ ] Install openpyxl
- [ ] Install paho-mqtt
- [ ] Install scapy
- [ ] Install psutil
- [ ] Install netifaces
- [ ] Verify all imports work

## Configuration Checklist

- [ ] Configure network interface in snort.lua
- [ ] Set DAQ mode to 'inline' in config
- [ ] Verify AI inspector paths in enhanced_ai_inspector.lua
- [ ] Configure MQTT broker settings
- [ ] Set PROJECT_DIR environment variable
- [ ] Update ML model paths in config.json

## Verification Checklist

- [ ] Snort3 version check (should be 3.1.0.0+)
- [ ] DAQ modules available (afpacket, nfq, pcap)
- [ ] Snort configuration test (snort -T -c config/snort.lua)
- [ ] Python dependencies test
- [ ] Database initialization test
- [ ] Network interface detection
- [ ] File permissions check

## Post-Installation Checklist

- [ ] Read INSTALLER_GUIDE.md troubleshooting section
- [ ] Test Snort3 in IDS mode first
- [ ] Test Snort3 in IPS mode
- [ ] Monitor logs directory
- [ ] Verify database writes
- [ ] Test MQTT integration (if applicable)

## Common Issues to Check

- [ ] Library paths (LD_LIBRARY_PATH)
- [ ] Snort permissions (setcap or sudo)
- [ ] Network interface exists and is up
- [ ] Firewall not blocking traffic
- [ ] Disk space available
- [ ] Python virtual environment (if used)
