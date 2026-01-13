# Snort3 Build Guide

## Automated Installation

The easiest way is to use the installer:

```bash
sudo ./installer/install.sh
```

This builds both libdaq and Snort3 from source.

## Manual Build (if needed)

### Step 1: Install Dependencies

```bash
sudo apt update
sudo apt install -y \
    build-essential cmake git pkg-config flex bison \
    libtool autoconf automake \
    libpcap-dev libpcre2-dev libpcre3-dev libdumbnet-dev \
    libhwloc-dev libluajit-5.1-dev luajit \
    libssl-dev zlib1g-dev liblzma-dev liblz4-dev \
    libnghttp2-dev libunwind-dev libfl-dev \
    libnetfilter-queue-dev libnetfilter-queue1 \
    libmnl-dev libnfnetlink-dev
```

### Step 2: Build libdaq

```bash
cd /tmp
git clone https://github.com/snort3/libdaq.git
cd libdaq
git checkout v3.0.23
./bootstrap
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig

# Verify NFQ module
ls /usr/local/lib/daq/daq_nfq.so
```

### Step 3: Build Snort3

```bash
cd /tmp
git clone https://github.com/snort3/snort3.git
cd snort3
git checkout 3.10.0.0
./configure_cmake.sh --prefix=/usr/local --enable-shell
cd build
make -j$(nproc)
sudo make install
sudo ldconfig

# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort

# Verify
snort --version
snort --daq-list
```

## Verification

```bash
# Should show version 3.10.0.0
snort --version

# Should include nfq, afpacket, pcap
snort --daq-list

# Validate config
snort -c config/mqtt_final.lua -T
```
