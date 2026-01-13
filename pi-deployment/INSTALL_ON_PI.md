# Installing AstraIPS on Raspberry Pi

## Prerequisites

- Raspberry Pi 4/5 (ARM64)
- Raspberry Pi OS (64-bit) or Kali Linux ARM
- 4GB+ RAM recommended
- Ethernet connection for IPS mode

## Installation

```bash
# Clone the repository
git clone https://github.com/YourUsername/AstraIPS.git
cd AstraIPS

# Run the installer (builds Snort3, libdaq, installs TensorFlow)
# This takes 30-60 minutes on Pi
sudo ./installer/install.sh

# Verify installation
./installer/verify_install.sh

# Start the IPS
sudo ./mqttlive
```

## Important Notes

### NFQ Module on ARM64

The installer ensures `libnetfilter-queue-dev` is installed BEFORE building libdaq.
This is critical for NFQ support on ARM64.

If NFQ is missing after install:
```bash
sudo apt install libnetfilter-queue-dev libmnl-dev
cd /tmp/libdaq
make clean && ./bootstrap && ./configure --prefix=/usr/local
make -j$(nproc) && sudo make install && sudo ldconfig
```

### TensorFlow on Pi

The installer tries both:
1. `tflite-runtime` (lightweight, Pi-optimized)
2. `tensorflow` (full version)

If ML features don't work, the system still functions with heuristic detection only.

## Troubleshooting

See `docs/TROUBLESHOOTING.md` for common issues.
