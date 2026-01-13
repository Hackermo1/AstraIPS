# 🍓 Raspberry Pi Migration Files

## What's Here

This directory contains **COPIES** of files with universal paths fixed for Raspberry Pi migration.

### Files Included:

1. **`mqttlive_pi`** - Universal version of mqttlive script
2. **`snortlive_pi.sh`** - Universal version of snortlive.sh
3. **`mqtt_final_pi.lua`** - Universal Snort MQTT config
4. **`enhanced_ai_inspector_pi.lua`** - Universal AI inspector

## How to Use

### On Raspberry Pi:

1. **Copy these files to replace originals**:
   ```bash
   cp mqttlive_pi ../mqttlive
   cp snortlive_pi.sh ../snortlive.sh
   cp mqtt_final_pi.lua ../config/mqtt_final.lua
   cp enhanced_ai_inspector_pi.lua ../config/enhanced_ai_inspector.lua
   ```

2. **Or use the automated fix_paths.sh script** (recommended):
   ```bash
   ../installer/fix_paths.sh
   ```

3. **Configure router scanning (optional)**:
   ```bash
   ../installer/setup_router.sh
   ```

## Key Changes

- ✅ All hardcoded paths → `$PROJECT_DIR` (auto-detected)
- ✅ Scripts auto-detect their location
- ✅ Lua files use `os.getenv('PROJECT_DIR')`
- ✅ Universal path detection throughout
- ✅ Router credentials NOT hardcoded (user must configure)

## Original Files Preserved

Original files remain unchanged in the parent directory. These are copies specifically for Pi migration.
