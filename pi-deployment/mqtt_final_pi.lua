-- Universal path detection - uses environment variable or auto-detects
local base_dir = os.getenv('PROJECT_DIR') or os.getenv('PWD') or (debug.getinfo(1, 'S').source:match('@(.*)/') or '.')

include 'snort_defaults.lua'

-- Load Enhanced AI Inspector - REQUIRED for intelligent rule firing based on heuristics and AI
-- Universal path: use PROJECT_DIR or auto-detect from current file location
local config_dir = base_dir .. '/config'
package.path = package.path .. ';' .. config_dir .. '/?.lua'
local enhanced_ai_inspector = require('enhanced_ai_inspector')
print("✅ Enhanced AI Inspector loaded - Snort will fire rules based on heuristics and AI output")

HOME_NET = 'any'
EXTERNAL_NET = 'any'

stream = { }
stream_tcp = { }
stream_udp = { }

-- Enable default wizard for service detection
wizard = default_wizard

-- Enable decode module explicitly
decode = { }

-- AppID configuration - DISABLED to prevent hang on resource-constrained systems
-- AppID detector loading can take 2-5 minutes or hang completely on smaller systems
-- We don't need AppID for MQTT detection (using content-based rules instead)
-- appid = {
--     -- Use default appid configuration
-- }

-- NOTE: MQTT service inspector removed - Snort doesn't have built-in MQTT inspector
-- We detect MQTT traffic using content-based rules instead
-- In IDS (passive) mode, we use rules to detect MQTT packets

-- Initialize IPS section for rules only (IDS mode - no inline blocking)
ips = {}

-- AI Integration Configuration - Snort sends alerts/logs to AI server via file-based IPC
local ai_config = {
    ipc_socket_path = "/tmp/ai_socket.sock",  -- Must match the path in ML related things files/ai_decision_server.py
    base_dir = base_dir  -- Base directory for Python helper script
}

-- Initialize Enhanced AI Inspector with configuration
local inspector = enhanced_ai_inspector:new()
inspector:setup(ai_config)

-- MQTT Intelligent Rules - fire based on heuristics, AI output, and patterns (must come after ips = {})
-- Priority system: 1=CRITICAL, 2=HIGH, 3=MEDIUM, 4=LOW
ips = {
    include = 'mqtt_intelligent_rules.rules'
}

-- NOTE: Enhanced AI Inspector integration for IDS mode
-- In IDS (passive) mode, the enhanced inspector:
-- 1. Queries database for heuristic_flag and ai_flag
-- 2. Queries AI server for real-time analysis
-- 3. Generates alerts with appropriate priorities:
--    - Priority 1: AI BLOCK + Heuristic MAL (CRITICAL)
--    - Priority 2: AI BLOCK OR Heuristic MAL (HIGH)
--    - Priority 3: Pattern-based detection (MEDIUM)
--    - Priority 4: Normal logging (LOW)
-- 4. Snort alert_logger.py logs enhanced alerts to database
print("✅ IDS (passive) mode - Enhanced AI analysis with heuristics and intelligent rule firing")
print("   Priority system: CRITICAL(1) > HIGH(2) > MEDIUM(3) > LOW(4)")

-- Enable verbose output FIRST
verbose = true

-- CONSOLE: Show our human-readable output AND standard alerts
-- alert_fast writes alerts to the log directory specified by -l flag
alert_fast = { 
    file = true,
    limit = 0  -- No limit on alerts
}

-- Print alerts to console (stdout) so they show up in mqttlive
alert_console = { }

-- JSON LOG: Save full analysis to a JSON file
alert_json = {
    file = true
}

-- CSV LOG: Structured alert data
alert_csv = {
    file = true,
    fields = 'timestamp action proto pkt_gen pkt_len dir src_ap dst_ap rule msg'
}

-- PCAP LOG: Save all logged packets to a pcap file for detailed analysis
-- This will create snort.log.<timestamp> files in the log directory
log_pcap = { }

-- HUMAN-READABLE LOG: Save all MQTT traffic to a human-readable file
log_file = {
    file = true,
    filename = 'mqtt_traffic.log',
    packet_print = true,
    payload_print = true
}
