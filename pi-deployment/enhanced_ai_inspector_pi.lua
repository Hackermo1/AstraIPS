-- File: enhanced_ai_inspector.lua
-- Enhanced AI Inspector for Snort - integrates heuristics and AI output
-- Queries database for flags and checks AI server for real-time analysis

EnhancedAiInspector = {}
function EnhancedAiInspector:new(o) 
    o = o or {}; 
    setmetatable(o, self); 
    self.__index = self; 
    return o; 
end

-- Configuration (set by setup function)
local config = nil
local python_helper_path = nil
local ai_request_file = nil
local ai_response_file = nil

-- Cache for recent queries (simple, in-memory)
local flag_cache = {}
local cache_max_age = 5  -- Cache for 5 seconds

function EnhancedAiInspector:setup(conf)
    -- Initialize inspector with configuration
    config = conf or {}
    
    -- Set paths
    local base_dir = config.base_dir or os.getenv('PROJECT_DIR') or os.getenv('MQTTLIVE_DIR') or '.'
    python_helper_path = base_dir .. '/query_flags_helper.py'
    
    -- AI server IPC paths
    local socket_path = config.ipc_socket_path or '/tmp/ai_socket.sock'
    ai_request_file = socket_path .. '.request'
    ai_response_file = socket_path .. '.response'
    
    print("✅ Enhanced AI Inspector initialized")
    print("   Python helper: " .. python_helper_path)
    print("   AI request file: " .. ai_request_file)
end

function EnhancedAiInspector:query_database_flags(command, device_ip)
    -- Query database for heuristic and AI flags using Python helper
    if not python_helper_path then
        return nil, nil, nil
    end
    
    -- Check cache first
    local cache_key = device_ip .. "|" .. command
    if flag_cache[cache_key] then
        local cached = flag_cache[cache_key]
        if os.time() - cached.timestamp < cache_max_age then
            return cached.heuristic_flag, cached.ai_flag, cached.ai_verdict
        end
    end
    
    -- Call Python helper script
    local cmd = string.format('python3 %s "%s" "%s"', 
        python_helper_path, 
        command:gsub('"', '\\"'),  -- Escape quotes
        device_ip)
    
    local handle = io.popen(cmd)
    if not handle then
        return nil, nil, nil
    end
    
    local output = handle:read("*line")
    handle:close()
    
    if not output then
        return nil, nil, nil
    end
    
    -- Parse output: heuristic_flag|ai_flag|ai_verdict
    local parts = {}
    for part in output:gmatch("([^|]+)") do
        table.insert(parts, part)
    end
    
    if #parts >= 3 then
        local heuristic_flag = parts[1] ~= "NONE" and parts[1] or nil
        local ai_flag = parts[2] ~= "NONE" and parts[2] or nil
        local ai_verdict = parts[3] ~= "NONE" and parts[3] or nil
        
        -- Cache result
        flag_cache[cache_key] = {
            heuristic_flag = heuristic_flag,
            ai_flag = ai_flag,
            ai_verdict = ai_verdict,
            timestamp = os.time()
        }
        
        return heuristic_flag, ai_flag, ai_verdict
    end
    
    return nil, nil, nil
end

function EnhancedAiInspector:query_ai_server(command, device_ip)
    -- Query AI server via file IPC for real-time analysis
    if not ai_request_file or not ai_response_file then
        return nil
    end
    
    -- Write request
    local request_file = io.open(ai_request_file, "w")
    if not request_file then
        return nil
    end
    
    local request_data = device_ip .. "|" .. command .. "\n"
    request_file:write(request_data)
    request_file:close()
    
    -- Wait for response (with timeout)
    local max_wait = 20  -- Check 20 times (2 seconds max)
    local wait_count = 0
    
    while wait_count < max_wait do
        local response_file = io.open(ai_response_file, "r")
        if response_file then
            local verdict = response_file:read("*line")
            response_file:close()
            
            -- Clean up files
            os.remove(ai_response_file)
            os.remove(ai_request_file)
            
            if verdict and (verdict:match("BLOCK") or verdict:match("ALLOW")) then
                return verdict:match("BLOCK") and "BLOCK" or "ALLOW"
            end
            return nil
        end
        
        -- Small delay (Lua doesn't have sleep, but we can yield)
        wait_count = wait_count + 1
    end
    
    -- Clean up request file if no response
    if os.remove then
        os.remove(ai_request_file)
    end
    
    return nil
end

function EnhancedAiInspector:extract_mqtt_payload(buffer)
    -- Extract MQTT payload from packet buffer
    if not buffer or #buffer < 2 then
        return nil
    end
    
    -- MQTT PUBLISH packet starts with 0x30
    -- Format: Fixed header (2+ bytes) + Variable header + Payload
    -- For simplicity, try to extract payload after topic
    
    -- Look for printable text (command)
    local payload = nil
    local start_idx = nil
    
    -- Find start of payload (after topic length and topic)
    -- This is simplified - real MQTT parsing is more complex
    for i = 1, math.min(#buffer, 1000) do
        local byte = string.byte(buffer, i)
        if byte >= 32 and byte <= 126 then  -- Printable ASCII
            if not start_idx then
                start_idx = i
            end
        elseif start_idx then
            -- Found end of printable text
            payload = string.sub(buffer, start_idx, i - 1)
            break
        end
    end
    
    -- If we found start but no end, take rest of buffer
    if start_idx and not payload then
        payload = string.sub(buffer, start_idx)
    end
    
    -- Clean up payload (remove null bytes, etc.)
    if payload then
        payload = payload:gsub("%z", "")  -- Remove null bytes
        payload = payload:gsub("^%s+", ""):gsub("%s+$", "")  -- Trim whitespace
        if #payload > 0 then
            return payload
        end
    end
    
    return nil
end

function EnhancedAiInspector:get_mac_from_ip(device_ip)
    -- Get MAC address from device IP using Python helper
    if not device_ip or device_ip == "" then
        return nil
    end
    
    local base_dir = config.base_dir or os.getenv('PROJECT_DIR') or os.getenv('MQTTLIVE_DIR') or '.'
    local mac_helper = base_dir .. '/get_mac_from_ip.py'
    
    local cmd = string.format('python3 %s "%s" 2>/dev/null', mac_helper, device_ip)
    local handle = io.popen(cmd)
    if not handle then
        return nil
    end
    
    local mac = handle:read("*line")
    handle:close()
    
    if mac and mac ~= "" and mac ~= "NONE" then
        return mac
    end
    
    return nil
end

function EnhancedAiInspector:record_detection_stage(mac_address, device_ip, command, threat_level, detection_type)
    -- Record detection and get current stage using Python helper
    if not mac_address or mac_address == "" then
        return 0  -- Stage 0: No detection
    end
    
    local base_dir = config.base_dir or os.getenv('PROJECT_DIR') or os.getenv('MQTTLIVE_DIR') or '.'
    local tracker_helper = base_dir .. '/record_detection.py'
    
    local cmd = string.format('python3 %s "%s" "%s" "%s" "%s" "%s" 2>/dev/null',
        tracker_helper,
        mac_address:gsub('"', '\\"'),
        device_ip:gsub('"', '\\"'),
        command:gsub('"', '\\"'),
        threat_level:gsub('"', '\\"'),
        detection_type:gsub('"', '\\"'))
    
    local handle = io.popen(cmd)
    if not handle then
        return 0
    end
    
    local stage_str = handle:read("*line")
    handle:close()
    
    if stage_str and tonumber(stage_str) then
        return tonumber(stage_str)
    end
    
    return 0
end

function EnhancedAiInspector:block_device_mac(mac_address)
    -- Block device MAC address at gateway level
    if not mac_address or mac_address == "" then
        return false
    end
    
    local base_dir = config.base_dir or os.getenv('PROJECT_DIR') or os.getenv('MQTTLIVE_DIR') or '.'
    local block_helper = base_dir .. '/gateway_block_manager.py'
    
    local cmd = string.format('python3 %s block "%s" 2>&1', block_helper, mac_address:gsub('"', '\\"'))
    local handle = io.popen(cmd)
    if not handle then
        return false
    end
    
    local output = handle:read("*all")
    handle:close()
    
    -- Check if blocking succeeded
    if output and (output:match("blocked") or output:match("Blocked")) then
        return true
    end
    
    return false
end

function EnhancedAiInspector:eval(p, buffer)
    -- Main evaluation function called by Snort for each packet
    -- 🐛 DEBUG: IPS debugging enabled
    local debug_log_file = "/tmp/snort_ips_debug.log"
    local function debug_log(msg)
        local f = io.open(debug_log_file, "a")
        if f then
            f:write(string.format("[%s] %s\n", os.date("%Y-%m-%d %H:%M:%S"), msg))
            f:close()
        end
    end
    
    debug_log("=== IPS EVAL START ===")
    
    if not config or not buffer then
        debug_log("ERROR: config or buffer is nil")
        return
    end
    
    -- Extract device IP from packet
    local device_ip = tostring(p.ip.src_addr)
    if not device_ip or device_ip == "" then
        debug_log("ERROR: device_ip is empty")
        return
    end
    
    debug_log(string.format("Packet from IP: %s", device_ip))
    
    -- Extract MQTT payload (command)
    local command = self:extract_mqtt_payload(buffer)
    if not command or #command == 0 then
        debug_log("No MQTT payload found")
        return
    end
    
    debug_log(string.format("MQTT Command: %s", command))
    
    -- Limit command length for safety
    if #command > 1000 then
        command = string.sub(command, 1, 1000)
    end
    
    -- ========================================================================
    -- 4-STAGE ENFORCEMENT SYSTEM IMPLEMENTATION
    -- ========================================================================
    
    -- Get MAC address for device tracking
    local mac_address = self:get_mac_from_ip(device_ip)
    if not mac_address or mac_address == "" then
        mac_address = device_ip  -- Fallback to IP if MAC not available
    end
    
    -- Query database for flags
    local heuristic_flag, ai_flag, ai_verdict_db = self:query_database_flags(command, device_ip)
    
    -- Query AI server for real-time analysis
    local ai_verdict_realtime = self:query_ai_server(command, device_ip)
    
    -- Use real-time verdict if available, otherwise use database verdict
    local ai_verdict = ai_verdict_realtime or ai_verdict_db
    
    -- ========================================================================
    -- 4-STAGE ENFORCEMENT SYSTEM WITH STATE TRACKING
    -- All detections are logged to database via detection_state_tracker
    -- ========================================================================
    
    -- ========================================================================
    -- STAGE 1: Initial Heuristic Flagging
    -- High-risk categories: Flag 2 (Scripting & Development) or Flag 9 (Networking)
    -- Action: Record "mental note" in state table, NO Snort enforcement
    -- ========================================================================
    local is_stage1_triggered = false
    if heuristic_flag == "MAL" then
        -- Stage 1: Heuristic detects high-risk (Flag 2 or Flag 9 map to MAL)
        -- Record detection in state table, but NO Snort action
        local stage = self:record_detection_stage(mac_address, device_ip, command, "medium", "heuristic")
        is_stage1_triggered = true
        
        -- No alert/drop at Stage 1 - just a "mental note" recorded
        -- Payload forwarded for deeper AI analysis (Stage 2)
        -- Continue processing to check AI verdict
    end
    
    -- ========================================================================
    -- STAGE 2: AI Confirmation and Active Alerting
    -- AI model confirms malicious → ALERT directive → Log but ALLOW traffic
    -- ========================================================================
    local is_malicious = false
    local threat_level = "low"
    local detection_method = "none"
    
    -- Check if AI confirms malicious (BLOCK verdict)
    debug_log(string.format("AI Verdict: %s, Heuristic Flag: %s", ai_verdict or "NONE", heuristic_flag or "NONE"))
    
    if ai_verdict == "BLOCK" then
        is_malicious = true
        threat_level = "high"
        detection_method = "ai"
        debug_log("MALICIOUS DETECTED: AI BLOCK verdict")
    elseif ai_verdict == "BLOCK" and heuristic_flag == "MAL" then
        is_malicious = true
        threat_level = "critical"
        detection_method = "both"
        debug_log("MALICIOUS DETECTED: AI BLOCK + Heuristic MAL (CRITICAL)")
    end
    
    if is_malicious then
        -- Record detection and get current stage (increments from Stage 1 if it was triggered)
        local stage = self:record_detection_stage(mac_address, device_ip, command, threat_level, "ai_alert")
        debug_log(string.format("Detection Stage: %d", stage))
        
        -- Stage 2: Generate ALERT directive (log but allow traffic)
        local alert_msg = string.format(
            "[STAGE 2] AI Alert - %s | IP: %s | MAC: %s | Command: %s | Stage: %d",
            detection_method == "both" and "AI BLOCK + Heuristic MAL" or "AI BLOCK",
            device_ip, mac_address, command, stage
        )
        
        debug_log(string.format("STAGE 2: Generating alert - %s", alert_msg))
        alert({
            msg = alert_msg,
            sid = 1002002,  -- Stage 2 alert
            gid = 1,
            rev = 1,
            priority = 2,
            class = "Attempted User Privilege Gain"
        })
        
        -- Traffic still permitted at Stage 2 - continue monitoring
        -- Check if we should escalate to Stage 3 or 4 based on detection count
        if stage >= 3 then
            -- ========================================================================
            -- STAGE 3: Packet-Level Enforcement (Drop)
            -- Third detection → DROP directive → Snort drops the packet
            -- ========================================================================
            if stage == 3 then
                local drop_msg = string.format(
                    "[STAGE 3] Packet Drop - %s | IP: %s | MAC: %s | Command: %s | Stage: %d",
                    detection_method,
                    device_ip, mac_address, command, stage
                )
                
                debug_log(string.format("STAGE 3: CALLING drop() - %s", drop_msg))
                debug_log("🐛 IPS DEBUG: drop() function called - packet should be BLOCKED")
                
                -- Drop the packet in inline IPS mode
                drop({
                    msg = drop_msg,
                    sid = 1002003,  -- Stage 3 drop
                    gid = 1,
                    rev = 1,
                    priority = 1,
                    class = "A Network Trojan was Detected"
                })
                
                debug_log("✅ drop() function executed - checking if packet was actually dropped...")
            end
            
            -- ========================================================================
            -- STAGE 4: Device-Level Enforcement (Block)
            -- Fourth+ detection → BLOCK directive → Gateway MAC blocking via iptables
            -- ========================================================================
            if stage >= 4 then
                debug_log(string.format("STAGE 4: Blocking device MAC: %s", mac_address))
                
                -- Block device MAC at gateway level (iptables)
                local blocked = self:block_device_mac(mac_address)
                
                local block_msg = string.format(
                    "[STAGE 4] Device Blocked - %s | IP: %s | MAC: %s | Command: %s | Stage: %d | Blocked: %s",
                    detection_method,
                    device_ip, mac_address, command, stage,
                    blocked and "YES" or "FAILED"
                )
                
                debug_log(string.format("STAGE 4: MAC blocking result: %s", blocked and "SUCCESS" or "FAILED"))
                debug_log(string.format("STAGE 4: CALLING drop() - %s", block_msg))
                
                -- Still drop the packet (in addition to MAC blocking)
                drop({
                    msg = block_msg,
                    sid = 1002004,  -- Stage 4 block
                    gid = 1,
                    rev = 1,
                    priority = 1,
                    class = "A Network Trojan was Detected"
                })
                
                debug_log("✅ Stage 4: drop() + MAC blocking executed")
            end
        end
        
        debug_log("=== IPS EVAL END (MALICIOUS HANDLED) ===")
        return  -- Exit after handling malicious detection
    end
    
    -- ========================================================================
    -- If Stage 1 was triggered but AI doesn't confirm malicious
    -- ========================================================================
    if is_stage1_triggered then
        debug_log("Stage 1 triggered but AI says ALLOW - no action")
        debug_log("=== IPS EVAL END (STAGE 1 ONLY) ===")
        return
    end
    
    -- ========================================================================
    -- Normal traffic (no malicious detection) - no action
    -- ========================================================================
    debug_log("Normal traffic - no malicious detection")
    debug_log("=== IPS EVAL END (NORMAL) ===")
    -- Don't generate alert for normal traffic (let rules handle pattern-based detection)
    return
end

-- Export module
return EnhancedAiInspector
