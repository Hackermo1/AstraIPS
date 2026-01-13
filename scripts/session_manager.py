#!/usr/bin/env python3
"""
Session Manager - Unified Logging System
ONE session.db for all test runs, ONE log file per type (append mode)
Date/time stamps in each entry identify test runs
"""

import os
import sys
from unified_logging_manager import get_unified_logger

class SessionManager:
    def __init__(self, base_dir="logs"):
        """
        Initialize Session Manager - Uses Unified Logging System
        
        Args:
            base_dir: Base directory for all logs (default: logs)
        """
        # Use unified logging manager
        self.logger = get_unified_logger(base_dir=base_dir)
        self.base_dir = self.logger.get_base_dir()
        self.session_dir = self.base_dir  # Unified: no per-session directories
        self.db_path = self.logger.get_db_path()
    
    def create_session(self, session_name=None):
        """
        Get unified logging directory (no per-session directories)
        
        Args:
            session_name: Ignored (kept for compatibility)
            
        Returns:
            Path to unified logs directory
        """
        # Return unified logs directory
        # Note: Messages printed to stderr are suppressed by mqttlive (2>/dev/null)
        return self.session_dir
    
    # Database initialization is handled by UnifiedLoggingManager
    
    def get_session_dir(self):
        """Get unified logs directory"""
        return self.session_dir
    
    def get_db_path(self):
        """Get unified database path"""
        return self.db_path
    
    def get_exports_dir(self):
        """Get exports directory"""
        return self.logger.get_exports_dir()
    
    def get_pcap_dir(self):
        """Get PCAP directory"""
        return self.logger.get_pcap_dir()
    
    def get_alerts_dir(self):
        """Get alerts directory (unified - same as base_dir)"""
        return self.base_dir
    
    def get_logs_dir(self):
        """Get logs directory (unified - same as base_dir)"""
        return self.base_dir
    
    def get_scans_dir(self):
        """Get scans directory"""
        return self.logger.get_scans_dir()
    
    def get_logger(self):
        """Get unified logging manager instance"""
        return self.logger
