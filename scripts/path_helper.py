#!/usr/bin/env python3
"""
Universal Path Helper - Auto-detects project directory and provides universal paths
Works regardless of where the script is run from or installed.
"""
import os
import sys
from pathlib import Path


def get_project_dir():
    """Get project directory - auto-detects from various sources"""
    # 1. Check environment variable (set by mqttlive or snortlive.sh)
    if os.environ.get('PROJECT_DIR'):
        return os.environ.get('PROJECT_DIR')
    
    if os.environ.get('MQTTLIVE_DIR'):
        return os.environ.get('MQTTLIVE_DIR')
    
    # 2. Check SESSION_LOG_DIR parent (if set)
    if os.environ.get('SESSION_LOG_DIR'):
        session_dir = Path(os.environ.get('SESSION_LOG_DIR'))
        # If logs/ subdirectory, go up one level
        if session_dir.name == 'logs':
            return str(session_dir.parent)
        # Otherwise assume project_dir/logs structure
        return str(session_dir.parent) if session_dir.parent.exists() else str(session_dir)
    
    # 3. Get directory of this file - scripts/path_helper.py is in scripts/ folder
    #    So we need to go up one level to get project root
    this_file = Path(__file__).resolve()
    if this_file.exists():
        # This file is in PROJECT_DIR/scripts/path_helper.py
        scripts_dir = this_file.parent
        project_dir = scripts_dir.parent
        # Verify this is actually the project root by checking for key files
        if (project_dir / 'mqttlive').exists() or (project_dir / 'config').exists():
            return str(project_dir)
    
    # 4. Try to find project by looking for key files from current directory
    current_dir = Path.cwd()
    for parent in [current_dir] + list(current_dir.parents):
        if (parent / 'mqttlive').exists() or \
           (parent / 'config' / 'snort.lua').exists() or \
           (parent / 'config' / 'mqtt_final.lua').exists():
            return str(parent)
    
    # 5. Fallback to current directory
    return str(Path.cwd())


def get_config_dir():
    """Get configuration directory"""
    return os.path.join(get_project_dir(), 'config')


def get_ml_dir():
    """Get ML models directory"""
    return os.path.join(get_project_dir(), 'ml-models')


def get_scripts_dir():
    """Get scripts directory"""
    return os.path.join(get_project_dir(), 'scripts')


def get_snort_bin():
    """Get Snort binary path - check system install first"""
    import shutil
    
    # Check PATH first (system install)
    snort_path = shutil.which('snort')
    if snort_path:
        return snort_path
    
    # Check common locations
    common_paths = [
        '/usr/local/bin/snort',
        '/usr/bin/snort',
        os.path.join(get_project_dir(), 'snort-install', 'bin', 'snort')
    ]
    for path in common_paths:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    
    return None


def get_logs_dir():
    """Get logs directory"""
    # Check if SESSION_LOG_DIR is set
    if os.environ.get('SESSION_LOG_DIR'):
        logs_dir = os.environ.get('SESSION_LOG_DIR')
    else:
        logs_dir = os.path.join(get_project_dir(), 'logs')
    
    os.makedirs(logs_dir, exist_ok=True)
    return logs_dir


def get_session_db_path():
    """Get session database path"""
    logs_dir = get_logs_dir()
    return os.path.join(logs_dir, 'session.db')


# Set environment variable for other scripts when this module is imported
PROJECT_DIR = get_project_dir()
os.environ['PROJECT_DIR'] = PROJECT_DIR


# For scripts that do: from path_helper import *
__all__ = [
    'get_project_dir',
    'get_config_dir', 
    'get_ml_dir',
    'get_scripts_dir',
    'get_snort_bin',
    'get_logs_dir',
    'get_session_db_path',
    'PROJECT_DIR'
]
