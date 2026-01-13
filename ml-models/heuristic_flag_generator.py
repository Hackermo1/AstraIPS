#!/usr/bin/env python3
"""
Heuristic Flag Generator
Converts full command strings to MAL (malicious) or NOR (normal) flags using Excel categories
"""

import pandas as pd
import os
import re

class HeuristicFlagGenerator:
    def __init__(self, excel_path=None):
        """
        Initialize heuristic flag generator
        
        Args:
            excel_path: Path to Excel file with command categories
        """
        if excel_path is None:
            # Default path relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            excel_path = os.path.join(base_dir, 'phase1_feature_dataset1111111111 (2).xlsx')
        
        self.excel_path = excel_path
        self.df = None
        self.command_to_flag = {}
        self.known_command_stems = []
        
        if os.path.exists(excel_path):
            self._load_excel()
            self._build_lookup()
        else:
            print(f"⚠️  Excel file not found: {excel_path}")
    
    def _load_excel(self):
        """Load Excel file into memory"""
        try:
            print(f"📊 Loading heuristic categories from: {self.excel_path}")
            self.df = pd.read_excel(self.excel_path, sheet_name='Sheet1')
            print(f"✅ Loaded {len(self.df)} command entries")
        except Exception as e:
            print(f"❌ Error loading Excel file: {e}")
            self.df = None
    
    def _build_lookup(self):
        """Build command to flag mapping from Excel"""
        if self.df is None:
            return
        
        try:
            # Build lookup dictionary: command -> flag
            for idx, row in self.df.iterrows():
                # Try different column name variations
                command_col = None
                for col in ['Command', 'command', 'COMMAND']:
                    if col in self.df.columns:
                        command_col = col
                        break
                
                if not command_col:
                    print("⚠️  No 'Command' column found. Available columns:", self.df.columns.tolist())
                    return
                
                command = str(row.get(command_col, '')).strip().lower()
                
                if not command or command == 'nan' or command == '':
                    continue
                
                # Try different label column name variations
                label_col = None
                for col in ['label name', 'label_name', 'Label Name', 'label', 'Label', 'flag']:
                    if col in self.df.columns:
                        label_col = col
                        break
                
                if not label_col:
                    print("⚠️  No label column found. Available columns:", self.df.columns.tolist())
                    return
                
                # Get label value (could be numeric or string)
                label_value = row.get(label_col)
                
                # Convert to flag: flag=9 (networking) or flag=2 (scripting) -> MAL
                # Other values -> NOR (or None if not recognized)
                flag = None
                if pd.notna(label_value):
                    label_str = str(label_value).strip()
                    label_num = None
                    try:
                        label_num = int(float(label_str))
                    except (ValueError, TypeError):
                        pass
                    
                    # Check numeric flags: 9 (networking) or 2 (scripting) = MAL
                    if label_num == 9 or label_num == 2:
                        flag = "MAL"
                    # Check string labels
                    elif label_str.lower() in ['mal', 'malicious', '9', '2']:
                        flag = "MAL"
                    elif label_str.lower() in ['normal', 'nor', '0', '1']:
                        flag = "NOR"
                    # Default: if flag exists but not recognized, treat as NOR
                    elif label_str and label_str != 'nan':
                        flag = "NOR"
                
                # Store flag if found
                if flag:
                    self.command_to_flag[command] = flag
            
            # Sort command stems by length (longest first) for partial matching
            self.known_command_stems = sorted(
                self.command_to_flag.keys(), 
                key=len, 
                reverse=True
            )
            
            print(f"✅ Built lookup: {len(self.command_to_flag)} commands mapped")
            mal_count = sum(1 for f in self.command_to_flag.values() if f == "MAL")
            nor_count = sum(1 for f in self.command_to_flag.values() if f == "NOR")
            print(f"   - MAL: {mal_count}, NOR: {nor_count}")
            
        except Exception as e:
            print(f"❌ Error building lookup: {e}")
    
    def get_flag(self, command_string):
        """
        Convert full command string to MAL or NOR flag
        
        Args:
            command_string: Full command string to analyze
            
        Returns:
            "MAL", "NOR", or None if no match found
        """
        if not command_string or not self.command_to_flag:
            return None
        
        # Normalize command (strip whitespace, lowercase)
        normalized = command_string.strip().lower()
        
        if not normalized:
            return None
        
        # Strategy 1: Exact match
        if normalized in self.command_to_flag:
            return self.command_to_flag[normalized]
        
        # Strategy 2: Try partial match (first token)
        tokens = normalized.split()
        if tokens:
            first_token = tokens[0]
            
            # Find commands starting with this token
            matching_commands = [
                cmd for cmd in self.known_command_stems 
                if cmd.startswith(first_token) or first_token.startswith(cmd)
            ]
            
            if matching_commands:
                # Get flags for matching commands
                matching_flags = [
                    self.command_to_flag[cmd] 
                    for cmd in matching_commands 
                    if cmd in self.command_to_flag
                ]
                
                if matching_flags:
                    # Prefer MAL over NOR (more suspicious)
                    if "MAL" in matching_flags:
                        return "MAL"
                    elif "NOR" in matching_flags:
                        return "NOR"
        
        # Strategy 3: Check Excel directly for partial matches
        if self.df is not None:
            try:
                # Find rows where Command column starts with first token
                first_token = tokens[0] if tokens else normalized
                matching_rows = self.df[
                    self.df['Command'].astype(str).str.lower().str.strip().str.startswith(first_token)
                ]
                
                if len(matching_rows) > 0:
                    # Check label name distribution
                    mal_count = len(matching_rows[matching_rows['label name'].astype(str).str.lower() == 'mal'])
                    normal_count = len(matching_rows[matching_rows['label name'].astype(str).str.lower() == 'normal'])
                    
                    # Prefer MAL if found
                    if mal_count > normal_count:
                        return "MAL"
                    elif normal_count > 0:
                        return "NOR"
            except Exception as e:
                # Silently fail and return None
                pass
        
        return None  # No flag found
    
    def get_flag_with_details(self, command_string):
        """
        Get flag with additional details
        
        Returns:
            dict with 'flag', 'method' (exact/partial/none), 'confidence'
        """
        if not command_string:
            return {'flag': None, 'method': 'none', 'confidence': 0.0}
        
        normalized = command_string.strip().lower()
        
        # Exact match
        if normalized in self.command_to_flag:
            return {
                'flag': self.command_to_flag[normalized],
                'method': 'exact',
                'confidence': 1.0
            }
        
        # Partial match
        tokens = normalized.split()
        if tokens:
            first_token = tokens[0]
            matching = [cmd for cmd in self.known_command_stems if cmd.startswith(first_token)]
            if matching:
                flags = [self.command_to_flag[cmd] for cmd in matching if cmd in self.command_to_flag]
                if flags:
                    flag = "MAL" if "MAL" in flags else ("NOR" if "NOR" in flags else None)
                    if flag:
                        return {
                            'flag': flag,
                            'method': 'partial',
                            'confidence': 0.7
                        }
        
        return {'flag': None, 'method': 'none', 'confidence': 0.0}
