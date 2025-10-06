import re
import pandas as pd
from datetime import datetime
import numpy as np

class LogParser:
    def __init__(self):
        # Common UNIX log patterns
        self.patterns = {
            'syslog': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)',
            'auth': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s*(.*)',
            'apache': r'(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)',
            'nginx': r'(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
        }
        
        # Suspicious patterns
        self.threat_indicators = {
            'brute_force': [r'Failed password', r'authentication failure', r'invalid user'],
            'privilege_escalation': [r'sudo', r'su:', r'COMMAND='],
            'network_scan': [r'port.*scan', r'nmap', r'masscan'],
            'malware': [r'virus', r'malware', r'trojan', r'backdoor'],
            'dos_attack': [r'connection.*refused', r'too many connections', r'rate limit'],
            'file_access': [r'permission denied', r'access denied', r'unauthorized']
        }
    
    def parse_logs(self, log_text):
        logs = []
        lines = log_text.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
                
            parsed_log = self._parse_single_log(line)
            if parsed_log:
                logs.append(parsed_log)
        
        return pd.DataFrame(logs)
    
    def _parse_single_log(self, line):
        # Try different patterns
        for log_type, pattern in self.patterns.items():
            match = re.match(pattern, line)
            if match:
                return self._extract_features(line, log_type, match)
        
        # Fallback for unmatched logs
        return self._extract_features(line, 'generic', None)
    
    def _extract_features(self, line, log_type, match):
        features = {
            'raw_log': line,
            'log_type': log_type,
            'timestamp': self._extract_timestamp(line),
            'source_ip': self._extract_ip(line),
            'user': self._extract_user(line),
            'command': self._extract_command(line),
            'threat_indicators': self._count_threat_indicators(line),
            'log_length': len(line),
            'has_numbers': int(bool(re.search(r'\d+', line))),
            'has_special_chars': int(bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', line))),
            'word_count': len(line.split())
        }
        
        return features
    
    def _extract_timestamp(self, line):
        # Try to extract timestamp
        timestamp_patterns = [
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return datetime.now().strftime('%b %d %H:%M:%S')
    
    def _extract_ip(self, line):
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, line)
        return match.group(0) if match else 'unknown'
    
    def _extract_user(self, line):
        user_patterns = [
            r'user\s+(\w+)',
            r'for\s+(\w+)',
            r'from\s+(\w+)'
        ]
        
        for pattern in user_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'unknown'
    
    def _extract_command(self, line):
        command_patterns = [
            r'COMMAND=(.+)',
            r'executed\s+(.+)',
            r'running\s+(.+)'
        ]
        
        for pattern in command_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return 'none'
    
    def _count_threat_indicators(self, line):
        threat_count = 0
        threat_types = []
        
        for threat_type, patterns in self.threat_indicators.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    threat_count += 1
                    threat_types.append(threat_type)
        
        return {
            'count': threat_count,
            'types': list(set(threat_types))
        }