import pandas as pd
import numpy as np
import joblib
import os
import json
import re
from datetime import datetime

class ThreatDetector:
    def __init__(self):
        self.rf_model = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = []
        self.model_loaded = False
        self.metadata = {}
        
        # Try to load pre-trained models
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            if (os.path.exists('models/random_forest.pkl') and 
                os.path.exists('models/isolation_forest.pkl') and 
                os.path.exists('models/scaler.pkl')):
                
                print("Loading pre-trained models...")
                self.rf_model = joblib.load('models/random_forest.pkl')
                self.isolation_forest = joblib.load('models/isolation_forest.pkl')
                self.scaler = joblib.load('models/scaler.pkl')
                
                # Load metadata if available
                if os.path.exists('models/model_metadata.json'):
                    with open('models/model_metadata.json', 'r') as f:
                        self.metadata = json.load(f)
                        self.feature_names = self.metadata.get('feature_names', [])
                
                self.model_loaded = True
                print("Pre-trained models loaded successfully!")
                
            else:
                print("Warning: Pre-trained models not found. Please run the training notebook first.")
                self.model_loaded = False
                
        except Exception as e:
            print(f"Error loading models: {e}")
            self.model_loaded = False
    
    def extract_features(self, log_text):
        """Extract features from a single log entry (matching training notebook)"""
        features = {}
        
        # Basic text features
        features['log_length'] = len(log_text)
        features['word_count'] = len(log_text.split())
        features['char_count'] = len(log_text)
        
        # Security-related keywords
        features['failed_count'] = len(re.findall(r'failed|fail', log_text, re.IGNORECASE))
        features['password_count'] = len(re.findall(r'password', log_text, re.IGNORECASE))
        features['root_count'] = len(re.findall(r'\\broot\\b', log_text, re.IGNORECASE))
        features['admin_count'] = len(re.findall(r'admin', log_text, re.IGNORECASE))
        features['sudo_count'] = len(re.findall(r'sudo|su:', log_text, re.IGNORECASE))
        features['error_count'] = len(re.findall(r'error|denied|invalid|unauthorized', log_text, re.IGNORECASE))
        features['connection_count'] = len(re.findall(r'connection|connect', log_text, re.IGNORECASE))
        features['attack_count'] = len(re.findall(r'attack|scan|probe|flood', log_text, re.IGNORECASE))
        
        # IP address patterns
        ip_pattern = r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'
        ip_matches = re.findall(ip_pattern, log_text)
        features['ip_count'] = len(ip_matches)
        features['has_external_ip'] = int(any(not ip.startswith(('192.168.', '10.', '172.')) for ip in ip_matches))
        
        # Port numbers
        port_pattern = r'port\\s+(\\d+)'
        port_matches = re.findall(port_pattern, log_text, re.IGNORECASE)
        features['port_count'] = len(port_matches)
        features['has_suspicious_port'] = int(any(int(port) in [22, 23, 21, 3389] for port in port_matches if port.isdigit()))
        
        # Time-based features
        time_pattern = r'(\\d{2}):(\\d{2}):(\\d{2})'
        time_match = re.search(time_pattern, log_text)
        if time_match:
            hour = int(time_match.group(1))
            features['hour'] = hour
            features['is_night_time'] = int(hour < 6 or hour > 22)
        else:
            features['hour'] = 12
            features['is_night_time'] = 0
        
        # Character analysis
        features['digit_ratio'] = sum(c.isdigit() for c in log_text) / len(log_text) if log_text else 0
        features['special_char_ratio'] = sum(not c.isalnum() and c != ' ' for c in log_text) / len(log_text) if log_text else 0
        features['uppercase_ratio'] = sum(c.isupper() for c in log_text) / len(log_text) if log_text else 0
        
        # HTTP status codes
        http_pattern = r'HTTP/1\\.[01]"\\s+(\\d{3})'
        http_match = re.search(http_pattern, log_text)
        if http_match:
            status_code = int(http_match.group(1))
            features['http_status'] = status_code
            features['is_http_error'] = int(status_code >= 400)
        else:
            features['http_status'] = 0
            features['is_http_error'] = 0
        
        return features
    
    def detect_threats(self, parsed_logs):
        """Detect threats in parsed logs using pre-trained models"""
        if not self.model_loaded:
            return {
                'threats_count': 0,
                'threat_types': [],
                'details': [],
                'risk_score': 0.0,
                'error': 'Models not loaded. Please run the training notebook first.'
            }
        
        if parsed_logs.empty:
            return {
                'threats_count': 0,
                'threat_types': [],
                'details': [],
                'risk_score': 0.0
            }
        
        try:
            # Extract features from parsed logs
            features = self._extract_features_from_parsed_logs(parsed_logs)
            
            if len(features) == 0:
                return {
                    'threats_count': 0,
                    'threat_types': [],
                    'details': [],
                    'risk_score': 0.0
                }
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Predict threats
            threat_predictions = self.rf_model.predict(features_scaled)
            threat_probabilities = self.rf_model.predict_proba(features_scaled)
            
            # Anomaly detection
            anomaly_predictions = self.isolation_forest.predict(features_scaled)
            
            # Combine results
            results = []
            threat_types = set()
            
            for i, (threat_pred, anomaly_pred) in enumerate(zip(threat_predictions, anomaly_predictions)):
                log_data = parsed_logs.iloc[i]
                
                is_threat = threat_pred == 1 or anomaly_pred == -1
                confidence = threat_probabilities[i][1] if threat_pred == 1 else 0.0
                
                if is_threat:
                    threat_type = self._classify_threat_type(log_data['raw_log'])
                    threat_types.add(threat_type)
                    
                    results.append({
                        'log': str(log_data['raw_log']),
                        'threat_type': str(threat_type),
                        'confidence': float(confidence),
                        'timestamp': str(log_data['timestamp']),
                        'source_ip': str(log_data['source_ip']),
                        'is_anomaly': bool(anomaly_pred == -1)
                    })
            
            # Calculate risk score
            risk_score = min(100.0, (len(results) / len(parsed_logs)) * 100 + 
                            sum(r['confidence'] for r in results) / max(len(results), 1) * 50)
            
            return {
                'threats_count': len(results),
                'threat_types': list(threat_types),
                'details': results,
                'risk_score': round(risk_score, 2)
            }
            
        except Exception as e:
            return {
                'threats_count': 0,
                'threat_types': [],
                'details': [],
                'risk_score': 0.0,
                'error': f'Error during threat detection: {str(e)}'
            }
    
    def _extract_features_from_parsed_logs(self, parsed_logs):
        """Extract features from parsed log DataFrame"""
        features = []
        
        for _, row in parsed_logs.iterrows():
            log = row['raw_log']
            feature_dict = self.extract_features(log)
            
            # Convert to ordered list matching training features
            if self.feature_names:
                feature_vector = [feature_dict.get(name, 0) for name in self.feature_names]
            else:
                # Fallback to basic features if metadata not available
                feature_vector = list(feature_dict.values())
            
            features.append(feature_vector)
        
        return np.array(features)
    
    def _classify_threat_type(self, log):
        """Classify the type of threat based on log content"""
        log_lower = log.lower()
        
        if any(word in log_lower for word in ['failed password', 'authentication failure', 'invalid user']):
            return 'brute_force'
        elif any(word in log_lower for word in ['sudo', 'su:', 'privilege']):
            return 'privilege_escalation'
        elif any(word in log_lower for word in ['scan', 'probe', 'nmap']):
            return 'network_scan'
        elif any(word in log_lower for word in ['dos', 'flood', 'too many']):
            return 'dos_attack'
        elif any(word in log_lower for word in ['denied', 'unauthorized', 'forbidden']):
            return 'unauthorized_access'
        else:
            return 'suspicious_activity'
    
    def get_model_stats(self):
        """Get model statistics"""
        if not self.model_loaded:
            return {'error': 'Models not loaded. Please run the training notebook first.'}
        
        stats = {
            'model_loaded': self.model_loaded,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names,
            'rf_estimators': self.rf_model.n_estimators if self.rf_model else 0,
        }
        
        # Add metadata if available
        if self.metadata:
            stats.update({
                'training_samples': self.metadata.get('training_samples', 'Unknown'),
                'test_samples': self.metadata.get('test_samples', 'Unknown'),
                'rf_accuracy': self.metadata.get('rf_accuracy', 'Unknown'),
                'if_accuracy': self.metadata.get('if_accuracy', 'Unknown'),
                'training_date': self.metadata.get('training_date', 'Unknown'),
                'model_version': self.metadata.get('model_version', '1.0')
            })
        
        return stats