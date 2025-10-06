from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
from datetime import datetime
import json
import os
from utils.log_parser import LogParser
from utils.threat_detector import ThreatDetector
from utils.data_generator import generate_sample_logs

app = Flask(__name__)

# Initialize components
log_parser = LogParser()
threat_detector = ThreatDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    try:
        data = request.get_json()
        log_text = data.get('logs', '')
        
        if not log_text.strip():
            return jsonify({'error': 'No log data provided'}), 400
        
        # Parse logs
        parsed_logs = log_parser.parse_logs(log_text)
        
        # Detect threats
        results = threat_detector.detect_threats(parsed_logs)
        
        # Ensure all data is JSON serializable
        serializable_results = {
            'success': True,
            'total_logs': int(len(parsed_logs)),
            'threats_detected': int(results['threats_count']),
            'threat_types': list(results['threat_types']),
            'details': results['details'],
            'risk_score': float(results['risk_score'])
        }
        
        return jsonify(serializable_results)
    
    except Exception as e:
        import traceback
        print(f"Error in analyze_logs: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/sample-logs')
def get_sample_logs():
    try:
        sample_logs = generate_sample_logs()
        return jsonify({'logs': sample_logs})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    try:
        stats = threat_detector.get_model_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Ensure directories exist
    os.makedirs('data', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    print("AI Cybersecurity Threat Detector")
    print("=" * 40)
    
    # Check if models are loaded
    if threat_detector.model_loaded:
        print("Pre-trained models loaded successfully!")
        print("Starting web application...")
    else:
        print("Warning: Pre-trained models not found!")
        print("Please run the 'train_models.ipynb' notebook first to train the models.")
        print("Starting web application in demo mode...")
    
    # Use PORT environment variable for cloud deployment
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)