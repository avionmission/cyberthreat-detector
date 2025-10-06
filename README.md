# AI Cybersecurity Threat Detector

A production-ready web application that uses machine learning to analyze UNIX system logs and detect cybersecurity threats in real-time.

## Features

- **AI-Powered Detection**: Random Forest + Isolation Forest algorithms
- **Real-time Analysis**: Sub-second threat detection with confidence scoring
- **Interactive Dashboard**: Modern web interface with visualizations
- **Multiple Threat Types**: Brute force, privilege escalation, DoS attacks, and more
- **Risk Assessment**: Comprehensive scoring with visual indicators
- **UNIX Log Support**: Syslog, auth, apache, nginx formats

## Quick Start

### Option 1: Automated Setup
```bash
git clone https://github.com/avionmission/cyberthreat-detector
cd cyberthreat-detector
chmod +x run.sh
./run.sh
```

### Option 2: Manual Setup
```bash
# Setup environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Train models (first time only)
jupyter notebook train_models.ipynb

# Run application
python app.py
```

**Access**: Open http://localhost:5000 in your browser

## Usage

### Web Interface
1. **Load Sample Data**: Click "Load Sample" for example logs
2. **Paste Your Logs**: Add your system logs to the text area
3. **Analyze**: Click "Analyze Logs" for AI-powered detection
4. **Review Results**: View threats, risk scores, and visualizations

### API Usage
```bash
# Analyze logs
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"logs": "Jan 15 10:30:15 server1 sshd[1234]: Failed password for root from 10.0.0.1"}'

# Get sample data
curl http://localhost:5000/api/sample-logs

# Model statistics
curl http://localhost:5000/api/stats
```

## Threat Detection

**Supported Threats:**
- **Brute Force**: Failed login attempts, authentication failures
- **Privilege Escalation**: Sudo usage, user switching
- **Network Scanning**: Port scans, reconnaissance activities
- **DoS Attacks**: Connection flooding, rate limiting
- **Unauthorized Access**: Permission denied, access violations
- **Suspicious Activity**: Anomalous patterns and behaviors

**ML Models:**
- **Random Forest**: Multi-class threat classification (22 features)
- **Isolation Forest**: Anomaly detection for unknown threats
- **Performance**: High accuracy on LogHub dataset

## Project Structure

```
cybersecurity-threat-detector/
├── app.py                    # Main Flask application
├── train_models.ipynb        # ML model training notebook
├── demo.py                   # Standalone demo script
├── inspect_data.py          # Data inspection utilities
├── run.sh                   # Quick startup script
├── utils/                   # Core processing modules
├── templates/               # HTML templates
├── static/                  # Frontend assets (CSS, JS)
├── models/                  # Pre-trained ML models
└── data/                    # Training datasets (CSV)
```

## Development

### Training Data
The training notebook uses LogHub dataset and generates CSV files for inspection:
- **`data/training_dataset.csv`**: LogHub log entries with labels and threat types (5000+ samples)
- **`data/feature_dataset.csv`**: Extracted features with original logs and labels

To inspect training data:
```bash
python inspect_data.py
```

### Adding New Threat Types
1. Update `threat_indicators` in `utils/log_parser.py`
2. Add classification logic in `utils/threat_detector.py`
3. Update frontend styling in `static/css/style.css`
4. Regenerate training data by running the notebook

## Production Deployment

```bash
# Production server
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# Environment setup
export FLASK_ENV=production
export FLASK_DEBUG=False
```

**Recommendations:**
- Use reverse proxy (Nginx/Apache)
- Enable HTTPS/SSL
- Add monitoring and logging
- Implement rate limiting

## Performance

- **Startup**: Instant (pre-trained models)
- **Analysis**: Sub-second processing
- **Memory**: ~50-100MB
- **Accuracy**: High performance on LogHub data
- **Features**: 22 engineered security features

## Documentation

- **README.md**: This user guide
- **ARCHITECTURE.md**: Comprehensive technical documentation
- **Jupyter Notebook**: Interactive model training guide

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see the LICENSE file for details.