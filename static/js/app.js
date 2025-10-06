// AI Cybersecurity Threat Detector - Frontend JavaScript

class ThreatDetectorApp {
    constructor() {
        this.init();
    }

    init() {
        this.loadModelStats();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Auto-resize textarea
        const logInput = document.getElementById('logInput');
        if (logInput) {
            logInput.addEventListener('input', this.autoResize);
        }
    }

    autoResize(event) {
        const textarea = event.target;
        textarea.style.height = 'auto';
        textarea.style.height = textarea.scrollHeight + 'px';
    }

    async loadModelStats() {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            
            if (stats.error) {
                document.getElementById('modelInfo').innerHTML = 
                    '<span class="text-warning">Models training...</span>';
                return;
            }

            document.getElementById('modelInfo').innerHTML = `
                <small class="text-muted">
                    <div>Features: ${stats.feature_count}</div>
                    <div>RF Trees: ${stats.rf_estimators}</div>
                    <div>Status: <span class="text-success">Ready</span></div>
                </small>
            `;
        } catch (error) {
            console.error('Error loading model stats:', error);
            document.getElementById('modelInfo').innerHTML = 
                '<span class="text-danger">Error loading stats</span>';
        }
    }

    async loadSampleLogs() {
        try {
            const response = await fetch('/api/sample-logs');
            const data = await response.json();
            
            if (data.error) {
                this.showAlert('Error loading sample logs: ' + data.error, 'danger');
                return;
            }

            document.getElementById('logInput').value = data.logs;
            this.showAlert('Sample logs loaded successfully!', 'success');
        } catch (error) {
            console.error('Error loading sample logs:', error);
            this.showAlert('Failed to load sample logs', 'danger');
        }
    }

    clearLogs() {
        document.getElementById('logInput').value = '';
        document.getElementById('results').style.display = 'none';
        this.updateQuickStats(0, 0, 0);
    }

    async analyzeLogs() {
        const logInput = document.getElementById('logInput');
        const logs = logInput.value.trim();

        if (!logs) {
            this.showAlert('Please enter some log data to analyze', 'warning');
            return;
        }

        // Show loading modal
        const loadingModalElement = document.getElementById('loadingModal');
        const loadingModal = new bootstrap.Modal(loadingModalElement);
        loadingModal.show();

        // Disable analyze button
        const analyzeBtn = document.getElementById('analyzeBtn');
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';

        // Record start time for minimum display duration
        const startTime = Date.now();
        const minDisplayTime = 2000; // 2 seconds minimum

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ logs: logs })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            console.log('Analysis result:', result);

            if (result.error) {
                // Ensure minimum display time before hiding modal
                const elapsedTime = Date.now() - startTime;
                const remainingTime = Math.max(0, minDisplayTime - elapsedTime);
                
                setTimeout(() => {
                    this.showAlert('Analysis error: ' + result.error, 'danger');
                    this.hideLoadingModal(loadingModal);
                    analyzeBtn.disabled = false;
                    analyzeBtn.innerHTML = '<i class="fas fa-play me-2"></i>Analyze Logs';
                }, remainingTime);
                return;
            }

            // Ensure minimum display time before showing results
            const elapsedTime = Date.now() - startTime;
            const remainingTime = Math.max(0, minDisplayTime - elapsedTime);
            
            setTimeout(() => {
                // Update UI with results
                this.displayResults(result);
                this.updateQuickStats(result.total_logs, result.threats_detected, result.risk_score);
                
                // Hide loading modal and restore button
                this.hideLoadingModal(loadingModal);
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="fas fa-play me-2"></i>Analyze Logs';
            }, remainingTime);

        } catch (error) {
            console.error('Error analyzing logs:', error);
            
            // Ensure minimum display time before hiding modal
            const elapsedTime = Date.now() - startTime;
            const remainingTime = Math.max(0, minDisplayTime - elapsedTime);
            
            setTimeout(() => {
                this.showAlert('Failed to analyze logs. Please try again.', 'danger');
                this.hideLoadingModal(loadingModal);
                analyzeBtn.disabled = false;
                analyzeBtn.innerHTML = '<i class="fas fa-play me-2"></i>Analyze Logs';
            }, remainingTime);
        }
    }

    displayResults(result) {
        const resultsSection = document.getElementById('results');
        const threatsList = document.getElementById('threatsList');
        const threatChart = document.getElementById('threatChart');

        // Show results section
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });

        // Display threats
        if (result.threats_detected === 0) {
            threatsList.innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    No threats detected in the analyzed logs. Your system appears secure!
                </div>
            `;
        } else {
            let threatsHtml = '';
            result.details.forEach(threat => {
                threatsHtml += this.createThreatCard(threat);
            });
            threatsList.innerHTML = threatsHtml;
        }

        // Create threat distribution chart
        this.createThreatChart(result.threat_types, threatChart);
    }

    createThreatCard(threat) {
        const confidencePercent = Math.round(threat.confidence * 100);
        const isAnomaly = threat.is_anomaly ? '<span class="badge bg-warning ms-2">Anomaly</span>' : '';
        
        return `
            <div class="threat-item">
                <div class="threat-header">
                    <div>
                        <span class="threat-type ${threat.threat_type}">${threat.threat_type.replace('_', ' ')}</span>
                        ${isAnomaly}
                    </div>
                    <div class="text-muted small">
                        <i class="fas fa-clock me-1"></i>${threat.timestamp}
                        <i class="fas fa-globe ms-2 me-1"></i>${threat.source_ip}
                    </div>
                </div>
                <div class="log-preview">${this.escapeHtml(threat.log)}</div>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${confidencePercent}%"></div>
                </div>
                <div class="text-end mt-2">
                    <small class="text-muted">Confidence: ${confidencePercent}%</small>
                </div>
            </div>
        `;
    }

    createThreatChart(threatTypes, container) {
        if (threatTypes.length === 0) {
            container.innerHTML = '<p class="text-muted text-center">No threats to display</p>';
            return;
        }

        // Count threat types
        const threatCounts = {};
        threatTypes.forEach(type => {
            threatCounts[type] = (threatCounts[type] || 0) + 1;
        });

        const data = [{
            values: Object.values(threatCounts),
            labels: Object.keys(threatCounts).map(type => type.replace('_', ' ')),
            type: 'pie',
            hole: 0.4,
            marker: {
                colors: ['#dc2626', '#d97706', '#7c3aed', '#be185d', '#059669', '#64748b']
            }
        }];

        const layout = {
            showlegend: true,
            height: 300,
            margin: { t: 20, b: 20, l: 20, r: 20 },
            font: { size: 12 }
        };

        Plotly.newPlot(container, data, layout, { responsive: true });
    }

    updateQuickStats(totalLogs, threatsDetected, riskScore) {
        document.getElementById('totalLogs').textContent = totalLogs;
        document.getElementById('threatsDetected').textContent = threatsDetected;
        
        const riskScoreElement = document.getElementById('riskScore');
        riskScoreElement.textContent = riskScore + '%';
        
        // Update risk score color
        riskScoreElement.className = 'stat-value';
        if (riskScore < 30) {
            riskScoreElement.classList.add('text-success');
        } else if (riskScore < 70) {
            riskScoreElement.classList.add('text-warning');
        } else {
            riskScoreElement.classList.add('text-danger');
        }
    }

    showAlert(message, type = 'info') {
        // Create alert element
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(alertDiv);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }

    hideLoadingModal(loadingModal) {
        try {
            // Try Bootstrap's hide method first
            loadingModal.hide();
            
            // Force cleanup after a short delay
            setTimeout(() => {
                // Remove any remaining backdrop
                const backdrops = document.querySelectorAll('.modal-backdrop');
                backdrops.forEach(backdrop => backdrop.remove());
                
                // Clean up body classes and styles
                document.body.classList.remove('modal-open');
                document.body.style.overflow = '';
                document.body.style.paddingRight = '';
                
                // Hide modal element directly if still visible
                const modalElement = document.getElementById('loadingModal');
                if (modalElement) {
                    modalElement.style.display = 'none';
                    modalElement.classList.remove('show');
                    modalElement.setAttribute('aria-hidden', 'true');
                }
            }, 100);
            
        } catch (error) {
            console.error('Error hiding modal:', error);
            
            // Fallback: force hide the modal
            const modalElement = document.getElementById('loadingModal');
            if (modalElement) {
                modalElement.style.display = 'none';
                modalElement.classList.remove('show');
            }
            
            // Clean up backdrop and body
            const backdrops = document.querySelectorAll('.modal-backdrop');
            backdrops.forEach(backdrop => backdrop.remove());
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
            document.body.style.paddingRight = '';
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Global functions for HTML onclick handlers
function scrollToAnalyzer() {
    document.getElementById('analyzer').scrollIntoView({ behavior: 'smooth' });
}

function loadSampleLogs() {
    app.loadSampleLogs();
}

function clearLogs() {
    app.clearLogs();
}

function analyzeLogs() {
    app.analyzeLogs();
}

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.app = new ThreatDetectorApp();
});