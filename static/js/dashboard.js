/**
 * Dashboard functionality for Telnet Scanner
 * Handles real-time updates and status monitoring
 */

// Global variables
let updateInterval;
let lastUpdateTime = new Date();

/**
 * Initialize dashboard functionality
 */
function initDashboard() {
    // Start automatic updates
    startStatusUpdates();
    
    // Update timestamps
    updateTimestamps();
    
    // Add event listeners for stop/start scanner forms
    setupEventListeners();
}

/**
 * Start automatic status updates via AJAX
 */
function startStatusUpdates() {
    // Clear any existing interval
    if (updateInterval) {
        clearInterval(updateInterval);
    }
    
    // Fetch initial status
    fetchScannerStatus();
    
    // Set interval for updates (every 2 seconds)
    updateInterval = setInterval(fetchScannerStatus, 2000);
}

/**
 * Fetch scanner status via AJAX
 */
function fetchScannerStatus() {
    fetch('/api/scanner_status')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            updateDashboard(data);
            lastUpdateTime = new Date();
        })
        .catch(error => {
            console.error('Error fetching scanner status:', error);
        });
}

/**
 * Update dashboard with latest status data
 */
function updateDashboard(data) {
    // Update statistics
    document.getElementById('scanned-count').textContent = data.scanned.toLocaleString();
    document.getElementById('attempts-count').textContent = data.attempts.toLocaleString();
    document.getElementById('hits-count').textContent = data.hits.toLocaleString();
    document.getElementById('rate').textContent = data.attempts_per_second.toFixed(1);
    
    // Update hit ratio
    const hitRatio = data.attempts > 0 ? (data.hits / data.attempts) * 100 : 0;
    const hitRatioBar = document.getElementById('hit-ratio-bar');
    hitRatioBar.style.width = hitRatio.toFixed(2) + '%';
    hitRatioBar.textContent = hitRatio.toFixed(2) + '% Success Rate';
    
    // Update status indicator
    const statusIndicator = document.getElementById('status-indicator');
    if (data.is_running) {
        statusIndicator.textContent = 'Running';
        statusIndicator.className = 'badge bg-success';
    } else {
        statusIndicator.textContent = 'Idle';
        statusIndicator.className = 'badge bg-secondary';
    }
    
    // Update elapsed time
    if (document.getElementById('elapsed-time')) {
        const hours = Math.floor(data.elapsed_time / 3600);
        const minutes = Math.floor((data.elapsed_time % 3600) / 60);
        const seconds = Math.floor(data.elapsed_time % 60);
        document.getElementById('elapsed-time').textContent = 
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
    
    // Update hit rate
    if (document.getElementById('hit-rate')) {
        const hitsPerMinute = data.elapsed_time > 0 ? (data.hits / data.elapsed_time) * 60 : 0;
        document.getElementById('hit-rate').textContent = hitsPerMinute.toFixed(2) + ' hits/min';
    }
    
    // Update time since last update
    document.getElementById('update-time').textContent = 'just now';
}

/**
 * Update relative timestamps periodically
 */
function updateTimestamps() {
    setInterval(() => {
        // Update "Last updated" timestamp
        const secondsAgo = Math.floor((new Date() - lastUpdateTime) / 1000);
        let updateText = 'just now';
        
        if (secondsAgo > 60) {
            updateText = Math.floor(secondsAgo / 60) + ' min ago';
        } else if (secondsAgo > 1) {
            updateText = secondsAgo + ' sec ago';
        }
        
        document.getElementById('update-time').textContent = updateText;
    }, 10000); // Every 10 seconds
}

/**
 * Setup event listeners for scanner forms
 */
function setupEventListeners() {
    // Add confirmation for stopping scanner
    const stopForm = document.querySelector('form[action="/stop_scan"]');
    if (stopForm) {
        stopForm.addEventListener('submit', function(e) {
            if (!confirm('Are you sure you want to stop the scanner?')) {
                e.preventDefault();
                return false;
            }
            return true;
        });
    }
    
    // Add validation for scanner settings
    const startScanForm = document.querySelector('form[action="/start_scan"]');
    if (startScanForm) {
        startScanForm.addEventListener('submit', function(e) {
            const batchSize = parseInt(document.getElementById('batch_size').value);
            const maxConcurrent = parseInt(document.getElementById('max_concurrent').value);
            
            if (batchSize < 10 || batchSize > 1000) {
                alert('Batch size must be between 10 and 1000');
                e.preventDefault();
                return false;
            }
            
            if (maxConcurrent < 10 || maxConcurrent > 200) {
                alert('Max concurrent connections must be between 10 and 200');
                e.preventDefault();
                return false;
            }
            
            return true;
        });
    }
    
    // Add validation for IP range input
    const ipRangeForm = document.querySelector('form[action="/scan_specific_range"]');
    if (ipRangeForm) {
        ipRangeForm.addEventListener('submit', function(e) {
            const ipRange = document.getElementById('ip_range').value.trim();
            const cidrPattern = /^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$/;
            
            if (!cidrPattern.test(ipRange)) {
                alert('Please enter a valid CIDR notation (e.g., 192.168.1.0/24)');
                e.preventDefault();
                return false;
            }
            
            return true;
        });
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the dashboard page
    if (document.getElementById('scanned-count')) {
        initDashboard();
    }
});
