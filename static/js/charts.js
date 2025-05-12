/**
 * Chart functionality for Telnet Scanner
 * Creates and manages charts for statistics display
 */

// Global chart instances
let scannerChart = null;

/**
 * Initialize scanner charts on the dashboard
 */
function initScannerCharts() {
    // Create scanner performance chart
    createScannerChart();
    
    // Fetch initial data and start updates
    fetchChartData();
    setInterval(fetchChartData, 30000); // Update every 30 seconds
}

/**
 * Create the main scanner performance chart
 */
function createScannerChart() {
    const ctx = document.getElementById('scannerChart');
    if (!ctx) return;
    
    // Create Chart.js instance with initial empty data
    scannerChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'IPs Scanned',
                    data: [],
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    borderWidth: 2,
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Login Attempts',
                    data: [],
                    borderColor: '#fd7e14',
                    backgroundColor: 'rgba(253, 126, 20, 0.1)',
                    borderWidth: 2,
                    tension: 0.2,
                    fill: true
                },
                {
                    label: 'Successful Logins',
                    data: [],
                    borderColor: '#198754',
                    backgroundColor: 'rgba(25, 135, 84, 0.1)',
                    borderWidth: 2,
                    tension: 0.2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        boxWidth: 6
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false
                }
            },
            scales: {
                x: {
                    grid: {
                        display: false
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    }
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            },
            animation: {
                duration: 800
            }
        }
    });
}

/**
 * Fetch chart data from the API
 */
function fetchChartData() {
    // Only proceed if chart exists
    if (!scannerChart) return;
    
    fetch('/api/stats_history')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            updateCharts(data);
        })
        .catch(error => {
            console.error('Error fetching chart data:', error);
        });
}

/**
 * Update charts with new data
 */
function updateCharts(data) {
    if (!scannerChart || !data.timestamps) return;
    
    // Update main scanner chart data
    scannerChart.data.labels = data.timestamps;
    scannerChart.data.datasets[0].data = data.ips_scanned;
    scannerChart.data.datasets[1].data = data.login_attempts;
    scannerChart.data.datasets[2].data = data.successful_logins;
    
    // Add scan rate dataset if we have enough data points
    if (data.scan_rate && data.scan_rate.length > 0) {
        // Check if we already have the scan rate dataset
        let scanRateDataset = scannerChart.data.datasets.find(ds => ds.label === 'Scan Rate');
        
        if (!scanRateDataset) {
            // Create the dataset if it doesn't exist
            scanRateDataset = {
                label: 'Scan Rate',
                data: data.scan_rate,
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                borderWidth: 2,
                borderDash: [5, 5],
                tension: 0.2,
                fill: false,
                yAxisID: 'y1'
            };
            
            // Add the dataset
            scannerChart.data.datasets.push(scanRateDataset);
            
            // Add the second Y axis for scan rate
            scannerChart.options.scales.y1 = {
                position: 'right',
                beginAtZero: true,
                grid: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Attempts/sec'
                }
            };
        } else {
            // Update existing dataset
            scanRateDataset.data = data.scan_rate;
        }
    }
    
    // Update the chart
    scannerChart.update();
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on a page with charts
    if (document.getElementById('scannerChart')) {
        initScannerCharts();
    }
});
