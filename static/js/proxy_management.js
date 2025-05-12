// Proxy Management JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Show/hide internet scan options based on selected scan type
    const localRadio = document.getElementById('scanTypeLocal');
    const internetRadio = document.getElementById('scanTypeInternet');
    const internetOptions = document.getElementById('internetScanOptions');
    
    if (localRadio && internetRadio && internetOptions) {
        function updateOptions() {
            internetOptions.style.display = internetRadio.checked ? 'block' : 'none';
        }
        
        // Initial update
        updateOptions();
        
        // Add event listeners
        localRadio.addEventListener('change', updateOptions);
        internetRadio.addEventListener('change', updateOptions);
    }
    
    // Add click handler for proxy test buttons
    const testButtons = document.querySelectorAll('.test-proxy-btn');
    testButtons.forEach(button => {
        button.addEventListener('click', function() {
            const proxyId = this.getAttribute('data-proxy-id');
            if (proxyId) {
                // Show spinner
                this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
                this.disabled = true;
                
                // Submit the form
                this.closest('form').submit();
            }
        });
    });
});