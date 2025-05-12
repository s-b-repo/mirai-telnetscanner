/**
 * Credentials Management JavaScript
 * Handles credential manipulation, validation, and related functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Add confirmation for credential deletion
    setupCredentialDeletionConfirmation();
    
    // Add validation for credential form
    setupCredentialFormValidation();
    
    // Add validation for batch credential form
    setupBatchCredentialValidation();
});

/**
 * Setup confirmation dialogs for credential deletion
 */
function setupCredentialDeletionConfirmation() {
    // Get all credential deletion forms
    const deleteForms = document.querySelectorAll('form[action^="/delete_credential/"]');
    
    deleteForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const username = this.closest('tr').querySelector('td:first-child').textContent;
            const password = this.closest('tr').querySelector('td:nth-child(2)').textContent;
            
            if (!confirm(`Are you sure you want to delete credential ${username}:${password}?`)) {
                e.preventDefault();
                return false;
            }
            
            return true;
        });
    });
}

/**
 * Setup validation for credential form
 */
function setupCredentialFormValidation() {
    const credForm = document.querySelector('form[action="/add_credential"]');
    
    if (credForm) {
        credForm.addEventListener('submit', function(e) {
            const usernameInput = document.getElementById('username');
            const passwordInput = document.getElementById('password');
            
            if (!usernameInput.value.trim()) {
                alert('Username cannot be empty');
                e.preventDefault();
                return false;
            }
            
            if (!passwordInput.value.trim()) {
                alert('Password cannot be empty');
                e.preventDefault();
                return false;
            }
            
            // Check length constraints
            if (usernameInput.value.length > 64) {
                alert('Username must be 64 characters or less');
                e.preventDefault();
                return false;
            }
            
            if (passwordInput.value.length > 64) {
                alert('Password must be 64 characters or less');
                e.preventDefault();
                return false;
            }
            
            return true;
        });
    }
}

/**
 * Setup validation for batch credential form
 */
function setupBatchCredentialValidation() {
    const batchForm = document.querySelector('form[action="/batch_add_credentials"]');
    
    if (batchForm) {
        batchForm.addEventListener('submit', function(e) {
            const credentialsText = document.getElementById('credentials').value.trim();
            
            // Check if empty
            if (!credentialsText) {
                alert('Please enter at least one credential pair');
                e.preventDefault();
                return false;
            }
            
            // Validate each line
            const lines = credentialsText.split('\n');
            let invalidLines = [];
            
            lines.forEach((line, index) => {
                line = line.trim();
                
                // Skip empty lines and comments
                if (!line || line.startsWith('#')) return;
                
                // Check format
                if (!line.includes(':')) {
                    invalidLines.push(`Line ${index + 1}: "${line}" is not in username:password format`);
                    return;
                }
                
                const [username, password] = line.split(':', 2);
                
                // Check username
                if (!username || username.length > 64) {
                    invalidLines.push(`Line ${index + 1}: Username must be 1-64 characters`);
                }
                
                // Check password
                if (!password || password.length > 64) {
                    invalidLines.push(`Line ${index + 1}: Password must be 1-64 characters`);
                }
            });
            
            if (invalidLines.length > 0) {
                alert('The following lines have issues:\n\n' + invalidLines.join('\n'));
                e.preventDefault();
                return false;
            }
            
            // Confirmation for large credential sets
            if (lines.length > 20) {
                if (!confirm(`You are adding ${lines.length} credential pairs. Continue?`)) {
                    e.preventDefault();
                    return false;
                }
            }
            
            return true;
        });
    }
}

/**
 * Setup toggles for enabling/disabling credentials
 */
function setupCredentialToggles() {
    const toggleForms = document.querySelectorAll('form[action^="/toggle_credential/"]');
    
    toggleForms.forEach(form => {
        const row = form.closest('tr');
        const statusBadge = row.querySelector('.badge');
        
        form.addEventListener('submit', function() {
            // Visual feedback while waiting for server response
            const isEnabled = statusBadge.textContent.trim() === 'Enabled';
            const toggleButton = this.querySelector('button');
            
            if (isEnabled) {
                toggleButton.innerHTML = '<i class="fas fa-toggle-on"></i>';
                toggleButton.classList.remove('btn-secondary');
                toggleButton.classList.add('btn-success');
                toggleButton.title = 'Enable';
                statusBadge.textContent = 'Disabled';
                statusBadge.classList.remove('bg-success');
                statusBadge.classList.add('bg-secondary');
            } else {
                toggleButton.innerHTML = '<i class="fas fa-toggle-off"></i>';
                toggleButton.classList.remove('btn-success');
                toggleButton.classList.add('btn-secondary');
                toggleButton.title = 'Disable';
                statusBadge.textContent = 'Enabled';
                statusBadge.classList.remove('bg-secondary');
                statusBadge.classList.add('bg-success');
            }
        });
    });
}

// Initialize toggle functionality
document.addEventListener('DOMContentLoaded', function() {
    setupCredentialToggles();
});
