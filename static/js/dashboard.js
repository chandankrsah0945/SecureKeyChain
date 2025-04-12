// static/js/dashboard.js
document.addEventListener('DOMContentLoaded', function() {
    // View password functionality
    function viewPassword(credentialId) {
        fetch(`/get_original_password/${credentialId}`)
            .then(response => response.json())
            .then(data => {
                if (data.password) {
                    const modal = new bootstrap.Modal(document.getElementById('passwordModal'));
                    
                    // Set modal content
                    document.getElementById('modalSiteName').textContent = document.querySelector(`[data-id="${credentialId}"]`).closest('.password-item').querySelector('h4').textContent;
                    document.getElementById('modalUsername').textContent = document.querySelector(`[data-id="${credentialId}"]`).closest('.password-item').querySelector('p').textContent;
                    document.getElementById('modalPassword').value = data.password;
                    
                    modal.show();
                }
            });
    }
    
    // Toggle password visibility in modal
    const togglePassword = document.getElementById('togglePassword');
    if (togglePassword) {
        togglePassword.addEventListener('click', function() {
            const passwordInput = document.getElementById('modalPassword');
            const icon = this.querySelector('i');
            const text = this.querySelector('span');
            
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
                text.textContent = 'Hide';
            } else {
                passwordInput.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
                text.textContent = 'Show';
            }
        });
    }
    
    // Copy password to clipboard
    const copyPassword = document.getElementById('copyPassword');
    if (copyPassword) {
        copyPassword.addEventListener('click', function() {
            const passwordInput = document.getElementById('modalPassword');
            passwordInput.select();
            document.execCommand('copy');
            
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-check"></i> Copied!';
            
            setTimeout(() => {
                this.innerHTML = originalText;
            }, 2000);
        });
    }
    
    // Make viewPassword function global
    window.viewPassword = viewPassword;
    
    // Handle flash messages
    const alerts = document.querySelectorAll('.alert');
    if (alerts.length > 0) {
        alerts.forEach(alert => {
            setTimeout(() => {
                alert.style.opacity = '0';
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 300);
            }, 3000);
        });
    }
});