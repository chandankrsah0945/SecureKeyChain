document.addEventListener("DOMContentLoaded", function() {
    // Handle flash messages
    const alerts = document.querySelectorAll(".alert");
    if (alerts.length > 0) {
        setTimeout(() => {
            alerts.forEach(alert => {
                alert.style.opacity = "0";
                setTimeout(() => {
                    alert.style.display = "none";
                }, 300);
            });
        }, 3000);
    }

    // Sidebar menu active state
    const currentPath = window.location.pathname;
    const menuLinks = document.querySelectorAll(".sidebar-menu a");
    
    menuLinks.forEach(link => {
        if (link.getAttribute("href") === currentPath) {
            link.classList.add("active");
        }
    });

    // Search functionality
    const searchInput = document.querySelector(".search-box input");
    if (searchInput) {
        searchInput.addEventListener("input", function() {
            const searchTerm = this.value.toLowerCase();
            const items = document.querySelectorAll(".password-item");
            
            items.forEach(item => {
                const siteName = item.querySelector(".password-item-title").textContent.toLowerCase();
                const username = item.querySelector(".password-item-username").textContent.toLowerCase();
                
                if (siteName.includes(searchTerm) || username.includes(searchTerm)) {
                    item.style.display = "flex";
                } else {
                    item.style.display = "none";
                }
            });
        });
    }
});

// Show loading spinner during AJAX requests
document.addEventListener("ajaxStart", function() {
    document.getElementById("loading-spinner").style.display = "block";
});

document.addEventListener("ajaxStop", function() {
    document.getElementById("loading-spinner").style.display = "none";
});

// Search functionality
document.getElementById('passwordSearch').addEventListener('input', function() {
    const searchTerm = this.value.toLowerCase();
    const clearBtn = this.nextElementSibling;
    
    // Show/hide clear button
    if (searchTerm.length > 0) {
        clearBtn.style.display = 'block';
    } else {
        clearBtn.style.display = 'none';
    }
    
    // Filter passwords (implementation depends on your password list structure)
    // You would filter your password items here
});

// Clear search
document.querySelector('.search-clear').addEventListener('click', function() {
    const searchInput = this.previousElementSibling;
    searchInput.value = '';
    searchInput.focus();
    this.style.display = 'none';
    
    // Reset password list filtering
});

// Import button functionality
document.getElementById('importBtn').addEventListener('click', function() {
    // Implement import functionality
    alert('Import feature would be implemented here');
});

document.addEventListener('DOMContentLoaded', function() {
    // Modal functionality
    const modal = document.getElementById('passwordModal');
    const viewButtons = document.querySelectorAll('.view-password');
    const closeModal = document.querySelector('.close-modal');
    
    // View password buttons
    viewButtons.forEach(button => {
        button.addEventListener('click', function() {
            modal.style.display = 'flex';
        });
    });
    
    // Close modal
    closeModal.addEventListener('click', function() {
        modal.style.display = 'none';
    });
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
    
    // Toggle password visibility
    const togglePassword = document.querySelector('.toggle-password');
    const passwordInput = document.querySelector('.password-field input');
    
    togglePassword.addEventListener('click', function() {
        const icon = this.querySelector('i');
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            passwordInput.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    });
    
    // Copy password to clipboard
    const copyPassword = document.querySelector('.copy-password');
    
    copyPassword.addEventListener('click', function() {
        passwordInput.select();
        document.execCommand('copy');
        
        // Show feedback
        const originalIcon = this.innerHTML;
        this.innerHTML = '<i class="fas fa-check"></i>';
        
        setTimeout(() => {
            this.innerHTML = originalIcon;
        }, 2000);
    });
    
    // Search functionality
    const searchInput = document.querySelector('.search-container input');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const items = document.querySelectorAll('.password-item');
            
            items.forEach(item => {
                const siteName = item.querySelector('h3').textContent.toLowerCase();
                const username = item.querySelector('p').textContent.toLowerCase();
                
                if (siteName.includes(searchTerm) || username.includes(searchTerm)) {
                    item.style.display = 'flex';
                } else {
                    item.style.display = 'none';
                }
            });
        });
    }
    
    // Password strength indicator (example)
    const passwordStrength = document.createElement('div');
    passwordStrength.className = 'password-strength';
    document.querySelector('.password-field').appendChild(passwordStrength);
    
    passwordInput.addEventListener('input', function() {
        const strength = calculatePasswordStrength(this.value);
        updateStrengthIndicator(strength);
    });
    
    function calculatePasswordStrength(password) {
        // Simple strength calculation
        if (password.length === 0) return 0;
        if (password.length < 6) return 1;
        
        let strength = 0;
        if (/[a-z]/.test(password)) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^a-zA-Z0-9]/.test(password)) strength++;
        
        return Math.min(strength, 4);
    }
    
    function updateStrengthIndicator(strength) {
        const colors = ['#ea4335', '#fbbc05', '#fbbc05', '#34a853', '#34a853'];
        const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
        
        passwordStrength.textContent = labels[strength];
        passwordStrength.style.color = colors[strength];
    }
});