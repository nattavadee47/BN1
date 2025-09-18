/**
 * ========================================
 * Login System - ระบบเข้าสู่ระบบ
 * login.js - JavaScript สำหรับหน้าล็อกอิน
 * ========================================
 */

class LoginSystem {
    constructor() {
        // Configuration
        this.config = {
            apiBaseUrl: 'http://localhost:3000/api/auth',
            isLoading: false,
            maxLoginAttempts: 5,
            lockoutDuration: 15 * 60 * 1000, // 15 minutes
            validationRules: this.getValidationRules()
        };

        // Initialize
        this.init();
    }

    /**
     * Initialize the login system
     */
    init() {
        this.bindEvents();
        this.checkExistingSession();
        this.checkConnection();
        
        console.log('✅ Login System initialized');
    }

    /**
     * Get validation rules
     */
    getValidationRules() {
        return {
            username: {
                required: true,
                pattern: /^[0-9]{10}$/,
                message: 'เบอร์โทรศัพท์ต้องเป็นตัวเลข 10 หลัก'
            },
            password: {
                required: true,
                minLength: 6,
                message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
            }
        };
    }

    /**
     * Bind event listeners
     */
    bindEvents() {
        // Form submission
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', this.handleLogin.bind(this));
        }

        // Password toggle
        const passwordToggle = document.getElementById('passwordToggle');
        if (passwordToggle) {
            passwordToggle.addEventListener('click', this.togglePassword.bind(this));
        }

        // Register button
        const registerBtn = document.getElementById('registerBtn');
        if (registerBtn) {
            registerBtn.addEventListener('click', this.redirectToRegister.bind(this));
        }

        // Real-time validation
        this.bindValidationEvents();

        // Enter key support
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !this.config.isLoading) {
                const submitBtn = document.getElementById('submitBtn');
                if (submitBtn && !submitBtn.disabled) {
                    submitBtn.click();
                }
            }
        });

        // Escape key to close modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModals();
            }
        });
    }

    /**
     * Bind validation events
     */
    bindValidationEvents() {
        const inputs = ['username', 'password'];
        
        inputs.forEach(inputId => {
            const input = document.getElementById(inputId);
            if (input) {
                input.addEventListener('blur', () => this.validateField(inputId));
                input.addEventListener('input', () => this.clearFieldError(inputId));
            }
        });
    }

    /**
     * Check for existing session
     */
    checkExistingSession() {
        const userData = this.getStoredUserData();
        if (userData && this.isValidSession(userData)) {
            console.log('🔄 Existing session found, redirecting...');
            this.redirectToDashboard(userData);
        }
    }

    /**
     * Get stored user data
     */
    getStoredUserData() {
        try {
            const sessionData = sessionStorage.getItem('userData');
            const localData = localStorage.getItem('userData');
            
            if (sessionData) {
                return JSON.parse(sessionData);
            } else if (localData) {
                return JSON.parse(localData);
            }
        } catch (error) {
            console.warn('Failed to parse stored user data:', error);
        }
        
        return null;
    }

    /**
     * Check if session is valid
     */
    isValidSession(userData) {
        if (!userData || !userData.loginTime) {
            return false;
        }

        const loginTime = new Date(userData.loginTime);
        const now = new Date();
        const timeDiff = now - loginTime;
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours

        return timeDiff < maxAge;
    }

    /**
     * Handle login form submission
     */
    async handleLogin(event) {
        event.preventDefault();
        
        if (this.config.isLoading) return;

        // Check lockout
        if (this.isLockedOut()) {
            const timeLeft = this.getLockoutTimeLeft();
            this.showErrorModal(`บัญชีถูกล็อค กรุณารอ ${Math.ceil(timeLeft / 60000)} นาที`);
            return;
        }

        const username = document.getElementById('username')?.value.trim();
        const password = document.getElementById('password')?.value;
        const remember = document.getElementById('remember')?.checked;

        // Validate input
        if (!this.validateLoginForm(username, password)) {
            return;
        }

        this.setLoadingState(true);

        try {
            console.log('🔄 Attempting login...', { username });

            const response = await fetch(`${this.config.apiBaseUrl}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    phone: username,
                    password: password
                })
            });

            const result = await response.json();

            if (response.ok && result.success) {
                console.log('✅ Login successful:', result.user);
                this.loginSuccess(result, remember);
                this.clearFailedAttempts();
            } else {
                console.log('❌ Login failed:', result.message);
                this.loginFailed(result.message || 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง');
            }

        } catch (error) {
            console.error('❌ Network Error:', error);
            
            // Fallback to localStorage
            console.log('⚠️ API unavailable, trying localStorage...');
            this.fallbackLogin(username, password, remember);
            
        } finally {
            this.setLoadingState(false);
        }
    }

    /**
     * Validate login form
     */
    validateLoginForm(username, password) {
        if (!username || !password) {
            this.showErrorModal('กรุณากรอกเบอร์โทรศัพท์และรหัสผ่าน');
            return false;
        }

        if (!this.validateField('username') || !this.validateField('password')) {
            return false;
        }

        return true;
    }

    /**
     * Validate a single field
     */
    validateField(fieldId) {
        const field = document.getElementById(fieldId);
        if (!field) return false;

        const value = field.value.trim();
        const rule = this.config.validationRules[fieldId];

        if (!rule) return true;

        // Clear previous state
        this.clearFieldError(fieldId);

        // Required validation
        if (rule.required && !value) {
            this.showFieldError(fieldId, rule.message);
            return false;
        }

        // Pattern validation
        if (value && rule.pattern && !rule.pattern.test(value)) {
            this.showFieldError(fieldId, rule.message);
            return false;
        }

        // Min length validation
        if (value && rule.minLength && value.length < rule.minLength) {
            this.showFieldError(fieldId, rule.message);
            return false;
        }

        // Show success state
        this.showFieldSuccess(fieldId);
        return true;
    }

    /**
     * Show field error
     */
    showFieldError(fieldId, message) {
        const formGroup = document.getElementById(fieldId)?.closest('.form-group');
        if (!formGroup) return;

        formGroup.classList.remove('success');
        formGroup.classList.add('error');

        const errorElement = formGroup.querySelector('.error-message');
        if (errorElement) {
            errorElement.textContent = message;
        }
    }

    /**
     * Show field success
     */
    showFieldSuccess(fieldId) {
        const formGroup = document.getElementById(fieldId)?.closest('.form-group');
        if (!formGroup) return;

        formGroup.classList.remove('error');
        formGroup.classList.add('success');
    }

    /**
     * Clear field error
     */
    clearFieldError(fieldId) {
        const formGroup = document.getElementById(fieldId)?.closest('.form-group');
        if (!formGroup) return;

        formGroup.classList.remove('error', 'success');

        const errorElement = formGroup.querySelector('.error-message');
        if (errorElement) {
            errorElement.textContent = '';
        }
    }

    /**
     * Fallback login using localStorage
     */
    fallbackLogin(username, password, remember) {
        try {
            const users = JSON.parse(localStorage.getItem('registrationBackup') || '[]');
            const user = users.find(u => 
                u.phone === username && 
                u.password === password
            );

            if (user) {
                // Convert to API format
                const apiResponse = {
                    success: true,
                    user: {
                        user_id: user.id,
                        phone: user.phone,
                        full_name: `${user.first_name} ${user.last_name}`,
                        role: user.role
                    },
                    token: 'fallback_token_' + Date.now()
                };
                
                this.loginSuccess(apiResponse, remember);
                this.clearFailedAttempts();
            } else {
                this.loginFailed('เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง');
            }
        } catch (error) {
            console.error('Fallback login failed:', error);
            this.loginFailed('ไม่สามารถเข้าสู่ระบบได้ กรุณาลองใหม่อีกครั้ง');
        }
    }

    /**
     * Handle successful login
     */
    loginSuccess(result, remember) {
        const userData = {
            user_id: result.user.user_id,
            phone: result.user.phone,
            full_name: result.user.full_name,
            role: result.user.role,
            token: result.token,
            loginTime: new Date().toISOString()
        };

        // Store user data
        if (remember) {
            localStorage.setItem('userData', JSON.stringify(userData));
        } else {
            sessionStorage.setItem('userData', JSON.stringify(userData));
        }

        // Record login history
        this.recordLoginHistory(userData);

        // Show success modal
        this.showSuccessModal();

        // Redirect after delay
        setTimeout(() => {
            this.redirectToDashboard(userData);
        }, 2000);
    }

    /**
     * Handle failed login
     */
    loginFailed(message) {
        this.incrementFailedAttempts();
        
        const attempts = this.getFailedAttempts();
        const remaining = this.config.maxLoginAttempts - attempts;

        if (remaining <= 0) {
            this.lockAccount();
            message = `เข้าสู่ระบบล้มเหลวหลายครั้ง บัญชีถูกล็อค ${this.config.lockoutDuration / 60000} นาที`;
        } else if (remaining <= 2) {
            message += ` (เหลือ ${remaining} ครั้ง)`;
        }

        this.showErrorModal(message);
    }

    /**
     * Redirect to appropriate dashboard
     */
    redirectToDashboard(userData) {
        let redirectUrl = 'index2.html'; // default

        switch (userData.role) {
            case 'Patient':
            case 'ผู้ป่วย':
                redirectUrl = 'patient-dashboard.html';
                break;
            case 'Physiotherapist':
            case 'นักกายภาพบำบัด':
                redirectUrl = 'therapist-dashboard.html';
                break;
            case 'Admin':
                redirectUrl = 'admin-dashboard.html';
                break;
            default:
                redirectUrl = 'patient-dashboard.html';
        }

        console.log(`🚀 Redirecting to ${redirectUrl}`);
        window.location.href = redirectUrl;
    }

    /**
     * Record login history
     */
    recordLoginHistory(userData) {
        try {
            const history = JSON.parse(localStorage.getItem('loginHistory') || '[]');
            history.push({
                userId: userData.user_id,
                phone: userData.phone,
                loginTime: userData.loginTime,
                userAgent: navigator.userAgent,
                success: true
            });

            // Keep only last 50 records
            if (history.length > 50) {
                history.splice(0, history.length - 50);
            }

            localStorage.setItem('loginHistory', JSON.stringify(history));
        } catch (error) {
            console.warn('Failed to record login history:', error);
        }
    }

    /**
     * Toggle password visibility
     */
    togglePassword() {
        const passwordInput = document.getElementById('password');
        const passwordToggle = document.getElementById('passwordToggle');
        const icon = passwordToggle?.querySelector('i');

        if (!passwordInput || !icon) return;

        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    /**
     * Set loading state
     */
    setLoadingState(loading) {
        this.config.isLoading = loading;

        const loadingOverlay = document.getElementById('loadingOverlay');
        const submitBtn = document.getElementById('submitBtn');
        const btnText = submitBtn?.querySelector('.btn-text');
        const btnIcon = submitBtn?.querySelector('.btn-icon');

        // Loading overlay
        if (loadingOverlay) {
            loadingOverlay.style.display = loading ? 'flex' : 'none';
        }

        // Submit button
        if (submitBtn) {
            submitBtn.disabled = loading;
            submitBtn.classList.toggle('loading', loading);
        }

        if (btnText) {
            btnText.textContent = loading ? 'กำลังเข้าสู่ระบบ...' : 'เข้าสู่ระบบ';
        }

        if (btnIcon) {
            btnIcon.className = loading ? 'btn-icon fas fa-spinner fa-spin' : 'btn-icon fas fa-arrow-right';
        }

        // Disable form inputs
        const formInputs = document.querySelectorAll('#loginForm input, #loginForm button');
        formInputs.forEach(input => {
            input.disabled = loading;
        });
    }

    /**
     * Show success modal
     */
    showSuccessModal() {
        const modal = document.getElementById('successModal');
        if (modal) {
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    /**
     * Show error modal
     */
    showErrorModal(message) {
        const modal = document.getElementById('errorModal');
        const messageElement = document.getElementById('errorMessage');
        
        if (modal && messageElement) {
            messageElement.textContent = message;
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    /**
     * Close all modals
     */
    closeModals() {
        const modals = document.querySelectorAll('.modal-overlay');
        modals.forEach(modal => {
            modal.style.display = 'none';
        });
        document.body.style.overflow = '';
    }

    /**
     * Redirect to registration page
     */
    redirectToRegister() {
        window.location.href = 'Useraccoun.html';
    }

    /**
     * Check server connection
     */
    async checkConnection() {
        const statusElement = document.getElementById('connectionStatus');
        const statusText = statusElement?.querySelector('.status-text');

        if (!statusElement) return;

        try {
            statusText.textContent = 'กำลังตรวจสอบ...';
            statusElement.className = 'connection-status';

            const healthUrl = this.config.apiBaseUrl.replace('/api/auth', '/health');
            const response = await fetch(healthUrl, {
                method: 'GET',
                headers: { 'Accept': 'application/json' },
                timeout: 5000
            });

            if (response.ok) {
                statusText.textContent = 'เชื่อมต่อแล้ว';
                statusElement.classList.add('connected');
                
                // Hide status after 3 seconds
                setTimeout(() => {
                    statusElement.style.display = 'none';
                }, 3000);
            } else {
                throw new Error('Server not responding');
            }

        } catch (error) {
            console.error('Connection check failed:', error);
            statusText.textContent = 'ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์';
            statusElement.classList.add('disconnected');
        }
    }

    /**
     * Failed attempts management
     */
    getFailedAttempts() {
        const attempts = localStorage.getItem('loginAttempts');
        return attempts ? parseInt(attempts) : 0;
    }

    incrementFailedAttempts() {
        const attempts = this.getFailedAttempts() + 1;
        localStorage.setItem('loginAttempts', attempts.toString());
        localStorage.setItem('lastFailedAttempt', Date.now().toString());
    }

    clearFailedAttempts() {
        localStorage.removeItem('loginAttempts');
        localStorage.removeItem('lastFailedAttempt');
        localStorage.removeItem('accountLocked');
    }

    isLockedOut() {
        const locked = localStorage.getItem('accountLocked');
        if (!locked) return false;

        const lockTime = parseInt(locked);
        const now = Date.now();
        
        if (now - lockTime < this.config.lockoutDuration) {
            return true;
        } else {
            // Lockout expired, clear it
            this.clearFailedAttempts();
            return false;
        }
    }

    lockAccount() {
        localStorage.setItem('accountLocked', Date.now().toString());
    }

    getLockoutTimeLeft() {
        const locked = localStorage.getItem('accountLocked');
        if (!locked) return 0;

        const lockTime = parseInt(locked);
        const elapsed = Date.now() - lockTime;
        return Math.max(0, this.config.lockoutDuration - elapsed);
    }

    /**
     * Static methods for external use
     */
    static checkAuthStatus() {
        const sessionData = sessionStorage.getItem('userData');
        const localData = localStorage.getItem('userData');
        
        try {
            if (sessionData) {
                return JSON.parse(sessionData);
            } else if (localData) {
                return JSON.parse(localData);
            }
        } catch (error) {
            console.warn('Failed to parse stored auth data:', error);
        }
        
        return null;
    }

    static logout() {
        sessionStorage.removeItem('userData');
        localStorage.removeItem('userData');
        window.location.href = 'login.html';
    }
}

// Global functions for HTML onclick handlers
window.closeErrorModal = function() {
    if (window.loginSystem) {
        window.loginSystem.closeModals();
    }
};

window.redirectToRegister = function() {
    window.location.href = 'Useraccoun.html';
};

window.testConnection = function() {
    if (window.loginSystem) {
        window.loginSystem.checkConnection();
    }
};

// Initialize system when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing Login System...');
    window.loginSystem = new LoginSystem();
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = LoginSystem;
}