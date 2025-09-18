/**
 * Patient Dashboard - แก้ไขปัญหาการค้างครบถ้วน
 * Version: 3.0 Final
 */

(function() {
    'use strict';

    // ป้องกันการรันซ้ำ
    if (window.patientDashboard) return;
    window.patientDashboard = true;

    let currentUser = null;
    let isInitialized = false;

    // Utility Functions
    function log(msg, type = 'info') {
        const prefix = type === 'error' ? '❌' : type === 'success' ? '✅' : 'ℹ️';
        console.log(`${prefix} ${msg}`);
    }

    function safeGetElement(selector) {
        try {
            return document.getElementById(selector) || document.querySelector(selector);
        } catch (e) {
            return null;
        }
    }

    function safeSetText(selector, text) {
        const el = safeGetElement(selector);
        if (el) el.textContent = text;
    }

    function safeHide(selector) {
        const el = safeGetElement(selector);
        if (el) {
            el.style.display = 'none';
            el.classList.add('hidden');
        }
    }

    function safeShow(selector) {
        const el = safeGetElement(selector);
        if (el) {
            el.style.display = '';
            el.classList.remove('hidden');
        }
    }

    // Authentication
    function getUserData() {
        try {
            // ลำดับความสำคัญ: sessionStorage > localStorage
            const sources = [
                () => sessionStorage.getItem('userData'),
                () => localStorage.getItem('userData'),
                () => localStorage.getItem('user')
            ];

            for (const getSource of sources) {
                const data = getSource();
                if (data) {
                    try {
                        const parsed = JSON.parse(data);
                        if (isValidUserData(parsed)) {
                            log('Found valid user data', 'success');
                            return parsed;
                        }
                    } catch (e) {
                        log('Invalid JSON data found', 'error');
                    }
                }
            }
            return null;
        } catch (error) {
            log(`Error getting user data: ${error.message}`, 'error');
            return null;
        }
    }

    function isValidUserData(data) {
        return data && typeof data === 'object' && 
               (data.user_id || data.phone || data.username || data.email);
    }

    function checkAuthentication() {
        log('Checking authentication...');
        
        const userData = getUserData();
        if (!userData) {
            log('No user data found - redirecting to login', 'error');
            redirectToLogin();
            return false;
        }

        // ตรวจสอบบทบาท (ยืดหยุ่น)
        const role = (userData.role || '').toLowerCase();
        const allowedRoles = ['patient', 'ผู้ป่วย', 'user', 'ผู้ใช้', ''];
        
        if (role && !allowedRoles.includes(role)) {
            log(`Invalid role: ${role} - redirecting`, 'error');
            redirectBasedOnRole(role);
            return false;
        }

        currentUser = userData;
        log('Authentication successful', 'success');
        return true;
    }

    function redirectBasedOnRole(role) {
        const routes = {
            'therapist': 'therapist-dashboard.html',
            'physiotherapist': 'therapist-dashboard.html',
            'นักกายภาพบำบัด': 'therapist-dashboard.html',
            'admin': 'admin-dashboard.html',
            'ผู้ดูแลระบบ': 'admin-dashboard.html'
        };

        const targetPage = routes[role] || 'login.html';
        setTimeout(() => window.location.href = targetPage, 1000);
    }

    function redirectToLogin() {
        clearUserData();
        showLoading('กำลังเปลี่ยนเส้นทางไปหน้าล็อกอิน...');
        setTimeout(() => window.location.href = 'login.html', 1500);
    }

    function clearUserData() {
        try {
            sessionStorage.removeItem('userData');
            localStorage.removeItem('userData');
            localStorage.removeItem('user');
            localStorage.removeItem('token');
            log('User data cleared');
        } catch (error) {
            log(`Error clearing data: ${error.message}`, 'error');
        }
    }

    // UI Functions
    function showLoading(message = 'กำลังโหลด...') {
        safeSetText('#loadingOverlay p', message);
        safeShow('#loadingOverlay');
    }

    function hideLoading() {
        const selectors = ['#loadingOverlay', '.loading-overlay', '.spinner'];
        selectors.forEach(safeHide);
    }

    function updateUserDisplay() {
        if (!currentUser) {
            setDefaultDisplay();
            return;
        }

        const displayName = getDisplayName(currentUser);
        const shortName = getShortName(currentUser);

        safeSetText('#userName', displayName);
        safeSetText('#userDisplayName', `Care ${shortName}`);

        log(`User display updated: ${displayName}`);
    }

    function getDisplayName(user) {
        const sources = [
            user.full_name,
            user.fullName,
            user.first_name && user.last_name ? `${user.first_name} ${user.last_name}` : null,
            user.firstName && user.lastName ? `${user.firstName} ${user.lastName}` : null,
            user.username,
            user.name,
            user.phone ? `ผู้ใช้ ${user.phone}` : null
        ];

        for (const name of sources) {
            if (name && typeof name === 'string' && name.trim()) {
                return name.trim();
            }
        }
        return 'ผู้ใช้งาน';
    }

    function getShortName(user) {
        return user.first_name || user.firstName || user.username || 'User';
    }

    function setDefaultDisplay() {
        safeSetText('#userName', 'ผู้ใช้งาน');
        safeSetText('#userDisplayName', 'Care User');
    }

    // Page Functions
    function initializePage() {
        if (isInitialized) return;
        
        log('Initializing page...');
        isInitialized = true;

        try {
            updateUserDisplay();
            setupEventListeners();
            initializeAnimations();
            hideLoading();
            log('Page initialized successfully', 'success');
        } catch (error) {
            log(`Initialization error: ${error.message}`, 'error');
            hideLoading();
        }
    }

    function setupEventListeners() {
        try {
            // Phone mockup click
            const phoneMockup = safeGetElement('.phone-mockup');
            if (phoneMockup) {
                phoneMockup.addEventListener('click', startAssessment);
                
                // Hover effects
                phoneMockup.addEventListener('mouseenter', () => {
                    phoneMockup.style.transform = 'translateY(-5px) scale(1.05)';
                    phoneMockup.style.transition = 'all 0.3s ease';
                });
                phoneMockup.addEventListener('mouseleave', () => {
                    phoneMockup.style.transform = 'translateY(0) scale(1)';
                });
            }

            // Step cards hover effects
            document.querySelectorAll('.step-card').forEach(card => {
                card.addEventListener('mouseenter', () => {
                    const icon = card.querySelector('.step-icon i');
                    if (icon) icon.style.transform = 'scale(1.1)';
                });
                card.addEventListener('mouseleave', () => {
                    const icon = card.querySelector('.step-icon i');
                    if (icon) icon.style.transform = 'scale(1)';
                });
            });

            log('Event listeners setup complete');
        } catch (error) {
            log(`Event listener error: ${error.message}`, 'error');
        }
    }

    function initializeAnimations() {
        try {
            const stepCards = document.querySelectorAll('.step-card');
            stepCards.forEach((card, index) => {
                card.style.opacity = '0';
                card.style.transform = 'translateY(30px)';
                card.style.transition = 'all 0.6s ease';
                
                setTimeout(() => {
                    card.style.opacity = '1';
                    card.style.transform = 'translateY(0)';
                }, (index + 1) * 150);
            });

            // Play button animation
            const playButton = safeGetElement('.play-button');
            if (playButton) {
                setInterval(() => {
                    playButton.style.transform = 'translateY(-2px)';
                    setTimeout(() => playButton.style.transform = 'translateY(0)', 1000);
                }, 3000);
            }

            log('Animations initialized');
        } catch (error) {
            log(`Animation error: ${error.message}`, 'error');
        }
    }

    // Navigation Functions
    function startAssessment() {
        log('Starting assessment...');
        try {
            const playButton = safeGetElement('.play-button');
            if (playButton) {
                playButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            }

            showLoading('กำลังเตรียมระบบประเมิน...');
            
            setTimeout(() => {
                window.location.href = 'index2-1.html';
            }, 1500);
        } catch (error) {
            log(`Assessment start error: ${error.message}`, 'error');
            hideLoading();
        }
    }

    function goToProfile() {
        log('Going to profile page...');
        try {
            showLoading('กำลังโหลดข้อมูลส่วนตัว...');
            setTimeout(() => {
                window.location.href = 'profile-edit.html';
            }, 1000);
        } catch (error) {
            log(`Profile navigation error: ${error.message}`, 'error');
            hideLoading();
        }
    }

    function exitSystem() {
        log('Exiting system...');
        if (confirm('คุณต้องการออกจากระบบหรือไม่?')) {
            try {
                showLoading('กำลังออกจากระบบ...');
                clearUserData();
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 1500);
            } catch (error) {
                log(`Exit error: ${error.message}`, 'error');
                window.location.href = 'login.html';
            }
        }
    }

    // Global Functions
    window.startAssessment = startAssessment;
    window.goToProfile = goToProfile;
    window.exitSystem = exitSystem;

    // Error Handlers
    window.addEventListener('error', (event) => {
        log(`Global error: ${event.error?.message}`, 'error');
        hideLoading();
    });

    window.addEventListener('unhandledrejection', (event) => {
        log(`Unhandled rejection: ${event.reason}`, 'error');
        event.preventDefault();
    });

    // Main Initialization
    function init() {
        log('Patient Dashboard starting...');
        
        // Emergency timeout
        const emergencyTimeout = setTimeout(() => {
            log('Emergency timeout - forcing page to work', 'error');
            hideLoading();
            setDefaultDisplay();
            isInitialized = true;
        }, 5000);

        try {
            if (checkAuthentication()) {
                initializePage();
                clearTimeout(emergencyTimeout);
            }
        } catch (error) {
            log(`Init error: ${error.message}`, 'error');
            clearTimeout(emergencyTimeout);
            redirectToLogin();
        }
    }

    // Start when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    log('Patient Dashboard script loaded');

})();