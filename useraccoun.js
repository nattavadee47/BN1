// ========================================
// User Account Registration System - แก้ไขปัญหาการสมัครสมาชิก
// useraccoun.js - เวอร์ชันสมบูรณ์แบบ
// ========================================

class RegistrationSystem {
    constructor() {
        this.config = {
            apiBaseUrl: 'http://localhost:3000/api/auth',
            currentStep: 1,
            totalSteps: 2,
            formData: {},
            validationRules: this.getValidationRules()
        };
        this.init();
    }

    init() {
        console.log('🚀 Starting Registration System initialization...');
        
        this.bindEvents();
        
        // รอให้ DOM โหลดเสร็จก่อนสร้าง dropdowns
        setTimeout(() => {
            console.log('📅 Setting up birth date fields...');
            this.debugBirthDateElements();
            this.populateBirthFields();
            this.setupBirthDateValidation();
        }, 100);
        
        this.setupPasswordStrength();
        this.showStep(1);
        console.log('✅ Registration System initialized');
    }

    getValidationRules() {
        return {
            phone: {
                required: true,
                pattern: /^[0-9]{10}$/,
                message: 'เบอร์โทรศัพท์ต้องเป็นตัวเลข 10 หลัก'
            },
            password: {
                required: true,
                minLength: 6,
                message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
            },
            confirmPassword: {
                required: true,
                match: 'password',
                message: 'รหัสผ่านไม่ตรงกัน'
            },
            firstName: {
                required: true,
                message: 'กรุณากรอกชื่อ'
            },
            lastName: {
                required: true,
                message: 'กรุณากรอกนามสกุล'
            },
            birthDate: {
                required: true,
                message: 'กรุณาเลือกวันเกิด'
            },
            birthMonth: {
                required: true,
                message: 'กรุณาเลือกเดือนเกิด'
            },
            birthYear: {
                required: true,
                message: 'กรุณาเลือกปีเกิด'
            },
            gender: {
                required: true,
                message: 'กรุณาเลือกเพศ'
            },
            userType: {
                required: true,
                message: 'กรุณาเลือกประเภทผู้ใช้'
            }
        };
    }

    bindEvents() {
        // Form submission
        const form = document.getElementById('signupForm');
        if (form) {
            form.addEventListener('submit', this.handleSubmit.bind(this));
        }

        // Step navigation
        const nextBtn = document.getElementById('nextButton');
        const backBtn = document.getElementById('backButton');
        
        if (nextBtn) {
            nextBtn.addEventListener('click', this.nextStep.bind(this));
        }
        if (backBtn) {
            backBtn.addEventListener('click', this.prevStep.bind(this));
        }

        // Password toggles
        document.querySelectorAll('.password-toggle').forEach(btn => {
            btn.addEventListener('click', this.togglePassword.bind(this));
        });

        // User type change
        const userTypeSelect = document.getElementById('userType');
        if (userTypeSelect) {
            userTypeSelect.addEventListener('change', this.handleUserTypeChange.bind(this));
        }

        // BMI calculation
        const weightInput = document.getElementById('weight');
        const heightInput = document.getElementById('height');
        if (weightInput) weightInput.addEventListener('input', this.calculateBMI.bind(this));
        if (heightInput) heightInput.addEventListener('input', this.calculateBMI.bind(this));

        // Phone formatting
        const phoneInput = document.getElementById('phone');
        if (phoneInput) {
            phoneInput.addEventListener('input', this.formatPhoneNumber.bind(this));
        }

        // Password strength
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.addEventListener('input', this.updatePasswordStrength.bind(this));
        }

        // Real-time validation
        this.setupRealTimeValidation();
    }

    debugBirthDateElements() {
        console.log('🔍 Debugging birth date elements...');
        
        const daySelect = document.getElementById('birthDate');
        const monthSelect = document.getElementById('birthMonth');
        const yearSelect = document.getElementById('birthYear');
        
        console.log('Day select:', daySelect);
        console.log('Day options count:', daySelect ? daySelect.children.length : 'Element not found');
        
        console.log('Month select:', monthSelect);
        console.log('Month options count:', monthSelect ? monthSelect.children.length : 'Element not found');
        
        console.log('Year select:', yearSelect);
        console.log('Year options count:', yearSelect ? yearSelect.children.length : 'Element not found');
        
        if (!daySelect || !monthSelect || !yearSelect) {
            console.error('❌ Some birth date elements are missing from DOM');
            console.log('🔄 Retrying in 500ms...');
            setTimeout(() => {
                this.populateBirthFields();
                this.setupBirthDateValidation();
            }, 500);
        } else {
            console.log('✅ All birth date elements found');
        }
    }

    populateBirthFields() {
        console.log('📅 populateBirthFields() called');
        
        // สร้างตัวเลือกวัน (1-31)
        const daySelect = document.getElementById('birthDate');
        if (daySelect) {
            console.log('🗓️ Creating day options...');
            daySelect.innerHTML = '<option value="">วัน</option>';
            for (let day = 1; day <= 31; day++) {
                const option = document.createElement('option');
                option.value = day;
                option.textContent = day;
                daySelect.appendChild(option);
            }
            console.log('✅ Created', daySelect.children.length - 1, 'day options');
        } else {
            console.error('❌ Day select element not found');
        }

        // สร้างตัวเลือกเดือน (ตรวจสอบและสร้างถ้าจำเป็น)
        const monthSelect = document.getElementById('birthMonth');
        if (monthSelect) {
            const existingOptions = monthSelect.children.length;
            console.log('📅 Month select found with', existingOptions, 'existing options');
            
            if (existingOptions <= 1) {
                console.log('🗓️ Creating month options...');
                monthSelect.innerHTML = `
                    <option value="">เดือน</option>
                    <option value="1">มกราคม</option>
                    <option value="2">กุมภาพันธ์</option>
                    <option value="3">มีนาคม</option>
                    <option value="4">เมษายน</option>
                    <option value="5">พฤษภาคม</option>
                    <option value="6">มิถุนายน</option>
                    <option value="7">กรกฎาคม</option>
                    <option value="8">สิงหาคม</option>
                    <option value="9">กันยายน</option>
                    <option value="10">ตุลาคม</option>
                    <option value="11">พฤศจิกายน</option>
                    <option value="12">ธันวาคม</option>
                `;
                console.log('✅ Month options created');
            } else {
                console.log('ℹ️ Month options already exist');
            }
        } else {
            console.error('❌ Month select element not found');
        }

        // สร้างตัวเลือกปี (ปี พ.ศ.)
        const yearSelect = document.getElementById('birthYear');
        if (yearSelect) {
            console.log('🗓️ Creating year options...');
            const currentYear = new Date().getFullYear();
            const thaiYear = currentYear + 543;

            yearSelect.innerHTML = '<option value="">ปี</option>';

            // เพิ่มปีจากปีปัจจุบันย้อนหลัง 100 ปี (แสดงเป็น พ.ศ.)
            for (let year = thaiYear; year >= thaiYear - 100; year--) {
                const option = document.createElement('option');
                option.value = year - 543; // เก็บเป็น ค.ศ.
                option.textContent = year; // แสดงเป็น พ.ศ.
                yearSelect.appendChild(option);
            }
            
            console.log('✅ Created', yearSelect.children.length - 1, 'year options');
        } else {
            console.error('❌ Year select element not found');
        }

        console.log('✅ All birth date fields populated successfully');
    }

    // ฟังก์ชันใหม่สำหรับการจัดการวันที่ให้ถูกต้อง
    setupBirthDateValidation() {
        const daySelect = document.getElementById('birthDate');
        const monthSelect = document.getElementById('birthMonth');
        const yearSelect = document.getElementById('birthYear');

        if (!daySelect || !monthSelect || !yearSelect) {
            console.warn('⚠️ Some birth date elements not found, skipping validation setup');
            return;
        }

        // ฟังก์ชันอัพเดทจำนวนวันตามเดือนและปี
        const updateDaysInMonth = () => {
            const month = parseInt(monthSelect.value);
            const year = parseInt(yearSelect.value);
            const currentDay = parseInt(daySelect.value);

            if (month && year) {
                // หาจำนวนวันในเดือนนั้น
                const daysInMonth = new Date(year, month, 0).getDate();
                
                console.log(`📅 Updating days for ${month}/${year}: ${daysInMonth} days`);
                
                // เคลียร์ตัวเลือกวันเดิม
                daySelect.innerHTML = '<option value="">วัน</option>';
                
                // เพิ่มวันตามจำนวนที่ถูกต้อง
                for (let day = 1; day <= daysInMonth; day++) {
                    const option = document.createElement('option');
                    option.value = day;
                    option.textContent = day;
                    daySelect.appendChild(option);
                }
                
                // ถ้าวันที่เลือกไว้ก่อนหน้ายังอยู่ในช่วงที่ถูกต้อง ให้เลือกใหม่
                if (currentDay && currentDay <= daysInMonth) {
                    daySelect.value = currentDay;
                    console.log(`✅ Restored day selection: ${currentDay}`);
                }
            }
        };

        // เพิ่ม event listener สำหรับเดือนและปี
        monthSelect.addEventListener('change', updateDaysInMonth);
        yearSelect.addEventListener('change', updateDaysInMonth);
        
        console.log('✅ Birth date validation setup complete');
    }

    // ฟังก์ชันเดิมที่ยังใช้งานได้ (เปลี่ยนชื่อเพื่อ backward compatibility)
    populateBirthYears() {
        this.populateBirthFields();
    }

    setupPasswordStrength() {
        const passwordInput = document.getElementById('password');
        if (!passwordInput) return;

        passwordInput.addEventListener('input', this.updatePasswordStrength.bind(this));
    }

    updatePasswordStrength(event) {
        const password = event.target.value;
        const strengthBar = document.querySelector('.strength-fill');
        const strengthText = document.querySelector('.strength-text');
        
        if (!strengthBar || !strengthText) return;

        let strength = 0;
        let text = 'อ่อนแอมาก';
        let color = '#ff4757';

        if (password.length >= 6) strength += 25;
        if (password.match(/[a-z]/)) strength += 25;
        if (password.match(/[A-Z]/)) strength += 25;
        if (password.match(/[0-9]/)) strength += 25;

        if (strength >= 75) {
            text = 'แข็งแกร่ง';
            color = '#2ed573';
        } else if (strength >= 50) {
            text = 'ปานกลาง';
            color = '#ffa502';
        } else if (strength >= 25) {
            text = 'อ่อนแอ';
            color = '#ff6b47';
        }

        strengthBar.style.width = strength + '%';
        strengthBar.style.backgroundColor = color;
        strengthText.textContent = text;
    }

    showStep(stepNumber) {
        // Hide all steps
        document.querySelectorAll('.form-step').forEach(step => {
            step.classList.remove('active');
        });

        // Show current step
        const currentStep = document.getElementById(`step${stepNumber}`);
        if (currentStep) {
            currentStep.classList.add('active');
        }

        // Update progress indicators
        document.querySelectorAll('.progress-step').forEach((step, index) => {
            if (index + 1 < stepNumber) {
                step.classList.add('completed');
                step.classList.remove('active');
            } else if (index + 1 === stepNumber) {
                step.classList.add('active');
                step.classList.remove('completed');
            } else {
                step.classList.remove('active', 'completed');
            }
        });

        this.config.currentStep = stepNumber;
    }

    nextStep() {
        if (this.validateStep(this.config.currentStep)) {
            this.collectStepData(this.config.currentStep);
            if (this.config.currentStep < this.config.totalSteps) {
                this.showStep(this.config.currentStep + 1);
            }
        }
    }

    prevStep() {
        if (this.config.currentStep > 1) {
            this.showStep(this.config.currentStep - 1);
        }
    }

    validateStep(stepNumber) {
        let isValid = true;

        if (stepNumber === 1) {
            // Validate step 1 fields
            const requiredFields = ['phone', 'password', 'confirmPassword'];
            
            requiredFields.forEach(fieldName => {
                if (!this.validateField(fieldName)) {
                    isValid = false;
                }
            });

            // Check password confirmation
            const password = document.getElementById('password')?.value;
            const confirmPassword = document.getElementById('confirmPassword')?.value;
            
            if (password !== confirmPassword) {
                this.showFieldError('confirmPassword', 'รหัสผ่านไม่ตรงกัน');
                isValid = false;
            }

        } else if (stepNumber === 2) {
            // Validate step 2 fields
            const requiredFields = ['firstName', 'lastName', 'birthDate', 'birthMonth', 'birthYear', 'gender', 'userType'];
            
            requiredFields.forEach(fieldName => {
                if (!this.validateField(fieldName)) {
                    isValid = false;
                }
            });

            // Additional validation for patient-specific fields
            const userType = document.getElementById('userType')?.value;
            if (userType === 'ผู้ป่วย') {
                // Weight and height validation (optional but if provided should be valid)
                const weight = document.getElementById('weight')?.value;
                const height = document.getElementById('height')?.value;
                
                if (weight && (parseFloat(weight) < 20 || parseFloat(weight) > 300)) {
                    this.showFieldError('weight', 'น้ำหนักต้องอยู่ระหว่าง 20-300 กิโลกรัม');
                    isValid = false;
                }
                
                if (height && (parseInt(height) < 100 || parseInt(height) > 250)) {
                    this.showFieldError('height', 'ส่วนสูงต้องอยู่ระหว่าง 100-250 เซนติเมตร');
                    isValid = false;
                }

                // Emergency contact phone validation (if provided)
                const emergencyPhone = document.getElementById('emergencyContactPhone')?.value;
                if (emergencyPhone && !/^\d{10}$/.test(emergencyPhone.replace(/-/g, ''))) {
                    this.showFieldError('emergencyContactPhone', 'เบอร์โทรศัพท์ต้องเป็นตัวเลข 10 หลัก');
                    isValid = false;
                }
            }
        }

        return isValid;
    }

    validateField(fieldName) {
        const field = document.getElementById(fieldName);
        if (!field) return true;

        const rule = this.config.validationRules[fieldName];
        if (!rule) return true;

        const value = field.value.trim();

        // Clear previous errors
        this.clearFieldError(fieldName);

        // Required validation
        if (rule.required && !value) {
            this.showFieldError(fieldName, rule.message);
            return false;
        }

        // Pattern validation
        if (value && rule.pattern && !rule.pattern.test(value)) {
            this.showFieldError(fieldName, rule.message);
            return false;
        }

        // Min length validation
        if (value && rule.minLength && value.length < rule.minLength) {
            this.showFieldError(fieldName, rule.message);
            return false;
        }

        // Match validation (for confirm password)
        if (rule.match) {
            const matchField = document.getElementById(rule.match);
            if (matchField && value !== matchField.value) {
                this.showFieldError(fieldName, rule.message);
                return false;
            }
        }

        this.showFieldSuccess(fieldName);
        return true;
    }

    showFieldError(fieldName, message) {
        const field = document.getElementById(fieldName);
        const formGroup = field?.closest('.form-group');
        const errorElement = formGroup?.querySelector('.error-message');
        
        if (formGroup && errorElement) {
            formGroup.classList.add('error');
            formGroup.classList.remove('success');
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
    }

    clearFieldError(fieldName) {
        const field = document.getElementById(fieldName);
        const formGroup = field?.closest('.form-group');
        const errorElement = formGroup?.querySelector('.error-message');
        
        if (formGroup && errorElement) {
            formGroup.classList.remove('error');
            errorElement.textContent = '';
            errorElement.style.display = 'none';
        }
    }

    showFieldSuccess(fieldName) {
        const field = document.getElementById(fieldName);
        const formGroup = field?.closest('.form-group');
        
        if (formGroup && field.value.trim()) {
            formGroup.classList.add('success');
            formGroup.classList.remove('error');
        }
    }

    collectStepData(stepNumber) {
        if (stepNumber === 1) {
            this.config.formData.phone = document.getElementById('phone')?.value.trim();
            this.config.formData.password = document.getElementById('password')?.value;
        } else if (stepNumber === 2) {
            // Basic info
            this.config.formData.first_name = document.getElementById('firstName')?.value.trim();
            this.config.formData.last_name = document.getElementById('lastName')?.value.trim();
            this.config.formData.gender = document.getElementById('gender')?.value;
            this.config.formData.role = document.getElementById('userType')?.value;

            // Birth date
            const day = document.getElementById('birthDate')?.value;
            const month = document.getElementById('birthMonth')?.value;
            const year = document.getElementById('birthYear')?.value;
            
            if (day && month && year) {
                this.config.formData.birth_date = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`;
            }

            // Patient-specific data
            if (this.config.formData.role === 'ผู้ป่วย') {
                this.config.formData.weight = parseFloat(document.getElementById('weight')?.value) || null;
                this.config.formData.height = parseInt(document.getElementById('height')?.value) || null;
                this.config.formData.injured_side = document.getElementById('injuredSide')?.value || null;
                this.config.formData.injured_part = document.getElementById('injuredPart')?.value || null;
                this.config.formData.emergency_contact_name = document.getElementById('emergencyContactName')?.value?.trim() || null;
                this.config.formData.emergency_contact_phone = document.getElementById('emergencyContactPhone')?.value?.replace(/-/g, '') || null;
                this.config.formData.emergency_contact_relation = document.getElementById('emergencyContactRelation')?.value?.trim() || null;
            }

            // Physiotherapist-specific data
            if (this.config.formData.role === 'นักกายภาพบำบัด') {
                this.config.formData.license_number = document.getElementById('licenseNumber')?.value?.trim() || null;
                this.config.formData.specialization = document.getElementById('specialization')?.value?.trim() || null;
            }

            // Caregiver-specific data
            if (this.config.formData.role === 'ผู้ดูแล') {
                this.config.formData.relationship = document.getElementById('relationship')?.value?.trim() || null;
            }
        }
    }

    async handleSubmit(event) {
        event.preventDefault();
        
        // Validate current step
        if (!this.validateStep(this.config.currentStep)) {
            return;
        }

        // Collect final step data
        this.collectStepData(this.config.currentStep);

        console.log('📋 Form data collected:', this.config.formData);

        try {
            this.showLoading(true);

            const response = await fetch(`${this.config.apiBaseUrl}/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(this.config.formData)
            });

            console.log('📡 Response status:', response.status);
            const result = await response.json();
            console.log('📋 Response data:', result);

            if (response.ok && result.success) {
                // Success - store user data as backup
                this.storeRegistrationBackup(this.config.formData);
                this.showSuccessModal();
            } else {
                console.error('❌ Registration failed:', result.message);
                this.showErrorModal(result.message || 'ไม่สามารถสมัครสมาชิกได้ กรุณาลองใหม่อีกครั้ง');
            }

        } catch (error) {
            console.error('❌ Network error:', error);
            
            // Fallback - store in localStorage
            console.log('⚠️ API unavailable, storing locally...');
            this.storeRegistrationBackup(this.config.formData);
            this.showSuccessModal('สมัครสมาชิกเรียบร้อยแล้ว (บันทึกในเครื่อง)');
            
        } finally {
            this.showLoading(false);
        }
    }

    storeRegistrationBackup(formData) {
        try {
            // Get existing registrations
            const existingUsers = JSON.parse(localStorage.getItem('registrationBackup') || '[]');
            
            // Create user object
            const user = {
                id: Date.now(),
                ...formData,
                created_at: new Date().toISOString()
            };
            
            // Add to array
            existingUsers.push(user);
            
            // Store back
            localStorage.setItem('registrationBackup', JSON.stringify(existingUsers));
            
            console.log('💾 Registration backup stored locally');
        } catch (error) {
            console.error('❌ Failed to store backup:', error);
        }
    }

    handleUserTypeChange(event) {
        const userType = event.target.value;
        
        // Show/hide conditional fields
        const patientFields = document.getElementById('patientFields');
        const therapistFields = document.getElementById('therapistFields');
        
        // Hide all conditional fields first
        if (patientFields) patientFields.style.display = 'none';
        if (therapistFields) therapistFields.style.display = 'none';
        
        // Show relevant fields
        if (userType === 'ผู้ป่วย' && patientFields) {
            patientFields.style.display = 'block';
        } else if (userType === 'นักกายภาพบำบัด' && therapistFields) {
            therapistFields.style.display = 'block';
        }
    }

    calculateBMI() {
        const weightInput = document.getElementById('weight');
        const heightInput = document.getElementById('height');
        const bmiDisplay = document.getElementById('bmiDisplay');
        const bmiNumber = document.getElementById('bmiNumber');
        const bmiCategory = document.getElementById('bmiCategory');
        const bmiStatus = document.getElementById('bmiStatus');
        
        if (!weightInput || !heightInput || !bmiDisplay) return;
        
        const weight = parseFloat(weightInput.value);
        const height = parseInt(heightInput.value);
        
        if (weight > 0 && height > 0) {
            const heightInM = height / 100;
            const bmi = weight / (heightInM * heightInM);
            
            let category = '';
            let status = '';
            let className = '';
            
            if (bmi < 18.5) {
                category = 'น้ำหนักน้อย';
                status = 'ต่ำกว่าเกณฑ์';
                className = 'underweight';
            } else if (bmi < 25) {
                category = 'ปกติ';
                status = 'อยู่ในเกณฑ์ปกติ';
                className = 'normal';
            } else if (bmi < 30) {
                category = 'น้ำหนักเกิน';
                status = 'เกินเกณฑ์';
                className = 'overweight';
            } else {
                category = 'อ้วน';
                status = 'เกินเกณฑ์มาก';
                className = 'obese';
            }
            
            if (bmiNumber) bmiNumber.textContent = bmi.toFixed(1);
            if (bmiCategory) {
                bmiCategory.textContent = category;
                bmiCategory.className = `bmi-category ${className}`;
            }
            if (bmiStatus) {
                bmiStatus.textContent = status;
                bmiStatus.className = `bmi-status ${className}`;
            }
            
            bmiDisplay.style.display = 'block';
        } else {
            bmiDisplay.style.display = 'none';
        }
    }

    formatPhoneNumber(event) {
        let value = event.target.value.replace(/\D/g, '');
        
        if (value.length > 10) {
            value = value.substring(0, 10);
        }
        
        event.target.value = value;
    }

    togglePassword(event) {
        const button = event.currentTarget;
        const targetId = button.getAttribute('data-target');
        const passwordInput = document.getElementById(targetId);
        const icon = button.querySelector('i');
        
        if (!passwordInput || !icon) return;
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            icon.className = 'fas fa-eye-slash';
        } else {
            passwordInput.type = 'password';
            icon.className = 'fas fa-eye';
        }
    }

    setupRealTimeValidation() {
        // Add blur event listeners for real-time validation
        Object.keys(this.config.validationRules).forEach(fieldName => {
            const field = document.getElementById(fieldName);
            if (field) {
                field.addEventListener('blur', () => this.validateField(fieldName));
                field.addEventListener('input', () => {
                    if (field.classList.contains('error')) {
                        this.clearFieldError(fieldName);
                    }
                });
            }
        });
    }

    showLoading(show) {
        const loadingOverlay = document.getElementById('loadingOverlay');
        const submitButton = document.getElementById('submitButton');
        
        if (loadingOverlay) {
            loadingOverlay.style.display = show ? 'flex' : 'none';
        }
        
        if (submitButton) {
            submitButton.disabled = show;
            if (show) {
                submitButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>กำลังสมัครสมาชิก...</span>';
            } else {
                submitButton.innerHTML = '<i class="fas fa-check"></i><span>ลงทะเบียน</span>';
            }
        }
    }

    showSuccessModal(customMessage = null) {
        const modal = document.getElementById('successModal');
        if (modal) {
            const messageElement = modal.querySelector('p');
            if (messageElement && customMessage) {
                messageElement.textContent = customMessage;
            }
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }

    showErrorModal(message) {
        const modal = document.getElementById('errorModal');
        const messageElement = document.getElementById('errorMessage');
        
        if (modal && messageElement) {
            messageElement.textContent = message;
            modal.style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }
    }
}

// Global functions for HTML onclick handlers
window.goToLogin = function() {
    window.location.href = 'login.html';
};

window.closeErrorModal = function() {
    const modal = document.getElementById('errorModal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
};

// Initialize system when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing Registration System...');
    
    // เพิ่มการตรวจสอบว่า DOM elements พร้อมใช้งาน
    const checkElements = () => {
        const requiredElements = [
            'signupForm', 'birthDate', 'birthMonth', 'birthYear',
            'nextButton', 'backButton', 'submitButton'
        ];
        
        const missingElements = requiredElements.filter(id => !document.getElementById(id));
        
        if (missingElements.length > 0) {
            console.warn('⚠️ Missing elements:', missingElements);
            setTimeout(checkElements, 100);
            return false;
        }
        
        console.log('✅ All required elements found');
        return true;
    };
    
    if (checkElements()) {
        window.registrationSystem = new RegistrationSystem();
    } else {
        console.log('🔄 Waiting for DOM elements...');
        setTimeout(() => {
            window.registrationSystem = new RegistrationSystem();
        }, 200);
    }
});

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = RegistrationSystem;
}

// เพิ่มฟังก์ชันช่วยสำหรับ debugging
window.debugRegistration = function() {
    if (window.registrationSystem) {
        window.registrationSystem.debugBirthDateElements();
    } else {
        console.log('❌ Registration system not initialized');
    }
};

// จัดการ async error ที่อาจเกิดขึ้น
window.addEventListener('unhandledrejection', function(event) {
    console.warn('⚠️ Unhandled promise rejection:', event.reason);
    // ป้องกันไม่ให้ error นี้ทำให้ระบบหยุดทำงาน
    event.preventDefault();
});

// จัดการ error ทั่วไป
window.addEventListener('error', function(event) {
    console.error('❌ JavaScript error:', event.error);
    // ไม่ต้องแสดง error popup เพราะอาจรบกวนผู้ใช้
});