// ========================================
// Profile Edit JavaScript - การจัดการหน้าแก้ไขข้อมูลส่วนตัว
// profile-edit.js (ฉบับสมบูรณ์)
// ========================================

// ตัวแปรสำหรับเก็บข้อมูลผู้ใช้
let currentUser = null;
let originalData = {};

// API Base URL (เปลี่ยนตามการตั้งค่าของคุณ)
const API_BASE_URL = 'http://localhost:3000';

// เมื่อหน้าเว็บโหลดเสร็จ
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 หน้าแก้ไขข้อมูลส่วนตัวโหลดเสร็จแล้ว');
    
    // ตรวจสอบการล็อกอิน
    checkUserLogin();
    
    // เริ่มต้นการทำงาน
    initializePage();
    
    // ตั้งค่า Event Listeners
    setupEventListeners();
    
    // โหลดข้อมูลผู้ใช้ (delay เล็กน้อยให้ DOM โหลดเสร็จ)
    setTimeout(() => {
        loadUserData();
    }, 100);
});

// ฟังก์ชันตรวจสอบการล็อกอิน
function checkUserLogin() {
    // ตรวจสอบจาก sessionStorage (ระบบที่ใช้อยู่)
    const sessionUserData = sessionStorage.getItem('userData');
    // ตรวจสอบจาก localStorage (ระบบใหม่)
    const localUserData = localStorage.getItem('user');
    
    if (!sessionUserData && !localUserData) {
        console.log('❌ ไม่พบข้อมูลผู้ใช้ กำลังเปลี่ยนเส้นทางไปหน้าล็อกอิน');
        window.location.href = 'login.html';
        return false;
    }
    
    try {
        // ให้ความสำคัญกับ sessionStorage ก่อน (ระบบที่ใช้อยู่)
        if (sessionUserData) {
            currentUser = JSON.parse(sessionUserData);
            console.log('✅ พบข้อมูลผู้ใช้จาก sessionStorage:', currentUser);
        } else if (localUserData) {
            currentUser = JSON.parse(localUserData);
            console.log('✅ พบข้อมูลผู้ใช้จาก localStorage:', currentUser);
        }
        
        return true;
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการอ่านข้อมูลผู้ใช้:', error);
        sessionStorage.removeItem('userData');
        localStorage.removeItem('user');
        window.location.href = 'login.html';
        return false;
    }
}

// ฟังก์ชันเริ่มต้นหน้าเว็บ
function initializePage() {
    // แสดงข้อมูลผู้ใช้ใน Header
    displayUserInfo();
    
    // สร้าง Dropdown สำหรับวันเกิด
    setupBirthDateDropdowns();
    
    // ซ่อนหรือแสดงส่วนข้อมูลทางการแพทย์ตามบทบาท
    setupMedicalSection();
    
    // อัพเดท select options ให้เป็นภาษาไทย
    updateSelectOptionsToThai();
}

// ฟังก์ชันแสดงข้อมูลผู้ใช้ใน Header
function displayUserInfo() {
    if (!currentUser) return;
    
    const userNameElement = document.getElementById('currentUserName');
    const userRoleElement = document.getElementById('currentUserRole');
    
    if (userNameElement) {
        // แสดงชื่อจากโครงสร้างข้อมูลที่หลากหลาย
        let displayName = 'ผู้ใช้';
        if (currentUser.first_name && currentUser.last_name) {
            displayName = `${currentUser.first_name} ${currentUser.last_name}`;
        } else if (currentUser.firstName && currentUser.lastName) {
            displayName = `${currentUser.firstName} ${currentUser.lastName}`;
        } else if (currentUser.username) {
            displayName = currentUser.username;
        } else if (currentUser.full_name) {
            displayName = currentUser.full_name;
        }
        userNameElement.textContent = displayName;
    }
    
    if (userRoleElement) {
        let roleText = 'ผู้ใช้';
        const role = currentUser.role?.toLowerCase();
        switch(role) {
            case 'patient':
            case 'ผู้ป่วย':
                roleText = 'ผู้ป่วย';
                break;
            case 'therapist':
            case 'physiotherapist':
            case 'นักกายภาพบำบัด':
                roleText = 'นักกายภาพบำบัด';
                break;
            case 'caregiver':
            case 'ผู้ดูแล':
                roleText = 'ผู้ดูแล';
                break;
        }
        userRoleElement.textContent = roleText;
    }
}

// ฟังก์ชันสร้าง Dropdown สำหรับวันเกิด
function setupBirthDateDropdowns() {
    const birthDateSelect = document.getElementById('birthDate');
    const birthMonthSelect = document.getElementById('birthMonth');
    const birthYearSelect = document.getElementById('birthYear');
    
    // สร้างตัวเลือกวัน (1-31)
    if (birthDateSelect) {
        birthDateSelect.innerHTML = '<option value="">วัน</option>';
        for (let day = 1; day <= 31; day++) {
            const option = document.createElement('option');
            option.value = day;
            option.textContent = day;
            birthDateSelect.appendChild(option);
        }
    }
    
    // สร้างตัวเลือกเดือน
    if (birthMonthSelect) {
        const months = [
            'มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน', 'พฤษภาคม', 'มิถุนายน',
            'กรกฎาคม', 'สิงหาคม', 'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม'
        ];
        
        birthMonthSelect.innerHTML = '<option value="">เดือน</option>';
        months.forEach((month, index) => {
            const option = document.createElement('option');
            option.value = index + 1;
            option.textContent = month;
            birthMonthSelect.appendChild(option);
        });
    }
    
    // สร้างตัวเลือกปี (ย้อนหลัง 100 ปี)
    if (birthYearSelect) {
        const currentYear = new Date().getFullYear();
        const thaiYear = currentYear + 543;
        
        birthYearSelect.innerHTML = '<option value="">ปี</option>';
        for (let year = thaiYear; year >= thaiYear - 100; year--) {
            const option = document.createElement('option');
            option.value = year - 543; // เก็บเป็นปี ค.ศ.
            option.textContent = year; // แสดงเป็นปี พ.ศ.
            birthYearSelect.appendChild(option);
        }
    }
}

// ฟังก์ชันอัพเดท select options ให้เป็นภาษาไทย
function updateSelectOptionsToThai() {
    // อัพเดท gender select
    const genderSelect = document.getElementById('gender');
    if (genderSelect) {
        genderSelect.innerHTML = `
            <option value="">เลือกเพศ</option>
            <option value="ชาย">ชาย</option>
            <option value="หญิง">หญิง</option>
            <option value="อื่นๆ">อื่นๆ</option>
        `;
    }
    
    // อัพเดท injured side select
    const injuredSideSelect = document.getElementById('injuredSide');
    if (injuredSideSelect) {
        injuredSideSelect.innerHTML = `
            <option value="">เลือกด้าน</option>
            <option value="ซ้าย">ด้านซ้าย</option>
            <option value="ขวา">ด้านขวา</option>
            <option value="ทั้งสองข้าง">ทั้งสองด้าน</option>
        `;
    }
    
    // อัพเดท injured part select  
    const injuredPartSelect = document.getElementById('injuredPart');
    if (injuredPartSelect) {
        injuredPartSelect.innerHTML = `
            <option value="">เลือกส่วนที่บาดเจ็บ</option>
            <option value="ขา">ขา</option>
            <option value="แขน">แขน</option>
            <option value="ลำตัว">ลำตัว</option>
            <option value="หัว">หัว</option>
            <option value="อื่นๆ">อื่นๆ</option>
        `;
    }
}

// ฟังก์ชันจัดการส่วนข้อมูลทางการแพทย์
function setupMedicalSection() {
    const medicalSection = document.getElementById('medicalSection');
    
    // แสดงเฉพาะสำหรับผู้ป่วย
    if (currentUser?.role?.toLowerCase() === 'patient' || currentUser?.role === 'ผู้ป่วย') {
        if (medicalSection) medicalSection.style.display = 'block';
    } else {
        if (medicalSection) medicalSection.style.display = 'none';
    }
}

// ฟังก์ชันตั้งค่า Event Listeners
function setupEventListeners() {
    const form = document.getElementById('profileForm');
    const weightInput = document.getElementById('weight');
    const heightInput = document.getElementById('height');
    const phoneInput = document.getElementById('emergencyContactPhone');
    
    // ส่งฟอร์ม
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }
    
    // คำนวณ BMI เมื่อเปลี่ยนน้ำหนักหรือส่วนสูง
    if (weightInput) {
        weightInput.addEventListener('input', calculateBMI);
    }
    if (heightInput) {
        heightInput.addEventListener('input', calculateBMI);
    }
    
    // จัดรูปแบบเบอร์โทรศัพท์
    if (phoneInput) {
        phoneInput.addEventListener('input', formatPhoneNumber);
    }
    
    // Validate ข้อมูลแบบ Real-time
    setupRealTimeValidation();
}

// ฟังก์ชันโหลดข้อมูลผู้ใช้
function loadUserData() {
    try {
        showLoading(true);
        
        if (currentUser && currentUser.user_id) {
            console.log('📊 Current user data:', currentUser);
            
            // เรียก API เพื่อดึงข้อมูลล่าสุดจากฐานข้อมูล
            fetchUserDataFromAPI();
        } else {
            console.error('❌ ไม่พบข้อมูลผู้ใช้');
            showToast('ไม่พบข้อมูลผู้ใช้', 'error');
            showLoading(false);
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการโหลดข้อมูล:', error);
        showToast('เกิดข้อผิดพลาดในการโหลดข้อมูล', 'error');
        showLoading(false);
    }
}
async function fetchUserDataFromAPI() {
    try {
        const url = `${API_BASE_URL}/api/users/${currentUser.user_id}`;
        console.log('📡 Fetching user data from API:', url);
        
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentUser.token}`
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            console.log('✅ API Response:', result);
            
            if (result.success && result.data) {
                // รวมข้อมูลจาก API กับข้อมูลเดิม
                const apiUserData = result.data;
                const patientInfo = apiUserData.patient_info || {};
                
                // สร้างโครงสร้างข้อมูลที่ฟอร์มเข้าใจ
                const formData = {
                    // ข้อมูลจาก Users table
                    user_id: apiUserData.user_id,
                    phone: apiUserData.phone,
                    full_name: apiUserData.full_name,
                    role: apiUserData.role,
                    
                    // ข้อมูลจาก Patients table (ถ้ามี)
                    first_name: patientInfo.first_name || extractFirstName(apiUserData.full_name),
                    last_name: patientInfo.last_name || extractLastName(apiUserData.full_name),
                    birth_date: patientInfo.birth_date,
                    gender: patientInfo.gender,
                    weight: patientInfo.weight,
                    height: patientInfo.height,
                    injured_side: patientInfo.injured_side,
                    injured_part: patientInfo.injured_part,
                    emergency_contact_name: patientInfo.emergency_contact_name,
                    emergency_contact_phone: patientInfo.emergency_contact_phone,
                    emergency_contact_relation: patientInfo.emergency_contact_relation,
                    
                    // ข้อมูลอื่นๆ
                    token: currentUser.token
                };
                
                console.log('📝 Processed form data:', formData);
                
                // เก็บข้อมูลเดิมไว้
                originalData = { ...formData };
                
                // อัพเดท currentUser
                currentUser = { ...currentUser, ...formData };
                
                // ใส่ข้อมูลในฟอร์ม
                setTimeout(() => {
                    populateForm(formData);
                    console.log('✅ โหลดข้อมูลผู้ใช้สำเร็จจาก API');
                }, 200);
                
            } else {
                console.warn('⚠️ API response ไม่มีข้อมูล');
                fallbackToSessionData();
            }
        } else {
            console.warn('⚠️ API call failed, using session data');
            fallbackToSessionData();
        }
        
    } catch (error) {
        console.error('❌ API Error:', error);
        fallbackToSessionData();
    } finally {
        setTimeout(() => showLoading(false), 500);
    }
}

// ฟังก์ชันใช้ข้อมูลจาก session เป็น fallback
function fallbackToSessionData() {
    console.log('📦 Using session data as fallback');
    originalData = { ...currentUser };
    
    setTimeout(() => {
        populateForm(currentUser);
        console.log('✅ โหลดข้อมูลผู้ใช้สำเร็จจาก session (fallback)');
    }, 200);
}

// ฟังก์ชันช่วยแยกชื่อจาก full_name
function extractFirstName(fullName) {
    if (!fullName) return '';
    const parts = fullName.trim().split(' ');
    return parts[0] || '';
}

// ฟังก์ชันช่วยแยกนามสกุลจาก full_name
function extractLastName(fullName) {
    if (!fullName) return '';
    const parts = fullName.trim().split(' ');
    return parts.slice(1).join(' ') || '';
}
// ฟังก์ชันใส่ข้อมูลลงในฟอร์ม
function populateForm(data) {
    console.log('📝 Populating form with data:', data);
    
    // ข้อมูลพื้นฐาน
    setFieldValue('firstName', data.first_name || data.firstName || '');
    setFieldValue('lastName', data.last_name || data.lastName || '');
    
    // อีเมลหรือเบอร์โทร (ใช้เบอร์โทรแทนอีเมล)
    setFieldValue('email', data.phone || data.email || '');
    
    // เพศ - แปลงค่าให้เป็นภาษาไทย
    const gender = convertGenderToThai(data.gender);
    setFieldValue('gender', gender);
    
    // วันเกิด
    if (data.birth_date || data.birthDate) {
        const birthDateStr = data.birth_date || data.birthDate;
        try {
            const birthDate = new Date(birthDateStr);
            if (!isNaN(birthDate.getTime())) {
                setFieldValue('birthDate', birthDate.getDate());
                setFieldValue('birthMonth', birthDate.getMonth() + 1);
                setFieldValue('birthYear', birthDate.getFullYear());
                console.log('✅ วันเกิดตั้งค่าเรียบร้อย:', {
                    day: birthDate.getDate(),
                    month: birthDate.getMonth() + 1,
                    year: birthDate.getFullYear()
                });
            }
        } catch (error) {
            console.warn('⚠️ ไม่สามารถแปลงวันเกิดได้:', birthDateStr);
        }
    }
    
    // ข้อมูลทางกาย
    setFieldValue('weight', data.weight || '');
    setFieldValue('height', data.height || '');
    
    // ข้อมูลทางการแพทย์ (สำหรับผู้ป่วย)
    if (currentUser?.role?.toLowerCase() === 'patient' || currentUser?.role === 'ผู้ป่วย') {
        const injuredSide = convertInjuredSideToThai(data.injured_side || data.injuredSide);
        const injuredPart = convertInjuredPartToThai(data.injured_part || data.injuredPart);
        
        setFieldValue('injuredSide', injuredSide);
        setFieldValue('injuredPart', injuredPart);
        
        console.log('🏥 ข้อมูลทางการแพทย์:', { injuredSide, injuredPart });
    }
    
    // ผู้ติดต่อฉุกเฉิน
    setFieldValue('emergencyContactName', data.emergency_contact_name || data.emergencyContactName || '');
    setFieldValue('emergencyContactPhone', data.emergency_contact_phone || data.emergencyContactPhone || '');
    setFieldValue('emergencyContactRelation', data.emergency_contact_relation || data.emergencyContactRelation || '');
    
    // คำนวณ BMI หากมีข้อมูลน้ำหนักและส่วนสูง
    if (data.weight && data.height) {
        setTimeout(() => calculateBMI(), 300);
    }
    
    console.log('✅ ฟอร์มถูกใส่ข้อมูลเรียบร้อยแล้ว');
}

// ฟังก์ชันแปลงเพศเป็นภาษาไทย
function convertGenderToThai(gender) {
    if (!gender) return '';
    
    const genderMapping = {
        'male': 'ชาย',
        'female': 'หญิง',
        'other': 'อื่นๆ',
        'Male': 'ชาย',
        'Female': 'หญิง',
        'Other': 'อื่นๆ',
        'ชาย': 'ชาย',
        'หญิง': 'หญิง',
        'อื่นๆ': 'อื่นๆ'
    };
    
    return genderMapping[gender] || gender;
}

// ฟังก์ชันแปลงด้านที่บาดเจ็บเป็นภาษาไทย
function convertInjuredSideToThai(injuredSide) {
    if (!injuredSide) return '';
    
    const sideMapping = {
        'left': 'ซ้าย',
        'right': 'ขวา',
        'both': 'ทั้งสองข้าง',
        'Left': 'ซ้าย',
        'Right': 'ขวา',
        'Both': 'ทั้งสองข้าง',
        'ซ้าย': 'ซ้าย',
        'ขวา': 'ขวา',
        'ทั้งสองข้าง': 'ทั้งสองข้าง'
    };
    
    return sideMapping[injuredSide] || injuredSide;
}

// ฟังก์ชันแปลงส่วนที่บาดเจ็บเป็นภาษาไทย
function convertInjuredPartToThai(injuredPart) {
    if (!injuredPart) return '';
    
    const partMapping = {
        'arm': 'แขน',
        'leg': 'ขา',
        'trunk': 'ลำตัว',
        'head': 'หัว',
        'other': 'อื่นๆ',
        'Arm': 'แขน',
        'Leg': 'ขา',
        'Trunk': 'ลำตัว',
        'Head': 'หัว',
        'Other': 'อื่นๆ',
        'แขน': 'แขน',
        'ขา': 'ขา',
        'ลำตัว': 'ลำตัว',
        'หัว': 'หัว',
        'อื่นๆ': 'อื่นๆ'
    };
    
    return partMapping[injuredPart] || injuredPart;
}

// ฟังก์ชันช่วยในการตั้งค่าข้อมูลฟิลด์
function setFieldValue(fieldName, value) {
    const field = document.getElementById(fieldName);
    if (!field) {
        console.warn(`Field ${fieldName} not found in DOM`);
        return;
    }
    
    if (value !== null && value !== undefined && value !== '') {
        field.value = value;
        console.log(`📝 Set ${fieldName} = ${value}`);
        
        // Trigger change event เพื่อให้ UI อัปเดต
        const event = new Event('input', { bubbles: true });
        field.dispatchEvent(event);
    } else {
        console.log(`⚠️ Field ${fieldName} ไม่มีค่าหรือค่าว่าง:`, value);
    }
}

// ฟังก์ชันจัดการการส่งฟอร์ม
async function handleFormSubmit(event) {
    event.preventDefault();
    
    if (isSubmitting) return;
    isSubmitting = true;
    
    console.log('Current User:', currentUser);
    
    if (!validateForm()) {
        showToast('กรุณาตรวจสอบข้อมูลที่กรอก', 'error');
        isSubmitting = false;
        return;
    }
    
    const formData = collectFormData();
    console.log('Form Data to send:', formData);
    
    try {
        showLoading(true);
        
        const url = `${API_BASE_URL}/api/users/${currentUser.user_id}`;
        console.log('API URL:', url);
        console.log('Token:', currentUser.token);
        
        const response = await fetch(url, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentUser.token}`
            },
            body: JSON.stringify(formData)
        });
        
        console.log('Response status:', response.status);
        const result = await response.json();
        console.log('Response data:', result);
        
        if (response.ok && result.success) {
            showToast('บันทึกข้อมูลเรียบร้อยแล้ว', 'success');
            updateLocalUserData(formData);
        } else {
            showToast(result.message || 'ไม่สามารถบันทึกข้อมูลได้', 'error');
        }
        
    } catch (error) {
        console.error('Error:', error);
        showToast('เกิดข้อผิดพลาดในการเชื่อมต่อ', 'error');
    } finally {
        showLoading(false);
        isSubmitting = false;
    }
}

// ฟังก์ชันรวบรวมข้อมูลฟอร์ม
function collectFormData() {
    const formData = {
        first_name: getFieldValue('firstName').substring(0, 50),
        last_name: getFieldValue('lastName').substring(0, 50),
        gender: getFieldValue('gender'),
        weight: parseFloat(getFieldValue('weight')) || null,
        height: parseInt(getFieldValue('height')) || null,
        emergency_contact_name: getFieldValue('emergencyContactName').substring(0, 100),
        emergency_contact_phone: getFieldValue('emergencyContactPhone').substring(0, 20),
        emergency_contact_relation: getFieldValue('emergencyContactRelation').substring(0, 50)
    };
    
    // วันเกิด
    const day = getFieldValue('birthDate');
    const month = getFieldValue('birthMonth');
    const year = getFieldValue('birthYear');
    
    if (day && month && year) {
        formData.birth_date = `${year}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
    }
    
    // ข้อมูลทางการแพทย์ (สำหรับผู้ป่วย)
    if (currentUser?.role?.toLowerCase() === 'patient' || currentUser?.role === 'ผู้ป่วย') {
        formData.injured_side = getFieldValue('injuredSide');
        formData.injured_part = getFieldValue('injuredPart');
    }
    
    // อัพเดท full_name
    if (formData.first_name && formData.last_name) {
        formData.full_name = `${formData.first_name} ${formData.last_name}`;
    }
    
    // ลบ field ที่เป็น empty string
    Object.keys(formData).forEach(key => {
        if (formData[key] === '') {
            formData[key] = null;
        }
    });
    
    console.log('Collected form data:', formData);
    return formData;
}

// ฟังก์ชันช่วยในการดึงค่าจากฟิลด์
function getFieldValue(fieldName) {
    const field = document.getElementById(fieldName);
    return field ? field.value.trim() : '';
}

// ฟังก์ชันอัปเดตข้อมูลผู้ใช้ใน sessionStorage
function updateLocalUserData(newData) {
    const updatedUser = { ...currentUser, ...newData };
    
    // บันทึกใน sessionStorage
    sessionStorage.setItem('userData', JSON.stringify(updatedUser));
    
    // บันทึกใน localStorage เป็น backup
    localStorage.setItem('user', JSON.stringify(updatedUser));
    
    currentUser = updatedUser;
    displayUserInfo();
}

// ฟังก์ชัน Validate ฟอร์ม
function validateForm() {
    let isValid = true;
    
    // ตรวจสอบฟิลด์ที่จำเป็น
    const requiredFields = ['firstName', 'lastName', 'birthDate', 'birthMonth', 'birthYear', 'gender'];
    
    requiredFields.forEach(fieldName => {
        const field = document.getElementById(fieldName);
        if (!field || !field.value.trim()) {
            setFieldError(fieldName, 'กรุณากรอกข้อมูลให้ครบถ้วน');
            isValid = false;
        } else {
            clearFieldError(fieldName);
        }
    });
    
    // ตรวจสอบเบอร์โทรศัพท์
    const phoneField = document.getElementById('emergencyContactPhone');
    if (phoneField && phoneField.value) {
        if (!/^\d{10}$/.test(phoneField.value.replace(/-/g, ''))) {
            setFieldError('emergencyContactPhone', 'กรุณากรอกเบอร์โทรศัพท์ที่ถูกต้อง (10 หลัก)');
            isValid = false;
        } else {
            clearFieldError('emergencyContactPhone');
        }
    }
    
    return isValid;
}

// ฟังก์ชันตั้งค่าการ Validate แบบ Real-time
function setupRealTimeValidation() {
    const fields = document.querySelectorAll('input, select');
    
    fields.forEach(field => {
        field.addEventListener('blur', function() {
            validateField(this);
        });
        
        field.addEventListener('input', function() {
            if (this.classList.contains('error')) {
                validateField(this);
            }
        });
    });
}

// ฟังก์ชัน Validate ฟิลด์เดี่ยว
function validateField(field) {
    const fieldName = field.id;
    const value = field.value.trim();
    
    // ลบ error state เดิม
    clearFieldError(fieldName);
    
    // ตรวจสอบฟิลด์ที่จำเป็น
    if (field.hasAttribute('required') && !value) {
        setFieldError(fieldName, 'กรุณากรอกข้อมูลให้ครบถ้วน');
        return false;
    }
    
    // ถ้าผ่านการตรวจสอบ
    setFieldSuccess(fieldName);
    return true;
}

// ฟังก์ชันแสดง Error สำหรับฟิลด์
function setFieldError(fieldName, message) {
    const field = document.getElementById(fieldName);
    const formGroup = field?.closest('.form-group');
    const errorMessage = formGroup?.querySelector('.error-message');
    
    if (formGroup && errorMessage) {
        formGroup.classList.remove('success');
        formGroup.classList.add('error');
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }
}

// ฟังก์ชันล้าง Error สำหรับฟิลด์
function clearFieldError(fieldName) {
    const field = document.getElementById(fieldName);
    const formGroup = field?.closest('.form-group');
    const errorMessage = formGroup?.querySelector('.error-message');
    
    if (formGroup && errorMessage) {
        formGroup.classList.remove('error');
        errorMessage.style.display = 'none';
    }
}

// ฟังก์ชันแสดงสถานะ Success สำหรับฟิลด์
function setFieldSuccess(fieldName) {
    const field = document.getElementById(fieldName);
    const formGroup = field?.closest('.form-group');
    
    if (formGroup && field.value.trim()) {
        formGroup.classList.remove('error');
        formGroup.classList.add('success');
    }
}

// ฟังก์ชันคำนวณ BMI
function calculateBMI() {
    const weightInput = document.getElementById('weight');
    const heightInput = document.getElementById('height');
    const bmiDisplay = document.getElementById('bmiDisplay');
    const bmiValue = document.getElementById('bmiValue');
    const bmiCategory = document.getElementById('bmiCategory');
    const bmiStatus = document.getElementById('bmiStatus');
    
    const weight = parseFloat(weightInput?.value);
    const height = parseInt(heightInput?.value);
    
    if (weight && height && weight > 0 && height > 0) {
        const heightInMeters = height / 100;
        const bmi = weight / (heightInMeters * heightInMeters);
        
        // อัปเดตค่า BMI
        if (bmiValue) {
            bmiValue.textContent = bmi.toFixed(1);
        }
        
        // กำหนดหมวดหมู่และสถานะ
        let category, status, categoryClass;
        
        if (bmi < 18.5) {
            category = 'น้ำหนักน้อย';
            status = 'ต่ำกว่าเกณฑ์';
            categoryClass = 'underweight';
        } else if (bmi < 25) {
            category = 'ปกติ';
            status = 'อยู่ในเกณฑ์ปกติ';
            categoryClass = 'normal';
        } else if (bmi < 30) {
            category = 'น้ำหนักเกิน';
            status = 'เกินเกณฑ์';
            categoryClass = 'overweight';
        } else {
            category = 'อ้วน';
            status = 'เกินเกณฑ์มาก';
            categoryClass = 'obese';
        }
        
        // อัปเดต UI
        if (bmiCategory) {
            bmiCategory.textContent = category;
            bmiCategory.className = `bmi-category ${categoryClass}`;
        }
        
        if (bmiStatus) {
            bmiStatus.textContent = status;
            bmiStatus.className = `bmi-status ${categoryClass}`;
        }
        
        // แสดง BMI display
        if (bmiDisplay) {
            bmiDisplay.style.display = 'block';
        }
        
    } else {
        // ซ่อน BMI display ถ้าไม่มีข้อมูลครบ
        if (bmiDisplay) {
            bmiDisplay.style.display = 'none';
        }
    }
}

// ฟังก์ชันจัดรูปแบบเบอร์โทรศัพท์
function formatPhoneNumber(event) {
    let value = event.target.value.replace(/\D/g, ''); // เก็บแค่ตัวเลข
    
    // จำกัดความยาวไม่เกิน 10 หลัก
    if (value.length > 10) {
        value = value.substring(0, 10);
    }
    
    // จัดรูปแบบ XXX-XXX-XXXX
    if (value.length >= 6) {
        value = `${value.substring(0, 3)}-${value.substring(3, 6)}-${value.substring(6)}`;
    } else if (value.length >= 3) {
        value = `${value.substring(0, 3)}-${value.substring(3)}`;
    }
    
    event.target.value = value;
}

// ฟังก์ชันรีเซ็ตฟอร์ม
function resetForm() {
    if (confirm('คุณต้องการรีเซ็ตข้อมูลทั้งหมดหรือไม่?')) {
        // รีเซ็ตฟอร์ม
        document.getElementById('profileForm').reset();
        
        // ลบ error states
        const formGroups = document.querySelectorAll('.form-group');
        formGroups.forEach(group => {
            group.classList.remove('error', 'success');
        });
        
        // ซ่อน BMI display
        const bmiDisplay = document.getElementById('bmiDisplay');
        if (bmiDisplay) {
            bmiDisplay.style.display = 'none';
        }
        
        // โหลดข้อมูลเดิมกลับมา
        if (originalData) {
            populateForm(originalData);
        }
        
        showToast('รีเซ็ตข้อมูลแล้ว', 'info');
    }
}

// ฟังก์ชันแสดง/ซ่อน Loading
function showLoading(show) {
    const loadingOverlay = document.getElementById('loadingOverlay');
    const saveButton = document.getElementById('saveButton');
    
    if (loadingOverlay) {
        if (show) {
            loadingOverlay.classList.add('show');
        } else {
            loadingOverlay.classList.remove('show');
        }
    }
    
    if (saveButton) {
        saveButton.disabled = show;
        if (show) {
            saveButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span>กำลังบันทึก...</span>';
        } else {
            saveButton.innerHTML = '<i class="fas fa-save"></i><span>บันทึกข้อมูล</span>';
        }
    }
}

// ฟังก์ชันแสดง Toast Notification
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastIcon = toast?.querySelector('.toast-icon i');
    const toastMessage = toast?.querySelector('.toast-message');
    
    if (!toast) return;
    
    // ตั้งค่าข้อความ
    if (toastMessage) {
        toastMessage.textContent = message;
    }
    
    // ตั้งค่าไอคอนและสีตาม type
    if (toastIcon) {
        toast.className = 'toast'; // รีเซ็ต class
        
        switch (type) {
            case 'success':
                toastIcon.className = 'fas fa-check-circle';
                break;
            case 'error':
                toast.classList.add('error');
                toastIcon.className = 'fas fa-exclamation-circle';
                break;
            case 'warning':
                toast.classList.add('warning');
                toastIcon.className = 'fas fa-exclamation-triangle';
                break;
            case 'info':
                toastIcon.className = 'fas fa-info-circle';
                break;
        }
    }
    
    // แสดง Toast
    toast.classList.add('show');
    
    // ซ่อน Toast หลัง 4 วินาที
    setTimeout(() => {
        toast.classList.remove('show');
    }, 4000);
}

// ฟังก์ชันกลับไปหน้าก่อนหน้า
function goBack() {
    // ตรวจสอบว่ามีการเปลี่ยนแปลงข้อมูลหรือไม่
    const currentData = collectFormData();
    const hasChanges = JSON.stringify(currentData) !== JSON.stringify(originalData);
    
    if (hasChanges) {
        if (confirm('คุณมีการเปลี่ยนแปลงข้อมูลที่ยังไม่ได้บันทึก ต้องการออกจากหน้านี้หรือไม่?')) {
            navigateBack();
        }
    } else {
        navigateBack();
    }
}

// ฟังก์ชันนำทางกลับ
function navigateBack() {
    // ตรวจสอบบทบาทผู้ใช้เพื่อกลับไปหน้าที่เหมาะสม
    switch (currentUser?.role?.toLowerCase()) {
        case 'patient':
        case 'ผู้ป่วย':
            window.location.href = 'patient-dashboard.html';
            break;
        case 'therapist':
        case 'physiotherapist':
        case 'นักกายภาพบำบัด':
            window.location.href = 'therapist-dashboard.html';
            break;
        case 'caregiver':
        case 'ผู้ดูแล':
            window.location.href = 'caregiver-dashboard.html';
            break;
        default:
            window.history.back();
    }
}

// ฟังก์ชันออกจากระบบ
function logout() {
    if (confirm('คุณต้องการออกจากระบบหรือไม่?')) {
        // ลบข้อมูลการล็อกอิน
        sessionStorage.removeItem('userData');
        localStorage.removeItem('user');
        localStorage.removeItem('token');
        
        // เปลี่ยนเส้นทางไปหน้าล็อกอิน
        window.location.href = 'login.html';
    }
}

// ฟังก์ชันตรวจสอบข้อมูลผู้ใช้ (สำหรับ debug)
function debugUserData() {
    console.log('🔍 Debug User Data:');
    console.log('currentUser:', currentUser);
    
    if (currentUser) {
        console.log('User properties:');
        Object.keys(currentUser).forEach(key => {
            console.log(`  ${key}:`, currentUser[key]);
        });
    }
    
    // ตรวจสอบ fields ในฟอร์ม
    const fields = ['firstName', 'lastName', 'email', 'gender', 'birthDate', 'birthMonth', 'birthYear', 'weight', 'height'];
    console.log('🔍 Form fields status:');
    fields.forEach(fieldName => {
        const field = document.getElementById(fieldName);
        if (field) {
            console.log(`  ${fieldName}: exists, value = "${field.value}"`);
        } else {
            console.log(`  ${fieldName}: NOT FOUND`);
        }
    });
}

// ป้องกันการส่งฟอร์มซ้ำ
let isSubmitting = false;

// Error Handlers
window.addEventListener('error', function(event) {
    console.error('❌ JavaScript Error:', event.error);
    showToast('เกิดข้อผิดพลาดในระบบ', 'error');
});

window.addEventListener('unhandledrejection', function(event) {
    console.error('❌ Unhandled Promise Rejection:', event.reason);
    showToast('เกิดข้อผิดพลาดในการเชื่อมต่อ', 'error');
    event.preventDefault();
});