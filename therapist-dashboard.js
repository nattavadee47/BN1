// therapist-dashboard.js - ไฟล์ JavaScript สำหรับหน้า Dashboard นักกายภาพบำบัด

// ตั้งค่า Base URL ของ API (เชื่อมต่อไปยัง server.js ที่ใช้ db.js)
const API_BASE_URL = 'http://localhost:3000';

// ตัวแปรสำหรับเก็บข้อมูลผู้ใช้
let currentTherapist = null;
let patientsList = [];

// เมื่อหน้าเว็บโหลดเสร็จ
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Therapist Dashboard โหลดเสร็จแล้ว');
    
    // ตรวจสอบการล็อกอิน
    checkTherapistLogin();
    
    // ทดสอบการเชื่อมต่อ API
    testApiConnection();
    
    // โหลดข้อมูลนักกายภาพบำบัด
    loadTherapistData();
    
    // โหลดรายชื่อผู้ป่วย
    loadPatientsList();
    
    // โหลดสถิติ
    loadStatistics();
});

// ฟังก์ชันตรวจสอบการล็อกอินของนักกายภาพบำบัด
function checkTherapistLogin() {
    const userData = localStorage.getItem('user');
    
    if (!userData) {
        console.log('❌ ไม่พบข้อมูลผู้ใช้ กำลังเปลี่ยนเส้นทางไปหน้าล็อกอิน');
        window.location.href = 'login.html';
        return;
    }
    
    try {
        currentTherapist = JSON.parse(userData);
        console.log('✅ พบข้อมูลนักกายภาพบำบัด:', currentTherapist);
        
        // ตรวจสอบบทบาท
        if (currentTherapist.role !== 'therapist') {
            console.log('❌ ไม่ใช่นักกายภาพบำบัด กำลังเปลี่ยนเส้นทาง');
            if (currentTherapist.role === 'patient') {
                window.location.href = 'patient-dashboard.html';
            } else {
                window.location.href = 'login.html';
            }
            return;
        }
        
        // แสดงข้อมูลผู้ใช้ในหน้าเว็บ
        displayTherapistInfo();
        
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการอ่านข้อมูลผู้ใช้:', error);
        localStorage.removeItem('user');
        window.location.href = 'login.html';
    }
}

// ฟังก์ชันแสดงข้อมูลนักกายภาพบำบัด
function displayTherapistInfo() {
    if (!currentTherapist) return;
    
    // อัปเดตชื่อผู้ใช้ในหน้าเว็บ
    const userNameElement = document.getElementById('therapistName');
    const welcomeElement = document.getElementById('welcomeMessage');
    
    if (userNameElement) {
        userNameElement.textContent = `${currentTherapist.first_name} ${currentTherapist.last_name}`;
    }
    
    if (welcomeElement) {
        welcomeElement.textContent = `สวัสดีคุณ ${currentTherapist.first_name}`;
    }
    
    console.log('✅ แสดงข้อมูลนักกายภาพบำบัดเสร็จแล้ว');
}

// ฟังก์ชันทดสอบการเชื่อมต่อ API
async function testApiConnection() {
    try {
        console.log('🔗 กำลังทดสอบการเชื่อมต่อ API...');
        
        const response = await fetch(`${API_BASE_URL}/test`, {
            method: 'GET',
            timeout: 5000
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('✅ เชื่อมต่อ API สำเร็จ:', data.message);
            updateConnectionStatus(true);
            return true;
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error('❌ ไม่สามารถเชื่อมต่อ API:', error);
        updateConnectionStatus(false);
        showAlert('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้ กรุณาตรวจสอบการเชื่อมต่อ', 'warning');
        return false;
    }
}

// ฟังก์ชันอัปเดตสถานะการเชื่อมต่อ
function updateConnectionStatus(isConnected) {
    let statusIndicator = document.getElementById('connectionStatus');
    
    if (!statusIndicator) {
        statusIndicator = document.createElement('div');
        statusIndicator.id = 'connectionStatus';
        statusIndicator.style.cssText = `
            position: fixed;
            top: 10px;
            right: 10px;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 12px;
            color: white;
            z-index: 1000;
        `;
        document.body.appendChild(statusIndicator);
    }
    
    if (isConnected) {
        statusIndicator.textContent = 'เชื่อมต่อแล้ว ✅';
        statusIndicator.style.background = '#4CAF50';
    } else {
        statusIndicator.textContent = 'ไม่เชื่อมต่อ ❌';
        statusIndicator.style.background = '#f44336';
    }
}

// ฟังก์ชันโหลดข้อมูลนักกายภาพบำบัด
async function loadTherapistData() {
    if (!currentTherapist || !currentTherapist.user_id) {
        console.log('❌ ไม่พบข้อมูลนักกายภาพบำบัด');
        return;
    }
    
    try {
        console.log('📊 กำลังโหลดข้อมูลนักกายภาพบำบัด...');
        
        const response = await fetch(`${API_BASE_URL}/therapist/${currentTherapist.user_id}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.success && data.therapist) {
                console.log('✅ โหลดข้อมูลนักกายภาพบำบัดสำเร็จ:', data.therapist);
                displayTherapistDetails(data.therapist);
            } else {
                console.log('⚠️ ไม่พบข้อมูลนักกายภาพบำบัด');
            }
        } else {
            throw new Error(`HTTP ${response.status}`);
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการโหลดข้อมูลนักกายภาพบำบัด:', error);
        showAlert('ไม่สามารถโหลดข้อมูลนักกายภาพบำบัดได้', 'error');
    }
}

// ฟังก์ชันแสดงข้อมูลรายละเอียดนักกายภาพบำบัด
function displayTherapistDetails(therapistData) {
    // แสดงข้อมูลใบอนุญาต
    const licenseElement = document.getElementById('licenseNumber');
    if (licenseElement && therapistData.license_number) {
        licenseElement.textContent = therapistData.license_number;
    }
    
    // แสดงข้อมูลความเชี่ยวชาญ
    const specializationElement = document.getElementById('specialization');
    if (specializationElement && therapistData.specialization) {
        specializationElement.textContent = therapistData.specialization;
    }
    
    // แสดงข้อมูลประสบการณ์
    const experienceElement = document.getElementById('yearsOfExperience');
    if (experienceElement && therapistData.years_of_experience) {
        experienceElement.textContent = `${therapistData.years_of_experience} ปี`;
    }
    
    // แสดงข้อมูลสถานที่ทำงาน
    const workplaceElement = document.getElementById('workplace');
    if (workplaceElement && therapistData.workplace) {
        workplaceElement.textContent = therapistData.workplace;
    }
    
    // แสดงสถานะการตรวจสอบ
    const verificationElement = document.getElementById('verificationStatus');
    if (verificationElement && therapistData.verification_status) {
        const statusMap = {
            'verified': '✅ ยืนยันแล้ว',
            'pending': '⏳ รอการตรวจสอบ',
            'rejected': '❌ ไม่ผ่านการตรวจสอบ'
        };
        verificationElement.textContent = statusMap[therapistData.verification_status] || therapistData.verification_status;
    }
    
    console.log('✅ แสดงข้อมูลรายละเอียดนักกายภาพบำบัดเสร็จแล้ว');
}

// ฟังก์ชันโหลดรายชื่อผู้ป่วย
async function loadPatientsList() {
    try {
        console.log('👥 กำลังโหลดรายชื่อผู้ป่วย...');
        
        const response = await fetch(`${API_BASE_URL}/therapist/${currentTherapist.user_id}/patients`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.success && data.patients) {
                console.log('✅ โหลดรายชื่อผู้ป่วยสำเร็จ:', data.patients);
                patientsList = data.patients;
                displayPatientsList(data.patients);
            } else {
                console.log('⚠️ ไม่พบรายชื่อผู้ป่วย');
                displayEmptyPatientsList();
            }
        } else {
            console.log('⚠️ ไม่สามารถโหลดรายชื่อผู้ป่วยได้');
            displayEmptyPatientsList();
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการโหลดรายชื่อผู้ป่วย:', error);
        displayEmptyPatientsList();
    }
}

// ฟังก์ชันแสดงรายชื่อผู้ป่วย
function displayPatientsList(patients) {
    const patientsContainer = document.getElementById('patientsContainer');
    
    if (!patientsContainer) {
        console.log('⚠️ ไม่พบ container สำหรับแสดงรายชื่อผู้ป่วย');
        return;
    }
    
    if (!patients || patients.length === 0) {
        displayEmptyPatientsList();
        return;
    }
    
    const patientsHTML = patients.map(patient => `
        <div class="patient-card" onclick="viewPatientDetails(${patient.patient_id})">
            <div class="patient-info">
                <h3>${patient.first_name} ${patient.last_name}</h3>
                <p><strong>ประเภทโรค:</strong> ${patient.stroke_type === 'ischemic' ? 'ขาดเลือด' : 'เลือดออก'}</p>
                <p><strong>ด้านที่ได้รับผลกระทบ:</strong> ${patient.affected_side === 'left' ? 'ซ้าย' : 'ขวา'}</p>
                <p><strong>ระดับความรุนแรง:</strong> ${getSeverityLabel(patient.severity_level)}</p>
                <p><strong>วันที่เกิดโรค:</strong> ${new Date(patient.stroke_date).toLocaleDateString('th-TH')}</p>
            </div>
            <div class="patient-actions">
                <button onclick="event.stopPropagation(); editTreatmentPlan(${patient.patient_id})" class="btn-edit">
                    แก้ไขแผนการรักษา
                </button>
                <button onclick="event.stopPropagation(); viewProgress(${patient.patient_id})" class="btn-progress">
                    ดูความก้าวหน้า
                </button>
            </div>
        </div>
    `).join('');
    
    patientsContainer.innerHTML = patientsHTML;
    
    // อัปเดตจำนวนผู้ป่วย
    const patientCountElement = document.getElementById('patientCount');
    if (patientCountElement) {
        patientCountElement.textContent = patients.length;
    }
    
    console.log('✅ แสดงรายชื่อผู้ป่วยเสร็จแล้ว');
}

// ฟังก์ชันแสดงข้อความเมื่อไม่มีผู้ป่วย
function displayEmptyPatientsList() {
    const patientsContainer = document.getElementById('patientsContainer');
    
    if (patientsContainer) {
        patientsContainer.innerHTML = `
            <div class="empty-patients">
                <i class="fas fa-user-plus"></i>
                <h3>ยังไม่มีผู้ป่วยในการดูแล</h3>
                <p>เมื่อมีผู้ป่วยถูกมอบหมายให้คุณ ข้อมูลจะแสดงที่นี่</p>
            </div>
        `;
    }
    
    const patientCountElement = document.getElementById('patientCount');
    if (patientCountElement) {
        patientCountElement.textContent = '0';
    }
}

// ฟังก์ชันโหลดสถิติ
async function loadStatistics() {
    try {
        console.log('📈 กำลังโหลดสถิติ...');
        
        const response = await fetch(`${API_BASE_URL}/therapist/${currentTherapist.user_id}/statistics`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.success && data.statistics) {
                console.log('✅ โหลดสถิติสำเร็จ:', data.statistics);
                displayStatistics(data.statistics);
            } else {
                console.log('⚠️ ไม่พบข้อมูลสถิติ');
                displayDefaultStatistics();
            }
        } else {
            console.log('⚠️ ไม่สามารถโหลดสถิติได้');
            displayDefaultStatistics();
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการโหลดสถิติ:', error);
        displayDefaultStatistics();
    }
}

// ฟังก์ชันแสดงสถิติ
function displayStatistics(stats) {
    // จำนวนผู้ป่วยทั้งหมด
    const totalPatientsElement = document.getElementById('totalPatients');
    if (totalPatientsElement) {
        totalPatientsElement.textContent = stats.total_patients || 0;
    }
    
    // จำนวนการรักษาในสัปดาห์นี้
    const weeklyTreatmentsElement = document.getElementById('weeklyTreatments');
    if (weeklyTreatmentsElement) {
        weeklyTreatmentsElement.textContent = stats.weekly_treatments || 0;
    }
    
    // ผู้ป่วยที่มีความก้าวหน้า
    const improvingPatientsElement = document.getElementById('improvingPatients');
    if (improvingPatientsElement) {
        improvingPatientsElement.textContent = stats.improving_patients || 0;
    }
    
    // อัตราความสำเร็จ
    const successRateElement = document.getElementById('successRate');
    if (successRateElement) {
        successRateElement.textContent = `${stats.success_rate || 0}%`;
    }
    
    console.log('✅ แสดงสถิติเสร็จแล้ว');
}

// ฟังก์ชันแสดงสถิติเริ่มต้น
function displayDefaultStatistics() {
    const defaultStats = {
        total_patients: 0,
        weekly_treatments: 0,
        improving_patients: 0,
        success_rate: 0
    };
    
    displayStatistics(defaultStats);
}

// ฟังก์ชันดูรายละเอียดผู้ป่วย
function viewPatientDetails(patientId) {
    console.log('👁️ ดูรายละเอียดผู้ป่วย ID:', patientId);
    
    // บันทึกการกระทำ
    logTherapistAction('view_patient_details', { patient_id: patientId });
    
    // เปลี่ยนเส้นทางไปหน้ารายละเอียดผู้ป่วย
    window.location.href = `patient-details.html?id=${patientId}`;
}

// ฟังก์ชันแก้ไขแผนการรักษา
function editTreatmentPlan(patientId) {
    console.log('✏️ แก้ไขแผนการรักษาผู้ป่วย ID:', patientId);
    
    // บันทึกการกระทำ
    logTherapistAction('edit_treatment_plan', { patient_id: patientId });
    
    // เปลี่ยนเส้นทางไปหน้าแก้ไขแผนการรักษา
    window.location.href = `treatment-plan.html?id=${patientId}`;
}

// ฟังก์ชันดูความก้าวหน้า
function viewProgress(patientId) {
    console.log('📊 ดูความก้าวหน้าผู้ป่วย ID:', patientId);
    
    // บันทึกการกระทำ
    logTherapistAction('view_progress', { patient_id: patientId });
    
    // เปลี่ยนเส้นทางไปหน้าความก้าวหน้า
    window.location.href = `patient-progress.html?id=${patientId}`;
}

// ฟังก์ชันออกจากระบบ
function exitSystem() {
    if (confirm('คุณต้องการออกจากระบบหรือไม่?')) {
        console.log('🚪 ออกจากระบบ');
        
        // บันทึกการออกจากระบบ
        logTherapistAction('logout');
        
        // ลบข้อมูลจาก localStorage
        localStorage.removeItem('user');
        localStorage.removeItem('token');
        
        // เปลี่ยนเส้นทางไปหน้าล็อกอิน
        window.location.href = 'login.html';
    }
}

// ฟังก์ชันบันทึกการกระทำของนักกายภาพบำบัด
async function logTherapistAction(action, additionalData = {}) {
    if (!currentTherapist) return;
    
    try {
        const response = await fetch(`${API_BASE_URL}/log-therapist-action`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            },
            body: JSON.stringify({
                therapist_id: currentTherapist.user_id,
                action: action,
                timestamp: new Date().toISOString(),
                page: 'therapist-dashboard',
                additional_data: additionalData
            })
        });
        
        if (response.ok) {
            console.log(`✅ บันทึกการกระทำ: ${action}`);
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการบันทึกการกระทำ:', error);
    }
}

// ฟังก์ชันแสดงข้อความแจ้งเตือน
function showAlert(message, type = 'info') {
    // ลบข้อความเก่า
    const oldAlert = document.querySelector('.alert-message');
    if (oldAlert) {
        oldAlert.remove();
    }
    
    // สร้างข้อความใหม่
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert-message alert-${type}`;
    alertDiv.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        padding: 15px 20px;
        border-radius: 5px;
        color: white;
        font-weight: 500;
        z-index: 9999;
        min-width: 300px;
        text-align: center;
        ${type === 'error' ? 'background: #f44336;' : 
          type === 'warning' ? 'background: #ff9800;' : 
          type === 'success' ? 'background: #4CAF50;' : 
          'background: #2196F3;'}
    `;
    
    alertDiv.innerHTML = `
        ${message}
        <button onclick="this.parentElement.remove()" style="
            background: none;
            border: none;
            color: white;
            font-size: 18px;
            float: right;
            margin-left: 10px;
            cursor: pointer;
        ">×</button>
    `;
    
    document.body.appendChild(alertDiv);
    
    // ลบข้อความอัตโนมัติหลัง 5 วินาที
    setTimeout(() => {
        if (alertDiv.parentElement) {
            alertDiv.remove();
        }
    }, 5000);
}

// ฟังก์ชันช่วยเหลือสำหรับแปลงระดับความรุนแรง
function getSeverityLabel(severity) {
    const severityMap = {
        'mild': 'เล็กน้อย',
        'moderate': 'ปานกลาง',
        'severe': 'รุนแรง'
    };
    return severityMap[severity] || severity;
}

// ฟังก์ชันรีเฟรชข้อมูล
async function refreshData() {
    console.log('🔄 รีเฟรชข้อมูล...');
    
    showAlert('กำลังโหลดข้อมูลใหม่...', 'info');
    
    await Promise.all([
        testApiConnection(),
        loadTherapistData(),
        loadPatientsList(),
        loadStatistics()
    ]);
    
    showAlert('รีเฟรชข้อมูลเสร็จแล้ว', 'success');
}

// ฟังก์ชันค้นหาผู้ป่วย
function searchPatients() {
    const searchInput = document.getElementById('patientSearch');
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
    
    if (!searchTerm) {
        // แสดงผู้ป่วยทั้งหมด
        displayPatientsList(patientsList);
        return;
    }
    
    // กรองผู้ป่วยตามคำค้นหา
    const filteredPatients = patientsList.filter(patient => 
        `${patient.first_name} ${patient.last_name}`.toLowerCase().includes(searchTerm) ||
        patient.stroke_type.toLowerCase().includes(searchTerm) ||
        patient.affected_side.toLowerCase().includes(searchTerm)
    );
    
    displayPatientsList(filteredPatients);
    
    console.log(`🔍 ค้นหา "${searchTerm}" พบ ${filteredPatients.length} ผู้ป่วย`);
}

// ฟังก์ชันส่งออกรายงาน
async function exportReport() {
    try {
        console.log('📊 กำลังส่งออกรายงาน...');
        
        showAlert('กำลังสร้างรายงาน...', 'info');
        
        const response = await fetch(`${API_BASE_URL}/therapist/${currentTherapist.user_id}/export-report`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('token') || ''}`
            }
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `therapist_report_${new Date().toISOString().split('T')[0]}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            showAlert('ส่งออกรายงานสำเร็จ', 'success');
            logTherapistAction('export_report');
        } else {
            throw new Error('ไม่สามารถส่งออกรายงานได้');
        }
    } catch (error) {
        console.error('❌ ข้อผิดพลาดในการส่งออกรายงาน:', error);
        showAlert('ไม่สามารถส่งออกรายงานได้', 'error');
    }
}

// Export functions สำหรับใช้งานในไฟล์อื่น
window.therapistDashboard = {
    viewPatientDetails,
    editTreatmentPlan,
    viewProgress,
    exitSystem,
    refreshData,
    searchPatients,
    exportReport,
    testApiConnection
};

console.log('✅ therapist-dashboard.js โหลดเสร็จแล้ว - เชื่อมต่อกับฐานข้อมูลผ่าน API');