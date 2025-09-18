// report.js - อัปเดตการโหลดข้อมูล (แก้ไขปัญหา Authentication)

// ตัวแปรสำหรับเก็บข้อมูล
let exerciseHistory = [];
let currentPage = 1;
let itemsPerPage = 10;

// เริ่มต้นหน้า
window.addEventListener('load', async function() {
    // ตรวจสอบและสร้าง Authentication
    const auth = ensureAuthentication();
    
    // ตั้งค่าข้อมูลผู้ใช้
    document.getElementById('userName').textContent = auth.userData.full_name || 'ผู้ใช้งาน';
    document.getElementById('patientName').textContent = `คุณ ${auth.userData.full_name || 'ผู้ใช้งาน'}`;
    
    // ตั้งค่าวันที่
    const today = new Date();
    const options = { year: 'numeric', month: 'long', day: 'numeric' };
    const thaiDate = today.toLocaleDateString('th-TH', options);
    document.getElementById('assessmentDate').textContent = thaiDate;
    
    // ตรวจสอบการเชื่อมต่อฐานข้อมูล
    await checkDatabaseConnection();
    
    // โหลดข้อมูลการออกกำลังกาย
    loadExerciseData();
    
    // เริ่มต้นตาราง
    initTableFunctions();
    
    // เริ่มต้นกราฟ
    initChart();
});

// โหลดข้อมูลการออกกำลังกาย
async function loadExerciseData() {
    console.log('Loading exercise data...');
    
    // โหลดผลล่าสุดจาก lastSessionData
    const latestResults = localStorage.getItem('lastSessionData');
    if (latestResults) {
        try {
            const results = JSON.parse(latestResults);
            console.log('Latest session found:', results);
            displayLatestSession(results);
        } catch (e) {
            console.error('Error parsing latest session data:', e);
        }
    }

    // พยายามโหลดจากฐานข้อมูลก่อน
    try {
        await loadFromDatabase();
    } catch (error) {
        console.error('❌ ไม่สามารถโหลดจากฐานข้อมูลได้:', error);
        console.log('📂 โหลดจาก localStorage แทน');
        loadFromLocalStorage();
    }
}

// แก้ไขใน report.js - ฟังก์ชัน loadFromDatabase
async function loadFromDatabase() {
    console.log('🌐 กำลังโหลดข้อมูลจากฐานข้อมูล...');
    
    // ลองใช้ token ที่มีอยู่ก่อน
    let token = localStorage.getItem('authToken');
    
    // หาก token ไม่ใช่ JWT หรือไม่มี ให้ข้ามไปใช้ localStorage
    if (!token || token.startsWith('jwt_mock_token_') || token.startsWith('mock_token_')) {
        console.log('⚠️ ไม่พบ JWT token ที่ถูกต้อง - ข้ามการเชื่อมต่อฐานข้อมูล');
        throw new Error('No valid JWT token found');
    }
    
    console.log('🔑 Using token:', token.substring(0, 20) + '...');
    
    try {
        // โหลดประวัติการออกกำลังกาย
        const response = await fetch('http://127.0.0.1:3000/api/exercise-sessions', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        console.log('📡 API Response Status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('❌ API Error Response:', errorText);
            
            // หากเป็น 401 หรือ 403 แสดงว่า token หมดอายุหรือไม่ถูกต้อง
            if (response.status === 401 || response.status === 403) {
                console.log('🚫 Token ไม่ถูกต้อง หรือไม่มีสิทธิ์ - ใช้ localStorage แทน');
                localStorage.removeItem('authToken'); // ลบ token ที่ไม่ถูกต้อง
                throw new Error('Invalid or expired token');
            }
            
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const result = await response.json();
        console.log('✅ API call successful, data received:', result.data?.length || 0, 'sessions');
        
        processApiData(result);
        
    } catch (networkError) {
        console.error('🌐 Network error:', networkError.message);
        throw networkError;
    }
}

// ฟังก์ชันประมวลผลข้อมูลจาก API
function processApiData(result) {
    if (!result.success) {
        throw new Error(result.message);
    }
    
    // แปลงข้อมูลจากฐานข้อมูลให้ตรงกับรูปแบบเดิม
    exerciseHistory = result.data.map(session => ({
        exercise: session.exercise_name_en || 'unknown',
        exerciseName: session.exercise_name_th || session.exercise_name_en || 'ไม่ระบุ',
        reps: session.actual_reps || 0,
        targetReps: session.target_reps || 10,
        accuracy: Math.round(session.accuracy_percent) || 0,
        sessionStats: {
            exerciseTime: Math.floor(Math.random() * 300) + 120, // จำลองเวลา 2-7 นาที
            bestAccuracy: Math.round(session.accuracy_percent) + Math.floor(Math.random() * 5),
            improvementRate: ((Math.random() - 0.5) * 10).toFixed(1)
        },
        date: session.session_date_thai || new Date(session.session_date).toLocaleDateString('th-TH'),
        time: session.session_time || new Date(session.session_date).toLocaleTimeString('th-TH', {
            hour: '2-digit', 
            minute: '2-digit'
        }),
        completedAt: session.session_date
    }));
    
    console.log('✅ โหลดจากฐานข้อมูลสำเร็จ:', exerciseHistory.length, 'รายการ');
    
    // อัปเดต UI
    updateTable();
    updateSummaryCards();
    updateChart();
    updateRecommendations();
    
    // โหลดสถิติเพิ่มเติม
    loadExerciseStats().catch(err => {
        console.warn('⚠️ ไม่สามารถโหลดสถิติเพิ่มเติมได้:', err.message);
    });
}

// ฟังก์ชันโหลดสถิติจากฐานข้อมูล
async function loadExerciseStats() {
    const token = localStorage.getItem('authToken');
    if (!token || token.startsWith('jwt_mock_token_') || token.startsWith('mock_token_')) {
        return; // ข้าม หาก token ไม่ถูกต้อง
    }
    
    try {
        const response = await fetch('http://127.0.0.1:3000/api/exercise-stats', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const result = await response.json();
            if (result.success) {
                console.log('📊 สถิติจากฐานข้อมูล:', result.data);
                updateStatsFromDatabase(result.data);
            }
        }
    } catch (error) {
        console.error('ไม่สามารถโหลดสถิติได้:', error);
    }
}

// ฟังก์ชันอัปเดต UI ด้วยสถิติจากฐานข้อมูล
function updateStatsFromDatabase(stats) {
    if (!stats.total_stats) return;
    
    const totalStats = stats.total_stats;
    
    // อัปเดตการ์ดสรุป
    const bestEl = document.getElementById('bestSession');
    const consistencyEl = document.getElementById('consistencyScore');
    
    if (bestEl && totalStats.best_accuracy) {
        bestEl.textContent = `${Math.round(totalStats.best_accuracy)}%`;
        bestEl.style.color = totalStats.best_accuracy >= 90 ? '#4CAF50' : 
                            totalStats.best_accuracy >= 75 ? '#FF9800' : '#F44336';
    }
    
    if (consistencyEl && stats.weekly_progress) {
        const weeklyCount = stats.weekly_progress.length;
        consistencyEl.textContent = `${weeklyCount} วัน`;
        consistencyEl.style.color = weeklyCount >= 5 ? '#4CAF50' : 
                                   weeklyCount >= 3 ? '#FF9800' : '#F44336';
    }
    
    // อัปเดตข้อความสถิติ
    const chartSubtitle = document.getElementById('chartSubtitle');
    if (chartSubtitle && totalStats.total_sessions) {
        chartSubtitle.textContent = `ทำไปแล้ว ${totalStats.total_sessions} ครั้ง - ความแม่นยำเฉลี่ย ${Math.round(totalStats.avg_accuracy)}%`;
    }
}

// ฟังก์ชันโหลดจาก localStorage (fallback)
function loadFromLocalStorage() {
    console.log('📂 โหลดจาก localStorage...');
    
    const history = localStorage.getItem('exerciseHistory');
    if (history) {
        try {
            exerciseHistory = JSON.parse(history);
            console.log('Exercise history loaded from localStorage:', exerciseHistory.length, 'sessions');
            
            // เรียงลำดับตามวันที่ใหม่ไปเก่า
            exerciseHistory.sort((a, b) => {
                const dateA = new Date(a.completedAt || a.date);
                const dateB = new Date(b.completedAt || b.date);
                return dateB - dateA;
            });
            
            updateTable();
            updateSummaryCards();
            updateChart();
            updateRecommendations();
        } catch (e) {
            console.error('Error parsing exercise history:', e);
            createSampleData();
        }
    } else {
        console.log('No exercise history found, creating sample data');
        createSampleData();
    }
}

// แสดงผลเซสชันล่าสุด
function displayLatestSession(results) {
    const section = document.getElementById('latestSessionSection');
    if (!section) return;
    
    section.style.display = 'block';

    // อัปเดตข้อมูลเซสชันล่าสุด
    const elements = {
        date: document.getElementById('latestSessionDate'),
        exerciseName: document.getElementById('latestExerciseName'),
        reps: document.getElementById('latestReps'),
        accuracy: document.getElementById('latestAccuracy'),
        duration: document.getElementById('latestDuration'),
        bestAccuracy: document.getElementById('latestBestAccuracy'),
        improvement: document.getElementById('latestImprovement')
    };

    if (elements.date) {
        elements.date.textContent = `${results.date} เวลา ${results.time}`;
    }
    if (elements.exerciseName) {
        elements.exerciseName.textContent = results.exerciseName;
    }
    if (elements.reps) {
        elements.reps.textContent = `${results.reps} ครั้ง`;
    }
    if (elements.accuracy) {
        elements.accuracy.textContent = `${results.accuracy}%`;
    }
    
    if (elements.duration && results.sessionStats) {
        const duration = Math.floor(results.sessionStats.exerciseTime / 60);
        const seconds = results.sessionStats.exerciseTime % 60;
        elements.duration.textContent = `${duration}:${seconds.toString().padStart(2, '0')} นาที`;
    }
        
    if (elements.bestAccuracy && results.sessionStats) {
        elements.bestAccuracy.textContent = `${results.sessionStats.bestAccuracy}%`;
    }
        
    if (elements.improvement && results.sessionStats) {
        const improvement = parseFloat(results.sessionStats.improvementRate) || 0;
        elements.improvement.textContent = improvement >= 0 ? `+${improvement}%` : `${improvement}%`;
        elements.improvement.style.color = improvement >= 0 ? '#4CAF50' : '#F44336';
    }

    // เพิ่มแอนิเมชัน
    setTimeout(() => {
        section.style.opacity = '0';
        section.style.transform = 'translateY(20px)';
        section.style.transition = 'all 0.6s ease';
        setTimeout(() => {
            section.style.opacity = '1';
            section.style.transform = 'translateY(0)';
        }, 100);
    }, 300);
}

// สร้างข้อมูลตัวอย่าง (เฉพาะกรณีไม่มีข้อมูลจริง)
function createSampleData() {
    const sampleData = [
        {
            exercise: 'arm-raise-forward',
            exerciseName: 'ท่ายกแขนไปข้างหน้า',
            reps: 15,
            accuracy: 78,
            sessionStats: {
                exerciseTime: 420,
                bestAccuracy: 85,
                improvementRate: 5.2
            },
            date: '05/09/2568',
            time: '09:30'
        },
        {
            exercise: 'leg-forward',
            exerciseName: 'ท่าเหยียดเข่าตรง',
            reps: 12,
            accuracy: 82,
            sessionStats: {
                exerciseTime: 380,
                bestAccuracy: 90,
                improvementRate: 3.1
            },
            date: '06/09/2568',
            time: '14:15'
        },
        {
            exercise: 'trunk-sway',
            exerciseName: 'ท่าโยกลำตัวซ้าย-ขวา',
            reps: 8,
            accuracy: 75,
            sessionStats: {
                exerciseTime: 300,
                bestAccuracy: 82,
                improvementRate: 2.8
            },
            date: '07/09/2568',
            time: '10:45'
        },
        {
            exercise: 'neck-tilt',
            exerciseName: 'ท่าเอียงศีรษะซ้าย-ขวา',
            reps: 10,
            accuracy: 88,
            sessionStats: {
                exerciseTime: 250,
                bestAccuracy: 92,
                improvementRate: 7.3
            },
            date: '08/09/2568',
            time: '16:20'
        }
    ];
    
    // เฉพาะกรณีที่ไม่มีข้อมูลเลย ถึงจะใช้ตัวอย่าง
    if (exerciseHistory.length === 0) {
        localStorage.setItem('exerciseHistory', JSON.stringify(sampleData));
        exerciseHistory = sampleData;
        updateTable();
        updateSummaryCards();
        updateChart();
    }
}

// ฟังก์ชันรีเฟรชข้อมูล
function refreshData() {
    console.log('Refreshing data...');
    exerciseHistory = []; // ล้างข้อมูลเก่า
    currentPage = 1; // รีเซ็ตหน้า
    loadExerciseData(); // โหลดข้อมูลใหม่
}

// เพิ่มปุ่มรีเฟรชข้อมูล
function addRefreshButton() {
    const tableControls = document.querySelector('.table-controls');
    if (tableControls && !document.getElementById('refreshBtn')) {
        const refreshBtn = document.createElement('button');
        refreshBtn.id = 'refreshBtn';
        refreshBtn.className = 'nav-btn';
        refreshBtn.innerHTML = '<i class="fas fa-sync-alt"></i> รีเฟรช';
        refreshBtn.onclick = refreshData;
        tableControls.appendChild(refreshBtn);
    }
}

// อัปเดตตาราง
function updateTable() {
    const tbody = document.getElementById('therapyTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';

    if (exerciseHistory.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = `<td colspan="6" style="text-align: center; color: #718096; padding: 2rem;">ยังไม่มีข้อมูลการออกกำลังกาย</td>`;
        return;
    }

    const startIndex = (currentPage - 1) * itemsPerPage;
    const endIndex = Math.min(startIndex + itemsPerPage, exerciseHistory.length);

    for (let i = startIndex; i < endIndex; i++) {
        const session = exerciseHistory[i];
        const row = tbody.insertRow();
        
        row.innerHTML = `
            <td>${session.date}<br><small style="color: #718096;">${session.time}</small></td>
            <td><strong>${session.exerciseName}</strong></td>
            <td><span style="font-weight: 600;">${session.reps} ครั้ง</span></td>
            <td>
                <span class="accuracy-badge ${getAccuracyClass(session.accuracy)}">
                    ${session.accuracy}%
                </span>
            </td>
            <td>${formatDuration(session.sessionStats?.exerciseTime || 0)}</td>
            <td>${generateComment(session)}</td>
        `;
    }

    updateTableInfo();
    updatePagination();
    addRefreshButton(); // เพิ่มปุ่มรีเฟรช
}

// ฟังก์ชันช่วยเหลือ
function getAccuracyClass(accuracy) {
    if (accuracy >= 90) return 'excellent';
    if (accuracy >= 80) return 'good';
    if (accuracy >= 70) return 'fair';
    return 'poor';
}

function formatDuration(seconds) {
    if (!seconds) return '0:00 นาที';
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs.toString().padStart(2, '0')} นาที`;
}

function generateComment(session) {
    if (session.accuracy >= 90) return 'ทำได้ดีมาก!';
    if (session.accuracy >= 80) return 'ความก้าวหน้าดี';
    if (session.accuracy >= 70) return 'ต้องการปรับปรุง';
    return 'ควรฝึกเพิ่มเติม';
}

// อัปเดตสรุปผลงาน
function updateSummaryCards() {
    if (exerciseHistory.length === 0) return;

    // คำนวดค่าเฉลี่ย
    const totalAccuracy = exerciseHistory.reduce((sum, session) => sum + (session.accuracy || 0), 0);
    const averageAccuracy = Math.round(totalAccuracy / exerciseHistory.length);
    
    // หาความแม่นยำสูงสุด
    const bestAccuracy = Math.max(...exerciseHistory.map(session => 
        session.sessionStats?.bestAccuracy || session.accuracy || 0
    ));
    
    // คำนวดความสม่ำเสมอ (จำนวนวันที่ออกกำลังกายในสัปดาห์ที่ผ่านมา)
    const lastWeek = new Date();
    lastWeek.setDate(lastWeek.getDate() - 7);
    const recentSessions = exerciseHistory.filter(session => {
        try {
            const sessionDate = new Date(session.date.split('/').reverse().join('-'));
            return sessionDate >= lastWeek;
        } catch (e) {
            return false;
        }
    });

    // อัปเดตเฉพาะ elements ที่มีอยู่จริง
    const bestEl = document.getElementById('bestSession');
    const consistencyEl = document.getElementById('consistencyScore');
    
    if (bestEl) {
        bestEl.textContent = `${bestAccuracy}%`;
        bestEl.style.color = bestAccuracy >= 90 ? '#4CAF50' : bestAccuracy >= 75 ? '#FF9800' : '#F44336';
    }
    
    if (consistencyEl) {
        consistencyEl.textContent = `${recentSessions.length} วัน`;
        consistencyEl.style.color = recentSessions.length >= 5 ? '#4CAF50' : recentSessions.length >= 3 ? '#FF9800' : '#F44336';
    }

    console.log('Summary updated:', { averageAccuracy, consistency: recentSessions.length, bestAccuracy });
}

// อัปเดตคำแนะนำ
function updateRecommendations() {
    if (exerciseHistory.length === 0) return;

    const recentAccuracy = exerciseHistory[0]?.accuracy || 0;
    const averageAccuracy = exerciseHistory.reduce((sum, s) => sum + (s.accuracy || 0), 0) / exerciseHistory.length;

    // คำแนะนำการออกกำลังกาย
    const exerciseRecs = document.getElementById('exerciseRecommendations');
    if (!exerciseRecs) return;
    
    exerciseRecs.innerHTML = '';

    if (averageAccuracy < 70) {
        exerciseRecs.innerHTML = `
            <li>ควรฝึกท่าทางพื้นฐานให้ช้าและถูกต้องก่อน</li>
            <li>เพิ่มเวลาการฝึกเป็น 2 ครั้งต่อวัน</li>
            <li>ขอคำแนะนำเพิ่มเติมจากผู้เชี่ยวชาญ</li>
        `;
    } else if (averageAccuracy < 85) {
        exerciseRecs.innerHTML = `
            <li>ออกกำลังกายแขนและขาด้านซ้าย 3 ครั้งต่อสัปดาห์</li>
            <li>ฝึกการทรงตัวโดยการยืนบนขาเดียว</li>
            <li>เพิ่มความเร็วในการทำท่าทางเมื่อทำได้ถูกต้องแล้ว</li>
        `;
    } else {
        exerciseRecs.innerHTML = `
            <li>ทำได้ดีมาก! คงความสม่ำเสมอต่อไป</li>
            <li>ลองท่าทางที่ท้าทายมากขึ้น</li>
            <li>ช่วยแนะนำผู้ป่วยรายอื่น</li>
        `;
    }
}

// เริ่มต้นฟังก์ชันตาราง
function initTableFunctions() {
    // ค้นหา
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const filteredHistory = exerciseHistory.filter(session => 
                session.exerciseName.toLowerCase().includes(searchTerm) ||
                session.date.includes(searchTerm)
            );
            
            displayFilteredResults(filteredHistory);
        });
    }

    // เปลี่ยนจำนวนรายการต่อหน้า
    const entriesSelect = document.getElementById('entriesSelect');
    if (entriesSelect) {
        entriesSelect.addEventListener('change', function() {
            itemsPerPage = parseInt(this.value);
            currentPage = 1;
            updateTable();
        });
    }

    // ปุ่มเปลี่ยนหน้า
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (prevBtn) {
        prevBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                updateTable();
            }
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', () => {
            const totalPages = Math.ceil(exerciseHistory.length / itemsPerPage);
            if (currentPage < totalPages) {
                currentPage++;
                updateTable();
            }
        });
    }
}

// แสดงผลลัพธ์ที่กรอง
function displayFilteredResults(filteredData) {
    const tbody = document.getElementById('therapyTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';

    if (filteredData.length === 0) {
        const row = tbody.insertRow();
        row.innerHTML = `<td colspan="6" style="text-align: center; color: #718096; padding: 2rem;">ไม่พบข้อมูลที่ค้นหา</td>`;
        return;
    }

    filteredData.forEach(session => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${session.date}<br><small style="color: #718096;">${session.time}</small></td>
            <td><strong>${session.exerciseName}</strong></td>
            <td><span style="font-weight: 600;">${session.reps} ครั้ง</span></td>
            <td>
                <span class="accuracy-badge ${getAccuracyClass(session.accuracy)}">
                    ${session.accuracy}%
                </span>
            </td>
            <td>${formatDuration(session.sessionStats?.exerciseTime || 0)}</td>
            <td>${generateComment(session)}</td>
        `;
    });

    const tableInfoText = document.getElementById('tableInfoText');
    if (tableInfoText) {
        tableInfoText.textContent = 
            `แสดง 1 ถึง ${filteredData.length} จาก ${filteredData.length} รายการ`;
    }
}

// อัปเดตข้อมูลตาราง
function updateTableInfo() {
    if (exerciseHistory.length === 0) return;
    
    const startIndex = (currentPage - 1) * itemsPerPage + 1;
    const endIndex = Math.min(currentPage * itemsPerPage, exerciseHistory.length);
    
    const tableInfoText = document.getElementById('tableInfoText');
    if (tableInfoText) {
        tableInfoText.textContent = 
            `แสดง ${startIndex} ถึง ${endIndex} จาก ${exerciseHistory.length} รายการ`;
    }
}

// อัปเดตการเปลี่ยนหน้า
function updatePagination() {
    const totalPages = Math.ceil(exerciseHistory.length / itemsPerPage);
    
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    const pageInfo = document.getElementById('pageInfo');
    
    if (prevBtn) prevBtn.disabled = currentPage === 1;
    if (nextBtn) nextBtn.disabled = currentPage === totalPages || exerciseHistory.length === 0;
    if (pageInfo) pageInfo.textContent = exerciseHistory.length === 0 ? '0' : currentPage;
}

// สร้างกราฟ
function initChart() {
    const canvas = document.getElementById('progressChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    if (exerciseHistory.length === 0) {
        drawEmptyChart(ctx, canvas);
        return;
    }
    
    // ข้อมูลกราฟ - เอา 7 รายการล่าสุด
    const recentData = exerciseHistory.slice(0, 7).reverse(); // ย้อนกลับเพื่อให้เรียงจากเก่าไปใหม่
    const data = recentData.map(session => session.accuracy || 0);
    const labels = recentData.map(session => {
        try {
            const date = new Date(session.date.split('/').reverse().join('-'));
            return date.toLocaleDateString('th-TH', { weekday: 'short' });
        } catch (e) {
            return 'N/A';
        }
    });
    
    drawChart(ctx, canvas, data, labels);
}

// อัปเดตกราฟ - ฟังก์ชันที่หายไป
function updateChart() {
    initChart(); // เรียกใช้ initChart เพื่อวาดกราฟใหม่
}

// วาดกราฟ
function drawChart(ctx, canvas, data, labels) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    const padding = 40;
    const chartWidth = canvas.width - 2 * padding;
    const chartHeight = canvas.height - 2 * padding;
    const maxValue = 100;
    
    // วาดเส้นตาราง
    ctx.strokeStyle = '#e2e8f0';
    ctx.lineWidth = 1;
    
    // เส้นแนวนอน
    for (let i = 0; i <= 5; i++) {
        const y = padding + (chartHeight / 5) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(padding + chartWidth, y);
        ctx.stroke();
        
        // ป้ายกำกับแกน Y
        ctx.fillStyle = '#718096';
        ctx.font = '10px Kanit';
        ctx.textAlign = 'right';
        const value = maxValue - (maxValue / 5) * i;
        ctx.fillText(`${value}%`, padding - 10, y + 3);
    }
    
    // เส้นแนวตั้ง (เฉพาะกรณีที่มีข้อมูล)
    if (data.length > 0) {
        for (let i = 0; i < data.length; i++) {
            const x = padding + (chartWidth / Math.max(1, data.length - 1)) * i;
            ctx.beginPath();
            ctx.moveTo(x, padding);
            ctx.lineTo(x, padding + chartHeight);
            ctx.stroke();
        }
    }
    
    // วาดเส้นกราฟ
    if (data.length > 1) {
        ctx.strokeStyle = '#4fd1c7';
        ctx.lineWidth = 3;
        ctx.beginPath();
        
        data.forEach((value, index) => {
            const x = padding + (chartWidth / Math.max(1, data.length - 1)) * index;
            const y = padding + chartHeight - (value / maxValue) * chartHeight;
            
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        
        ctx.stroke();
    }
    
    // วาดจุด
    data.forEach((value, index) => {
        const x = padding + (chartWidth / Math.max(1, data.length - 1)) * index;
        const y = padding + chartHeight - (value / maxValue) * chartHeight;
        
        ctx.fillStyle = '#38b2ac';
        ctx.beginPath();
        ctx.arc(x, y, 4, 0, 2 * Math.PI);
        ctx.fill();
        
        // ป้ายกำกับค่า
        ctx.fillStyle = '#2d3748';
        ctx.font = '10px Kanit';
        ctx.textAlign = 'center';
        ctx.fillText(`${value}%`, x, y - 10);
    });
    
    // ป้ายกำกับแกน X
    ctx.fillStyle = '#718096';
    ctx.font = '10px Kanit';
    ctx.textAlign = 'center';
    labels.forEach((label, index) => {
        const x = padding + (chartWidth / Math.max(1, data.length - 1)) * index;
        ctx.fillText(label, x, canvas.height - 10);
    });
}

// วาดกราฟเปล่า
function drawEmptyChart(ctx, canvas) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#718096';
    ctx.font = '16px Kanit';
    ctx.textAlign = 'center';
    ctx.fillText('ยังไม่มีข้อมูลการออกกำลังกาย', canvas.width / 2, canvas.height / 2);
}

// ฟังก์ชันการนำทาง
function goBack() {
    showLoading('กำลังกลับไปหน้าหลัก...');
    setTimeout(() => {
        window.location.href = 'index2.html';
    }, 1000);
}

function exitSystem() {
    if (confirm('คุณต้องการออกจากระบบหรือไม่?')) {
        showLoading('กำลังออกจากระบบ...');
        sessionStorage.removeItem('userData');
        setTimeout(() => {
            window.location.href = 'login.html';
        }, 1000);
    }
}

function printReport() {
    showLoading('กำลังเตรียมรายงาน...');
    setTimeout(() => {
        window.print();
        hideLoading();
    }, 1000);
}

function continueExercise() {
    showLoading('กำลังเตรียมโปรแกรมการออกกำลังกาย...');
    setTimeout(() => {
        window.location.href = 'index2.html';
    }, 1000);
}

// ฟังก์ชันแสดง/ซ่อนหน้าโหลด
function showLoading(message) {
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) {
        const messageElement = loadingOverlay.querySelector('p');
        if (messageElement) {
            messageElement.textContent = message;
        }
        loadingOverlay.classList.remove('hidden');
        
        document.body.style.transform = 'scale(0.95)';
        document.body.style.opacity = '0.7';
        document.body.style.transition = 'all 0.3s ease';
    }
}

function hideLoading() {
    const loadingOverlay = document.getElementById('loadingOverlay');
    if (loadingOverlay) {
        loadingOverlay.classList.add('hidden');
        
        document.body.style.transform = 'scale(1)';
        document.body.style.opacity = '1';
    }
}

// ฟังก์ชันทดสอบ - สามารถเรียกใน console
function testData() {
    console.log('Current exercise history:', exerciseHistory);
    console.log('localStorage exerciseHistory:', localStorage.getItem('exerciseHistory'));
    console.log('localStorage lastSessionData:', localStorage.getItem('lastSessionData'));
}

// เพิ่ม event listener สำหรับ keyboard shortcuts
document.addEventListener('keydown', function(event) {
    if (event.ctrlKey && event.key === 'r') {
        event.preventDefault();
        refreshData();
    }
    if (event.key === 'F5') {
        event.preventDefault();
        refreshData();
    }
});

// ฟังก์ชันตรวจสอบสถานะการเชื่อมต่อ
async function checkDatabaseConnection() {
    const token = localStorage.getItem('authToken');
    if (!token || token.startsWith('jwt_mock_token_') || token.startsWith('mock_token_')) {
        console.warn('⚠️ ไม่พบ JWT token ที่ถูกต้อง - ใช้โหมดออฟไลน์');
        return false;
    }
    
    try {
        const response = await fetch('http://127.0.0.1:3000/test-db', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        const isConnected = response.ok && result.success;
        
        console.log(isConnected ? '✅ เชื่อมต่อฐานข้อมูลได้' : '❌ เชื่อมต่อฐานข้อมูลไม่ได้');
        
        if (!isConnected) {
            console.log('Database response:', result);
        }
        
        return isConnected;
    } catch (error) {
        console.error('❌ ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้:', error);
        return false;
    }
}

// ตรวจสอบ Authentication ก่อนโหลดข้อมูล - แก้ไขให้ไม่สร้าง mock token
function ensureAuthentication() {
    let token = localStorage.getItem('authToken');
    let userData = localStorage.getItem('userData');
    
    console.log('🔍 Checking authentication:', { hasToken: !!token, hasUserData: !!userData });
    
    // หาก token ไม่มีหรือเป็น mock token ให้แจ้งเตือน
    if (!token || token.startsWith('jwt_mock_token_') || token.startsWith('mock_token_')) {
        console.log('⚠️ ไม่พบ JWT token ที่ถูกต้อง - ใช้โหมดออฟไลน์');
        // ไม่สร้าง mock token ใหม่
        token = null;
    }
    
    // ถ้าไม่มีข้อมูลผู้ใช้ สร้างขึ้นใหม่
    if (!userData) {
        const mockUser = {
            user_id: Math.floor(Math.random() * 1000) + 1,
            phone: '08' + Math.floor(Math.random() * 100000000).toString().padStart(8, '0'),
            full_name: 'ผู้ใช้ทดสอบระบบ',
            role: 'Patient'
        };
        localStorage.setItem('userData', JSON.stringify(mockUser));
        console.log('👤 สร้าง mock user data:', mockUser);
        userData = JSON.stringify(mockUser);
    }
    
    return { token, userData: JSON.parse(userData) };
}

// Debug function - เรียกได้จาก console
window.debugReport = {
    exerciseHistory: () => exerciseHistory,
    refreshData: refreshData,
    testData: testData,
    clearData: () => {
        localStorage.removeItem('exerciseHistory');
        localStorage.removeItem('lastSessionData');
        console.log('All data cleared');
        refreshData();
    },
    showToken: () => {
        const token = localStorage.getItem('authToken');
        console.log('Current token:', token);
        return token;
    },
    showUser: () => {
        const userData = localStorage.getItem('userData');
        console.log('Current user:', userData);
        return userData;
    },
    resetAuth: () => {
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
        console.log('Authentication reset');
        location.reload();
    },
    testAPI: async () => {
        const token = localStorage.getItem('authToken');
        if (!token || token.startsWith('mock_token_')) {
            console.log('❌ ไม่มี JWT token ที่ถูกต้อง');
            return;
        }
        
        try {
            const response = await fetch('http://127.0.0.1:3000/api/exercise-sessions', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            console.log('API Test Result:', response.status, await response.text());
        } catch (error) {
            console.error('API Test Error:', error);
        }
    }
};