// ========================================
// ฟังก์ชันยูทิลิตี้สำหรับระบบกายภาพบำบัด
// utils.js
// ========================================

class StrokeUtils {
    // คำนวณมุมระหว่างจุดสามจุด
    static calculateAngle(point1, point2, point3) {
        try {
            const radians = Math.atan2(point3.y - point2.y, point3.x - point2.x) - 
                          Math.atan2(point1.y - point2.y, point1.x - point2.x);
            let angle = Math.abs(radians * (180 / Math.PI));
            
            if (angle > 180) {
                angle = 360 - angle;
            }
            
            return angle;
        } catch (error) {
            console.warn('⚠️ Error calculating angle:', error);
            return 0;
        }
    }

    // คำนวณระยะทางระหว่างสองจุด
    static calculateDistance(point1, point2) {
        try {
            const dx = point2.x - point1.x;
            const dy = point2.y - point1.y;
            return Math.sqrt(dx * dx + dy * dy);
        } catch (error) {
            console.warn('⚠️ Error calculating distance:', error);
            return 0;
        }
    }

    // คำนวณความแม่นยำ
    static calculateAccuracy(currentValue, targetValue, tolerance = 10) {
        try {
            const difference = Math.abs(currentValue - targetValue);
            const maxDifference = tolerance;
            
            if (difference <= maxDifference) {
                const accuracy = 100 - (difference / maxDifference) * 30;
                return Math.max(70, Math.min(100, Math.round(accuracy)));
            } else {
                const accuracy = 70 - ((difference - maxDifference) / maxDifference) * 70;
                return Math.max(0, Math.round(accuracy));
            }
        } catch (error) {
            console.warn('⚠️ Error calculating accuracy:', error);
            return 0;
        }
    }

    // ตรวจสอบความถูกต้องของ landmarks
    static validateLandmarks(landmarks, requiredIndices) {
        if (!landmarks || !Array.isArray(landmarks)) return false;
        
        for (const index of requiredIndices) {
            const landmark = landmarks[index];
            if (!landmark || 
                typeof landmark.x !== 'number' || 
                typeof landmark.y !== 'number' ||
                (landmark.visibility && landmark.visibility < 0.5)) {
                return false;
            }
        }
        return true;
    }

    // แปลงเวลาเป็นรูปแบบ MM:SS
    static formatTime(seconds) {
        try {
            const minutes = Math.floor(seconds / 60);
            const remainingSeconds = seconds % 60;
            return `${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`;
        } catch (error) {
            console.warn('⚠️ Error formatting time:', error);
            return '00:00';
        }
    }

    // ได้ชื่อการออกกำลังกายภาษาไทย
    static getExerciseName(exerciseId) {
        const exerciseData = StrokeConfig.EXERCISE_DATA[exerciseId];
        return exerciseData ? exerciseData.name : 'ไม่ทราบชื่อท่า';
    }

    // คำนวณสถิติพื้นฐาน
    static calculateStatistics(values) {
        if (!values || values.length === 0) {
            return {
                min: 0,
                max: 0,
                avg: 0,
                std: 0
            };
        }

        try {
            const min = Math.min(...values);
            const max = Math.max(...values);
            const avg = values.reduce((sum, val) => sum + val, 0) / values.length;
            
            // คำนวณ standard deviation
            const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / values.length;
            const std = Math.sqrt(variance);

            return {
                min: Math.round(min),
                max: Math.round(max),
                avg: Math.round(avg),
                std: Math.round(std)
            };
        } catch (error) {
            console.warn('⚠️ Error calculating statistics:', error);
            return { min: 0, max: 0, avg: 0, std: 0 };
        }
    }

    // สร้าง Session ID
    static generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    // สร้าง UUID
    static generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }

    // บันทึกข้อมูลใน localStorage
    static saveToStorage(key, data) {
        try {
            localStorage.setItem(key, JSON.stringify(data));
            return true;
        } catch (error) {
            console.warn('⚠️ Error saving to storage:', error);
            return false;
        }
    }

    // ดึงข้อมูลจาก localStorage
    static getFromStorage(key, defaultValue = null) {
        try {
            const data = localStorage.getItem(key);
            return data ? JSON.parse(data) : defaultValue;
        } catch (error) {
            console.warn('⚠️ Error getting from storage:', error);
            return defaultValue;
        }
    }

    // ลบข้อมูลจาก localStorage
    static removeFromStorage(key) {
        try {
            localStorage.removeItem(key);
            return true;
        } catch (error) {
            console.warn('⚠️ Error removing from storage:', error);
            return false;
        }
    }

    // แปลงองศาเป็นเรเดียน
    static degreesToRadians(degrees) {
        return degrees * (Math.PI / 180);
    }

    // แปลงเรเดียนเป็นองศา
    static radiansToDegrees(radians) {
        return radians * (180 / Math.PI);
    }

    // ปรับค่าให้อยู่ในช่วงที่กำหนด
    static clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    // ปรับให้เป็นทศนิยม 2 ตำแหน่ง
    static toFixed2(value) {
        return Math.round(value * 100) / 100;
    }

    // ตรวจสอบว่าเป็นตัวเลขหรือไม่
    static isNumber(value) {
        return typeof value === 'number' && !isNaN(value) && isFinite(value);
    }

    // เล่นเสียงสำเร็จ
    static playSuccessSound() {
        try {
            // สร้างเสียง beep สั้นๆ
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
            oscillator.frequency.setValueAtTime(1000, audioContext.currentTime + 0.1);
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.3, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.2);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.2);
        } catch (error) {
            console.log('🔇 เสียงไม่สามารถเล่นได้');
        }
    }

    // เล่นเสียงเตือน
    static playWarningSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(400, audioContext.currentTime);
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.2, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.15);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.15);
        } catch (error) {
            console.log('🔇 เสียงไม่สามารถเล่นได้');
        }
    }

    // เล่นเสียงข้อผิดพลาด
    static playErrorSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(200, audioContext.currentTime);
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.3, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.3);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.3);
        } catch (error) {
            console.log('🔇 เสียงไม่สามารถเล่นได้');
        }
    }

    // เล่นเสียงพร้อม
    static playReadySound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            const oscillator = audioContext.createOscillator();
            const gainNode = audioContext.createGain();
            
            oscillator.connect(gainNode);
            gainNode.connect(audioContext.destination);
            
            oscillator.frequency.setValueAtTime(600, audioContext.currentTime);
            
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);
            gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.01);
            gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
            
            oscillator.start(audioContext.currentTime);
            oscillator.stop(audioContext.currentTime + 0.1);
        } catch (error) {
            console.log('🔇 เสียงไม่สามารถเล่นได้');
        }
    }

    // เล่นเสียงเสร็จสิ้น
    static playCompleteSound() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();
            
            // เล่นเสียง 3 โน้ต
            const frequencies = [600, 800, 1000];
            
            frequencies.forEach((freq, index) => {
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                oscillator.frequency.setValueAtTime(freq, audioContext.currentTime);
                
                const startTime = audioContext.currentTime + (index * 0.2);
                gainNode.gain.setValueAtTime(0, startTime);
                gainNode.gain.linearRampToValueAtTime(0.2, startTime + 0.01);
                gainNode.gain.exponentialRampToValueAtTime(0.01, startTime + 0.15);
                
                oscillator.start(startTime);
                oscillator.stop(startTime + 0.15);
            });
        } catch (error) {
            console.log('🔇 เสียงไม่สามารถเล่นได้');
        }
    }

    // ตรวจสอบการรองรับ Web Audio API
    static isAudioSupported() {
        return !!(window.AudioContext || window.webkitAudioContext);
    }

    // ดีบัก: แสดงข้อมูล landmarks
    static debugLandmarks(landmarks, title = 'Landmarks') {
        console.group(`🔍 ${title}`);
        
        if (!landmarks || !Array.isArray(landmarks)) {
            console.log('❌ Invalid landmarks data');
            console.groupEnd();
            return;
        }
        
        console.log(`📊 จำนวน landmarks: ${landmarks.length}`);
        
        // แสดงจุดสำคัญ
        const importantPoints = [0, 11, 12, 13, 14, 15, 16, 23, 24, 25, 26];
        const pointNames = ['NOSE', 'L_SHOULDER', 'R_SHOULDER', 'L_ELBOW', 'R_ELBOW', 'L_WRIST', 'R_WRIST', 'L_HIP', 'R_HIP', 'L_KNEE', 'R_KNEE'];
        
        importantPoints.forEach((index, i) => {
            const landmark = landmarks[index];
            if (landmark) {
                console.log(`${pointNames[i]}: x=${landmark.x.toFixed(3)}, y=${landmark.y.toFixed(3)}, v=${(landmark.visibility || 0).toFixed(3)}`);
            }
        });
        
        console.groupEnd();
    }

    // ดีบัก: แสดงข้อมูลมุม
    static debugAngles(angles, title = 'Angles') {
        console.group(`📐 ${title}`);
        
        Object.entries(angles).forEach(([joint, angle]) => {
            console.log(`${joint}: ${Math.round(angle)}°`);
        });
        
        console.groupEnd();
    }

    // คำนวณความเร็วการเคลื่อนไหว
    static calculateMovementSpeed(currentPos, previousPos, timeDelta) {
        if (!currentPos || !previousPos || timeDelta <= 0) return 0;
        
        const distance = this.calculateDistance(currentPos, previousPos);
        return distance / timeDelta; // pixels per millisecond
    }

    // ตรวจจับการสั่น (tremor)
    static detectTremor(positionHistory, threshold = 0.02) {
        if (!positionHistory || positionHistory.length < 5) return false;
        
        const recentPositions = positionHistory.slice(-5);
        let changeCount = 0;
        
        for (let i = 1; i < recentPositions.length - 1; i++) {
            const prev = recentPositions[i - 1];
            const curr = recentPositions[i];
            const next = recentPositions[i + 1];
            
            const d1 = this.calculateDistance(prev, curr);
            const d2 = this.calculateDistance(curr, next);
            
            if (d1 > threshold && d2 > threshold) {
                changeCount++;
            }
        }
        
        return changeCount >= 3; // ถ้าเปลี่ยนตำแหน่งมากกว่า 3 ครั้งถือว่าสั่น
    }
}

// ส่งออกเป็น global variable
window.StrokeUtils = StrokeUtils;
console.log('✅ utils.js โหลดเรียบร้อยแล้ว');