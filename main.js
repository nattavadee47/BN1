// ========================================
// ระบบกายภาพบำบัดสำหรับผู้ป่วย Stroke - ไฟล์หลัก (แก้ไขแล้ว)
// main.js
// ========================================

class StrokeTherapySystem {
    constructor() {
        this.poseDetection = null;
        this.exerciseAnalyzer = null;
        this.canvasRenderer = null;
        this.uiController = null;
        
        this.isSystemReady = false;
        this.isExercising = false;
        this.currentSession = null;
        
        this.sessionTimer = null;
        this.sessionStartTime = null;
        this.sessionDuration = 0;

        // การตั้งค่าเพิ่มเติม
        this.settings = {
            sensitivity: 80,
            soundEnabled: true
        };
    }

    // เริ่มต้นระบบ
    async initialize() {
        try {
            console.log('🚀 เริ่มโหลดระบบกายภาพบำบัด Stroke...');
            
            // ตรวจสอบการรองรับของเบราว์เซอร์
            const browserCheck = this.checkBrowserSupport();
            if (!browserCheck.supported) {
                throw new Error(`เบราว์เซอร์ไม่รองรับ: ${browserCheck.missing.join(', ')}`);
            }

            // รอให้ MediaPipe โหลดเสร็จ
            await this.waitForMediaPipe();
            
            // เริ่มต้นคอมโพเนนต์ต่างๆ
            this.initializeComponents();
            
            // ตั้งค่า Event Listeners
            this.setupEventListeners();
            
            // ตั้งค่าระบบตรวจจับท่าทาง
            await this.setupPoseDetection();
            
            this.isSystemReady = true;
            console.log('✅ ระบบพร้อมใช้งาน');
            
            return true;

        } catch (error) {
            console.error('❌ ไม่สามารถเริ่มต้นระบบได้:', error);
            this.showError(`เกิดข้อผิดพลาด: ${error.message}`);
            return false;
        }
    }

    // ตรวจสอบการรองรับของเบราว์เซอร์
    checkBrowserSupport() {
        const missing = [];
        const supported = {
            webrtc: false,
            webgl: false,
            audioContext: false,
            localStorage: false
        };

        // ตรวจสอบ WebRTC
        if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
            supported.webrtc = true;
        } else {
            missing.push('Camera Access');
        }

        // ตรวจสอบ WebGL
        const canvas = document.createElement('canvas');
        if (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')) {
            supported.webgl = true;
        } else {
            missing.push('WebGL');
        }

        // ตรวจสอบ Audio Context
        if (window.AudioContext || window.webkitAudioContext) {
            supported.audioContext = true;
        } else {
            missing.push('Audio');
        }

        // ตรวจสอบ Local Storage
        if (window.localStorage) {
            supported.localStorage = true;
        } else {
            missing.push('Local Storage');
        }

        return {
            supported: missing.length === 0,
            missing: missing,
            details: supported
        };
    }

    // รอให้ MediaPipe โหลด
    async waitForMediaPipe() {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const maxAttempts = 100;
            
            const checkMediaPipe = () => {
                attempts++;
                
                if (window.Pose && window.Camera && window.drawConnectors) {
                    console.log('✅ MediaPipe พร้อมใช้งาน');
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('MediaPipe libraries ไม่โหลด'));
                } else {
                    setTimeout(checkMediaPipe, 100);
                }
            };
            
            checkMediaPipe();
        });
    }

    // เริ่มต้นคอมโพเนนต์ต่างๆ
    initializeComponents() {
        try {
            // UI Controller
            this.uiController = new UIController();
            this.uiController.initialize();

            // Exercise Analyzer
            this.exerciseAnalyzer = new ExerciseAnalyzer();

            // Pose Detection System
            this.poseDetection = new PoseDetectionSystem();

            // Canvas Renderer
            const videoElement = document.getElementById('input-video');
            const canvasElement = document.getElementById('output-canvas');
            
            if (videoElement && canvasElement) {
                this.canvasRenderer = new CanvasRenderer(canvasElement, videoElement);
            } else {
                console.warn('⚠️ ไม่พบ video หรือ canvas element');
            }

            console.log('🔧 เริ่มต้นคอมโพเนนต์เรียบร้อย');
        } catch (error) {
            console.error('❌ ข้อผิดพลาดในการเริ่มต้นคอมโพเนนต์:', error);
            throw error;
        }
    }

    // ตั้งค่า Event Listeners
    setupEventListeners() {
        try {
            // Pose detection callbacks
            if (this.poseDetection) {
                this.poseDetection.addDetectionCallback((data) => {
                    this.handlePoseDetection(data);
                });
            }

            console.log('🎯 Event Listeners ตั้งค่าเรียบร้อย');
        } catch (error) {
            console.error('❌ ข้อผิดพลาดในการตั้งค่า Event Listeners:', error);
        }
    }

    // ตั้งค่าระบบตรวจจับท่าทาง
    async setupPoseDetection() {
        try {
            this.updateDetectionStatus('กำลังเตรียมกล้อง...');
            
            // เริ่มต้นการตรวจจับท่าทาง
            await this.poseDetection.initialize();
            
            // ตั้งค่ากล้อง
            const videoElement = document.getElementById('input-video');
            if (!videoElement) {
                throw new Error('ไม่พบ video element');
            }
            
            await this.poseDetection.setupCamera(videoElement);
            
            this.updateDetectionStatus('กล้องพร้อมใช้งาน', 'detected');
            this.showFeedback('กล้องพร้อมใช้งาน - ระบบพร้อมตรวจจับท่าทาง');

        } catch (error) {
            console.error('❌ ไม่สามารถตั้งค่ากล้องได้:', error);
            this.updateDetectionStatus('ไม่สามารถเข้าถึงกล้อง', 'error');
            throw error;
        }
    }

    // เริ่มการออกกำลังกาย
    startExercise(exerciseId) {
        try {
            if (!this.isSystemReady) {
                this.showFeedback('ระบบยังไม่พร้อม กรุณารอสักครู่', 'warning');
                return false;
            }

            if (!exerciseId) {
                this.showFeedback('กรุณาเลือกท่าออกกำลังกายก่อน', 'warning');
                return false;
            }

            // เริ่มการวิเคราะห์ท่า
            const success = this.exerciseAnalyzer.startExercise(exerciseId);
            if (!success) {
                this.showFeedback('ไม่สามารถเริ่มการฝึกได้', 'error');
                return false;
            }
            
            // เริ่มจับเวลา
            this.startSessionTimer();
            
            this.isExercising = true;
            
            // อัปเดต UI
            this.updateDetectionStatus('กำลังตรวจจับท่าทาง...', 'detecting');
            
            const exerciseName = StrokeUtils.getExerciseName(exerciseId);
            this.showFeedback(`เริ่มการฝึก: ${exerciseName}`, 'success');
            
            console.log(`🏃‍♂️ เริ่มการฝึก: ${exerciseName}`);
            return true;

        } catch (error) {
            console.error('❌ ไม่สามารถเริ่มการฝึกได้:', error);
            this.showFeedback(`เกิดข้อผิดพลาด: ${error.message}`, 'error');
            return false;
        }
    }

    // หยุดการออกกำลังกาย
    stopExercise() {
        if (!this.isExercising) return null;

        try {
            // หยุดการวิเคราะห์
            const sessionStats = this.exerciseAnalyzer.stopExercise();
            
            // หยุดจับเวลา
            this.stopSessionTimer();
            
            this.isExercising = false;

            // อัปเดต UI
            this.updateDetectionStatus('หยุดการตรวจจับแล้ว');
            this.showFeedback('หยุดการฝึกแล้ว');

            console.log('⏹️ หยุดการฝึกแล้ว');
            return sessionStats;

        } catch (error) {
            console.error('❌ ข้อผิดพลาดในการหยุดการฝึก:', error);
            return null;
        }
    }

    // รีเซ็ตการออกกำลังกาย
    resetExercise() {
        try {
            this.stopExercise();
            this.exerciseAnalyzer.reset();
            
            this.showFeedback('รีเซ็ตการฝึกเรียบร้อย');
            console.log('🔄 รีเซ็ตการฝึกเรียบร้อย');
        } catch (error) {
            console.error('❌ ข้อผิดพลาดในการรีเซ็ต:', error);
        }
    }

    // จัดการการตรวจจับท่าทาง
    handlePoseDetection(data) {
        try {
            if (data.type === 'pose_detected') {
                // อัปเดตมุมเรียลไทม์
                if (this.uiController) {
                    this.uiController.updateRealtimeAngles(data.angles);
                }
                
                // วิเคราะห์การออกกำลังกาย
                if (this.isExercising && this.exerciseAnalyzer) {
                    const analysis = this.exerciseAnalyzer.analyzeExercise(data.results, data.angles);
                    this.handleExerciseAnalysis(analysis);
                }
                
                // วาดผลการตรวจจับ
                if (this.canvasRenderer) {
                    const exerciseState = this.getCurrentExerciseState();
                    this.canvasRenderer.drawPoseResults(data.results, exerciseState);
                }

            } else if (data.type === 'pose_lost') {
                this.updateDetectionStatus('กำลังค้นหาบุคคลในกรอบภาพ...', 'waiting');
            }
        } catch (error) {
            console.warn('⚠️ ข้อผิดพลาดในการจัดการ pose detection:', error);
        }
    }

    // จัดการผลการวิเคราะห์การออกกำลังกาย
    handleExerciseAnalysis(analysis) {
        if (!analysis) return;

        try {
            // อัปเดตข้อมูลเรียลไทม์
            if (this.uiController) {
                this.uiController.updateRealtimeInfo({
                    currentAngle: analysis.currentAngle,
                    accuracy: analysis.accuracy,
                    reps: this.exerciseAnalyzer.repCounter,
                    phase: analysis.phase
                });

                // อัปเดตสถิติ
                this.uiController.updateStatistics({
                    reps: this.exerciseAnalyzer.repCounter,
                    accuracy: analysis.accuracy,
                    score: this.exerciseAnalyzer.repCounter * 10,
                    targetReps: this.exerciseAnalyzer.exerciseState.targetReps
                });
            }

            // แสดงข้อความ feedback
            if (analysis.feedback) {
                let feedbackType = 'info';
                if (analysis.feedback.includes('สำเร็จ') || analysis.feedback.includes('ดี') || analysis.feedback.includes('ยอดเยี่ยม')) {
                    feedbackType = 'success';
                } else if (analysis.feedback.includes('ปรับ') || analysis.feedback.includes('ช้า')) {
                    feedbackType = 'warning';
                }
                
                this.showFeedback(analysis.feedback, feedbackType);
            }

            // ถ้าเสร็จครบแล้ว
            if (analysis.shouldCount) {
                this.handleRepetitionComplete();
            }

        } catch (error) {
            console.warn('⚠️ ข้อผิดพลาดในการจัดการ exercise analysis:', error);
        }
    }

    // จัดการเมื่อเสร็จ 1 ครั้ง
    handleRepetitionComplete() {
        try {
            // แสดงเอฟเฟกต์สำเร็จ
            if (this.canvasRenderer) {
                this.canvasRenderer.drawSuccessEffect();
            }
            
            // เล่นเสียงแจ้งเตือน
            if (this.settings.soundEnabled) {
                StrokeUtils.playSuccessSound();
            }
            
            // ตรวจสอบว่าเสร็จครบหรือยัง
            const state = this.exerciseAnalyzer.getCurrentState();
            if (state.reps >= state.targetReps) {
                this.handleExerciseComplete();
            }

        } catch (error) {
            console.warn('⚠️ ข้อผิดพลาดในการจัดการ repetition complete:', error);
        }
    }

    // จัดการเมื่อออกกำลังกายเสร็จ
    handleExerciseComplete() {
        try {
            this.showFeedback('🎉 ยินดีด้วย! ออกกำลังกายครบแล้ว 🎉', 'success');
            
            if (this.canvasRenderer) {
                this.canvasRenderer.drawMotivationMessage('ยอดเยี่ยม! เสร็จสิ้นการฝึก');
            }
            
            // เล่นเสียงเสร็จสิ้น
            if (this.settings.soundEnabled) {
                StrokeUtils.playCompleteSound();
            }
            
            // หยุดการฝึกหลังจาก 3 วินาที
            setTimeout(() => {
                this.stopExercise();
            }, 3000);

        } catch (error) {
            console.warn('⚠️ ข้อผิดพลาดในการจัดการ exercise complete:', error);
        }
    }

    // เริ่มจับเวลาเซสชัน
    startSessionTimer() {
        this.sessionStartTime = Date.now();
        this.sessionDuration = 0;
        
        this.sessionTimer = setInterval(() => {
            this.sessionDuration = Math.floor((Date.now() - this.sessionStartTime) / 1000);
            if (this.uiController) {
                this.uiController.updateTimer(this.sessionDuration);
            }
        }, 1000);
    }

    // หยุดจับเวลาเซสชัน
    stopSessionTimer() {
        if (this.sessionTimer) {
            clearInterval(this.sessionTimer);
            this.sessionTimer = null;
        }
    }

    // อัปเดตสถานะการตรวจจับ
    updateDetectionStatus(message, status = 'waiting') {
        const statusElement = document.getElementById('detection-status');
        if (!statusElement) return;

        const statusIcon = statusElement.querySelector('.status-icon i');
        const statusText = statusElement.querySelector('.status-text');
        
        if (statusText) {
            statusText.textContent = message;
        }
        
        if (statusIcon) {
            // เปลี่ยนไอคอนตามสถานะ
            switch(status) {
                case 'correct':
                    statusIcon.className = 'fas fa-check-circle';
                    statusElement.className = 'detection-status correct';
                    break;
                case 'detecting':
                    statusIcon.className = 'fas fa-sync fa-spin';
                    statusElement.className = 'detection-status detecting';
                    break;
                case 'error':
                    statusIcon.className = 'fas fa-exclamation-triangle';
                    statusElement.className = 'detection-status error';
                    break;
                case 'waiting':
                default:
                    statusIcon.className = 'fas fa-search';
                    statusElement.className = 'detection-status waiting';
            }
        }
    }

    // แสดงข้อความ feedback
    showFeedback(message, type = 'info') {
        const feedbackElement = document.getElementById('feedback-text');
        if (!feedbackElement) {
            console.log(`Feedback: ${message}`);
            return;
        }

        feedbackElement.textContent = message;
        feedbackElement.className = `feedback-text ${type}`;
        
        // แสดงผลชั่วขณะ
        setTimeout(() => {
            feedbackElement.textContent = '';
            feedbackElement.className = 'feedback-text';
        }, 3000);
    }

    // แสดงข้อผิดพลาด
    showError(message) {
        console.error('System Error:', message);
        
        const errorDiv = document.createElement('div');
        errorDiv.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #f44336;
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            z-index: 9999;
            max-width: 400px;
        `;
        errorDiv.innerHTML = `
            <h3>เกิดข้อผิดพลาด</h3>
            <p>${message}</p>
            <button onclick="this.parentElement.remove()" style="
                background: white;
                color: #f44336;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
                margin-top: 10px;
            ">ปิด</button>
        `;
        document.body.appendChild(errorDiv);
    }

    // ได้สถานะการออกกำลังกายปัจจุบัน
    getCurrentExerciseState() {
        if (!this.exerciseAnalyzer) return null;
        
        const state = this.exerciseAnalyzer.getCurrentState();
        return {
            exercise: state.exercise,
            phase: state.phase,
            reps: state.reps,
            targetReps: state.targetReps,
            currentAngle: this.exerciseAnalyzer.lastAngle,
            accuracy: 0 // จะถูกอัปเดตในการวิเคราะห์
        };
    }

    // บันทึกเซสชัน
    saveSession(sessionStats) {
        try {
            const sessionData = {
                ...sessionStats,
                id: StrokeUtils.generateUUID(),
                savedAt: new Date().toISOString()
            };

            // บันทึกลง localStorage
            const sessions = StrokeUtils.getFromStorage('therapy-sessions', []);
            sessions.push(sessionData);
            
            // เก็บแค่ 50 เซสชันล่าสุด
            if (sessions.length > 50) {
                sessions.splice(0, sessions.length - 50);
            }
            
            StrokeUtils.saveToStorage('therapy-sessions', sessions);
            
            console.log('💾 บันทึกเซสชันเรียบร้อย:', sessionData);
            return true;

        } catch (error) {
            console.error('❌ ไม่สามารถบันทึกเซสชันได้:', error);
            return false;
        }
    }

    // แสดงสรุปผลการฝึก
    showSessionSummary(sessionStats) {
        if (!sessionStats) return;

        try {
            const summary = {
                exerciseName: sessionStats.exerciseName || 'ไม่ระบุ',
                repetitions: sessionStats.repetitions || 0,
                accuracy: Math.round(sessionStats.averageAccuracy || 0),
                duration: StrokeUtils.formatTime(Math.floor(sessionStats.duration / 1000) || 0)
            };
            
            console.log('📊 สรุปผลการฝึก:', summary);

        } catch (error) {
            console.warn('⚠️ ข้อผิดพลาดในการแสดงสรุปผล:', error);
        }
    }

    // ทำลายระบบ
    destroy() {
        console.log('🧹 กำลังทำลายระบบ...');
        
        try {
            this.stopExercise();
            
            if (this.sessionTimer) {
                clearInterval(this.sessionTimer);
            }
            
            if (this.poseDetection) {
                this.poseDetection.destroy();
            }
            
            if (this.exerciseAnalyzer) {
                this.exerciseAnalyzer.reset();
            }
            
            if (this.canvasRenderer) {
                this.canvasRenderer.destroy();
            }
            
            if (this.uiController) {
                this.uiController.destroy();
            }
            
            this.isSystemReady = false;
            this.isExercising = false;
            
            console.log('✅ ทำลายระบบเรียบร้อย');

        } catch (error) {
            console.error('❌ ข้อผิดพลาดในการทำลายระบบ:', error);
        }
    }
}

// ส่งออกระบบสำหรับการใช้งานภายนอก
window.StrokeTherapySystem = StrokeTherapySystem;

console.log('✅ main.js โหลดเรียบร้อย - ระบบกายภาพบำบัด Stroke พร้อมใช้งาน');