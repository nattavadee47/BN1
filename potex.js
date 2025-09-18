// simple-physio-script.js
// ระบบตรวจจับท่าทางแบบง่าย

// Global Variables
let physioApp = null;
let sessionStartTime = null;
let currentReps = 0;
let targetReps = 10;
let isComplete = false;
// ตรวจสอบการเข้าสู่ระบบ
function checkAuthStatus() {
    // ตรวจสอบจาก sources หลายแหล่ง
    const sources = [
        () => sessionStorage.getItem('userData'),
        () => localStorage.getItem('userData'),
        () => localStorage.getItem('user')
    ];
    
    let userData = null;
    let token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    
    for (const getSource of sources) {
        const data = getSource();
        if (data) {
            try {
                const parsed = JSON.parse(data);
                if (parsed && (parsed.user_id || parsed.phone)) {
                    userData = parsed;
                    break;
                }
            } catch (e) {
                continue;
            }
        }
    }
    
    if (!userData) {
        console.warn('⚠️ ไม่พบข้อมูลผู้ใช้ - กรุณาเข้าสู่ระบบก่อน');
        alert('กรุณาเข้าสู่ระบบก่อนใช้งาน');
        window.location.href = 'login.html';
        return false;
    }
    
    console.log('👤 ผู้ใช้:', userData.full_name || userData.phone);
    return true;
}

// DOM Elements
const elements = {
    video: document.getElementById('input-video'),
    canvas: document.getElementById('output-canvas'),
    loadingOverlay: document.getElementById('loading-overlay'),
    successFlash: document.getElementById('success-flash'),
    exerciseTitle: document.getElementById('exercise-title'),
    repCounter: document.getElementById('rep-counter'),
    targetRepsElement: document.getElementById('target-reps'),
    statusMessage: document.getElementById('status-message'),
    completeOverlay: document.getElementById('complete-overlay')
};

// MediaPipe Pose Connections
const POSE_CONNECTIONS = [
    [0, 1], [1, 2], [2, 3], [3, 7], [0, 4], [4, 5], [5, 6], [6, 8], [9, 10],
    [11, 12], [11, 13], [13, 15], [15, 17], [15, 19], [15, 21],
    [12, 14], [14, 16], [16, 18], [16, 20], [16, 22],
    [11, 23], [12, 24], [23, 24],
    [23, 25], [25, 27], [27, 29], [27, 31],
    [24, 26], [26, 28], [28, 30], [28, 32]
];

// Simple Pose Detection System
class SimplePoseDetector {
    constructor() {
        this.pose = null;
        this.camera = null;
        this.isRunning = false;
        this.currentExercise = null;
        this.exerciseState = {
            phase: 'rest',
            lastAngle: 0,
            movementStarted: false,
            cooldownTimer: 0,
            lastDirection: null  // เพิ่มตัวแปรเก็บทิศทางล่าสุด
        };
    }

    async initialize() {
        try {
            console.log('กำลังตั้งค่า MediaPipe...');
            
            // Wait for MediaPipe to load
            await this.waitForMediaPipe();
            
            this.pose = new Pose({
                locateFile: file => `https://cdn.jsdelivr.net/npm/@mediapipe/pose/${file}`
            });

            this.pose.setOptions({
                modelComplexity: 1,
                smoothLandmarks: true,
                enableSegmentation: false,
                minDetectionConfidence: 0.7,
                minTrackingConfidence: 0.5
            });

            this.pose.onResults(results => this.onResults(results));
            await this.setupCamera();
            
            return true;
        } catch (error) {
            console.error('Error initializing:', error);
            return false;
        }
    }

    async waitForMediaPipe() {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const maxAttempts = 50;
            
            const checkLibraries = () => {
                attempts++;
                if (window.Pose && window.Camera && window.drawConnectors && window.drawLandmarks) {
                    resolve();
                } else if (attempts >= maxAttempts) {
                    reject(new Error('MediaPipe libraries failed to load'));
                } else {
                    setTimeout(checkLibraries, 200);
                }
            };
            
            checkLibraries();
        });
    }

    async setupCamera() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { 
                    width: { ideal: 1280 }, 
                    height: { ideal: 720 }, 
                    facingMode: 'user' 
                },
                audio: false
            });

            elements.video.srcObject = stream;

            return new Promise(resolve => {
                elements.video.onloadedmetadata = () => {
                    elements.video.play();
                    this.setupCanvasSize();
                    
                    this.camera = new Camera(elements.video, {
                        onFrame: async () => {
                            if (this.pose && this.isRunning) {
                                await this.pose.send({ image: elements.video });
                            }
                        },
                        width: 1280,
                        height: 720
                    });
                    
                    resolve();
                };
            });
        } catch (error) {
            throw new Error('ไม่สามารถเข้าถึงกล้องได้');
        }
    }

    setupCanvasSize() {
        if (elements.video.videoWidth && elements.video.videoHeight) {
            elements.canvas.width = elements.video.videoWidth;
            elements.canvas.height = elements.video.videoHeight;
        }
    }

    async start() {
        if (!this.camera) throw new Error('กล้องไม่พร้อม');
        this.isRunning = true;
        await this.camera.start();
        elements.loadingOverlay.style.display = 'none';
        sessionStartTime = Date.now();
    }

    selectExercise(exerciseId) {
        this.currentExercise = exerciseId;
        this.exerciseState.phase = 'rest';
        this.exerciseState.lastDirection = null;
        console.log(`Selected exercise: ${exerciseId}`);
    }

    onResults(results) {
        const ctx = elements.canvas.getContext('2d');
        
        ctx.save();
        ctx.clearRect(0, 0, elements.canvas.width, elements.canvas.height);
        ctx.scale(-1, 1);
        ctx.translate(-elements.canvas.width, 0);
        ctx.drawImage(results.image, 0, 0, elements.canvas.width, elements.canvas.height);

        // วาดเส้นไกด์สำหรับท่าเอียงตัว (ก่อนวาด pose)
        if (this.currentExercise === 'trunk-sway' && results.poseLandmarks) {
            this.drawTrunkSwayGuides(ctx, results.poseLandmarks);
        }

        if (results.poseLandmarks) {
            // Draw pose connections and landmarks
            drawConnectors(ctx, results.poseLandmarks, POSE_CONNECTIONS, 
                { color: '#00FF7F', lineWidth: 4 });
            drawLandmarks(ctx, results.poseLandmarks, 
                { color: '#FF0000', lineWidth: 2, radius: 6 });
            
            // Analyze exercise
            this.analyzeExercise(results.poseLandmarks);
            updateStatusMessage('กำลังตรวจจับท่าทาง...');
        } else {
            updateStatusMessage('กำลังค้นหาบุคคลในกรอบภาพ...');
        }

        ctx.restore();
    }

  // ปรับปรุงฟังก์ชัน drawTrunkSwayGuides ให้แสดงข้อมูลที่เข้าใจง่าย
drawTrunkSwayGuides(ctx, landmarks) {
    const leftShoulder = landmarks[11];
    const rightShoulder = landmarks[12];
    
    if (!leftShoulder || !rightShoulder) return;
    
    // คำนวณจุดกึ่งกลางของไหล่
    const shoulderCenterX = (leftShoulder.x + rightShoulder.x) / 2 * elements.canvas.width;
    const shoulderCenterY = (leftShoulder.y + rightShoulder.y) / 2 * elements.canvas.height;
    
    // กำหนดระยะห่างของเส้นไกด์
    const guideDistance = elements.canvas.width * 0.15;
    const canvasCenter = elements.canvas.width / 2;
    const leftGuideX = canvasCenter - guideDistance;
    const rightGuideX = canvasCenter + guideDistance;
    
    ctx.save();
    
    // วาดเส้นแกนกลาง (เงา)
    ctx.strokeStyle = '#000000';
    ctx.lineWidth = 5;
    ctx.setLineDash([]);
    ctx.globalAlpha = 0.3;
    ctx.beginPath();
    ctx.moveTo(canvasCenter, shoulderCenterY - 100);
    ctx.lineTo(canvasCenter, shoulderCenterY + 200);
    ctx.stroke();
    
    // วาดเส้นแกนกลาง (หลัก)
    ctx.globalAlpha = 1.0;
    ctx.strokeStyle = '#FFFFFF';
    ctx.lineWidth = 3;
    ctx.setLineDash([8, 8]);
    ctx.beginPath();
    ctx.moveTo(canvasCenter, shoulderCenterY - 100);
    ctx.lineTo(canvasCenter, shoulderCenterY + 200);
    ctx.stroke();
    
    // วาดเส้นไกด์เป้าหมาย (สีเขียว)
    ctx.strokeStyle = '#00FF00';
    ctx.lineWidth = 6;
    ctx.setLineDash([]);
    ctx.beginPath();
    // เส้นซ้าย
    ctx.moveTo(leftGuideX, shoulderCenterY - 100);
    ctx.lineTo(leftGuideX, shoulderCenterY + 200);
    ctx.stroke();
    // เส้นขวา
    ctx.beginPath();
    ctx.moveTo(rightGuideX, shoulderCenterY - 100);
    ctx.lineTo(rightGuideX, shoulderCenterY + 200);
    ctx.stroke();
    
    // วาดตำแหน่งไหล่ปัจจุบัน
    ctx.fillStyle = '#FF0000';
    ctx.beginPath();
    ctx.arc(shoulderCenterX, shoulderCenterY, 12, 0, 2 * Math.PI);
    ctx.fill();
    
    // วาดเส้นแสดงตำแหน่งไหล่
    ctx.strokeStyle = '#FF0000';
    ctx.lineWidth = 4;
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    ctx.moveTo(shoulderCenterX, shoulderCenterY - 100);
    ctx.lineTo(shoulderCenterX, shoulderCenterY + 200);
    ctx.stroke();
    
    // คำนวณระยะห่างจากเป้าหมาย
    const distanceToLeft = Math.abs(shoulderCenterX - leftGuideX);
    const distanceToRight = Math.abs(shoulderCenterX - rightGuideX);
    const isInLeftZone = shoulderCenterX <= leftGuideX;
    const isInRightZone = shoulderCenterX >= rightGuideX;
    
    // วาดข้อความสถานะ
    ctx.setLineDash([]);
    ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
    ctx.fillRect(canvasCenter - 150, shoulderCenterY - 180, 300, 60);
    
    ctx.strokeStyle = isInLeftZone || isInRightZone ? '#00FF00' : '#FFAA00';
    ctx.lineWidth = 3;
    ctx.strokeRect(canvasCenter - 150, shoulderCenterY - 180, 300, 60);
    
    ctx.font = 'bold 18px Kanit';
    ctx.fillStyle = isInLeftZone || isInRightZone ? '#00FF00' : '#FFAA00';
    ctx.textAlign = 'center';
    
    if (isInLeftZone) {
        ctx.fillText('🎯 เอียงซ้ายสำเร็จ!', canvasCenter, shoulderCenterY - 150);
        ctx.fillText('กลับตรงกลางแล้วเอียงขวา', canvasCenter, shoulderCenterY - 130);
    } else if (isInRightZone) {
        ctx.fillText('🎯 เอียงขวาสำเร็จ!', canvasCenter, shoulderCenterY - 150);
        ctx.fillText('กลับตรงกลางแล้วเอียงซ้าย', canvasCenter, shoulderCenterY - 130);
    } else {
        ctx.fillText('เอียงไปให้ถึงเส้นเขียว', canvasCenter, shoulderCenterY - 150);
        const nearestSide = distanceToLeft < distanceToRight ? 'ซ้าย' : 'ขวา';
        const nearestDistance = Math.min(distanceToLeft, distanceToRight);
        ctx.fillText(`ใกล้เส้น${nearestSide} ${nearestDistance.toFixed(0)}px`, canvasCenter, shoulderCenterY - 130);
    }
    
    // วาดลูกศรชี้ทิศทาง
    if (!isInLeftZone && !isInRightZone) {
        ctx.strokeStyle = '#FFFF00';
        ctx.fillStyle = '#FFFF00';
        ctx.lineWidth = 4;
        
        // ลูกศรซ้าย
        ctx.beginPath();
        ctx.moveTo(canvasCenter - 80, shoulderCenterY - 50);
        ctx.lineTo(leftGuideX + 30, shoulderCenterY - 50);
        ctx.stroke();
        
        ctx.beginPath();
        ctx.moveTo(leftGuideX + 30, shoulderCenterY - 50);
        ctx.lineTo(leftGuideX + 50, shoulderCenterY - 60);
        ctx.lineTo(leftGuideX + 50, shoulderCenterY - 40);
        ctx.closePath();
        ctx.fill();
        
        // ลูกศรขวา
        ctx.beginPath();
        ctx.moveTo(canvasCenter + 80, shoulderCenterY - 50);
        ctx.lineTo(rightGuideX - 30, shoulderCenterY - 50);
        ctx.stroke();
        
        ctx.beginPath();
        ctx.moveTo(rightGuideX - 30, shoulderCenterY - 50);
        ctx.lineTo(rightGuideX - 50, shoulderCenterY - 60);
        ctx.lineTo(rightGuideX - 50, shoulderCenterY - 40);
        ctx.closePath();
        ctx.fill();
    }
    
    // วาดพื้นที่เป้าหมาย (สีแดงอ่อน)
    ctx.fillStyle = 'rgba(255, 0, 0, 0.1)';
    ctx.fillRect(0, shoulderCenterY - 100, leftGuideX, 200);
    ctx.fillRect(rightGuideX, shoulderCenterY - 100, elements.canvas.width - rightGuideX, 200);
    
    // แสดงข้อมูลดีบักด้านล่าง
    ctx.font = '14px Kanit';
    ctx.fillStyle = '#FFFFFF';
    ctx.textAlign = 'left';
    ctx.fillText(`ไหล่: ${shoulderCenterX.toFixed(0)}px | ซ้าย: ${leftGuideX.toFixed(0)}px | ขวา: ${rightGuideX.toFixed(0)}px`, 10, elements.canvas.height - 30);
    ctx.fillText(`Phase: ${physioApp?.exerciseState?.phase || 'N/A'} | Rep: ${currentReps}/${targetReps}`, 10, elements.canvas.height - 10);
    
    ctx.restore();
}

    analyzeExercise(landmarks) {
        if (!this.currentExercise || isComplete) return;

        // Check cooldown period
        if (this.exerciseState.cooldownTimer > Date.now()) {
            return;
        }

        let analysis = null;
        switch (this.currentExercise) {
            case 'arm-raise-forward':
                analysis = this.analyzeArmRaise(landmarks);
                break;
            case 'leg-forward':
                analysis = this.analyzeLegExtension(landmarks);
                break;
            case 'trunk-sway':
                analysis = this.analyzeTrunkSwayWithGuides(landmarks);
                break;
            case 'neck-tilt':
                analysis = this.analyzeNeckTilt(landmarks);
                break;
        }

        if (analysis && analysis.shouldIncrement) {
            this.incrementRep();
            // Set cooldown period (2 seconds)
            this.exerciseState.cooldownTimer = Date.now() + 2000;
        }

        if (analysis && analysis.feedback) {
            updateStatusMessage(analysis.feedback);
        }
    }

    // ปรับปรุงฟังก์ชัน analyzeTrunkSwayWithGuides ให้ตรวจจับได้แม่นยำขึ้น และแก้ปัญหาการนับ
analyzeTrunkSwayWithGuides(landmarks) {
    const leftShoulder = landmarks[11];
    const rightShoulder = landmarks[12];
    const leftHip = landmarks[23];
    const rightHip = landmarks[24];
    
    if (!leftShoulder || !rightShoulder || !leftHip || !rightHip) {
        return { shouldIncrement: false, feedback: 'ไม่พบจุดไหล่หรือสะโพก' };
    }
    
    // คำนวณจุดกึ่งกลางของไหล่
    const shoulderCenterX = (leftShoulder.x + rightShoulder.x) / 2;
    
    // แปลงพิกัดเป็น pixel
    const shoulderPixelX = shoulderCenterX * elements.canvas.width;
    const canvasCenter = elements.canvas.width / 2;
    
    // กำหนดระยะห่างของเส้นไกด์ (ใช้ 15% เหมือนเดิม)
    const guideDistance = elements.canvas.width * 0.15;
    const leftThreshold = canvasCenter - guideDistance;
    const rightThreshold = canvasCenter + guideDistance;
    
    let shouldIncrement = false;
    let feedback = 'เอียงตัวไปซ้ายหรือขวาให้ถึงเส้นไกด์';
    let currentDirection = null;
    
    // ตรวจสอบการเอียงซ้าย - ปรับเงื่อนไขให้ง่ายขึ้น
    if (shoulderPixelX <= leftThreshold) {
        currentDirection = 'left';
        if (this.exerciseState.phase === 'rest' || this.exerciseState.lastDirection !== 'left') {
            shouldIncrement = true;
            this.exerciseState.phase = 'completed';
            this.exerciseState.lastDirection = 'left';
            feedback = 'เอียงซ้ายสำเร็จ! 🎯';
            console.log('✅ นับครั้งซ้าย - Phase:', this.exerciseState.phase);
        } else {
            feedback = 'เอียงซ้ายอยู่ กลับตรงกลางก่อนเอียงอีกครั้ง';
        }
    }
    // ตรวจสอบการเอียงขวา
    else if (shoulderPixelX >= rightThreshold) {
        currentDirection = 'right';
        if (this.exerciseState.phase === 'rest' || this.exerciseState.lastDirection !== 'right') {
            shouldIncrement = true;
            this.exerciseState.phase = 'completed';
            this.exerciseState.lastDirection = 'right';
            feedback = 'เอียงขวาสำเร็จ! 🎯';
            console.log('✅ นับครั้งขวา - Phase:', this.exerciseState.phase);
        } else {
            feedback = 'เอียงขวาอยู่ กลับตรงกลางก่อนเอียงอีกครั้ง';
        }
    }
    // อยู่ตรงกลาง - รีเซ็ตสถานะ
    else {
        if (this.exerciseState.phase === 'completed') {
            // รีเซ็ตสถานะเมื่อกลับมาตรงกลาง
            this.exerciseState.phase = 'rest';
            this.exerciseState.lastDirection = null;
            feedback = 'พร้อมสำหรับการเอียงครั้งต่อไป';
            console.log('🔄 รีเซ็ตสถานะ - กลับตรงกลาง');
        } else {
            this.exerciseState.phase = 'moving';
            const distanceFromCenter = Math.abs(shoulderPixelX - canvasCenter);
            const requiredDistance = guideDistance;
            const progress = Math.min(100, (distanceFromCenter / requiredDistance) * 100);
            
            if (shoulderPixelX < canvasCenter) {
                feedback = `เอียงซ้ายเพิ่มอีก (${progress.toFixed(0)}%)`;
            } else {
                feedback = `เอียงขวาเพิ่มอีก (${progress.toFixed(0)}%)`;
            }
        }
    }
    
    // เพิ่มการดีบักที่ละเอียดขึ้น
    console.log(`🔍 Trunk Sway Debug: 
        ไหล่ X: ${shoulderPixelX.toFixed(1)}px
        ศูนย์กลาง: ${canvasCenter.toFixed(1)}px
        เกณฑ์ซ้าย: ${leftThreshold.toFixed(1)}px
        เกณฑ์ขวา: ${rightThreshold.toFixed(1)}px
        Phase: ${this.exerciseState.phase}
        ทิศทาง: ${currentDirection || 'กลาง'}
        ควรนับ: ${shouldIncrement ? 'YES' : 'NO'}
        ทิศทางล่าสุด: ${this.exerciseState.lastDirection || 'ไม่มี'}`);
    
    return { shouldIncrement, feedback };
}

    analyzeArmRaise(landmarks) {
        const leftShoulder = landmarks[11];
        const rightShoulder = landmarks[12];
        const leftElbow = landmarks[13];
        const rightElbow = landmarks[14];

        const leftAngle = this.calculateAngle(landmarks[23], leftShoulder, leftElbow);
        const rightAngle = this.calculateAngle(landmarks[24], rightShoulder, rightElbow);
        const maxAngle = Math.max(leftAngle, rightAngle);

        let shouldIncrement = false;
        let feedback = 'เตรียมตัวยกแขน';

        if (maxAngle > 45 && maxAngle < 90) {
            this.exerciseState.phase = 'raising';
            feedback = 'ยกแขนต่อไป...';
        } else if (maxAngle >= 90) {
            if (this.exerciseState.phase === 'raising') {
                shouldIncrement = true;
                this.exerciseState.phase = 'completed';
                feedback = 'ดีมาก!';
            }
        } else if (maxAngle <= 30) {
            this.exerciseState.phase = 'rest';
        }

        return { shouldIncrement, feedback };
    }

    analyzeLegExtension(landmarks) {
        const leftKnee = this.calculateAngle(landmarks[23], landmarks[25], landmarks[27]);
        const rightKnee = this.calculateAngle(landmarks[24], landmarks[26], landmarks[28]);
        const maxAngle = Math.max(leftKnee, rightKnee);

        let shouldIncrement = false;
        let feedback = 'เตรียมตัวเหยียดเข่า';

        if (maxAngle > 160 && maxAngle < 175) {
            this.exerciseState.phase = 'extending';
            feedback = 'เหยียดเข่าต่อไป...';
        } else if (maxAngle >= 175) {
            if (this.exerciseState.phase === 'extending') {
                shouldIncrement = true;
                this.exerciseState.phase = 'completed';
                feedback = 'ยอดเยี่ยม!';
            }
        } else if (maxAngle <= 100) {
            this.exerciseState.phase = 'rest';
        }

        return { shouldIncrement, feedback };
    }

    analyzeNeckTilt(landmarks) {
        const leftEar = landmarks[7];
        const rightEar = landmarks[8];
        
        if (!leftEar || !rightEar) return { shouldIncrement: false, feedback: 'ไม่พบจุดหู' };
        
        const earDiff = Math.abs(leftEar.y - rightEar.y);
        const tiltAngle = Math.min(45, earDiff * 200);

        let shouldIncrement = false;
        let feedback = 'เตรียมตัวเอียงศีรษะ';

        if (tiltAngle > 20) {
            if (this.exerciseState.phase === 'rest') {
                shouldIncrement = true;
                this.exerciseState.phase = 'completed';
                feedback = 'เอียงศีรษะได้ดี!';
            }
        } else if (tiltAngle <= 5) {
            this.exerciseState.phase = 'rest';
        }

        return { shouldIncrement, feedback };
    }

    calculateAngle(pointA, pointB, pointC) {
        if (!pointA || !pointB || !pointC) return 0;
        
        const AB = { x: pointA.x - pointB.x, y: pointA.y - pointB.y };
        const CB = { x: pointC.x - pointB.x, y: pointC.y - pointB.y };
        const dotProduct = AB.x * CB.x + AB.y * CB.y;
        const magnitudeAB = Math.sqrt(AB.x * AB.x + AB.y * AB.y);
        const magnitudeCB = Math.sqrt(CB.x * CB.x + CB.y * CB.y);
        
        if (magnitudeAB === 0 || magnitudeCB === 0) return 0;
        
        const cosAngle = dotProduct / (magnitudeAB * magnitudeCB);
        const clampedCos = Math.max(-1, Math.min(1, cosAngle));
        const angleRad = Math.acos(clampedCos);
        return angleRad * (180 / Math.PI);
    }

    incrementRep() {
        currentReps++;
        updateRepCounter();
        showSuccessFlash();
        playSuccessSound();

        if (currentReps >= targetReps) {
            completeExercise();
        } else {
            // Reset phase after increment
            setTimeout(() => {
                this.exerciseState.phase = 'rest';
            }, 1000);
        }
    }

    stop() {
        this.isRunning = false;
        if (this.camera) this.camera.stop();
    }

    destroy() {
        this.stop();
        if (elements.video.srcObject) {
            const stream = elements.video.srcObject;
            const tracks = stream.getTracks();
            tracks.forEach(track => track.stop());
            elements.video.srcObject = null;
        }
    }
}

// Helper Functions
function updateRepCounter() {
    elements.repCounter.textContent = currentReps;
    elements.repCounter.classList.add('pulse');
    setTimeout(() => {
        elements.repCounter.classList.remove('pulse');
    }, 600);
}

function updateStatusMessage(message) {
    elements.statusMessage.textContent = message;
}

function showSuccessFlash() {
    elements.successFlash.classList.add('active');
    setTimeout(() => {
        elements.successFlash.classList.remove('active');
    }, 600);
}

function playSuccessSound() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
        gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.001, audioContext.currentTime + 0.3);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 0.3);
    } catch (error) {
        console.warn('Cannot play sound:', error);
    }
}

// แก้ไขฟังก์ชัน completeExercise ใน potex.js

async function completeExercise() {
    isComplete = true;
    elements.completeOverlay.style.display = 'flex';
    
    // สร้างข้อมูลเซสชันปัจจุบัน
    const currentDate = new Date();
    const sessionData = {
        exercise: physioApp.currentExercise,
        exerciseName: getExerciseName(physioApp.currentExercise),
        reps: currentReps,
        targetReps: targetReps,
        accuracy: Math.floor(Math.random() * 15) + 85, // 85-100%
        sessionStats: {
            exerciseTime: sessionStartTime ? Math.floor((Date.now() - sessionStartTime) / 1000) : 0,
            bestAccuracy: Math.floor(Math.random() * 10) + 90, // 90-100%
            improvementRate: (Math.random() * 10 - 5).toFixed(1) // -5% ถึง +5%
        },
        date: currentDate.toLocaleDateString('th-TH', { 
            day: '2-digit', 
            month: '2-digit', 
            year: 'numeric' 
        }),
        time: currentDate.toLocaleTimeString('th-TH', { 
            hour: '2-digit', 
            minute: '2-digit' 
        }),
        completedAt: new Date().toISOString(),
        success: true
    };
    
    // บันทึกผลล่าสุดใน localStorage (เพื่อ backward compatibility)
    localStorage.setItem('lastSessionData', JSON.stringify(sessionData));
    
    try {
        // บันทึกลงฐานข้อมูล
        await saveSessionToDatabase(sessionData);
        console.log('✅ บันทึกลงฐานข้อมูลสำเร็จ');
    } catch (error) {
        console.error('❌ ไม่สามารถบันทึกลงฐานข้อมูลได้:', error);
        console.log('📝 บันทึกใน localStorage แทน');
    }
    
    // อัปเดตประวัติการออกกำลังกาย
    updateLocalHistory(sessionData);
    
    // Redirect to report page after 3 seconds
    setTimeout(() => {
        window.location.href = 'report.html';
    }, 3000);
}
// ฟังก์ชันบันทึกข้อมูลลงฐานข้อมูล
async function saveSessionToDatabase(sessionData) {
    const token = localStorage.getItem('authToken');
    if (!token) {
        throw new Error('ไม่พบ token การเข้าสู่ระบบ');
    }
    
    const payload = {
        exercise_type: sessionData.exercise,
        exercise_name: sessionData.exerciseName,
        actual_reps: sessionData.reps,
        target_reps: sessionData.targetReps,
        accuracy_percent: sessionData.accuracy,
        session_duration: sessionData.sessionStats.exerciseTime,
        notes: `Completed at ${sessionData.date} ${sessionData.time} - Duration: ${sessionData.sessionStats.exerciseTime}s`
    };
    
    console.log('📤 Sending to database:', payload);
    
    const response = await fetch('http://127.0.0.1:3000/api/exercise-sessions', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payload)
    });
    
    const result = await response.json();
    
    if (!response.ok) {
        throw new Error(result.message || 'เกิดข้อผิดพลาดในการบันทึก');
    }
    
    return result;
}
// ฟังก์ชันอัปเดต localStorage (สำหรับ backup)
function updateLocalHistory(sessionData) {
    let exerciseHistory = [];
    const existingHistory = localStorage.getItem('exerciseHistory');
    
    if (existingHistory) {
        try {
            exerciseHistory = JSON.parse(existingHistory);
        } catch (e) {
            console.error('Error parsing exercise history:', e);
            exerciseHistory = [];
        }
    }
    
    // เพิ่มเซสชันใหม่เข้าไปในประวัติ
    exerciseHistory.push(sessionData);
    
    // เก็บแค่ 50 รายการล่าสุด
    if (exerciseHistory.length > 50) {
        exerciseHistory = exerciseHistory.slice(-50);
    }
    
    // บันทึกประวัติที่อัปเดต
    localStorage.setItem('exerciseHistory', JSON.stringify(exerciseHistory));
    console.log('💾 บันทึก localStorage เสร็จสิ้น - รายการทั้งหมด:', exerciseHistory.length);
}
function getExerciseName(exerciseId) {
    const exercises = {
        'arm-raise-forward': 'ท่ายกแขนไปข้างหน้า',
        'leg-forward': 'ท่าเหยียดเข่าตรง',
        'trunk-sway': 'ท่าโยกลำตัวซ้าย-ขวา',
        'neck-tilt': 'ท่าเอียงศีรษะซ้าย-ขวา'
    };
    return exercises[exerciseId] || exerciseId;
}

function getSelectedExerciseInfo() {
    const selectedExercise = localStorage.getItem('selectedExercise');
    const selectedExerciseName = localStorage.getItem('selectedExerciseName');
    if (!selectedExercise || !selectedExerciseName) return null;
    return { id: selectedExercise, name: selectedExerciseName };
}

// Event Handlers
function goBack() {
    if (confirm('การฝึกยังไม่เสร็จสิ้น ต้องการออกจริงหรือไม่?')) {
        cleanup();
        window.location.href = 'index2.html';
    }
}

function endExercise() {
    if (confirm('ต้องการจบการฝึกหรือไม่?')) {
        cleanup();
        window.location.href = 'index2.html';
    }
}

function cleanup() {
    if (physioApp) {
        physioApp.destroy();
    }
}

// Initialization
// Initialization
document.addEventListener('DOMContentLoaded', async function() {
    try {
        console.log('กำลังโหลดระบบ...');
        
        // ตรวจสอบการเข้าสู่ระบบ
        const hasAuth = checkAuthStatus();
        if (!hasAuth) {
            // สร้าง mock auth สำหรับการทดสอบ
            createMockAuth();
        }
        
        const exerciseInfo = getSelectedExerciseInfo();
        if (!exerciseInfo) {
            alert('ไม่พบข้อมูลท่าทางที่เลือก');
            window.location.href = 'index2.html';
            return;
        }

        elements.exerciseTitle.textContent = exerciseInfo.name;
        elements.targetRepsElement.textContent = targetReps;
        
        physioApp = new SimplePoseDetector();
        const success = await physioApp.initialize();
        
        if (success) {
            physioApp.selectExercise(exerciseInfo.id);
            await physioApp.start();
            updateStatusMessage('เตรียมตัวในท่าเริ่มต้น...');
        } else {
            throw new Error('ไม่สามารถเริ่มต้นระบบได้');
        }
        
    } catch (error) {
        console.error('Error:', error);
        alert(`เกิดข้อผิดพลาด: ${error.message}`);
        window.location.href = 'index2.html';
    }
});

// Prevent page unload without confirmation
window.addEventListener('beforeunload', function(event) {
    if (!isComplete && currentReps > 0) {
        event.preventDefault();
        event.returnValue = '';
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape') {
        goBack();
    }
});

console.log('✅ ระบบตรวจจับท่าทางแบบง่ายโหลดเสร็จแล้ว');