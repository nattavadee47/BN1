// ========================================
// ระบบตรวจจับท่าทางสำหรับกายภาพบำบัด - แก้ไขแล้ว
// pose-detection.js
// ========================================

class PoseDetectionSystem {
    constructor() {
        this.poseDetection = null;
        this.camera = null;
        this.isInitialized = false;
        this.lastProcessTime = 0;
        this.processInterval = 100; // 100ms
        
        // Pose results
        this.currentPoseResults = null;
        this.realtimeAngles = this.initializeAngles();
        
        // Detection state
        this.detectionCallbacks = [];
        this.isDetecting = false;
    }

    // เริ่มต้นค่ามุมทั้งหมด
    initializeAngles() {
        return {
            leftShoulder: 0,
            rightShoulder: 0,
            leftElbow: 0,
            rightElbow: 0,
            leftKnee: 0,
            rightKnee: 0,
            leftHip: 0,
            rightHip: 0,
            neckTilt: 0,
            trunkTilt: 0
        };
    }

    // ตั้งค่า MediaPipe Pose Detection
    async initialize() {
        if (this.isInitialized) return true;

        try {
            console.log('🎥 กำลังตั้งค่า MediaPipe Pose Detection...');
            
            // ตรวจสอบว่า MediaPipe โหลดแล้วหรือไม่
            if (!window.Pose) {
                throw new Error('MediaPipe Pose ยังไม่โหลด');
            }

            // สร้าง Pose detection instance
            this.poseDetection = new window.Pose({
                locateFile: (file) => {
                    return `https://cdn.jsdelivr.net/npm/@mediapipe/pose@0.5.1675469404/${file}`;
                }
            });

            // ตั้งค่า options
            const config = StrokeConfig.CONFIG.MEDIAPIPE;
            this.poseDetection.setOptions({
                modelComplexity: config.MODEL_COMPLEXITY,
                smoothLandmarks: config.SMOOTH_LANDMARKS,
                enableSegmentation: config.ENABLE_SEGMENTATION,
                minDetectionConfidence: config.MIN_DETECTION_CONFIDENCE,
                minTrackingConfidence: config.MIN_TRACKING_CONFIDENCE,
                selfieMode: config.SELFIE_MODE
            });

            // ตั้งค่า callback สำหรับผลลัพธ์
            this.poseDetection.onResults(this.onPoseResults.bind(this));
            
            this.isInitialized = true;
            console.log('✅ MediaPipe Pose Detection ตั้งค่าสำเร็จ');
            return true;

        } catch (error) {
            console.error('❌ Error ในการตั้งค่า MediaPipe:', error);
            return false;
        }
    }

    // ตั้งค่ากล้อง
    async setupCamera(videoElement) {
        if (!this.isInitialized) {
            await this.initialize();
        }

        try {
            console.log('📹 กำลังตั้งค่ากล้อง...');

            // ตรวจสอบว่ามี Camera class หรือไม่
            if (!window.Camera) {
                throw new Error('MediaPipe Camera utils ไม่พร้อมใช้งาน');
            }

            const cameraConfig = StrokeConfig.CONFIG.CAMERA;
            
            // สร้าง Camera instance
            this.camera = new window.Camera(videoElement, {
                onFrame: async () => {
                    if (this.shouldProcessFrame()) {
                        await this.processFrame(videoElement);
                    }
                },
                width: cameraConfig.WIDTH,
                height: cameraConfig.HEIGHT
            });

            // เริ่มกล้อง
            await this.camera.start();
            this.isDetecting = true;
            
            console.log('✅ กล้องเริ่มทำงานสำเร็จ');
            return true;

        } catch (error) {
            console.error('❌ ไม่สามารถเริ่มกล้องได้:', error);
            throw new Error('ไม่สามารถเข้าถึงกล้องได้ กรุณาอนุญาตการใช้กล้อง');
        }
    }

    // ตรวจสอบว่าควร process frame หรือไม่
    shouldProcessFrame() {
        const now = Date.now();
        if (now - this.lastProcessTime > this.processInterval) {
            this.lastProcessTime = now;
            return true;
        }
        return false;
    }

    // ประมวลผล frame
    async processFrame(videoElement) {
        if (this.poseDetection && videoElement.videoWidth > 0) {
            try {
                await this.poseDetection.send({ image: videoElement });
            } catch (error) {
                console.warn('⚠️ Error processing frame:', error);
            }
        }
    }

    // Callback เมื่อได้ผลการตรวจจับ
    onPoseResults(results) {
        this.currentPoseResults = results;

        try {
            if (results.poseLandmarks && results.poseLandmarks.length > 0) {
                // คำนวณมุมแบบเรียลไทม์
                this.calculateRealtimeAngles(results.poseLandmarks);
                
                // แจ้งให้ callback ทราบ
                this.notifyDetectionCallbacks({
                    type: 'pose_detected',
                    results: results,
                    angles: this.realtimeAngles,
                    landmarks: results.poseLandmarks
                });
            } else {
                // ไม่พบท่าทาง
                this.notifyDetectionCallbacks({
                    type: 'pose_lost',
                    results: results
                });
            }
        } catch (error) {
            console.warn('⚠️ Error in onPoseResults:', error);
        }
    }

    // คำนวณมุมแบบเรียลไทม์
    calculateRealtimeAngles(landmarks) {
        if (!landmarks || landmarks.length < 33) {
            console.warn('⚠️ Landmarks ไม่ครบ:', landmarks ? landmarks.length : 0);
            return;
        }

        try {
            // คำนวณมุมไหล่
            this.realtimeAngles.leftShoulder = this.calculateShoulderAngle(landmarks, 'left');
            this.realtimeAngles.rightShoulder = this.calculateShoulderAngle(landmarks, 'right');
            
            // คำนวณมุมศอก
            this.realtimeAngles.leftElbow = this.calculateElbowAngle(landmarks, 'left');
            this.realtimeAngles.rightElbow = this.calculateElbowAngle(landmarks, 'right');
            
            // คำนวณมุมเข่า
            this.realtimeAngles.leftKnee = this.calculateKneeAngle(landmarks, 'left');
            this.realtimeAngles.rightKnee = this.calculateKneeAngle(landmarks, 'right');
            
            // คำนวณมุมสะโพก
            this.realtimeAngles.leftHip = this.calculateHipAngle(landmarks, 'left');
            this.realtimeAngles.rightHip = this.calculateHipAngle(landmarks, 'right');
            
            // คำนวณมุมคอและลำตัว
            this.realtimeAngles.neckTilt = this.calculateNeckTiltAngle(landmarks);
            this.realtimeAngles.trunkTilt = this.calculateTrunkTiltAngle(landmarks);

        } catch (error) {
            console.warn('⚠️ Error calculating realtime angles:', error);
        }
    }

    // คำนวณมุมไหล่
    calculateShoulderAngle(landmarks, side) {
        const indices = this.getSideIndices(side);
        const [shoulder, elbow, wrist, hip] = indices;
        
        if (!this.validateLandmarks(landmarks, [shoulder, elbow, hip])) {
            return 0;
        }
        
        const angle = StrokeUtils.calculateAngle(
            {x: landmarks[hip].x, y: landmarks[hip].y},
            {x: landmarks[shoulder].x, y: landmarks[shoulder].y},
            {x: landmarks[elbow].x, y: landmarks[elbow].y}
        );
        
        return Math.round(angle);
    }

    // คำนวณมุมศอก
    calculateElbowAngle(landmarks, side) {
        const indices = this.getSideIndices(side);
        const [shoulder, elbow, wrist] = indices;
        
        if (!this.validateLandmarks(landmarks, [shoulder, elbow, wrist])) {
            return 0;
        }
        
        const angle = StrokeUtils.calculateAngle(
            {x: landmarks[shoulder].x, y: landmarks[shoulder].y},
            {x: landmarks[elbow].x, y: landmarks[elbow].y},
            {x: landmarks[wrist].x, y: landmarks[wrist].y}
        );
        
        return Math.round(angle);
    }

    // คำนวณมุมเข่า
    calculateKneeAngle(landmarks, side) {
        const indices = this.getSideIndices(side);
        const [, , , hip, knee, ankle] = indices;
        
        if (!this.validateLandmarks(landmarks, [hip, knee, ankle])) {
            return 0;
        }
        
        const angle = StrokeUtils.calculateAngle(
            {x: landmarks[hip].x, y: landmarks[hip].y},
            {x: landmarks[knee].x, y: landmarks[knee].y},
            {x: landmarks[ankle].x, y: landmarks[ankle].y}
        );
        
        return Math.round(angle);
    }

    // คำนวณมุมสะโพก
    calculateHipAngle(landmarks, side) {
        const indices = this.getSideIndices(side);
        const [shoulder, , , hip, knee] = indices;
        
        if (!this.validateLandmarks(landmarks, [shoulder, hip, knee])) {
            return 0;
        }
        
        const angle = StrokeUtils.calculateAngle(
            {x: landmarks[shoulder].x, y: landmarks[shoulder].y},
            {x: landmarks[hip].x, y: landmarks[hip].y},
            {x: landmarks[knee].x, y: landmarks[knee].y}
        );
        
        return Math.round(angle);
    }

    // คำนวณมุมการเอียงคอ
    calculateNeckTiltAngle(landmarks) {
        const { LEFT_EAR, RIGHT_EAR } = StrokeConfig.POSE_LANDMARKS;
        
        if (!landmarks[LEFT_EAR] || !landmarks[RIGHT_EAR]) return 0;
        
        const leftEar = landmarks[LEFT_EAR];
        const rightEar = landmarks[RIGHT_EAR];
        const earDistance = Math.abs(leftEar.y - rightEar.y);
        const tiltAngle = Math.min(45, earDistance * 200);
        
        return Math.round(tiltAngle);
    }

    // คำนวณมุมการเอียงลำตัว
    calculateTrunkTiltAngle(landmarks) {
        const { LEFT_SHOULDER, RIGHT_SHOULDER, LEFT_HIP, RIGHT_HIP } = StrokeConfig.POSE_LANDMARKS;
        
        if (!landmarks[LEFT_SHOULDER] || !landmarks[RIGHT_SHOULDER] || 
            !landmarks[LEFT_HIP] || !landmarks[RIGHT_HIP]) return 0;
        
        const shoulderCenter = {
            x: (landmarks[LEFT_SHOULDER].x + landmarks[RIGHT_SHOULDER].x) / 2,
            y: (landmarks[LEFT_SHOULDER].y + landmarks[RIGHT_SHOULDER].y) / 2
        };
        const hipCenter = {
            x: (landmarks[LEFT_HIP].x + landmarks[RIGHT_HIP].x) / 2,
            y: (landmarks[LEFT_HIP].y + landmarks[RIGHT_HIP].y) / 2
        };
        
        const tilt = Math.abs(shoulderCenter.x - hipCenter.x) * 100;
        return Math.round(Math.min(30, tilt));
    }

    // ตรวจสอบความถูกต้องของ landmarks
    validateLandmarks(landmarks, requiredIndices) {
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

    // ได้ indices ของข้างซ้ายหรือขวา
    getSideIndices(side) {
        const { 
            LEFT_SHOULDER, RIGHT_SHOULDER,
            LEFT_ELBOW, RIGHT_ELBOW,
            LEFT_WRIST, RIGHT_WRIST,
            LEFT_HIP, RIGHT_HIP,
            LEFT_KNEE, RIGHT_KNEE,
            LEFT_ANKLE, RIGHT_ANKLE
        } = StrokeConfig.POSE_LANDMARKS;
        
        if (side === 'left') {
            return [LEFT_SHOULDER, LEFT_ELBOW, LEFT_WRIST, LEFT_HIP, LEFT_KNEE, LEFT_ANKLE];
        } else {
            return [RIGHT_SHOULDER, RIGHT_ELBOW, RIGHT_WRIST, RIGHT_HIP, RIGHT_KNEE, RIGHT_ANKLE];
        }
    }

    // ลงทะเบียน callback สำหรับการตรวจจับ
    addDetectionCallback(callback) {
        if (typeof callback === 'function') {
            this.detectionCallbacks.push(callback);
        }
    }

    // ลบ callback
    removeDetectionCallback(callback) {
        const index = this.detectionCallbacks.indexOf(callback);
        if (index > -1) {
            this.detectionCallbacks.splice(index, 1);
        }
    }

    // แจ้ง callback ทั้งหมด
    notifyDetectionCallbacks(data) {
        this.detectionCallbacks.forEach(callback => {
            try {
                callback(data);
            } catch (error) {
                console.warn('⚠️ Error in detection callback:', error);
            }
        });
    }

    // ได้ผลการตรวจจับปัจจุบัน
    getCurrentPoseResults() {
        return this.currentPoseResults;
    }

    // ได้มุมแบบเรียลไทม์
    getRealtimeAngles() {
        return { ...this.realtimeAngles };
    }

    // ตรวจสอบสถานะการทำงาน
    isRunning() {
        return this.isDetecting && this.isInitialized;
    }

    // หยุดกล้อง
    stop() {
        this.isDetecting = false;
        if (this.camera) {
            this.camera.stop();
        }
        console.log('📹 หยุดการตรวจจับท่าทาง');
    }

    // ทำลายระบบ
    destroy() {
        console.log('🧹 กำลังทำลายระบบตรวจจับท่าทาง...');
        
        this.stop();
        this.detectionCallbacks = [];
        this.currentPoseResults = null;
        
        if (this.poseDetection) {
            this.poseDetection.close();
            this.poseDetection = null;
        }
        
        this.camera = null;
        this.isInitialized = false;
        
        console.log('✅ ทำลายระบบตรวจจับท่าทางเสร็จแล้ว');
    }
}

// ส่งออกคลาส
window.PoseDetectionSystem = PoseDetectionSystem;