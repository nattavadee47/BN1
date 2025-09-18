// ========================================
// ระบบวิเคราะห์ท่าการออกกำลังกายสำหรับกายภาพบำบัด
// exercise-analyzer.js - แก้ไขแล้ว
// ========================================

class ExerciseAnalyzer {
    constructor() {
        this.currentExercise = null;
        this.exerciseState = this.initializeState();
        this.movementPhase = 'rest';
        this.repCounter = 0;
        this.lastAngle = 0;
        this.angleHistory = [];
        this.accuracyHistory = [];
        this.sessionStartTime = null;
    }

    // เริ่มต้นสถานะการออกกำลังกาย
    initializeState() {
        return {
            currentReps: 0,
            targetReps: 10,
            currentSet: 1,
            targetSets: 2,
            lastAngle: 0,
            isInPosition: false,
            movementStarted: false,
            holdTimer: 0,
            requiredHoldTime: 2000,
            lastMovementTime: 0
        };
    }

    // เริ่มการออกกำลังกาย
    startExercise(exerciseId) {
        this.currentExercise = exerciseId;
        const exerciseData = StrokeConfig.EXERCISE_DATA[exerciseId];
        
        if (!exerciseData) {
            throw new Error(`ไม่พบข้อมูลท่า: ${exerciseId}`);
        }

        this.exerciseState = this.initializeState();
        this.exerciseState.targetReps = exerciseData.targetReps || 10;
        this.exerciseState.targetSets = exerciseData.targetSets || 2;
        this.movementPhase = 'rest';
        this.repCounter = 0;
        this.angleHistory = [];
        this.accuracyHistory = [];
        this.sessionStartTime = Date.now();

        console.log(`🏃‍♂️ เริ่มท่า: ${exerciseData.name}`);
        return true;
    }

    // วิเคราะห์ท่าการออกกำลังกาย
    analyzeExercise(poseResults, angles) {
        if (!this.currentExercise || !poseResults?.poseLandmarks) {
            return null;
        }

        const exerciseData = StrokeConfig.EXERCISE_DATA[this.currentExercise];
        const landmarks = poseResults.poseLandmarks;

        // ตรวจสอบว่า landmarks ที่จำเป็นมีอยู่
        if (!StrokeUtils.validateLandmarks(landmarks, exerciseData.landmarks)) {
            return {
                status: 'invalid',
                message: 'ไม่สามารถตรวจจับท่าทางได้ชัดเจน กรุณาปรับตำแหน่ง'
            };
        }

        // วิเคราะห์ตามประเภทท่า
        let analysis = null;
        switch (this.currentExercise) {
            case 'arm-raise-forward':
                analysis = this.analyzeArmRaiseForward(landmarks, angles);
                break;
            case 'leg-forward':
                analysis = this.analyzeLegForward(landmarks, angles);
                break;
            case 'trunk-sway':
                analysis = this.analyzeTrunkSway(landmarks, angles);
                break;
            case 'neck-tilt':
                analysis = this.analyzeNeckTilt(landmarks, angles);
                break;
            default:
                analysis = {
                    status: 'unknown',
                    message: `ไม่รองรับท่า: ${this.currentExercise}`
                };
        }

        // อัปเดตประวัติ
        if (analysis && analysis.currentAngle) {
            this.updateAngleHistory(analysis.currentAngle);
            this.updateAccuracyHistory(analysis.accuracy || 0);
        }

        return analysis;
    }

    // วิเคราะห์ท่ายกแขนไปข้างหน้า (ปรับปรุงใหม่ - เรียบง่าย)
analyzeArmRaiseForward(landmarks, angles) {
    const { LEFT_SHOULDER, RIGHT_SHOULDER, LEFT_ELBOW, RIGHT_ELBOW, LEFT_WRIST, RIGHT_WRIST } = StrokeConfig.POSE_LANDMARKS;
    
    // ตรวจสอบ landmarks ที่จำเป็น
    if (!StrokeUtils.validateLandmarks(landmarks, [LEFT_SHOULDER, RIGHT_SHOULDER, LEFT_ELBOW, RIGHT_ELBOW, LEFT_WRIST, RIGHT_WRIST])) {
        return {
            status: 'invalid',
            message: 'ไม่สามารถตรวจจับแขนได้ชัดเจน กรุณาปรับตำแหน่ง'
        };
    }

    // เริ่มต้นสถานะการสลับข้าง ถ้าไม่มี
    if (!this.armRaiseState) {
        this.armRaiseState = {
            currentSide: 'left',
            leftCount: 0,
            rightCount: 0,
            lastSoundTime: 0,
            hasPlayedReady: false
        };
    }

    const currentSide = this.armRaiseState.currentSide;
    const isLeftSide = currentSide === 'left';
    
    // เลือกข้อมือ ไหล่ และข้อศอกตามข้างที่กำลังทำ
    const wristIndex = isLeftSide ? LEFT_WRIST : RIGHT_WRIST;
    const shoulderIndex = isLeftSide ? LEFT_SHOULDER : RIGHT_SHOULDER;
    const elbowIndex = isLeftSide ? LEFT_ELBOW : RIGHT_ELBOW;
    
    // คำนวณมุมแขน (ไหล่-ข้อศอก-ข้อมือ)
    const armAngle = StrokeUtils.calculateAngle(
        {x: landmarks[shoulderIndex].x, y: landmarks[shoulderIndex].y},
        {x: landmarks[elbowIndex].x, y: landmarks[elbowIndex].y},
        {x: landmarks[wristIndex].x, y: landmarks[wristIndex].y}
    );
    
    // ปรับมุมให้เป็นค่าปกติ (0-90 องศา)
    const normalizedAngle = Math.max(0, 180 - armAngle);
    
    // เกณฑ์ที่ปรับให้เหมาะกับผู้ป่วย
    const REST_POSITION = 10;      // แขนอยู่ข้างตัว (ง่ายขึ้น)
    const FORWARD_POSITION = 50;   // ยกแขนไปข้างหน้า (เหมาะกับผู้ป่วย)
    const MOVEMENT_THRESHOLD = 3;  // เกณฑ์การเคลื่อนไหว (ไวขึ้น)

    const sideName = isLeftSide ? 'ซ้าย' : 'ขวา';
    const totalCount = this.armRaiseState.leftCount + this.armRaiseState.rightCount;
    
    let analysis = {
        currentAngle: Math.round(normalizedAngle),
        targetAngle: FORWARD_POSITION,
        accuracy: this.calculateArmAccuracy(normalizedAngle, FORWARD_POSITION),
        phase: this.movementPhase,
        feedback: '',
        shouldCount: false,
        currentSide: currentSide,
        sideName: sideName,
        totalCount: totalCount,
        leftCount: this.armRaiseState.leftCount,
        rightCount: this.armRaiseState.rightCount
    };

    switch (this.movementPhase) {
        case 'rest':
            // เล่นเสียงเตรียมครั้งเดียว
            if (!this.armRaiseState.hasPlayedReady) {
                StrokeUtils.playReadySound();
                this.armRaiseState.hasPlayedReady = true;
            }
            
            if (normalizedAngle > REST_POSITION + MOVEMENT_THRESHOLD) {
                this.movementPhase = 'raising';
                analysis.feedback = `กำลังยกแขน${sideName}ไปข้างหน้า...`;
            } else {
                analysis.feedback = `ยกแขน${sideName} (${totalCount + 1}/${this.exerciseState.targetReps})`;
            }
            break;

        case 'raising':
            if (normalizedAngle >= FORWARD_POSITION * 0.95) {
                this.movementPhase = 'holding';
                this.exerciseState.holdTimer = Date.now();
                analysis.feedback = `ยกแขน${sideName}ได้ดี! ค้างท่าแล้วลงแขน`;
                
                // ตั้งเวลาให้เปลี่ยนเป็น lowering อัตโนมัติ
                setTimeout(() => {
                    if (this.movementPhase === 'holding') {
                        this.movementPhase = 'lowering';
                    }
                }, 1500);
            } else {
                const progress = Math.round((normalizedAngle / FORWARD_POSITION) * 100);
                analysis.feedback = `ยกแขน${sideName}ต่อไป... ${progress}%`;
            }
            break;

        case 'holding':
            const holdTime = Date.now() - this.exerciseState.holdTimer;
            const remainingTime = Math.max(0, Math.ceil((1500 - holdTime) / 1000));
            
            if (remainingTime > 0) {
                analysis.feedback = `ค้างท่ายกแขน${sideName}... ${remainingTime}s`;
            } else {
                analysis.feedback = `ลงแขน${sideName}กลับ...`;
            }
            break;

        case 'lowering':
            if (normalizedAngle <= REST_POSITION + 5) {
                this.completeSideRep(currentSide);
                analysis.shouldCount = true;
                analysis.feedback = `ทำท่ายกแขน${sideName}สำเร็จ! (${totalCount + 1}/${this.exerciseState.targetReps})`;
            } else {
                analysis.feedback = `ลงแขน${sideName}กลับ...`;
            }
            break;
    }

    return analysis;
}

// ฟังก์ชันคำนวณความแม่นยำสำหรับแขน
calculateArmAccuracy(currentAngle, targetAngle) {
    const REST_POSITION = 10;
    let accuracy = 50;
    
    if (this.movementPhase === 'raising') {
        accuracy = Math.min(95, 50 + ((currentAngle - REST_POSITION) / (targetAngle - REST_POSITION)) * 45);
    } else if (this.movementPhase === 'lowering') {
        accuracy = Math.min(95, 50 + ((targetAngle - currentAngle) / (targetAngle - REST_POSITION)) * 45);
    } else if (this.movementPhase === 'holding') {
        accuracy = 95;
    }
    
    return Math.max(0, Math.round(accuracy));
}

// เสร็จสิ้น 1 ครั้งของข้างนั้นๆ
completeSideRep(side) {
    // นับครั้ง
    if (side === 'left') {
        this.armRaiseState.leftCount++;
    } else {
        this.armRaiseState.rightCount++;
    }
    
    const totalReps = this.armRaiseState.leftCount + this.armRaiseState.rightCount;
    this.exerciseState.currentReps = totalReps;
    this.repCounter = totalReps;
    
    // เล่นเสียงสำเร็จ
    StrokeUtils.playSuccessSound();
    
    const sideName = side === 'left' ? 'ซ้าย' : 'ขวา';
    console.log(`✅ เสร็จ${sideName} | L:${this.armRaiseState.leftCount} R:${this.armRaiseState.rightCount} | รวม:${totalReps}`);
    
    // สลับข้าง
    this.armRaiseState.currentSide = side === 'left' ? 'right' : 'left';
    
    // ตรวจสอบว่าเสร็จครบหรือยัง
    if (totalReps >= this.exerciseState.targetReps) {
        this.resetArmRaiseState();
        return this.completeSet();
    } else {
        this.movementPhase = 'rest';
        this.armRaiseState.hasPlayedReady = false; // รีเซ็ตเสียงเตรียมสำหรับข้างใหม่
        return false;
    }
}

// รีเซ็ตสถานะการยกแขน
resetArmRaiseState() {
    this.armRaiseState = {
        currentSide: 'left',
        leftCount: 0,
        rightCount: 0,
        lastSoundTime: 0,
        hasPlayedReady: false
    };
}

    // วิเคราะห์ท่าเหยียดเข่าตรง
    analyzeLegForward(landmarks, angles) {
        const { LEFT_HIP, RIGHT_HIP, LEFT_KNEE, RIGHT_KNEE, LEFT_ANKLE, RIGHT_ANKLE } = StrokeConfig.POSE_LANDMARKS;
        
        const leftKneeAngle = StrokeUtils.calculateAngle(
            {x: landmarks[LEFT_HIP].x, y: landmarks[LEFT_HIP].y},
            {x: landmarks[LEFT_KNEE].x, y: landmarks[LEFT_KNEE].y},
            {x: landmarks[LEFT_ANKLE].x, y: landmarks[LEFT_ANKLE].y}
        );
        
        const rightKneeAngle = StrokeUtils.calculateAngle(
            {x: landmarks[RIGHT_HIP].x, y: landmarks[RIGHT_HIP].y},
            {x: landmarks[RIGHT_KNEE].x, y: landmarks[RIGHT_KNEE].y},
            {x: landmarks[RIGHT_ANKLE].x, y: landmarks[RIGHT_ANKLE].y}
        );

        const currentAngle = Math.max(leftKneeAngle, rightKneeAngle);
        const targetAngle = 170;

        const SITTING_ANGLE = 90;
        const TARGET_EXTENSION = 165;

        let analysis = {
            currentAngle: Math.round(currentAngle),
            targetAngle: targetAngle,
            accuracy: StrokeUtils.calculateAccuracy(currentAngle, targetAngle, 10),
            phase: this.movementPhase,
            feedback: '',
            shouldCount: false
        };

        switch (this.movementPhase) {
            case 'rest':
                if (currentAngle > SITTING_ANGLE + 20) {
                    this.movementPhase = 'extending';
                    analysis.feedback = 'กำลังเหยียดเข่า... เหยียดต่อไป';
                } else if (currentAngle >= SITTING_ANGLE - 10 && currentAngle <= SITTING_ANGLE + 10) {
                    analysis.feedback = `ท่านั่งดี! เตรียมเหยียดเข่า (ครั้งที่ ${this.repCounter + 1}/${this.exerciseState.targetReps})`;
                } else {
                    analysis.feedback = 'นั่งในท่าที่สะดวก ก่อนเหยียดเข่า';
                }
                break;

            case 'extending':
                if (currentAngle >= TARGET_EXTENSION) {
                    this.movementPhase = 'holding';
                    this.exerciseState.holdTimer = Date.now();
                    analysis.feedback = 'เหยียดเข่าได้ดี! คงท่าไว้ 2 วินาที';
                } else {
                    analysis.feedback = `เหยียดเข่าต่อไป... เป้าหมาย: ${TARGET_EXTENSION}° ปัจจุบัน: ${Math.round(currentAngle)}°`;
                }
                break;

            case 'holding':
                const holdTime = Date.now() - this.exerciseState.holdTimer;
                const remainingTime = Math.ceil((2000 - holdTime) / 1000);
                
                if (holdTime >= 2000) {
                    this.movementPhase = 'flexing';
                    analysis.feedback = 'เยี่ยม! งอเข่ากลับสู่ท่าเดิม';
                } else if (currentAngle >= TARGET_EXTENSION - 5) {
                    analysis.feedback = `คงท่าไว้... เหลือ ${remainingTime} วินาที`;
                } else {
                    this.movementPhase = 'extending';
                    analysis.feedback = 'เหยียดเข่าให้ตรงที่สุด';
                }
                break;

            case 'flexing':
                if (currentAngle <= SITTING_ANGLE + 15) {
                    this.completeRepetition();
                    analysis.shouldCount = true;
                    analysis.feedback = `สำเร็จ! ครั้งที่ ${this.repCounter}/${this.exerciseState.targetReps}`;
                } else {
                    analysis.feedback = 'งอเข่ากลับสู่ท่านั่งปกติ';
                }
                break;
        }

        return analysis;
    }

    // วิเคราะห์ท่าโยกลำตัวซ้าย-ขวา
    analyzeTrunkSway(landmarks, angles) {
        const { LEFT_SHOULDER, RIGHT_SHOULDER, LEFT_HIP, RIGHT_HIP } = StrokeConfig.POSE_LANDMARKS;
        
        const shoulderCenter = {
            x: (landmarks[LEFT_SHOULDER].x + landmarks[RIGHT_SHOULDER].x) / 2,
            y: (landmarks[LEFT_SHOULDER].y + landmarks[RIGHT_SHOULDER].y) / 2
        };
        const hipCenter = {
            x: (landmarks[LEFT_HIP].x + landmarks[RIGHT_HIP].x) / 2,
            y: (landmarks[LEFT_HIP].y + landmarks[RIGHT_HIP].y) / 2
        };
        
        const tiltX = Math.abs(shoulderCenter.x - hipCenter.x);
        const currentAngle = Math.min(30, tiltX * 100);
        const targetAngle = 20;

        const REST_POSITION = 2;
        const TARGET_SWAY = 15;

        let analysis = {
            currentAngle: Math.round(currentAngle),
            targetAngle: targetAngle,
            accuracy: StrokeUtils.calculateAccuracy(currentAngle, targetAngle, 8),
            phase: this.movementPhase,
            feedback: '',
            shouldCount: false
        };

        switch (this.movementPhase) {
            case 'rest':
                if (currentAngle > REST_POSITION + 3) {
                    this.movementPhase = 'swaying';
                    analysis.feedback = 'กำลังโยกลำตัว... โยกต่อไป';
                } else {
                    analysis.feedback = `ท่าตรงดี! เตรียมโยกลำตัว (ครั้งที่ ${this.repCounter + 1}/${this.exerciseState.targetReps})`;
                }
                break;

            case 'swaying':
                if (currentAngle >= TARGET_SWAY) {
                    this.movementPhase = 'holding';
                    this.exerciseState.holdTimer = Date.now();
                    analysis.feedback = 'โยกลำตัวได้ดี! คงท่าไว้ 2 วินาที';
                } else {
                    analysis.feedback = `โยกลำตัวต่อไป... เป้าหมาย: ${TARGET_SWAY}° ปัจจุบัน: ${Math.round(currentAngle)}°`;
                }
                break;

            case 'holding':
                const holdTime = Date.now() - this.exerciseState.holdTimer;
                const remainingTime = Math.ceil((2000 - holdTime) / 1000);
                
                if (holdTime >= 2000) {
                    this.movementPhase = 'returning';
                    analysis.feedback = 'เยี่ยม! กลับสู่ท่าตรง';
                } else if (currentAngle >= TARGET_SWAY - 3) {
                    analysis.feedback = `คงท่าไว้... เหลือ ${remainingTime} วินาที`;
                } else {
                    this.movementPhase = 'swaying';
                    analysis.feedback = 'โยกลำตัวให้ถึงเป้าหมาย';
                }
                break;

            case 'returning':
                if (currentAngle <= REST_POSITION + 1) {
                    this.completeRepetition();
                    analysis.shouldCount = true;
                    analysis.feedback = `สำเร็จ! ครั้งที่ ${this.repCounter}/${this.exerciseState.targetReps}`;
                } else {
                    analysis.feedback = 'กลับสู่ท่าตรงช้าๆ';
                }
                break;
        }

        return analysis;
    }

    // วิเคราะห์ท่าเอียงศีรษะซ้าย-ขวา
    analyzeNeckTilt(landmarks, angles) {
        const { LEFT_EAR, RIGHT_EAR } = StrokeConfig.POSE_LANDMARKS;
        
        const earHeightDiff = Math.abs(landmarks[LEFT_EAR].y - landmarks[RIGHT_EAR].y);
        const currentAngle = Math.min(30, earHeightDiff * 150);
        const targetAngle = 20;

        const REST_POSITION = 2;
        const TARGET_TILT = 15;

        let analysis = {
            currentAngle: Math.round(currentAngle),
            targetAngle: targetAngle,
            accuracy: StrokeUtils.calculateAccuracy(currentAngle, targetAngle, 5),
            phase: this.movementPhase,
            feedback: '',
            shouldCount: false
        };

        switch (this.movementPhase) {
            case 'rest':
                if (currentAngle > REST_POSITION + 2) {
                    this.movementPhase = 'tilting';
                    analysis.feedback = 'กำลังเอียงศีรษะ... เอียงต่อไป';
                } else {
                    analysis.feedback = `ท่าตรงดี! เตรียมเอียงศีรษะ (ครั้งที่ ${this.repCounter + 1}/${this.exerciseState.targetReps})`;
                }
                break;

            case 'tilting':
                if (currentAngle >= TARGET_TILT) {
                    this.movementPhase = 'holding';
                    this.exerciseState.holdTimer = Date.now();
                    analysis.feedback = 'เอียงศีรษะได้ดี! คงท่าไว้ 2 วินาที';
                } else {
                    analysis.feedback = `เอียงศีรษะต่อไป... เป้าหมาย: ${TARGET_TILT}° ปัจจุบัน: ${Math.round(currentAngle)}°`;
                }
                break;

            case 'holding':
                const holdTime = Date.now() - this.exerciseState.holdTimer;
                const remainingTime = Math.ceil((2000 - holdTime) / 1000);
                
                if (holdTime >= 2000) {
                    this.movementPhase = 'returning';
                    analysis.feedback = 'เยี่ยม! กลับสู่ท่าตรง';
                } else if (currentAngle >= TARGET_TILT - 2) {
                    analysis.feedback = `คงท่าไว้... เหลือ ${remainingTime} วินาที`;
                } else {
                    this.movementPhase = 'tilting';
                    analysis.feedback = 'เอียงศีรษะให้ถึงเป้าหมาย';
                }
                break;

            case 'returning':
                if (currentAngle <= REST_POSITION + 1) {
                    this.completeRepetition();
                    analysis.shouldCount = true;
                    analysis.feedback = `สำเร็จ! ครั้งที่ ${this.repCounter}/${this.exerciseState.targetReps}`;
                } else {
                    analysis.feedback = 'กลับสู่ท่าตรงช้าๆ';
                }
                break;
        }

        return analysis;
    }

    // เสร็จสิ้น 1 ครั้ง
    completeRepetition() {
        this.repCounter++;
        this.exerciseState.currentReps++;
        this.movementPhase = 'rest';
        this.exerciseState.lastMovementTime = Date.now();
        
        StrokeUtils.playSuccessSound();
        
        if (this.repCounter >= this.exerciseState.targetReps) {
            return this.completeSet();
        }
        
        return false;
    }

    // เสร็จสิ้น 1 เซต
    completeSet() {
        this.exerciseState.currentSet++;
        
        if (this.exerciseState.currentSet > this.exerciseState.targetSets) {
            StrokeUtils.playCompleteSound();
            return 'complete';
        } else {
            this.exerciseState.currentReps = 0;
            this.repCounter = 0;
            this.movementPhase = 'rest';
            return 'new_set';
        }
    }

    // อัปเดตประวัติมุม
    updateAngleHistory(angle) {
        this.angleHistory.push({
            angle: angle,
            timestamp: Date.now()
        });
        
        if (this.angleHistory.length > 100) {
            this.angleHistory.shift();
        }
        
        this.lastAngle = angle;
    }

    // อัปเดตประวัติความแม่นยำ
    updateAccuracyHistory(accuracy) {
        this.accuracyHistory.push({
            accuracy: accuracy,
            timestamp: Date.now()
        });
        
        if (this.accuracyHistory.length > 100) {
            this.accuracyHistory.shift();
        }
    }

    // ได้สถิติของเซสชัน
    getSessionStatistics() {
        if (!this.sessionStartTime) return null;

        const now = Date.now();
        const duration = Math.floor((now - this.sessionStartTime) / 1000);
        
        const accuracyValues = this.accuracyHistory.map(item => item.accuracy);
        const averageAccuracy = accuracyValues.length > 0 
            ? accuracyValues.reduce((sum, val) => sum + val, 0) / accuracyValues.length 
            : 0;

        const angleValues = this.angleHistory.map(item => item.angle);
        const angleStats = StrokeUtils.calculateStatistics(angleValues);

        return {
            sessionId: StrokeUtils.generateSessionId(),
            exercise: this.currentExercise,
            exerciseName: StrokeUtils.getExerciseName(this.currentExercise),
            duration: duration,
            formattedDuration: StrokeUtils.formatTime(duration),
            repetitions: this.repCounter,
            targetReps: this.exerciseState.targetReps,
            completionRate: (this.repCounter / this.exerciseState.targetReps) * 100,
            averageAccuracy: Math.round(averageAccuracy),
            angleStatistics: angleStats,
            consistency: this.calculateConsistency(),
            timestamp: this.sessionStartTime,
            endTime: now
        };
    }

    // คำนวณความสม่ำเสมอ
    calculateConsistency() {
        if (this.angleHistory.length < 5) return 0;
        
        const recentAngles = this.angleHistory.slice(-10).map(item => item.angle);
        const stats = StrokeUtils.calculateStatistics(recentAngles);
        
        const maxStd = 20;
        const consistency = Math.max(0, 100 - (stats.std / maxStd) * 100);
        
        return Math.round(consistency);
    }

    // รีเซ็ตการออกกำลังกาย
    reset() {
        this.currentExercise = null;
        this.exerciseState = this.initializeState();
        this.movementPhase = 'rest';
        this.repCounter = 0;
        this.lastAngle = 0;
        this.angleHistory = [];
        this.accuracyHistory = [];
        this.sessionStartTime = null;
    }

    // ได้สถานะปัจจุบัน
    getCurrentState() {
        return {
            exercise: this.currentExercise,
            exerciseName: this.currentExercise ? StrokeUtils.getExerciseName(this.currentExercise) : null,
            phase: this.movementPhase,
            reps: this.repCounter,
            targetReps: this.exerciseState.targetReps,
            set: this.exerciseState.currentSet,
            targetSets: this.exerciseState.targetSets,
            lastAngle: this.lastAngle,
            isActive: this.currentExercise !== null
        };
    }

    // ตรวจสอบว่ากำลังออกกำลังกายอยู่หรือไม่
    isExercising() {
        return this.currentExercise !== null;
    }

    // หยุดการออกกำลังกาย
    stopExercise() {
        const sessionStats = this.getSessionStatistics();
        this.reset();
        return sessionStats;
    }
}

// ส่งออกคลาส
window.ExerciseAnalyzer = ExerciseAnalyzer;