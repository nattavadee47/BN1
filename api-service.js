// ========================================
// API Service สำหรับเชื่อมต่อฐานข้อมูล
// api-service.js
// ========================================

class APIService {
    constructor() {
        this.baseURL = StrokeConfig.API_CONFIG.BASE_URL;
        this.headers = StrokeConfig.API_CONFIG.HEADERS;
        this.timeout = StrokeConfig.API_CONFIG.TIMEOUT;
        this.currentUser = this.getCurrentUser();
    }

    // ดึงข้อมูลผู้ใช้ปัจจุบัน
    getCurrentUser() {
        try {
            const userData = localStorage.getItem('user');
            return userData ? JSON.parse(userData) : null;
        } catch (error) {
            console.error('Error getting current user:', error);
            return null;
        }
    }

    // HTTP Request Helper
    async makeRequest(url, options = {}) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);

            const config = {
                ...options,
                headers: {
                    ...this.headers,
                    ...options.headers
                },
                signal: controller.signal
            };

            const response = await fetch(`${this.baseURL}${url}`, config);
            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.error(`API Request failed for ${url}:`, error);
            throw error;
        }
    }

    // ===== EXERCISE SESSION MANAGEMENT =====

    // สร้างเซสชันการฝึกใหม่
    async createExerciseSession(sessionData) {
        const payload = {
            patient_id: this.currentUser?.user_id,
            plan_id: sessionData.plan_id || null,
            session_date: new Date().toISOString(),
            exercise_type: sessionData.exercise,
            exercise_phase: 'starting',
            primary_joint: sessionData.primaryJoints?.[0] || '',
            affected_side: sessionData.affected_side || 'both',
            session_type: 'self_practice',
            target_reps: sessionData.targetReps || 10,
            target_sets: sessionData.targetSets || 2,
            target_angle_min: sessionData.targetAngleRange?.[0] || 0,
            target_angle_max: sessionData.targetAngleRange?.[1] || 180
        };

        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.CREATE_SESSION,
            {
                method: 'POST',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // อัปเดตเซสชันปัจจุบัน
    async updateExerciseSession(sessionId, updateData) {
        const payload = {
            session_id: sessionId,
            duration_minutes: Math.round(updateData.duration / 60000), // convert ms to minutes
            completed_reps: updateData.reps || 0,
            current_set: updateData.currentSet || 1,
            session_duration: updateData.duration || 0,
            average_accuracy: Math.round(updateData.averageAccuracy || 0),
            max_angle_achieved: updateData.maxAngle || 0,
            min_angle_achieved: updateData.minAngle || 0,
            pose_detection_rate: updateData.detectionRate || 0,
            movement_smoothness: updateData.smoothness || 0,
            exercise_phase: updateData.phase || 'in_progress'
        };

        const response = await this.makeRequest(
            `${StrokeConfig.API_CONFIG.ENDPOINTS.UPDATE_SESSION}/${sessionId}`,
            {
                method: 'PUT',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // เสร็จสิ้นเซสชัน
    async completeExerciseSession(sessionId, finalData) {
        const payload = {
            session_id: sessionId,
            completion_status: 'complete',
            duration_minutes: Math.round(finalData.duration / 60000),
            completed_reps: finalData.reps || 0,
            target_reps: finalData.targetReps || 10,
            current_set: finalData.currentSet || 1,
            target_sets: finalData.targetSets || 2,
            session_duration: finalData.duration || 0,
            average_accuracy: Math.round(finalData.averageAccuracy || 0),
            max_angle_achieved: finalData.maxAngle || 0,
            min_angle_achieved: finalData.minAngle || 0,
            total_frames_processed: finalData.totalFrames || 0,
            pose_detection_rate: finalData.detectionRate || 0,
            movement_smoothness: finalData.smoothness || 0,
            session_quality: this.calculateSessionQuality(finalData),
            pain_level: finalData.painLevel || 0,
            fatigue_level: finalData.fatigueLevel || 0,
            mood_rating: finalData.moodRating || 5,
            notes: finalData.notes || '',
            video_recorded: finalData.videoRecorded || false,
            video_filename: finalData.videoFilename || null
        };

        const response = await this.makeRequest(
            `${StrokeConfig.API_CONFIG.ENDPOINTS.COMPLETE_SESSION}/${sessionId}`,
            {
                method: 'PUT',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // คำนวณคุณภาพเซสชัน
    calculateSessionQuality(data) {
        const accuracy = data.averageAccuracy || 0;
        const completion = (data.reps / (data.targetReps || 1)) * 100;
        const consistency = data.smoothness || 0;
        
        const qualityScore = (accuracy * 0.4) + (completion * 0.4) + (consistency * 0.2);
        
        if (qualityScore >= 85) return 'excellent';
        if (qualityScore >= 70) return 'good';
        if (qualityScore >= 50) return 'fair';
        return 'needs_improvement';
    }

    // ===== POSE DATA MANAGEMENT =====

    // บันทึกข้อมูลมุมข้อต่อ
    async savePoseAngles(sessionId, anglesData) {
        const payload = {
            session_id: sessionId,
            timestamp: new Date().toISOString(),
            left_shoulder_angle: anglesData.leftShoulder || 0,
            right_shoulder_angle: anglesData.rightShoulder || 0,
            left_elbow_angle: anglesData.leftElbow || 0,
            right_elbow_angle: anglesData.rightElbow || 0,
            left_hip_angle: anglesData.leftHip || 0,
            right_hip_angle: anglesData.rightHip || 0,
            left_knee_angle: anglesData.leftKnee || 0,
            right_knee_angle: anglesData.rightKnee || 0,
            neck_tilt_angle: anglesData.neckTilt || 0,
            trunk_tilt_angle: anglesData.trunkTilt || 0,
            pose_confidence: anglesData.confidence || 0,
            frame_number: anglesData.frameNumber || 0,
            accuracy_score: anglesData.accuracy || 0,
            movement_phase: anglesData.phase || 'rest',
            target_angle: anglesData.targetAngle || 0,
            angle_difference: anglesData.angleDifference || 0,
            is_correct_form: anglesData.isCorrect || false,
            joint_speed: anglesData.jointSpeed || 0
        };

        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.POSE_ANGLES,
            {
                method: 'POST',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // บันทึกข้อมูล landmarks (แบบ batch)
    async savePoseLandmarks(sessionId, landmarksArray) {
        const payload = {
            session_id: sessionId,
            landmarks: landmarksArray.map(landmark => ({
                timestamp: landmark.timestamp,
                landmark_index: landmark.index,
                x_coordinate: landmark.x,
                y_coordinate: landmark.y,
                z_coordinate: landmark.z || 0,
                visibility: landmark.visibility || 0,
                presence: landmark.presence || 0,
                frame_number: landmark.frameNumber || 0,
                landmark_name: this.getLandmarkName(landmark.index),
                normalized_x: landmark.normalizedX || landmark.x,
                normalized_y: landmark.normalizedY || landmark.y,
                normalized_z: landmark.normalizedZ || landmark.z || 0,
                world_x: landmark.worldX || 0,
                world_y: landmark.worldY || 0,
                world_z: landmark.worldZ || 0
            }))
        };

        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.POSE_LANDMARKS,
            {
                method: 'POST',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // ได้ชื่อ landmark จาก index
    getLandmarkName(index) {
        const landmarkNames = {
            0: 'nose', 1: 'left_eye_inner', 2: 'left_eye', 3: 'left_eye_outer',
            4: 'right_eye_inner', 5: 'right_eye', 6: 'right_eye_outer',
            7: 'left_ear', 8: 'right_ear', 9: 'mouth_left', 10: 'mouth_right',
            11: 'left_shoulder', 12: 'right_shoulder', 13: 'left_elbow', 14: 'right_elbow',
            15: 'left_wrist', 16: 'right_wrist', 17: 'left_pinky', 18: 'right_pinky',
            19: 'left_index', 20: 'right_index', 21: 'left_thumb', 22: 'right_thumb',
            23: 'left_hip', 24: 'right_hip', 25: 'left_knee', 26: 'right_knee',
            27: 'left_ankle', 28: 'right_ankle', 29: 'left_heel', 30: 'right_heel',
            31: 'left_foot_index', 32: 'right_foot_index'
        };
        return landmarkNames[index] || `landmark_${index}`;
    }

    // ===== MOVEMENT ANALYSIS =====

    // บันทึกผลการวิเคราะห์การเคลื่อนไหว
    async saveMovementAnalysis(sessionId, analysisData) {
        const payload = {
            session_id: sessionId,
            exercise_type: analysisData.exerciseType,
            posture_score: analysisData.postureScore || 0,
            movement_range: analysisData.movementRange || 0,
            movement_speed: analysisData.movementSpeed || 0,
            stability_score: analysisData.stabilityScore || 0,
            rhythm_consistency: analysisData.rhythmConsistency || 0,
            pause_duration_avg: analysisData.pauseDurationAvg || 0,
            movement_duration_avg: analysisData.movementDurationAvg || 0,
            symmetry_score: analysisData.symmetryScore || 0,
            compensation_detected: analysisData.compensationDetected || false,
            compensation_details: analysisData.compensationDetails || '',
            tremor_detected: analysisData.tremorDetected || false,
            tremor_severity: analysisData.tremorSeverity || 0,
            improvement_percentage: analysisData.improvementPercentage || 0
        };

        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.SAVE_ANALYSIS,
            {
                method: 'POST',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // ===== PROGRESS TRACKING =====

    // บันทึกความคืบหน้า
    async saveProgress(progressData) {
        const payload = {
            patient_id: this.currentUser?.user_id,
            measurement_date: new Date().toISOString(),
            measurement_type: progressData.type || 'exercise_performance',
            body_part: progressData.bodyPart || '',
            value: progressData.value || 0,
            unit: progressData.unit || '',
            notes: progressData.notes || '',
            recorded_by: this.currentUser?.user_id,
            weekly_sessions: progressData.weeklySessions || 0,
            weekly_duration: progressData.weeklyDuration || 0,
            weekly_avg_accuracy: progressData.weeklyAvgAccuracy || 0,
            improvement_trend: progressData.improvementTrend || 'stable',
            milestone_achieved: progressData.milestoneAchieved || false,
            consistency_score: progressData.consistencyScore || 0,
            motivation_level: progressData.motivationLevel || 5
        };

        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.SAVE_PROGRESS,
            {
                method: 'POST',
                body: JSON.stringify(payload)
            }
        );

        return response;
    }

    // ดึงความคืบหน้าของผู้ป่วย
    async getPatientProgress(patientId = null, dateRange = null) {
        const userId = patientId || this.currentUser?.user_id;
        let url = `${StrokeConfig.API_CONFIG.ENDPOINTS.PROGRESS}/${userId}`;
        
        if (dateRange) {
            const params = new URLSearchParams({
                start_date: dateRange.start,
                end_date: dateRange.end
            });
            url += `?${params.toString()}`;
        }

        const response = await this.makeRequest(url, { method: 'GET' });
        return response;
    }

    // ===== EXERCISE DATA =====

    // ดึงข้อมูลท่าทั้งหมด
    async getExercises() {
        const response = await this.makeRequest(
            StrokeConfig.API_CONFIG.ENDPOINTS.EXERCISES,
            { method: 'GET' }
        );
        return response;
    }

    // ดึงข้อมูลท่าเฉพาะ
    async getExerciseById(exerciseId) {
        const response = await this.makeRequest(
            `${StrokeConfig.API_CONFIG.ENDPOINTS.EXERCISE_BY_ID}/${exerciseId}`,
            { method: 'GET' }
        );
        return response;
    }

    // ===== UTILITY METHODS =====

    // ตรวจสอบการเชื่อมต่อ API
    async testConnection() {
        try {
            const response = await this.makeRequest('/test', { method: 'GET' });
            return { success: true, data: response };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Batch save สำหรับข้อมูลมาก
    async batchSave(dataArray, endpoint, batchSize = 50) {
        const results = [];
        
        for (let i = 0; i < dataArray.length; i += batchSize) {
            const batch = dataArray.slice(i, i + batchSize);
            try {
                const response = await this.makeRequest(
                    endpoint,
                    {
                        method: 'POST',
                        body: JSON.stringify({ batch: batch })
                    }
                );
                results.push(response);
            } catch (error) {
                console.error(`Batch save failed for batch ${i / batchSize + 1}:`, error);
                results.push({ success: false, error: error.message });
            }
        }
        
        return results;
    }
}

// สร้าง instance ส่วนกลาง
window.APIService = APIService;
window.apiService = new APIService();