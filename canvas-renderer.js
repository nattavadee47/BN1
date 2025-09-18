// ========================================
// ระบบแสดงผล Canvas สำหรับกายภาพบำบัด
// canvas-renderer.js
// ========================================

class CanvasRenderer {
    constructor(canvasElement, videoElement) {
        this.canvas = canvasElement;
        this.video = videoElement;
        this.ctx = canvasElement.getContext('2d');
        this.isInitialized = false;
        
        this.setupCanvas();
    }

    // ตั้งค่า Canvas
    setupCanvas() {
        if (!this.canvas || !this.video) {
            console.error('❌ ไม่พบ canvas หรือ video element');
            return;
        }

        // อัปเดตขนาด canvas ตามขนาดวิดีโอ
        const updateCanvasSize = () => {
            if (this.video.videoWidth > 0 && this.video.videoHeight > 0) {
                this.canvas.width = this.video.videoWidth;
                this.canvas.height = this.video.videoHeight;
                
                // ปรับ CSS ให้แสดงผลได้ดี
                this.canvas.style.width = '100%';
                this.canvas.style.height = 'auto';
                
                this.isInitialized = true;
                console.log(`✅ Canvas ขนาด: ${this.canvas.width}x${this.canvas.height}`);
            } else {
                setTimeout(updateCanvasSize, 100);
            }
        };
        
        updateCanvasSize();
    }

    // วาดผลการตรวจจับท่าทาง
    drawPoseResults(poseResults, exerciseAnalysis = null) {
        if (!this.isInitialized || !this.ctx || !poseResults) return;
        
        try {
            // เคลียร์ canvas
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
            
            // วาดภาพจากวิดีโอ
            if (this.video && this.video.videoWidth > 0) {
                this.ctx.drawImage(this.video, 0, 0, this.canvas.width, this.canvas.height);
            }
            
            if (poseResults.poseLandmarks) {
                // วาดเส้นเชื่อมโครงกระดูก
                this.drawPoseConnections(poseResults.poseLandmarks);
                
                // วาดจุด landmarks
                this.drawLandmarks(poseResults.poseLandmarks);
                
                // ไฮไลท์จุดสำคัญ
                if (exerciseAnalysis?.exercise) {
                    this.highlightExercisePoints(poseResults.poseLandmarks, exerciseAnalysis.exercise);
                }
                
                // วาดข้อมูลการออกกำลังกาย
                if (exerciseAnalysis) {
                    this.drawExerciseInfo(exerciseAnalysis);
                }
            }
        } catch (error) {
            console.warn('⚠️ Error in drawPoseResults:', error);
        }
    }

    // วาดเส้นเชื่อมโครงกระดูก
    drawPoseConnections(landmarks) {
        if (!window.drawConnectors || !window.POSE_CONNECTIONS) return;
        
        try {
            const config = StrokeConfig.CONFIG.CANVAS;
            window.drawConnectors(this.ctx, landmarks, window.POSE_CONNECTIONS, {
                color: config.CONNECTION_COLOR,
                lineWidth: config.LINE_WIDTH
            });
        } catch (error) {
            console.warn('⚠️ Error drawing pose connections:', error);
        }
    }

    // วาดจุด landmarks
    drawLandmarks(landmarks) {
        if (!window.drawLandmarks) return;
        
        try {
            const config = StrokeConfig.CONFIG.CANVAS;
            window.drawLandmarks(this.ctx, landmarks, {
                color: config.LANDMARK_COLOR,
                lineWidth: config.LINE_WIDTH,
                radius: config.LANDMARK_RADIUS
            });
        } catch (error) {
            console.warn('⚠️ Error drawing landmarks:', error);
        }
    }

    // ไฮไลท์จุดสำคัญตามท่าออกกำลังกาย
    highlightExercisePoints(landmarks, exerciseId) {
        if (!window.drawLandmarks || !exerciseId) return;

        const exerciseData = StrokeConfig.EXERCISE_DATA[exerciseId];
        if (!exerciseData) return;

        // ได้จุดที่ต้องไฮไลท์
        const highlightIndices = exerciseData.landmarks;
        const highlightLandmarks = highlightIndices
            .map(index => landmarks[index])
            .filter(landmark => landmark && landmark.visibility > 0.5);

        if (highlightLandmarks.length > 0) {
            try {
                const config = StrokeConfig.CONFIG.CANVAS;
                window.drawLandmarks(this.ctx, highlightLandmarks, {
                    color: config.HIGHLIGHT_COLOR,
                    lineWidth: config.LINE_WIDTH + 1,
                    radius: config.LANDMARK_RADIUS + 2
                });
            } catch (error) {
                console.warn('⚠️ Error highlighting exercise points:', error);
            }
        }
    }

    // วาดข้อมูลการออกกำลังกาย
    drawExerciseInfo(analysis) {
        if (!analysis) return;

        try {
            // ตั้งค่าฟอนต์
            this.ctx.font = '16px Kanit, Arial, sans-serif';
            this.ctx.fillStyle = '#FFFFFF';
            this.ctx.strokeStyle = '#000000';
            this.ctx.lineWidth = 3;

            let yPosition = 30;
            const lineHeight = 25;

            // แสดงชื่อท่า
            if (analysis.exercise) {
                const exerciseName = StrokeUtils.getExerciseName(analysis.exercise);
                this.drawTextWithOutline(`ท่า: ${exerciseName}`, 10, yPosition);
                yPosition += lineHeight;
            }

            // แสดงเฟสปัจจุบัน
            if (analysis.phase && analysis.phase !== 'rest') {
                const phaseText = `สถานะ: ${this.getPhaseDisplayName(analysis.phase)}`;
                this.drawTextWithOutline(phaseText, 10, yPosition);
                yPosition += lineHeight;
            }

            // แสดงมุมปัจจุบัน
            if (analysis.currentAngle > 0) {
                const angleText = `มุม: ${analysis.currentAngle}°`;
                this.drawTextWithOutline(angleText, 10, yPosition);
                yPosition += lineHeight;
            }

            // แสดงความแม่นยำ
            if (analysis.accuracy !== undefined) {
                const accuracyText = `ความแม่นยำ: ${Math.round(analysis.accuracy)}%`;
                this.ctx.fillStyle = this.getAccuracyColor(analysis.accuracy);
                this.drawTextWithOutline(accuracyText, 10, yPosition);
                yPosition += lineHeight;
            }

            // แสดงจำนวนครั้ง
            if (analysis.reps !== undefined) {
                this.ctx.fillStyle = '#FFFFFF';
                const repText = `ครั้งที่: ${analysis.reps}/${analysis.targetReps || 10}`;
                this.drawTextWithOutline(repText, 10, yPosition);
            }

            // วาดแถบความคืบหน้า
            if (analysis.reps !== undefined && analysis.targetReps) {
                this.drawProgressBar(analysis.reps, analysis.targetReps);
            }

        } catch (error) {
            console.warn('⚠️ Error drawing exercise info:', error);
        }
    }

    // วาดข้อความพร้อมขอบ
    drawTextWithOutline(text, x, y) {
        // วาดขอบข้อความ
        this.ctx.strokeText(text, x, y);
        // วาดข้อความ
        this.ctx.fillText(text, x, y);
    }

    // วาดแถบความคืบหน้า
    drawProgressBar(current, total) {
        const barWidth = 200;
        const barHeight = 10;
        const barX = 10;
        const barY = this.canvas.height - 40;

        // วาดพื้นหลังแถบ
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
        this.ctx.fillRect(barX, barY, barWidth, barHeight);

        // คำนวณความคืบหน้า
        const progress = Math.min(1, current / total);
        const progressWidth = barWidth * progress;

        // วาดแถบความคืบหน้า
        this.ctx.fillStyle = this.getProgressColor(progress);
        this.ctx.fillRect(barX, barY, progressWidth, barHeight);

        // วาดขอบ
        this.ctx.strokeStyle = '#FFFFFF';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(barX, barY, barWidth, barHeight);

        // วาดข้อความความคืบหน้า
        this.ctx.fillStyle = '#FFFFFF';
        this.ctx.font = '12px Kanit, Arial, sans-serif';
        const progressText = `${current}/${total}`;
        const textWidth = this.ctx.measureText(progressText).width;
        this.ctx.fillText(progressText, barX + (barWidth - textWidth) / 2, barY - 5);
    }

    // วาดเอฟเฟกต์สำเร็จ
    drawSuccessEffect(message = 'สำเร็จ!') {
        if (!this.isInitialized) return;

        try {
            const centerX = this.canvas.width / 2;
            const centerY = this.canvas.height / 2;

            // วาดวงกลมเรืองแสง
            this.ctx.save();
            this.ctx.globalAlpha = 0.7;
            this.ctx.fillStyle = '#4CAF50';
            this.ctx.beginPath();
            this.ctx.arc(centerX, centerY, 80, 0, 2 * Math.PI);
            this.ctx.fill();
            this.ctx.restore();

            // วาดข้อความสำเร็จ
            this.ctx.font = 'bold 28px Kanit, Arial, sans-serif';
            this.ctx.fillStyle = '#FFFFFF';
            this.ctx.strokeStyle = '#000000';
            this.ctx.lineWidth = 4;

            const textWidth = this.ctx.measureText(message).width;
            const textX = centerX - textWidth / 2;
            const textY = centerY + 10;

            this.ctx.strokeText(message, textX, textY);
            this.ctx.fillText(message, textX, textY);

        } catch (error) {
            console.warn('⚠️ Error drawing success effect:', error);
        }
    }

    // วาดข้อความกำลังใจ
    drawMotivationMessage(message, duration = 3000) {
        if (!message) return;

        try {
            const centerX = this.canvas.width / 2;
            const bottomY = this.canvas.height - 60;

            this.ctx.font = '20px Kanit, Arial, sans-serif';
            this.ctx.fillStyle = '#FFD700';
            this.ctx.strokeStyle = '#000000';
            this.ctx.lineWidth = 2;

            const textWidth = this.ctx.measureText(message).width;
            const textX = centerX - textWidth / 2;

            this.ctx.strokeText(message, textX, bottomY);
            this.ctx.fillText(message, textX, bottomY);

        } catch (error) {
            console.warn('⚠️ Error drawing motivation message:', error);
        }
    }

    // ได้ชื่อเฟสการเคลื่อนไหว
    getPhaseDisplayName(phase) {
        const phaseNames = {
            'rest': 'พร้อม',
            'raising': 'กำลังยก',
            'lowering': 'กำลังลด',
            'extending': 'กำลังเหยียด',
            'flexing': 'กำลังงอ',
            'holding': 'คงท่า',
            'swaying': 'กำลังโยก',
            'tilting': 'กำลังเอียง',
            'returning': 'กลับท่าเดิม'
        };
        return phaseNames[phase] || phase;
    }

    // ได้สีตามความแม่นยำ
    getAccuracyColor(accuracy) {
        if (accuracy >= 90) return '#4CAF50'; // เขียว
        if (accuracy >= 70) return '#FFC107'; // เหลือง
        if (accuracy >= 50) return '#FF9800'; // ส้ม
        return '#F44336'; // แดง
    }

    // ได้สีแถบความคืบหน้า
    getProgressColor(progress) {
        if (progress >= 1.0) return '#4CAF50'; // เขียว - เสร็จ
        if (progress >= 0.7) return '#2196F3'; // น้ำเงิน - ใกล้เสร็จ
        if (progress >= 0.3) return '#FF9800'; // ส้ม - ครึ่งทาง
        return '#9E9E9E'; // เทา - เริ่มต้น
    }

    // จับภาพหน้าจอ
    captureScreenshot() {
        if (!this.isInitialized) return null;

        try {
            return this.canvas.toDataURL('image/png');
        } catch (error) {
            console.warn('⚠️ Error capturing screenshot:', error);
            return null;
        }
    }

    // ดาวน์โหลดภาพหน้าจอ
    downloadScreenshot(filename = null) {
        const dataURL = this.captureScreenshot();
        if (!dataURL) return false;

        try {
            const link = document.createElement('a');
            link.download = filename || `stroke-therapy-${Date.now()}.png`;
            link.href = dataURL;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            return true;
        } catch (error) {
            console.warn('⚠️ Error downloading screenshot:', error);
            return false;
        }
    }

    // รีเซ็ต canvas
    clear() {
        if (this.ctx) {
            this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        }
    }

    // ปรับขนาด canvas
    resize() {
        this.setupCanvas();
    }

    // ทำลายระบบแสดงผล
    destroy() {
        this.clear();
        this.canvas = null;
        this.video = null;
        this.ctx = null;
        this.isInitialized = false;
    }
}

// ส่งออกคลาส
window.CanvasRenderer = CanvasRenderer;