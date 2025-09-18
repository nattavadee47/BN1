// ========================================
// ระบบควบคุม UI สำหรับกายภาพบำบัด
// ui-controller.js
// ========================================
class UIController {
    constructor() {
        this.elements = this.initializeElements();
        this.updateInterval = null;
        this.notifications = [];
    }

    // เริ่มต้น DOM elements
    initializeElements() {
        return {
            // Video และ Canvas
            video: document.getElementById('input-video'),
            canvas: document.getElementById('output-canvas'),
            
            // Status elements
            detectionStatus: document.getElementById('detection-status'),
            realtimeInfo: document.getElementById('realtime-info'),
            
            // Exercise selector
            exerciseSelect: document.getElementById('exercise-select'),
            
            // Control buttons
            startBtn: document.getElementById('start-btn'),
            
            // Statistics displays
            repCounter: document.getElementById('rep-counter'),
            accuracyValue: document.getElementById('accuracy-value'),
            timerDisplay: document.getElementById('timer-display'),
            scoreDisplay: document.getElementById('score-display'),
            progressFill: document.getElementById('progress-fill'),
            feedbackText: document.getElementById('feedback-text'),
            
            // Angle displays
            angleGrid: document.getElementById('angle-grid'),
            toggleAngleBtn: document.getElementById('toggle-angle-display'),
            
            // Realtime angle elements
            currentAngle: document.getElementById('current-angle'),
            currentAccuracy: document.getElementById('current-accuracy'),
            repCount: document.getElementById('rep-count'),
            movementPhase: document.getElementById('movement-phase'),
            
            // Individual angle displays
            leftShoulderAngle: document.getElementById('left-shoulder-angle'),
            rightShoulderAngle: document.getElementById('right-shoulder-angle'),
            leftElbowAngle: document.getElementById('left-elbow-angle'),
            rightElbowAngle: document.getElementById('right-elbow-angle'),
            leftKneeAngle: document.getElementById('left-knee-angle'),
            rightKneeAngle: document.getElementById('right-knee-angle'),
            neckTiltAngle: document.getElementById('neck-tilt-angle'),
            trunkTiltAngle: document.getElementById('trunk-tilt-angle'),
            
            // Progress bars
            leftShoulderFill: document.getElementById('left-shoulder-fill'),
            rightShoulderFill: document.getElementById('right-shoulder-fill'),
            leftElbowFill: document.getElementById('left-elbow-fill'),
            rightElbowFill: document.getElementById('right-elbow-fill'),
            leftKneeFill: document.getElementById('left-knee-fill'),
            rightKneeFill: document.getElementById('right-knee-fill'),
            neckTiltFill: document.getElementById('neck-tilt-fill'),
            trunkTiltFill: document.getElementById('trunk-tilt-fill')
        };
    }

    // เริ่มต้นระบบ UI
    initialize() {
        this.setupEventListeners();
        this.updateDetectionStatus('กำลังเตรียมระบบ...');
        return true;
    }

    // ตั้งค่า Event Listeners
    setupEventListeners() {
        // ปุ่มเปิด/ปิดการแสดงมุม
        if (this.elements.toggleAngleBtn) {
            this.elements.toggleAngleBtn.addEventListener('click', () => {
                this.toggleAngleDisplay();
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (event) => {
            this.handleKeyboardShortcuts(event);
        });

        // Resize handler
        window.addEventListener('resize', () => {
            this.handleResize();
        });
    }

    // จัดการ keyboard shortcuts
    handleKeyboardShortcuts(event) {
        // หลีกเลี่ยงการทำงานเมื่อกำลังพิมพ์ในช่อง input
        if (event.target.tagName.toLowerCase() === 'input' || 
            event.target.tagName.toLowerCase() === 'select') {
            return;
        }

        switch (event.key.toLowerCase()) {
            case ' ':
                event.preventDefault();
                this.triggerStartButton();
                break;
            case 'r':
                event.preventDefault();
                this.resetExercise();
                break;
            case 's':
                event.preventDefault();
                this.takeScreenshot();
                break;
        }
    }

    // จัดการการปรับขนาดหน้าจอ
    handleResize() {
        // ปรับปรุง UI สำหรับขนาดหน้าจอที่เปลี่ยน
        const isMobile = window.innerWidth <= 768;
        
        if (isMobile) {
            this.switchToMobileLayout();
        } else {
            this.switchToDesktopLayout();
        }
    }

    // อัปเดตสถานะการตรวจจับ
    updateDetectionStatus(message, status = 'waiting') {
        if (!this.elements.detectionStatus) return;

        this.elements.detectionStatus.textContent = message;
        this.elements.detectionStatus.className = `detection-status ${status}`;

        // เพิ่มไอคอนตามสถานะ
        let icon = '';
        switch (status) {
            case 'waiting':
                icon = '<i class="fas fa-search"></i> ';
                break;
            case 'detected':
                icon = '<i class="fas fa-check-circle"></i> ';
                break;
            case 'detecting':
                icon = '<i class="fas fa-sync fa-spin"></i> ';
                break;
            default:
                icon = '<i class="fas fa-info-circle"></i> ';
        }

        this.elements.detectionStatus.innerHTML = icon + message;
    }

    // อัปเดตข้อมูลเรียลไทม์
    updateRealtimeInfo(data) {
        if (!this.elements.realtimeInfo || !data) return;

        // แสดง realtime info
        this.elements.realtimeInfo.style.display = 'block';

        // อัปเดตค่าต่างๆ
        if (this.elements.currentAngle) {
            this.elements.currentAngle.textContent = data.currentAngle ? `${Math.round(data.currentAngle)}°` : '0°';
        }
        
        if (this.elements.currentAccuracy) {
            this.elements.currentAccuracy.textContent = data.accuracy ? `${Math.round(data.accuracy)}%` : '0%';
        }
        
        if (this.elements.repCount) {
            this.elements.repCount.textContent = data.reps || 0;
        }
        
        if (this.elements.movementPhase) {
            this.elements.movementPhase.textContent = data.phase || 'rest';
        }
    }

    // อัปเดตมุมแบบเรียลไทม์
    updateRealtimeAngles(angles) {
        if (!angles) return;

        // อัปเดตค่ามุมทั้งหมด
        this.updateAngleDisplay('leftShoulder', angles.leftShoulder, 180);
        this.updateAngleDisplay('rightShoulder', angles.rightShoulder, 180);
        this.updateAngleDisplay('leftElbow', angles.leftElbow, 180);
        this.updateAngleDisplay('rightElbow', angles.rightElbow, 180);
        this.updateAngleDisplay('leftKnee', angles.leftKnee, 180);
        this.updateAngleDisplay('rightKnee', angles.rightKnee, 180);
        this.updateAngleDisplay('neckTilt', angles.neckTilt, 45);
        this.updateAngleDisplay('trunkTilt', angles.trunkTilt, 30);
    }

    // อัปเดตการแสดงมุมแต่ละตัว
    updateAngleDisplay(joint, angle, maxAngle) {
        const angleElement = this.elements[`${joint}Angle`];
        const fillElement = this.elements[`${joint}Fill`];

        if (angleElement && fillElement) {
            // อัปเดตค่ามุม
            angleElement.textContent = `${Math.round(angle)}°`;

            // คำนวณเปอร์เซ็นต์
            const percentage = Math.min(100, (angle / maxAngle) * 100);
            fillElement.style.width = `${percentage}%`;

            // เปลี่ยนสีตามระดับ
            if (percentage > 80) {
                fillElement.style.backgroundColor = '#e74c3c'; // แดง
            } else if (percentage > 50) {
                fillElement.style.backgroundColor = '#f39c12'; // ส้ม
            } else if (percentage > 20) {
                fillElement.style.backgroundColor = '#2ecc71'; // เขียว
            } else {
                fillElement.style.backgroundColor = '#3498db'; // น้ำเงิน
            }

            // เอฟเฟกต์เมื่อมีการเปลี่ยนแปลงมาก
            const lastAngle = parseInt(angleElement.dataset.lastAngle) || 0;
            if (Math.abs(angle - lastAngle) > 10) {
                angleElement.classList.add('pulse-animation');
                setTimeout(() => {
                    angleElement.classList.remove('pulse-animation');
                }, 300);
            }
            
            angleElement.dataset.lastAngle = angle;
        }
    }

    // อัปเดตสถิติ
    updateStatistics(stats) {
        if (!stats) return;

        // จำนวนครั้ง
        if (this.elements.repCounter) {
            const newValue = stats.reps || 0;
            if (this.elements.repCounter.textContent !== newValue.toString()) {
                this.elements.repCounter.textContent = newValue;
                this.elements.repCounter.classList.add('bounce-animation');
                setTimeout(() => {
                    this.elements.repCounter.classList.remove('bounce-animation');
                }, 600);
            }
        }

        // ความแม่นยำ
        if (this.elements.accuracyValue && stats.accuracy !== undefined) {
            const accuracy = Math.round(stats.accuracy);
            this.elements.accuracyValue.textContent = `${accuracy}%`;
            
            // เปลี่ยนสีตามความแม่นยำ
            if (accuracy >= 90) {
                this.elements.accuracyValue.style.color = '#4CAF50';
            } else if (accuracy >= 70) {
                this.elements.accuracyValue.style.color = '#FF9800';
            } else {
                this.elements.accuracyValue.style.color = '#F44336';
            }
        }

        // คะแนน
        if (this.elements.scoreDisplay && stats.score !== undefined) {
            this.elements.scoreDisplay.textContent = Math.round(stats.score);
        }

        // แถบความคืบหน้า
        if (this.elements.progressFill && stats.reps !== undefined && stats.targetReps) {
            const progress = Math.min(100, (stats.reps / stats.targetReps) * 100);
            this.elements.progressFill.style.width = `${progress}%`;
        }
    }

    // อัปเดตตัวจับเวลา
    updateTimer(seconds) {
        if (this.elements.timerDisplay) {
            this.elements.timerDisplay.textContent = StrokeUtils.formatTime(seconds);
        }
    }

    // แสดงข้อความ feedback
    showFeedback(message, type = 'info') {
        if (!this.elements.feedbackText) return;

        this.elements.feedbackText.textContent = message;

        // ตั้งค่าสไตล์ตามประเภท
        const colors = StrokeConfig.COLORS;
        switch (type) {
            case 'success':
                this.elements.feedbackText.style.color = colors.SUCCESS;
                this.elements.feedbackText.style.backgroundColor = 'rgba(40, 167, 69, 0.1)';
                this.elements.feedbackText.style.borderColor = colors.SUCCESS;
                break;
            case 'warning':
                this.elements.feedbackText.style.color = colors.WARNING;
                this.elements.feedbackText.style.backgroundColor = 'rgba(255, 193, 7, 0.1)';
                this.elements.feedbackText.style.borderColor = colors.WARNING;
                break;
            case 'error':
                this.elements.feedbackText.style.color = colors.ERROR;
                this.elements.feedbackText.style.backgroundColor = 'rgba(220, 53, 69, 0.1)';
                this.elements.feedbackText.style.borderColor = colors.ERROR;
                break;
            default:
                this.elements.feedbackText.style.color = colors.INFO;
                this.elements.feedbackText.style.backgroundColor = 'rgba(23, 162, 184, 0.1)';
                this.elements.feedbackText.style.borderColor = colors.INFO;
        }

        // เอฟเฟกต์การแสดงผล
        this.elements.feedbackText.style.transform = 'scale(1.02)';
        setTimeout(() => {
            this.elements.feedbackText.style.transform = 'scale(1)';
        }, 200);

        // เล่นเสียงตามประเภท
        if (type === 'success') {
            StrokeUtils.playSuccessSound();
        } else if (type === 'error') {
            StrokeUtils.playErrorSound();
        }
    }

    // เปิด/ปิดการแสดงมุม
    toggleAngleDisplay() {
        if (!this.elements.angleGrid || !this.elements.toggleAngleBtn) return;

        const isVisible = this.elements.angleGrid.style.display !== 'none';
        
        if (isVisible) {
            this.elements.angleGrid.style.display = 'none';
            this.elements.toggleAngleBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
            this.elements.toggleAngleBtn.title = 'แสดงมุม';
        } else {
            this.elements.angleGrid.style.display = 'block';
            this.elements.toggleAngleBtn.innerHTML = '<i class="fas fa-eye"></i>';
            this.elements.toggleAngleBtn.title = 'ซ่อนมุม';
        }
    }

    // อัปเดตสถานะปุ่มเริ่ม
    updateStartButton(isEnabled, text = null, isActive = false) {
        if (!this.elements.startBtn) return;

        this.elements.startBtn.disabled = !isEnabled;
        
        if (text) {
            this.elements.startBtn.innerHTML = text;
        }

        if (isActive) {
            this.elements.startBtn.classList.add('btn-accent');
        } else {
            this.elements.startBtn.classList.remove('btn-accent');
        }
    }

    // เรียกใช้ปุ่มเริ่ม
    triggerStartButton() {
        if (this.elements.startBtn && !this.elements.startBtn.disabled) {
            this.elements.startBtn.click();
        }
    }

    // รีเซ็ตการออกกำลังกาย
    resetExercise() {
        if (confirm('ต้องการรีเซ็ตการฝึกหรือไม่?')) {
            // ส่งสัญญาณรีเซ็ต
            this.dispatchEvent('exercise-reset');
        }
    }

    // ถ่ายภาพหน้าจอ
    takeScreenshot() {
        this.dispatchEvent('screenshot-request');
    }

    // สลับเป็น layout มือถือ
    switchToMobileLayout() {
        document.body.classList.add('mobile-layout');
        
        // ซ่อนข้อมูลที่ไม่จำเป็นในมือถือ
        if (this.elements.realtimeInfo) {
            this.elements.realtimeInfo.style.display = 'none';
        }
    }

    // สลับเป็น layout เดสก์ท็อป
    switchToDesktopLayout() {
        document.body.classList.remove('mobile-layout');
    }

    // แสดงการแจ้งเตือน
    showNotification(title, message, type = 'info', duration = 5000) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        notification.innerHTML = `
            <div class="notification-header">
                <i class="fas fa-${this.getNotificationIcon(type)}"></i>
                <strong>${title}</strong>
                <button class="notification-close">&times;</button>
            </div>
            <div class="notification-body">${message}</div>
        `;

        // เพิ่ม CSS
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            padding: 16px;
            max-width: 300px;
            z-index: 1000;
            border-left: 4px solid ${this.getNotificationColor(type)};
            transform: translateX(100%);
            transition: transform 0.3s ease;
        `;

        document.body.appendChild(notification);

        // แอนิเมชันเข้า
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);

        // ปุ่มปิด
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.onclick = () => this.removeNotification(notification);

        // ปิดอัตโนมัติ
        setTimeout(() => this.removeNotification(notification), duration);

        // เก็บรายการแจ้งเตือน
        this.notifications.push(notification);
    }

    // ลบการแจ้งเตือน
    removeNotification(notification) {
        if (notification.parentElement) {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.parentElement.removeChild(notification);
                }
                // ลบออกจากรายการ
                const index = this.notifications.indexOf(notification);
                if (index > -1) {
                    this.notifications.splice(index, 1);
                }
            }, 300);
        }
    }

    // ได้ไอคอนสำหรับการแจ้งเตือน
    getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'warning': 'exclamation-triangle',
            'error': 'times-circle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    // ได้สีสำหรับการแจ้งเตือน
    getNotificationColor(type) {
        const colors = StrokeConfig.COLORS;
        return colors[type.toUpperCase()] || colors.INFO;
    }

    // ส่งอีเวนต์
    dispatchEvent(eventName, data = null) {
        const event = new CustomEvent(eventName, { detail: data });
        document.dispatchEvent(event);
    }

    // ล้างการแจ้งเตือนทั้งหมด
    clearNotifications() {
        this.notifications.forEach(notification => {
            this.removeNotification(notification);
        });
    }

    // ทำลายระบบ UI
    destroy() {
        this.clearNotifications();
        
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        
        // ล้าง event listeners
        document.removeEventListener('keydown', this.handleKeyboardShortcuts);
        window.removeEventListener('resize', this.handleResize);
    }
}

// ส่งออกคลาส
window.UIController = UIController;