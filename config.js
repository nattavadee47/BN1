// ========================================
// ไฟล์การตั้งค่าระบบกายภาพบำบัด
// config.js
// ========================================

// การตั้งค่าหลักของระบบ
const StrokeConfig = {
    // การตั้งค่า MediaPipe
    CONFIG: {
        MEDIAPIPE: {
            MODEL_COMPLEXITY: 1,
            SMOOTH_LANDMARKS: true,
            ENABLE_SEGMENTATION: false,
            MIN_DETECTION_CONFIDENCE: 0.5,
            MIN_TRACKING_CONFIDENCE: 0.5,
            SELFIE_MODE: true
        },
        
        CAMERA: {
            WIDTH: 640,
            HEIGHT: 480,
            FACING_MODE: 'user'
        },
        
        CANVAS: {
            CONNECTION_COLOR: '#00FF00',
            LANDMARK_COLOR: '#FF0000',
            HIGHLIGHT_COLOR: '#FFFF00',
            LINE_WIDTH: 2,
            LANDMARK_RADIUS: 3
        }
    },

    // สีที่ใช้ในระบบ
    COLORS: {
        SUCCESS: '#28a745',
        WARNING: '#ffc107',
        ERROR: '#dc3545',
        INFO: '#17a2b8',
        PRIMARY: '#007bff',
        SECONDARY: '#6c757d'
    },

    // ตำแหน่งของ Pose landmarks
    POSE_LANDMARKS: {
        NOSE: 0,
        LEFT_EYE_INNER: 1,
        LEFT_EYE: 2,
        LEFT_EYE_OUTER: 3,
        RIGHT_EYE_INNER: 4,
        RIGHT_EYE: 5,
        RIGHT_EYE_OUTER: 6,
        LEFT_EAR: 7,
        RIGHT_EAR: 8,
        MOUTH_LEFT: 9,
        MOUTH_RIGHT: 10,
        LEFT_SHOULDER: 11,
        RIGHT_SHOULDER: 12,
        LEFT_ELBOW: 13,
        RIGHT_ELBOW: 14,
        LEFT_WRIST: 15,
        RIGHT_WRIST: 16,
        LEFT_PINKY: 17,
        RIGHT_PINKY: 18,
        LEFT_INDEX: 19,
        RIGHT_INDEX: 20,
        LEFT_THUMB: 21,
        RIGHT_THUMB: 22,
        LEFT_HIP: 23,
        RIGHT_HIP: 24,
        LEFT_KNEE: 25,
        RIGHT_KNEE: 26,
        LEFT_ANKLE: 27,
        RIGHT_ANKLE: 28,
        LEFT_HEEL: 29,
        RIGHT_HEEL: 30,
        LEFT_FOOT_INDEX: 31,
        RIGHT_FOOT_INDEX: 32
    },

    // ข้อมูลการออกกำลังกาย
    EXERCISE_DATA: {
        'arm-raise-forward': {
            name: 'ยกแขนไปข้างหน้า',
            description: 'ยกแขนทั้งสองข้างไปข้างหน้าสลับกัน',
            landmarks: [11, 12, 13, 14, 15, 16], // ไหล่, ศอก, ข้อมือ
            targetReps: 10,
            targetSets: 2,
            targetAngleRange: [0, 90],
            primaryJoints: ['shoulder', 'elbow'],
            difficulty: 'easy'
        },
        'leg-forward': {
            name: 'เหยียดเข่าตรง',
            description: 'เหยียดเข่าให้ตรงจากท่านั่ง',
            landmarks: [23, 24, 25, 26, 27, 28], // สะโพก, เข่า, ข้อเท้า
            targetReps: 10,
            targetSets: 2,
            targetAngleRange: [90, 170],
            primaryJoints: ['knee', 'hip'],
            difficulty: 'medium'
        },
        'trunk-sway': {
            name: 'โยกลำตัวซ้าย-ขวา',
            description: 'โยกลำตัวไปทางซ้ายและขวาสลับกัน',
            landmarks: [11, 12, 23, 24], // ไหล่, สะโพก
            targetReps: 10,
            targetSets: 2,
            targetAngleRange: [0, 30],
            primaryJoints: ['trunk'],
            difficulty: 'easy'
        },
        'neck-tilt': {
            name: 'เอียงศีรษะซ้าย-ขวา',
            description: 'เอียงศีรษะไปทางซ้ายและขวาสลับกัน',
            landmarks: [7, 8], // หู
            targetReps: 10,
            targetSets: 2,
            targetAngleRange: [0, 30],
            primaryJoints: ['neck'],
            difficulty: 'easy'
        }
    },

    // การตั้งค่า API (ถ้ามี)
    API_CONFIG: {
        BASE_URL: 'https://api.stroketherapy.com/v1',
        TIMEOUT: 30000,
        HEADERS: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        ENDPOINTS: {
            CREATE_SESSION: '/sessions',
            UPDATE_SESSION: '/sessions',
            COMPLETE_SESSION: '/sessions/complete',
            POSE_ANGLES: '/data/pose-angles',
            POSE_LANDMARKS: '/data/pose-landmarks',
            SAVE_ANALYSIS: '/data/movement-analysis',
            SAVE_PROGRESS: '/progress',
            PROGRESS: '/progress',
            EXERCISES: '/exercises',
            EXERCISE_BY_ID: '/exercises'
        }
    }
};

// ส่งออกเป็น global variable
window.StrokeConfig = StrokeConfig;
console.log('✅ config.js โหลดเรียบร้อยแล้ว');