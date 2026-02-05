const express = require('express');
const app = express();
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const hostname = '0.0.0.0';
const port = process.env.PORT || 4000;

app.use(cors({
    origin: '*',
    credentials: true
}));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = 'stroke_rehab_secret_key_2024';

const createConnection = async () => {
  const connection = await mysql.createConnection({
    host: 'gateway01.ap-northeast-1.prod.aws.tidbcloud.com',
    user: '3HZNLzyS4E2dJfG.root',
    password: '1CmpzXSMTQxYdngG',
    database: 'stroke_rehab_db',
    ssl: { minVersion: 'TLSv1.2' },
    timezone: '+07:00'
  });
  
  await connection.execute("SET time_zone = '+07:00'");
  await connection.execute("SET SESSION time_zone = '+07:00'");
  
  return connection;
};

// Middleware JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ 
      success: false, 
      message: 'ต้องระบุ Access token' 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('❌ Token verification failed:', err.message);
      return res.status(403).json({ 
        success: false, 
        message: 'Token ไม่ถูกต้อง' 
      });
    }
    
    if (user.user_id) {
      user.user_id = parseInt(user.user_id);
    }
    
    console.log('✅ Token verified:', { 
      user_id: user.user_id, 
      role: user.role 
    });
    
    req.user = user;
    next();
  });
};

// ทดสอบ DB
(async () => {
  try {
    const connection = await createConnection();
    console.log('✅ เชื่อมต่อฐานข้อมูลสำเร็จ');
    await connection.end();
  } catch (error) {
    console.error('❌ เชื่อมต่อฐานข้อมูลล้มเหลว:', error.message);
  }
})();

// Route พื้นฐาน
app.get('/', (req, res) => {
  res.json({ 
    message: 'เซิร์ฟเวอร์ระบบกายภาพบำบัดทำงานปกติ!', 
    timestamp: new Date().toISOString(), 
    version: '1.0.0' 
  });
});

app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    server: 'ระบบกายภาพบำบัดสำหรับผู้ป่วยหลังเส้นเลือดสมองแตก', 
    port 
  });
});

// ========================
// 1. สมัครสมาชิก
// ========================
app.post('/api/auth/register', async (req, res) => {
  const connection = await createConnection();
  
  try {
    console.log('🔍 Registration request received');
    
    const {
      phone,
      password,
      first_name,
      last_name,
      birth_date,
      gender,
      weight,
      height,
      injured_side,
      injured_part,
      emergency_contact_name,
      emergency_contact_phone,
      emergency_contact_relation
    } = req.body;

    // ตรวจสอบข้อมูลจำเป็น
    if (!phone || !password || !first_name || !last_name || !birth_date || !gender) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลที่จำเป็นให้ครบถ้วน'
      });
    }

    // ตรวจสอบรูปแบบเบอร์โทรศัพท์
    if (!/^[0-9]{10}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง (ต้องเป็นตัวเลข 10 หลัก)'
      });
    }

    // ตรวจสอบรหัสผ่าน
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
      });
    }

    // ตรวจสอบเบอร์โทรซ้ำ
    const [existingUsers] = await connection.execute(
      'SELECT user_id FROM Users WHERE phone = ?',
      [phone]
    );

    if (existingUsers.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว'
      });
    }

    await connection.beginTransaction();

    // เข้ารหัสรหัสผ่าน
    const password_hash = await bcrypt.hash(password, 12);
    const full_name = `${first_name} ${last_name}`;

    // เพิ่มข้อมูลใน Users
    const [userResult] = await connection.execute(
      'INSERT INTO Users (phone, password_hash, full_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
      [phone, password_hash, full_name, 'Patient']
    );

    const user_id = userResult.insertId;
    console.log(`✅ User created with ID: ${user_id}`);

    // เพิ่มข้อมูลผู้ป่วย
    await connection.execute(
      `INSERT INTO Patients (
        user_id, first_name, last_name, birth_date, gender, weight, height, 
        patient_phone, injured_side, injured_part, emergency_contact_name, 
        emergency_contact_phone, emergency_contact_relation
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user_id,
        first_name.substring(0, 50),
        last_name.substring(0, 50),
        birth_date,
        gender.substring(0, 10),
        weight ? parseFloat(weight) : null,
        height ? parseFloat(height) : null,
        phone,
        injured_side || 'Left',
        injured_part || 'Other',
        emergency_contact_name || null,
        emergency_contact_phone || null,
        emergency_contact_relation || null
      ]
    );

    await connection.commit();

    // สร้าง JWT Token
    const token = jwt.sign(
      { 
        user_id: parseInt(user_id),
        phone: phone, 
        role: 'Patient'
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('🎉 Registration completed successfully for:', phone);

    res.status(201).json({
      success: true,
      message: 'ลงทะเบียนสำเร็จ',
      user: {
        user_id: user_id,
        phone: phone,
        full_name: full_name,
        role: 'Patient'
      },
      token: token
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Registration error:', error);
    
    let errorMessage = 'เกิดข้อผิดพลาดในการลงทะเบียน';
    
    if (error.code === 'ER_DUP_ENTRY') {
      errorMessage = 'เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว';
    }
    
    res.status(500).json({
      success: false,
      message: errorMessage,
      error_code: error.code
    });

  } finally {
    await connection.end();
  }
});

// ========================
// 2. เข้าสู่ระบบ
// ========================
app.post('/api/auth/login', async (req, res) => {
  let connection;
  
  try {
    const { phone, password } = req.body;
    
    console.log('🔍 Login attempt:', { phone, hasPassword: !!password });
    
    if (!phone || !password) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกเบอร์โทรศัพท์และรหัสผ่าน'
      });
    }

    if (!/^[0-9]{10}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง (ต้องเป็นตัวเลข 10 หลัก)'
      });
    }

    connection = await createConnection();
    
    const [users] = await connection.execute(
      'SELECT user_id, phone, password_hash, full_name, role FROM Users WHERE phone = ?',
      [phone]
    );

    if (users.length === 0) {
      await connection.end();
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (!passwordMatch) {
      await connection.end();
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const token = jwt.sign(
      { 
        user_id: parseInt(user.user_id),
        phone: user.phone,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    await connection.execute(
      'INSERT INTO Login_History (user_id, login_time, ip_address, status) VALUES (?, NOW(), ?, ?)',
      [user.user_id, req.ip, 'Success']
    );

    console.log('✅ Login successful for:', phone);

    res.json({
      success: true,
      message: 'เข้าสู่ระบบสำเร็จ',
      user: {
        user_id: user.user_id,
        phone: user.phone,
        full_name: user.full_name,
        role: user.role
      },
      token: token
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// 3. ดูข้อมูลโปรไฟล์
// ========================
app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const requestedUserId = parseInt(req.params.userId);
    const authUserId = req.user.user_id;

    if (requestedUserId !== authUserId) {
      return res.status(403).json({
        success: false,
        message: 'คุณไม่มีสิทธิ์เข้าถึงข้อมูลนี้'
      });
    }

    connection = await createConnection();

    const [users] = await connection.execute(
      'SELECT user_id, phone, full_name, role, created_at, updated_at FROM Users WHERE user_id = ?',
      [requestedUserId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }

    const user = users[0];
    const responseData = { ...user };

    if (user.role === 'Patient' || user.role === 'ผู้ป่วย') {
      const [patients] = await connection.execute(
        `SELECT 
          first_name, last_name, birth_date, gender, weight, height,
          patient_phone, injured_side, injured_part,
          emergency_contact_name, emergency_contact_phone, emergency_contact_relation
        FROM Patients WHERE user_id = ?`,
        [requestedUserId]
      );

      if (patients.length > 0) {
        responseData.patient_info = patients[0];
      }
    }

    console.log('✅ User profile retrieved for:', requestedUserId);

    res.json({
      success: true,
      data: responseData
    });

  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// 4. อัพเดทโปรไฟล์
// ========================
app.put('/api/users/:userId', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const requestedUserId = parseInt(req.params.userId);
    const authUserId = req.user.user_id;

    if (requestedUserId !== authUserId) {
      return res.status(403).json({
        success: false,
        message: 'คุณไม่มีสิทธิ์แก้ไขข้อมูลนี้'
      });
    }

    connection = await createConnection();
    await connection.beginTransaction();

    const { full_name, patient_info } = req.body;

    if (full_name) {
      await connection.execute(
        'UPDATE Users SET full_name = ?, updated_at = NOW() WHERE user_id = ?',
        [full_name, requestedUserId]
      );
    }

    if (patient_info) {
      const {
        first_name, last_name, birth_date, gender, weight, height,
        injured_side, injured_part,
        emergency_contact_name, emergency_contact_phone, emergency_contact_relation
      } = patient_info;

      await connection.execute(
        `UPDATE Patients SET
          first_name = COALESCE(?, first_name),
          last_name = COALESCE(?, last_name),
          birth_date = COALESCE(?, birth_date),
          gender = COALESCE(?, gender),
          weight = COALESCE(?, weight),
          height = COALESCE(?, height),
          injured_side = COALESCE(?, injured_side),
          injured_part = COALESCE(?, injured_part),
          emergency_contact_name = COALESCE(?, emergency_contact_name),
          emergency_contact_phone = COALESCE(?, emergency_contact_phone),
          emergency_contact_relation = COALESCE(?, emergency_contact_relation)
        WHERE user_id = ?`,
        [
          first_name, last_name, birth_date, gender, weight, height,
          injured_side, injured_part,
          emergency_contact_name, emergency_contact_phone, emergency_contact_relation,
          requestedUserId
        ]
      );
    }

    await connection.commit();

    console.log('✅ Profile updated for:', requestedUserId);

    res.json({
      success: true,
      message: 'อัพเดทข้อมูลสำเร็จ'
    });

  } catch (error) {
    if (connection) await connection.rollback();
    console.error('❌ Update error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการอัพเดทข้อมูล',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// 5. ดูรายการท่าออกกำลังกาย
// ========================
app.get('/api/exercises', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    connection = await createConnection();

    const [exercises] = await connection.execute(
      `SELECT 
        exercise_id, name_th, name_en, description,
        angle_range, hold_time, repetitions, sets, rest_time
      FROM Exercises
      ORDER BY exercise_id`
    );

    console.log(`✅ Retrieved ${exercises.length} exercises`);

    res.json({
      success: true,
      data: exercises,
      count: exercises.length
    });

  } catch (error) {
    console.error('❌ Error exercises:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// 6. บันทึกการฝึก
// ========================
app.post('/api/exercise-sessions', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const userId = req.user.user_id;
    const {
      exercise_name,
      exercise_type,
      left_count = 0,
      right_count = 0,
      total_reps,
      accuracy = 0,
      session_duration = 0
    } = req.body;
    
    console.log('📝 บันทึกการฝึก:', {
      userId,
      exercise_name,
      left_count,
      right_count,
      total_reps,
      accuracy
    });
    
    connection = await createConnection();
    
    const actual_reps = total_reps || (parseInt(left_count) + parseInt(right_count));
    
    // ตรวจสอบ Treatment_Plans
    let plan_id = null;
    try {
      const [existingPlans] = await connection.execute(
        `SELECT plan_id FROM Treatment_Plans 
         WHERE patient_id = ? AND status = 'Active' 
         ORDER BY plan_id DESC LIMIT 1`,
        [userId]
      );
      
      if (existingPlans.length > 0) {
        plan_id = existingPlans[0].plan_id;
        console.log('✅ ใช้ plan_id:', plan_id);
      } else {
        // สร้าง plan ใหม่
        const [newPlan] = await connection.execute(
          `INSERT INTO Treatment_Plans (
            patient_id, 
            therapist_id, 
            plan_name, 
            start_date
          ) VALUES (?, 1, 'แผนการฟื้นฟูอัตโนมัติ', CURRENT_DATE)`,
          [userId]
        );
        plan_id = newPlan.insertId;
        console.log('✅ สร้าง plan_id ใหม่:', plan_id);
      }
    } catch (planError) {
      // ถ้าตาราง Treatment_Plans ไม่มี ให้ใช้ค่า default
      console.log('⚠️ ใช้ plan_id = 1 (default)');
      plan_id = 1;
    }
    
    // ✅ บันทึกข้อมูล
    const [result] = await connection.execute(
      `INSERT INTO Exercise_Sessions (
        patient_id,
        plan_id,
        exercise_id,
        session_date,
        actual_reps_left,
        actual_reps_right,
        actual_reps,
        actual_sets,
        accuracy_percent,
        duration_seconds,
        notes
      ) VALUES (?, ?, NULL, NOW(), ?, ?, ?, 1, ?, ?, ?)`,
      [
        userId,
        plan_id,
        left_count,
        right_count,
        actual_reps,
        accuracy,
        session_duration,
        `${exercise_name} (${exercise_type})`
      ]
    );
    
    console.log('✅ บันทึกสำเร็จ session_id:', result.insertId);
    
    res.status(201).json({
      success: true,
      message: 'บันทึกข้อมูลการฝึกสำเร็จ',
      data: {
        session_id: result.insertId,
        patient_id: userId,
        exercise_name: exercise_name,
        actual_reps: actual_reps,
        left_count: left_count,
        right_count: right_count
      }
    });
    
  } catch (error) {
    console.error('❌ Error saving session:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// 7. ดูประวัติการฝึก (✅ แก้ไขแล้ว)
// ========================
app.get('/api/exercise-sessions', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    console.log('✅ Token verified:', { user_id: req.user.user_id, role: req.user.role });
    
    const userId = req.user.user_id;
    
    // ✅ แปลงและกำหนดค่า default
    const limit = parseInt(req.query.limit, 10) || 100;
    const offset = parseInt(req.query.offset, 10) || 0;
    const period = req.query.period || '7days';
    
    console.log('📊 ดึงข้อมูลของ user_id:', userId);
    console.log('📋 Parameters:', { limit, offset, period });
    
    // ✅ Validate parameters
    if (isNaN(limit) || isNaN(offset)) {
      return res.status(400).json({
        success: false,
        message: 'limit และ offset ต้องเป็นตัวเลข',
        received: { limit: req.query.limit, offset: req.query.offset }
      });
    }
    
    if (limit < 1 || limit > 1000) {
      return res.status(400).json({
        success: false,
        message: 'limit ต้องอยู่ระหว่าง 1-1000'
      });
    }
    
    // ✅ สร้าง connection
    connection = await createConnection();
    
    // คำนวณ date filter
    let dateCondition = '';
    if (period === '7days') {
      dateCondition = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
    } else if (period === '30days') {
      dateCondition = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    } else if (period === '90days') {
      dateCondition = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 90 DAY)';
    }
    
    // ✅ SQL Query
    const query = `
      SELECT 
        es.session_id,
        es.patient_id,
        es.plan_id,
        es.exercise_id,
        es.session_date,
        es.actual_reps_left,
        es.actual_reps_right,
        es.actual_reps,
        es.actual_sets,
        es.accuracy_percent,
        es.duration_seconds,
        es.notes,
        es.completed,
        es.created_at,
        e.name_th as exercise_name_th,
        e.name_en as exercise_name_en,
        e.description,
        COALESCE(e.name_th, SUBSTRING_INDEX(es.notes, ' (', 1), 'ท่ากายภาพ') as exercise_name
      FROM Exercise_Sessions es
      LEFT JOIN Exercises e ON es.exercise_id = e.exercise_id
      WHERE es.patient_id = ?
      ${dateCondition}
      ORDER BY es.session_date DESC, es.session_id DESC
      LIMIT ? OFFSET ?
    `;
    
    console.log('📝 Executing query with params:', [userId, limit, offset]);
    
    // ✅ Execute query with connection (แก้จาก pool.execute)
    const [rows] = await connection.execute(query, [userId, limit, offset]);
    
    console.log(`✅ ดึงข้อมูลสำเร็จ: ${rows.length} sessions`);
    
    res.json({
      success: true,
      data: rows,
      count: rows.length,
      period: period,
      limit: limit,
      offset: offset,
      message: 'ดึงข้อมูลสำเร็จ'
    });
    
  } catch (error) {
    console.error('❌ Error fetching sessions:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error : undefined
    });
  } finally {
    // ✅ ปิด connection เสมอ
    if (connection) {
      await connection.end();
    }
  }
});

// ========================
// 8. ดูสถิติการฝึก
// ========================
app.get('/api/exercise-stats', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const userId = req.user.user_id;
    const { period = '7days' } = req.query;
    
    console.log('📈 ดึงสถิติของ user_id:', userId);
    
    connection = await createConnection();
    
    let dateFilter = '';
    if (period === '7days') {
      dateFilter = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
    } else if (period === '30days') {
      dateFilter = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    }
    
    const [stats] = await connection.execute(
      `SELECT 
        COUNT(*) as total_sessions,
        SUM(actual_reps) as total_reps,
        SUM(actual_reps_left) as total_left_reps,
        SUM(actual_reps_right) as total_right_reps,
        AVG(accuracy_percent) as avg_accuracy,
        SUM(duration_seconds) as total_duration
      FROM Exercise_Sessions
      WHERE patient_id = ? ${dateFilter}`,
      [userId]
    );
    
    const [byExercise] = await connection.execute(
      `SELECT 
        SUBSTRING_INDEX(notes, ' (', 1) as exercise_name,
        COUNT(*) as session_count,
        SUM(actual_reps) as total_reps,
        AVG(accuracy_percent) as avg_accuracy
      FROM Exercise_Sessions
      WHERE patient_id = ? ${dateFilter}
      GROUP BY SUBSTRING_INDEX(notes, ' (', 1)
      ORDER BY session_count DESC`,
      [userId]
    );
    
    const [dailyStats] = await connection.execute(
      `SELECT 
        DATE(session_date) as exercise_date,
        COUNT(*) as session_count,
        SUM(actual_reps) as total_reps,
        AVG(accuracy_percent) as avg_accuracy
      FROM Exercise_Sessions
      WHERE patient_id = ?
      AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY DATE(session_date)
      ORDER BY exercise_date DESC`,
      [userId]
    );
    
    console.log('✅ ดึงสถิติสำเร็จ');
    
    res.json({
      success: true,
      message: 'ดึงสถิติสำเร็จ',
      data: {
        summary: stats[0],
        by_exercise: byExercise,
        daily: dailyStats,
        period: period
      }
    });
    
  } catch (error) {
    console.error('❌ Error stats:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงสถิติ',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// จัดการข้อผิดพลาด
// ========================
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: 'ไม่พบเส้นทาง API ที่ระบุ',
    path: req.originalUrl
  });
});

app.use((error, req, res, next) => {
  console.error('ข้อผิดพลาดของเซิร์ฟเวอร์:', error);
  res.status(500).json({
    success: false,
    message: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์'
  });
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
});
