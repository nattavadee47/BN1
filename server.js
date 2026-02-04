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
      'SELECT user_id, phone, password_hash, full_name, role FROM Users WHERE phone = ? AND role = ?',
      [phone, 'Patient']
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const user = users[0];
    
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
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

    console.log('✅ Login successful:', { 
      phone: user.phone, 
      user_id: user.user_id 
    });

    res.json({
      success: true,
      message: 'เข้าสู่ระบบสำเร็จ',
      user: {
        user_id: parseInt(user.user_id),
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
      message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
    });
  } finally {
    if (connection) {
      await connection.end();
    }
  }
});

// ========================
// 3. ออกจากระบบ
// ========================
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'ออกจากระบบสำเร็จ'
  });
});

// ========================
// 4. ดูโปรไฟล์ของตนเอง
// ========================
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const userId = parseInt(req.params.id);
  
  try {
    // ตรวจสอบว่าเป็นข้อมูลของตนเอง
    if (parseInt(req.user.user_id) !== userId) {
      return res.status(403).json({ 
        success: false, 
        message: 'ไม่มีสิทธิ์เข้าถึง' 
      });
    }

    const [users] = await connection.execute(
      'SELECT user_id, phone, full_name, role, created_at FROM Users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }

    const user = users[0];

    // ดึงข้อมูลผู้ป่วย
    const [patients] = await connection.execute(
      'SELECT * FROM Patients WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      data: {
        ...user,
        patient_info: patients[0] || null
      }
    });

  } catch (error) {
    console.error('Error loading profile:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลโปรไฟล์'
    });
  } finally {
    await connection.end();
  }
});

// ========================
// 5. แก้ไขข้อมูลส่วนตัว
// ========================
app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const userId = parseInt(req.params.id);
  
  try {
    // ตรวจสอบว่าเป็นข้อมูลของตนเอง
    if (parseInt(req.user.user_id) !== userId) {
      return res.status(403).json({ 
        success: false, 
        message: 'ไม่มีสิทธิ์เข้าถึง' 
      });
    }

    const {
      full_name, first_name, last_name, birth_date, gender, weight, height,
      injured_side, injured_part, emergency_contact_name,
      emergency_contact_phone, emergency_contact_relation
    } = req.body;

    // ✅ เพิ่ม debug log
    console.log('📝 Update request for user:', userId);
    console.log('📊 Received data:', {
      first_name, last_name, gender, weight, height,
      injured_side, injured_part, birth_date
    });

    await connection.beginTransaction();

    // อัพเดท Users
    if (full_name || (first_name && last_name)) {
      const nameToUpdate = full_name || `${first_name} ${last_name}`;
      await connection.execute(
        'UPDATE Users SET full_name = ?, updated_at = NOW() WHERE user_id = ?',
        [nameToUpdate, userId]
      );
      console.log('✅ Updated Users table');
    }

    // อัพเดท Patients
    const updates = [];
    const values = [];

    // ✅ ตรวจสอบและเพิ่มฟิลด์ที่จำเป็น
    if (first_name !== undefined && first_name.trim() !== '') { 
      updates.push('first_name = ?'); 
      values.push(first_name.substring(0, 50)); 
    }
    
    if (last_name !== undefined && last_name.trim() !== '') { 
      updates.push('last_name = ?'); 
      values.push(last_name.substring(0, 50)); 
    }
    
    if (birth_date !== undefined && birth_date.trim() !== '') { 
      updates.push('birth_date = ?'); 
      values.push(birth_date); 
    }
    
    // ✅ แก้ไขการตรวจสอบ gender
    if (gender !== undefined && gender.trim() !== '') { 
      const validGenders = ['ชาย', 'หญิง', 'อื่นๆ', 'Male', 'Female', 'Other'];
      if (validGenders.includes(gender)) {
        updates.push('gender = ?'); 
        values.push(gender); 
      } else {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: `เพศไม่ถูกต้อง: ${gender}. ต้องเป็น: ชาย, หญิง, หรือ อื่นๆ`
        });
      }
    }
    
    // ✅ แก้ไขการจัดการ weight และ height
    if (weight !== undefined) { 
      const weightNum = parseFloat(weight);
      if (!isNaN(weightNum) && weightNum > 0) {
        updates.push('weight = ?'); 
        values.push(Math.min(999.99, Math.max(0.01, weightNum))); 
      } else if (weight === '' || weight === null) {
        updates.push('weight = ?');
        values.push(null);
      }
    }
    
    if (height !== undefined) { 
      const heightNum = parseFloat(height);
      if (!isNaN(heightNum) && heightNum > 0) {
        updates.push('height = ?'); 
        values.push(Math.min(999.99, Math.max(0.01, heightNum))); 
      } else if (height === '' || height === null) {
        updates.push('height = ?');
        values.push(null);
      }
    }
    
    // ✅ แก้ไขการตรวจสอบ injured_side
    if (injured_side !== undefined && injured_side.trim() !== '') {
      const validSides = ['ซ้าย', 'ขวา', 'ทั้งสองข้าง', 'Left', 'Right', 'Both'];
      if (validSides.includes(injured_side)) {
        updates.push('injured_side = ?'); 
        values.push(injured_side); 
      } else {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: `ด้านที่บาดเจ็บไม่ถูกต้อง: ${injured_side}. ต้องเป็น: ซ้าย, ขวา, หรือ ทั้งสองข้าง`
        });
      }
    }
    
    // ✅ แก้ไขการตรวจสอบ injured_part
    if (injured_part !== undefined && injured_part.trim() !== '') {
      const validParts = ['แขน', 'ขา', 'ลำตัว', 'หัว', 'อื่นๆ', 'Arm', 'Leg', 'Trunk', 'Head', 'Other'];
      if (validParts.includes(injured_part)) {
        updates.push('injured_part = ?'); 
        values.push(injured_part); 
      } else {
        await connection.rollback();
        return res.status(400).json({
          success: false,
          message: `ส่วนที่บาดเจ็บไม่ถูกต้อง: ${injured_part}. ต้องเป็น: แขน, ขา, ลำตัว, หัว, หรือ อื่นๆ`
        });
      }
    }
    
    if (emergency_contact_name !== undefined) { 
      updates.push('emergency_contact_name = ?'); 
      values.push(emergency_contact_name && emergency_contact_name.trim() !== '' ? emergency_contact_name.substring(0, 100) : null); 
    }
    
    if (emergency_contact_phone !== undefined) { 
      if (emergency_contact_phone && emergency_contact_phone.trim() !== '') {
        const cleanPhone = emergency_contact_phone.replace(/\D/g, '').substring(0, 10); // ✅ ตัดที่ 10 ตัว
        if (/^\d{10}$/.test(cleanPhone)) {
          updates.push('emergency_contact_phone = ?'); 
          values.push(cleanPhone); 
        } else {
          await connection.rollback();
          return res.status(400).json({
            success: false,
            message: 'เบอร์โทรศัพท์ผู้ติดต่อฉุกเฉินไม่ถูกต้อง (ต้องเป็นตัวเลข 10 หลัก)'
          });
        }
      } else {
        updates.push('emergency_contact_phone = ?'); 
        values.push(null); 
      }
    }
    
    if (emergency_contact_relation !== undefined) { 
      updates.push('emergency_contact_relation = ?'); 
      values.push(emergency_contact_relation && emergency_contact_relation.trim() !== '' ? emergency_contact_relation.substring(0, 50) : null); 
    }

    // ✅ เพิ่มการตรวจสอบก่อน execute
    if (updates.length > 0) {
      values.push(userId);
      const updateQuery = `UPDATE Patients SET ${updates.join(', ')} WHERE user_id = ?`;
      
      console.log('📝 Update query:', updateQuery);
      console.log('📊 Update values:', values);
      
      try {
        await connection.execute(updateQuery, values);
        console.log('✅ Updated Patients table successfully');
      } catch (updateError) {
        console.error('❌ Update query failed:', updateError);
        await connection.rollback();
        return res.status(500).json({
          success: false,
          message: 'เกิดข้อผิดพลาดในการอัพเดทข้อมูล: ' + updateError.message
        });
      }
    } else {
      console.log('⚠️ No fields to update');
    }

    await connection.commit();
    console.log('✅ Transaction committed');

    res.json({
      success: true,
      message: 'อัพเดทข้อมูลสำเร็จ'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Profile update error:', error);
    
    // ✅ ส่งข้อความ error ที่ละเอียด
    let errorMessage = 'เกิดข้อผิดพลาดในการอัพเดทข้อมูล';
    
    if (error.code === 'ER_BAD_NULL_ERROR') {
      errorMessage = 'ข้อมูลที่จำเป็นไม่ครบถ้วน';
    } else if (error.code === 'ER_DATA_TOO_LONG') {
      errorMessage = 'ข้อมูลยาวเกินไป';
    } else if (error.message && error.message.includes('Data truncated')) {
      errorMessage = 'รูปแบบข้อมูลไม่ถูกต้อง';
    }
    
    res.status(500).json({
      success: false,
      message: errorMessage,
      error_code: error.code,
      error_detail: error.message // ✅ เพิ่มเพื่อ debug
    });
  } finally {
    await connection.end();
  }
});

// ========================
// 6. บันทึกผลการฝึก
// ========================
app.post('/api/exercise-sessions', authenticateToken, async (req, res) => {
    const connection = await createConnection();

    try {
        const {
            exercise_type,
            exercise_name,
            actual_reps_left,
            actual_reps_right,
            accuracy_percent,
            duration_seconds,
            notes
        } = req.body;

        const total_reps = (parseInt(actual_reps_left) || 0) + (parseInt(actual_reps_right) || 0);

        // หา patient_id
        const [patients] = await connection.execute(
            'SELECT patient_id FROM Patients WHERE user_id = ?',
            [req.user.user_id]
        );

        if (patients.length === 0) {
            return res.status(404).json({ 
                success: false, 
                message: 'ไม่พบข้อมูลผู้ป่วย' 
            });
        }
        const patientId = patients[0].patient_id;

        // หา/สร้าง Exercise
        let exerciseId = null;
        const [existingExercises] = await connection.execute(
            'SELECT exercise_id FROM Exercises WHERE name_en = ?',
            [exercise_type]
        );

        if (existingExercises.length > 0) {
            exerciseId = existingExercises[0].exercise_id;
        } else {
            const [exerciseResult] = await connection.execute(
                `INSERT INTO Exercises (name_th, name_en, description) VALUES (?, ?, ?)`,
                [exercise_name, exercise_type, `การออกกำลังกาย: ${exercise_name}`]
            );
            exerciseId = exerciseResult.insertId;
        }

        // หา/สร้าง Plan
        const [physios] = await connection.execute(
            'SELECT physio_id FROM Physiotherapists LIMIT 1'
        );
        
        if (physios.length === 0) {
            return res.status(500).json({ 
                success: false, 
                message: 'ไม่พบนักกายภาพบำบัด' 
            });
        }

        let planId = null;
        const [existingPlans] = await connection.execute(
            `SELECT plan_id FROM ExercisePlans 
             WHERE patient_id = ? AND (end_date IS NULL OR end_date >= CURDATE())
             LIMIT 1`,
            [patientId]
        );

        if (existingPlans.length > 0) {
            planId = existingPlans[0].plan_id;
        } else {
            const [planResult] = await connection.execute(
                `INSERT INTO ExercisePlans 
                 (patient_id, physio_id, plan_name, start_date, end_date) 
                 VALUES (?, ?, ?, CURDATE(), DATE_ADD(CURDATE(), INTERVAL 30 DAY))`,
                [patientId, physios[0].physio_id, 'แผนการฝึกอัตโนมัติ']
            );
            planId = planResult.insertId;
        }

        // บันทึก Session
        const [sessionResult] = await connection.execute(
            `INSERT INTO Exercise_Sessions 
            (patient_id, plan_id, exercise_id, session_date, 
              actual_reps, actual_reps_left, actual_reps_right,
              actual_sets, accuracy_percent, duration_seconds, notes) 
            VALUES (?, ?, ?, NOW(), ?, ?, ?, 1, ?, ?, ?)`,
            [
                patientId,
                planId,
                exerciseId,
                total_reps,
                parseInt(actual_reps_left) || 0,
                parseInt(actual_reps_right) || 0,
                parseFloat(accuracy_percent) || 0,
                parseInt(duration_seconds) || 0,
                notes || ''
            ]
        );

        console.log('✅ Session saved:', {
            session_id: sessionResult.insertId,
            left: actual_reps_left,
            right: actual_reps_right,
            total: total_reps
        });

        res.status(201).json({
            success: true,
            message: 'บันทึกสำเร็จ',
            data: {
                session_id: sessionResult.insertId,
                actual_reps_left: parseInt(actual_reps_left) || 0,
                actual_reps_right: parseInt(actual_reps_right) || 0,
                total: total_reps,
                accuracy_percent: parseFloat(accuracy_percent) || 0,
                duration_seconds: parseInt(duration_seconds) || 0
            }
        });

    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'เกิดข้อผิดพลาด'
        });
    } finally {
        if (connection) await connection.end();
    }
});

// ========================
// 7. ดูประวัติการฝึก
// ========================
app.get('/api/exercise-sessions', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [patients] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (patients.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'ไม่พบข้อมูลผู้ป่วย' 
      });
    }
    
    const patientId = patients[0].patient_id;

    const [sessions] = await connection.execute(`
      SELECT 
          es.session_id,
          es.session_date,
          es.actual_reps,
          es.actual_reps_left,
          es.actual_reps_right,
          es.accuracy_percent,
          es.duration_seconds,
          es.notes,
          e.name_th as exercise_name_th,
          e.name_en as exercise_name_en
      FROM Exercise_Sessions es
      JOIN Exercises e ON es.exercise_id = e.exercise_id
      WHERE es.patient_id = ?
      ORDER BY es.session_date DESC
      LIMIT 50
    `, [patientId]);

    res.json({
      success: true,
      data: sessions,
      total: sessions.length
    });

  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'เกิดข้อผิดพลาด' 
    });
  } finally {
    await connection.end();
  }
});

// ========================
// 8. ดูสถิติการฝึก
// ========================
app.get('/api/exercise-stats', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [patients] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (patients.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ป่วย'
      });
    }
    
    const patientId = patients[0].patient_id;

    // สถิติรวม
    const [totalStats] = await connection.execute(`
      SELECT 
        COUNT(*) as total_sessions,
        AVG(accuracy_percent) as avg_accuracy,
        SUM(actual_reps) as total_reps,
        MAX(accuracy_percent) as best_accuracy,
        MIN(session_date) as first_session,
        MAX(session_date) as last_session
      FROM Exercise_Sessions 
      WHERE patient_id = ?
    `, [patientId]);

    // สถิติ 7 วันล่าสุด
    const [weeklyStats] = await connection.execute(`
      SELECT 
        DATE(session_date) as session_date,
        COUNT(*) as sessions_count,
        AVG(accuracy_percent) as avg_accuracy,
        SUM(actual_reps) as total_reps
      FROM Exercise_Sessions 
      WHERE patient_id = ? AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY DATE(session_date)
      ORDER BY session_date DESC
    `, [patientId]);

    // แบบฝึกยอดนิยม
    const [popularExercises] = await connection.execute(`
      SELECT 
        e.name_th,
        e.name_en,
        COUNT(*) as session_count,
        AVG(es.accuracy_percent) as avg_accuracy
      FROM Exercise_Sessions es
      JOIN Exercises e ON es.exercise_id = e.exercise_id
      WHERE es.patient_id = ?
      GROUP BY es.exercise_id, e.name_th, e.name_en
      ORDER BY session_count DESC
      LIMIT 5
    `, [patientId]);

    res.json({
      success: true,
      data: {
        total_stats: totalStats[0],
        weekly_progress: weeklyStats,
        popular_exercises: popularExercises
      }
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงสถิติ:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงสถิติการออกกำลังกาย'
    });
  } finally {
    await connection.end();
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

app.listen(port, '0.0.0.0', () => { // ✅ ถูกต้องแล้ว
    console.log(`Server running on port ${port}`);
});
