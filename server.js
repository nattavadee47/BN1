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
    
    // ตรวจสอบรหัสผ่าน
    let isValidPassword = false;
    try {
      isValidPassword = await bcrypt.compare(password, user.password_hash);
    } catch (bcryptError) {
      console.error('❌ Bcrypt error:', bcryptError);
      await connection.end();
      return res.status(500).json({
        success: false,
        message: 'เกิดข้อผิดพลาดในการตรวจสอบรหัสผ่าน'
      });
    }
    
    if (!isValidPassword) {
      try {
        await connection.execute(
          'INSERT INTO Login_History (user_id, ip_address, status) VALUES (?, ?, ?)',
          [user.user_id, req.ip || '0.0.0.0', 'Failed']
        );
      } catch (e) {}
      
      await connection.end();
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    // ✅ สร้าง JWT Token พร้อม parseInt
    const token = jwt.sign(
      { 
        user_id: parseInt(user.user_id), // ✅ ต้องมี parseInt
        phone: user.phone, 
        role: user.role // ✅ ใช้ role จาก database ตรงๆ
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // บันทึก login success
    try {
      await connection.execute(
        'INSERT INTO Login_History (user_id, ip_address, status) VALUES (?, ?, ?)',
        [user.user_id, req.ip || '0.0.0.0', 'Success']
      );
    } catch (e) {}

    console.log('✅ Login successful:', { 
      phone: user.phone, 
      role: user.role,
      user_id: user.user_id 
    });

    res.json({
      success: true,
      message: 'เข้าสู่ระบบสำเร็จ',
      user: {
        user_id: parseInt(user.user_id), // ✅ ส่งเป็น number
        phone: user.phone,
        full_name: user.full_name,
        role: user.role // ✅ ส่ง role ตรงจาก DB
      },
      token: token
    });

  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ',
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    if (connection) {
      try {
        await connection.end();
      } catch (e) {}
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
    const tokenUserId = parseInt(req.user.user_id);
    const requestedUserId = parseInt(userId);
    
    if (tokenUserId !== requestedUserId && !isAdmin(req.user.role)) {
      return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
    }

    const {
      full_name, first_name, last_name, birth_date, gender, weight, height,
      injured_side, injured_part, emergency_contact_name,
      emergency_contact_phone, emergency_contact_relation,
      license_number, specialization, relationship
    } = req.body;

    await connection.beginTransaction();

    // อัพเดทตาราง Users (มี updated_at อยู่แล้ว)
    if (full_name || (first_name && last_name)) {
      const nameToUpdate = full_name || `${first_name} ${last_name}`;
      await connection.execute(
        'UPDATE Users SET full_name = ?, updated_at = NOW() WHERE user_id = ?',
        [nameToUpdate, userId]
      );
      console.log('✅ Updated Users table');
    }

    // ดึงข้อมูลผู้ใช้เพื่อทราบบทบาท
    const [users] = await connection.execute(
      'SELECT role FROM Users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      await connection.rollback();
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }

    const userRole = users[0].role;

    // อัพเดทข้อมูลเฉพาะตามบทบาท
    if (userRole === 'Patient' || userRole === 'ผู้ป่วย') {
      // ตรวจสอบว่ามี record ใน Patients หรือไม่
      const [existingPatients] = await connection.execute(
        'SELECT patient_id FROM Patients WHERE user_id = ?',
        [userId]
      );

      if (existingPatients.length === 0) {
        await connection.rollback();
        return res.status(404).json({
          success: false,
          message: 'ไม่พบข้อมูลผู้ป่วย'
        });
      }

      const updates = [];
      const values = [];

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
      
      if (gender !== undefined && gender.trim() !== '') { 
        // ตรวจสอบว่าเป็นค่าที่ยอมรับได้
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
      
      if (weight !== undefined) { 
        if (weight === '' || weight === null || weight === 0) {
          updates.push('weight = ?');
          values.push(null);
        } else {
          const weightNum = parseFloat(weight);
          if (!isNaN(weightNum) && weightNum > 0) {
            updates.push('weight = ?'); 
            values.push(Math.min(999.99, Math.max(0.01, weightNum))); 
          }
        }
      }
      
      if (height !== undefined) { 
        if (height === '' || height === null || height === 0) {
          updates.push('height = ?');
          values.push(null);
        } else {
          const heightNum = parseFloat(height);
          if (!isNaN(heightNum) && heightNum > 0) {
            updates.push('height = ?'); 
            values.push(Math.min(999.99, Math.max(0.01, heightNum))); 
          }
        }
      }
      
      if (injured_side !== undefined && injured_side.trim() !== '') {
        // injured_side เป็น NOT NULL ต้องมีค่า
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
      
      if (injured_part !== undefined && injured_part.trim() !== '') {
        // injured_part เป็น NOT NULL ต้องมีค่า
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
          const cleanPhone = emergency_contact_phone.replace(/\D/g, '');
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

      if (updates.length > 0) {
        values.push(userId);
        const updateQuery = `UPDATE Patients SET ${updates.join(', ')} WHERE user_id = ?`;
        
        console.log('Update query:', updateQuery);
        console.log('Update values:', values);
        
        await connection.execute(updateQuery, values);
        console.log('✅ Updated Patients table');
      }
      
    } else if (userRole === 'Physiotherapist' || userRole === 'นักกายภาพบำบัด') {
      // ตรวจสอบว่ามี record ใน Physiotherapists หรือไม่
      const [existingPhysios] = await connection.execute(
        'SELECT physio_id FROM Physiotherapists WHERE user_id = ?',
        [userId]
      );

      if (existingPhysios.length === 0) {
        await connection.rollback();
        return res.status(404).json({
          success: false,
          message: 'ไม่พบข้อมูลนักกายภาพบำบัด'
        });
      }

      const updates = [];
      const values = [];

      if (license_number !== undefined) { 
        updates.push('license_number = ?'); 
        values.push(license_number && license_number.trim() !== '' ? license_number.substring(0, 50) : null); 
      }
      
      if (specialization !== undefined) { 
        updates.push('specialization = ?'); 
        values.push(specialization && specialization.trim() !== '' ? specialization.substring(0, 100) : null); 
      }

      if (updates.length > 0) {
        values.push(userId);
        
        await connection.execute(
          `UPDATE Physiotherapists SET ${updates.join(', ')} WHERE user_id = ?`,
          values
        );
        console.log('✅ Updated Physiotherapists table');
      }
      
    } else if (userRole === 'Caregiver' || userRole === 'ผู้ดูแล') {
      // ตรวจสอบว่ามี record ใน Caregivers หรือไม่
      const [existingCaregivers] = await connection.execute(
        'SELECT caregiver_id FROM Caregivers WHERE user_id = ?',
        [userId]
      );

      if (existingCaregivers.length === 0) {
        await connection.rollback();
        return res.status(404).json({
          success: false,
          message: 'ไม่พบข้อมูลผู้ดูแล'
        });
      }

      if (relationship !== undefined) {
        await connection.execute(
          'UPDATE Caregivers SET relationship = ? WHERE user_id = ?',
          [relationship && relationship.trim() !== '' ? relationship.substring(0, 50) : null, userId]
        );
        console.log('✅ Updated Caregivers table');
      }
    }

    await connection.commit();
    console.log('✅ Profile update completed successfully');

    res.json({
      success: true,
      message: 'อัพเดทข้อมูลสำเร็จ'
    });

  } catch (error) {
    await connection.rollback();
    console.error('❌ Profile update error:', error);
    
    // ส่งข้อความแสดงข้อผิดพลาดที่ละเอียด
    let errorMessage = 'เกิดข้อผิดพลาดในการอัพเดทข้อมูล';
    
    if (error.code === 'ER_BAD_NULL_ERROR') {
      errorMessage = 'ข้อมูลที่จำเป็นไม่ครบถ้วน (injured_side และ injured_part ต้องมีค่า)';
    } else if (error.code === 'ER_DATA_TOO_LONG') {
      errorMessage = 'ข้อมูลยาวเกินไป กรุณาตรวจสอบและลองใหม่';
    } else if (error.message.includes('Data truncated')) {
      errorMessage = 'รูปแบบข้อมูลไม่ถูกต้อง (ตรวจสอบ ENUM values)';
    } else if (error.code === 'ER_BAD_FIELD_ERROR') {
      errorMessage = `โครงสร้างฐานข้อมูลไม่ถูกต้อง: ${error.message}`;
    } else if (error.code === 'ER_TRUNCATED_WRONG_VALUE' || error.code === 'ER_WRONG_VALUE') {
      errorMessage = 'ค่าข้อมูลไม่ถูกต้องตามรูปแบบที่กำหนด (ตรวจสอบ ENUM values)';
    }
    
    res.status(500).json({
      success: false,
      message: `${errorMessage}: ${error.message}`,
      error_code: error.code,
      debug: process.env.NODE_ENV === 'development' ? error.sqlMessage : undefined
    });
  } finally {
    await connection.end();
  }
});

// ========================
// 6. บันทึกผลการฝึก
// ========================
app.post('/api/exercise-sessions', authenticateToken, async (req, res) => {
  let connection;

  try {
    const userId = Number(req.user.user_id);

    const {
      exercise_id = null,
      exercise_type = 'unknown',
      exercise_name = 'ท่าการฝึก',
      actual_reps = 0,
      target_reps = 10, // เก็บไว้เฉย ๆ
      accuracy = 0,
      session_duration = 0,
      left_count = 0,
      right_count = 0,
    } = req.body;

    console.log('💾 บันทึกข้อมูลการฝึก:', {
      userId,
      exercise_id,
      exercise_name,
      exercise_type,
      actual_reps,
      left_count,
      right_count,
    });

    connection = await createConnection();

    // ----------------------------
    // ✅ 0) map user_id -> Patients.patient_id  (สำคัญที่สุด แก้ FK)
    // ----------------------------
    const [pRows] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ? LIMIT 1',
      [userId]
    );

    if (!pRows || pRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบ patient_id ในตาราง Patients สำหรับ user_id นี้ (ต้องมีข้อมูลผู้ป่วยก่อน)',
      });
    }

    const patientId = Number(pRows[0].patient_id);
    console.log('✅ Resolved patientId:', patientId, 'from userId:', userId);

    // ----------------------------
    // ✅ 1) หา/สร้าง plan_id จากตาราง exerciseplans
    //    Structure: plan_id(PK), patient_id(NOT NULL), physio_id(NOT NULL),
    //               plan_name, start_date, end_date, notes
    // ----------------------------
    let plan_id = null;

    try {
      // ค้นหา plan ที่มีอยู่แล้วของ patient นี้
      const [existingPlans] = await connection.execute(
        'SELECT plan_id FROM ExercisePlans WHERE patient_id = ? ORDER BY plan_id DESC LIMIT 1',
        [patientId]
      );

      if (existingPlans.length > 0) {
        plan_id = existingPlans[0].plan_id;
        console.log('✅ ใช้ plan_id จาก exerciseplans:', plan_id);
      } else {
        // ต้องหา physio_id เพราะเป็น NOT NULL
        // ดึง physio_id คนแรกที่มีในระบบ (default physio)
        let physioId = 1;
        try {
          const [physios] = await connection.execute(
            'SELECT physio_id FROM Physiotherapists ORDER BY physio_id ASC LIMIT 1'
          );
          if (physios.length > 0) {
            physioId = physios[0].physio_id;
            console.log('✅ ใช้ physio_id:', physioId);
          }
        } catch (e) {
          console.warn('⚠️ หา physio_id ไม่ได้ ใช้ default = 1');
        }

        const [newPlan] = await connection.execute(
          `INSERT INTO ExercisePlans (patient_id, physio_id, plan_name, start_date)
           VALUES (?, ?, 'แผนการฟื้นฟูอัตโนมัติ', CURRENT_DATE)`,
          [patientId, physioId]
        );
        plan_id = newPlan.insertId;
        console.log('✅ สร้าง plan_id ใหม่ใน exerciseplans:', plan_id);
      }
    } catch (planError) {
      console.error('❌ หา/สร้าง plan_id ไม่สำเร็จ:', planError.message);
      plan_id = null;
    }

    // ----------------------------
    // ✅ 2) Resolve exercise_id (ห้าม null)
    // ----------------------------
    let resolvedExerciseId = exercise_id ? Number(exercise_id) : null;

    // ถ้า client ไม่ส่ง id มา ลองหาใน Exercises จากชื่อ
    if (!resolvedExerciseId) {
      const [found] = await connection.execute(
        'SELECT exercise_id FROM Exercises WHERE name_th = ? OR name_en = ? LIMIT 1',
        [exercise_name, exercise_name]
      );

      if (found.length > 0) {
        resolvedExerciseId = Number(found[0].exercise_id);
        console.log('✅ พบ exercise_id จาก Exercises:', resolvedExerciseId);
      } else {
        // ถ้าไม่เจอ สร้าง Exercises ใหม่
        const [created] = await connection.execute(
          `INSERT INTO Exercises (
            name_th, name_en, description, angle_range, hold_time, repetitions, sets, rest_time
          ) VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL)`,
          [exercise_name, exercise_name, `AUTO-CREATED (${exercise_type})`]
        );
        resolvedExerciseId = created.insertId;
        console.log('✅ สร้าง Exercises ใหม่ exercise_id:', resolvedExerciseId);
      }
    }

    if (!resolvedExerciseId) {
      return res.status(400).json({
        success: false,
        message: 'exercise_id ไม่ถูกต้อง/ไม่สามารถสร้างได้',
      });
    }

    // ----------------------------
    // ✅ 3) INSERT Exercise_Sessions (ใช้ patientId!)
    // ----------------------------
    const safeActualReps = Number(actual_reps) || 0;
    const safeLeft = Number(left_count) || 0;
    const safeRight = Number(right_count) || 0;
    const safeAccuracy = Number(accuracy) || 0;
    const safeDuration = Number(session_duration) || 0;

    const notes = `${exercise_name} - ซ้าย:${safeLeft} ขวา:${safeRight} รวม:${safeActualReps} ครั้งใน ${safeDuration} วินาที`;

    // ✅ INSERT แบบ conditional: ถ้าหา plan_id ได้ใส่, ถ้าไม่ได้ข้าม (plan_id = NULL)
    let result;
    if (plan_id) {
      [result] = await connection.execute(
        `INSERT INTO Exercise_Sessions (
          patient_id, plan_id, exercise_id, session_date,
          actual_reps_left, actual_reps_right, actual_reps,
          actual_sets, accuracy_percent, duration_seconds, notes
        ) VALUES (?, ?, ?, NOW(), ?, ?, ?, 1, ?, ?, ?)`,
        [patientId, plan_id, resolvedExerciseId, safeLeft, safeRight, safeActualReps, safeAccuracy, safeDuration, notes]
      );
      console.log('✅ INSERT พร้อม plan_id:', plan_id);
    } else {
      // plan_id = NULL → INSERT โดยไม่ระบุ plan_id
      // ⚠️ ต้องให้ column plan_id เป็น NULLABLE: ALTER TABLE Exercise_Sessions MODIFY plan_id INT NULL;
      [result] = await connection.execute(
        `INSERT INTO Exercise_Sessions (
          patient_id, exercise_id, session_date,
          actual_reps_left, actual_reps_right, actual_reps,
          actual_sets, accuracy_percent, duration_seconds, notes
        ) VALUES (?, ?, NOW(), ?, ?, ?, 1, ?, ?, ?)`,
        [patientId, resolvedExerciseId, safeLeft, safeRight, safeActualReps, safeAccuracy, safeDuration, notes]
      );
      console.log('⚠️ INSERT โดยไม่มี plan_id (plan_id = NULL)');
    }

    console.log('✅ บันทึกสำเร็จ session_id:', result.insertId);

    return res.status(201).json({
      success: true,
      message: 'บันทึกข้อมูลการฝึกสำเร็จ',
      data: {
        session_id: result.insertId,
        patient_id: patientId,
        user_id: userId,
        plan_id,
        exercise_id: resolvedExerciseId,
        exercise_name,
        exercise_type,
        actual_reps: safeActualReps,
        left_count: safeLeft,
        right_count: safeRight,
        accuracy: safeAccuracy,
        session_duration: safeDuration,
      },
    });
  } catch (error) {
    console.error('❌ Error saving session:', error);
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล',
      error: error.message,
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ================================
// 7.GET: ประวัติการออกกำลังกาย
// ================================
app.get('/api/exercise-sessions', authenticateToken, async (req, res) => {
  let connection;

  try {
    console.log('✅ Token verified:', { user_id: req.user.user_id, role: req.user.role });

    const userId = Number(req.user.user_id);

    // 1) Parse + validate params
    const period = (req.query.period || '7days').toString();
    let limit = Number.parseInt(req.query.limit, 10);
    let offset = Number.parseInt(req.query.offset, 10);

    if (!Number.isFinite(limit) || !Number.isInteger(limit)) limit = 100;
    if (!Number.isFinite(offset) || !Number.isInteger(offset)) offset = 0;

    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    if (offset < 0) offset = 0;

    // 2) Date filter
    let dateCondition = '';
    if (period === '7days') dateCondition = 'AND es.session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
    else if (period === '30days') dateCondition = 'AND es.session_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    else if (period === '90days') dateCondition = 'AND es.session_date >= DATE_SUB(NOW(), INTERVAL 90 DAY)';

    connection = await createConnection();

    // 3) IMPORTANT: map user_id -> Patients.patient_id
    const [pRows] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ? LIMIT 1',
      [userId]
    );

    if (!pRows || pRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ป่วยในตาราง Patients (user_id นี้ยังไม่มี patient_id)',
      });
    }

    const patientId = Number(pRows[0].patient_id);

    // 4) Query (อย่า select es.completed / es.created_at ถ้าไม่มีจริง)
    // NOTE: ฝัง LIMIT/OFFSET หลัง validate เพื่อตัดปัญหา Incorrect arguments to LIMIT
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
        e.name_th AS exercise_name_th,
        e.name_en AS exercise_name_en,
        e.description,
        COALESCE(e.name_th, SUBSTRING_INDEX(es.notes, ' (', 1), 'ท่ากายภาพ') AS exercise_name
      FROM Exercise_Sessions es
      LEFT JOIN Exercises e ON es.exercise_id = e.exercise_id
      WHERE es.patient_id = ?
      ${dateCondition}
      ORDER BY es.session_date DESC, es.session_id DESC
      LIMIT ${limit} OFFSET ${offset}
    `;

    console.log('📝 Executing query with params:', [patientId], { userId, patientId, limit, offset, period });

    const [rows] = await connection.execute(query, [patientId]);

    console.log(`✅ ดึงข้อมูลสำเร็จ: ${rows.length} sessions`);

    res.json({
      success: true,
      data: rows,
      count: rows.length,
      period,
      limit,
      offset,
      patient_id: patientId,
      message: 'ดึงข้อมูลสำเร็จ',
    });
  } catch (error) {
    console.error('❌ Error fetching sessions:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: error.message,
    });
  } finally {
    if (connection) await connection.end();
  }
});
// ========================
// 8. ดูสถิติการฝึก
// ========================
app.get('/api/exercise-stats', authenticateToken, async (req, res) => {
  let connection;

  try {
    const userId = Number(req.user.user_id);
    const { period = '7days' } = req.query;

    console.log('📈 ดึงสถิติของ user_id:', userId);

    connection = await createConnection();

    // ✅ map user_id -> Patients.patient_id
    const [pRows] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ? LIMIT 1',
      [userId]
    );

    if (!pRows || pRows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบ patient_id ในตาราง Patients สำหรับ user_id นี้',
      });
    }

    const patientId = Number(pRows[0].patient_id);

    let dateFilter = '';
    if (period === '7days') dateFilter = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
    else if (period === '30days') dateFilter = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
    else if (period === '90days') dateFilter = 'AND session_date >= DATE_SUB(NOW(), INTERVAL 90 DAY)';

    const [stats] = await connection.execute(
      `SELECT 
        COUNT(*) as total_sessions,
        COALESCE(SUM(actual_reps),0) as total_reps,
        COALESCE(SUM(actual_reps_left),0) as total_left_reps,
        COALESCE(SUM(actual_reps_right),0) as total_right_reps,
        COALESCE(AVG(accuracy_percent),0) as avg_accuracy,
        COALESCE(SUM(duration_seconds),0) as total_duration
      FROM Exercise_Sessions
      WHERE patient_id = ? ${dateFilter}`,
      [patientId]
    );

    const [byExercise] = await connection.execute(
      `SELECT 
        COALESCE(e.name_th, SUBSTRING_INDEX(notes, ' - ', 1)) as exercise_name,
        COUNT(*) as session_count,
        COALESCE(SUM(actual_reps),0) as total_reps,
        COALESCE(AVG(accuracy_percent),0) as avg_accuracy
      FROM Exercise_Sessions es
      LEFT JOIN Exercises e ON es.exercise_id = e.exercise_id
      WHERE es.patient_id = ? ${dateFilter}
      GROUP BY COALESCE(e.name_th, SUBSTRING_INDEX(notes, ' - ', 1))
      ORDER BY session_count DESC`,
      [patientId]
    );

    const [dailyStats] = await connection.execute(
      `SELECT 
        DATE(session_date) as exercise_date,
        COUNT(*) as session_count,
        COALESCE(SUM(actual_reps),0) as total_reps,
        COALESCE(AVG(accuracy_percent),0) as avg_accuracy
      FROM Exercise_Sessions
      WHERE patient_id = ? ${dateFilter}
      GROUP BY DATE(session_date)
      ORDER BY exercise_date DESC`,
      [patientId]
    );

    console.log('✅ ดึงสถิติสำเร็จ');

    return res.json({
      success: true,
      message: 'ดึงสถิติสำเร็จ',
      data: {
        summary: stats[0],
        by_exercise: byExercise,
        daily: dailyStats,
        period,
        patient_id: patientId,
      },
    });

  } catch (error) {
    console.error('❌ Error stats:', error);
    return res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงสถิติ',
      error: error.message,
    });
  } finally {
    if (connection) await connection.end();
  }
});
// ========================
// ดึงแผนการฝึกล่าสุดที่นักกายภาพกำหนด
// GET /api/exercise-plans
app.get('/api/exercise-plans', authenticateToken, async (req, res) => {
  let connection;
  try {
    const userId = Number(req.user.user_id);
    connection = await createConnection();

    const [pRows] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ? LIMIT 1', [userId]
    );
    if (!pRows || pRows.length === 0)
      return res.status(404).json({ success: false, message: 'ไม่พบข้อมูลผู้ป่วย' });

    const patientId = Number(pRows[0].patient_id);
    console.log('🔍 patient_id:', patientId);

    // ดึงแผนล่าสุดของผู้ป่วย
    let plans = [];
    try {
      [plans] = await connection.execute(
        `SELECT ep.plan_id, ep.plan_name, ep.start_date, ep.end_date, ep.notes,
                u.full_name as physio_name
         FROM ExercisePlans ep
         LEFT JOIN Users u ON ep.physio_id = u.user_id
         WHERE ep.patient_id = ?
         ORDER BY ep.plan_id DESC LIMIT 1`,
        [patientId]
      );
    } catch (e1) {
      console.error('❌ ดึงแผนไม่ได้:', e1.message);
    }

    console.log('🔍 plans found:', plans.length, plans[0]?.plan_id);

    if (!plans || plans.length === 0) {
      return res.json({
        success: true, has_plan: false, plan: null,
        exercises: [
          { exercise_id: 1, name_th: 'ยกแขนไปข้างหน้า',  exercise_type: 'arm-raise-forward', icon: 'fa-hand-paper', sets: 3, reps_per_set: 10, color: 'orange' },
          { exercise_id: 2, name_th: 'เหยียดเข่าตรง',     exercise_type: 'leg-extension',      icon: 'fa-walking',    sets: 3, reps_per_set: 10, color: 'green'  },
          { exercise_id: 3, name_th: 'โยกลำตัวซ้าย-ขวา', exercise_type: 'trunk-sway',         icon: 'fa-sync-alt',   sets: 3, reps_per_set: 10, color: 'teal'   }
        ]
      });
    }

    const plan = plans[0];

    // ดึง exercises จาก Plan_Exercises
    let planExs = [];
    try {
      [planExs] = await connection.execute(
        `SELECT pe.exercise_id,
                pe.target_sets AS sets,
                pe.target_reps AS reps_per_set,
                e.name_th, e.name_en, e.exercise_type
         FROM Plan_Exercises pe
         JOIN Exercises e ON pe.exercise_id = e.exercise_id
         WHERE pe.plan_id = ?
         ORDER BY pe.plan_exercise_id ASC`,
        [plan.plan_id]
      );
    } catch (e) {
      console.error('❌ ดึง Plan_Exercises ไม่ได้:', e.message);
    }

    console.log('🔍 plan_id used:', plan.plan_id, '| exercises found:', planExs.length);

    let exercises = planExs && planExs.length > 0 ? planExs : [
      { exercise_id: 1, name_th: 'ยกแขนไปข้างหน้า',  exercise_type: 'arm-raise-forward', sets: 3, reps_per_set: 10 },
      { exercise_id: 2, name_th: 'เหยียดเข่าตรง',     exercise_type: 'leg-extension',      sets: 3, reps_per_set: 10 },
      { exercise_id: 3, name_th: 'โยกลำตัวซ้าย-ขวา', exercise_type: 'trunk-sway',         sets: 3, reps_per_set: 10 }
    ];

    const colorList = ['orange','green','teal','blue','purple','pink'];
    const iconMap = {
      'arm-raise-forward': 'fa-hand-paper', 'arm':   'fa-hand-paper',
      'leg-extension':     'fa-walking',    'leg':   'fa-walking',
      'trunk-sway':        'fa-sync-alt',   'trunk': 'fa-sync-alt',
      'balance': 'fa-balance-scale', 'default': 'fa-dumbbell'
    };
    function iconFromName(name) {
      if (!name) return iconMap['default'];
      const n = name.toLowerCase();
      if (n.includes('แขน') || n.includes('ยก') || n.includes('มือ')) return 'fa-hand-paper';
      if (n.includes('เข่า') || n.includes('ขา') || n.includes('เหยียด')) return 'fa-walking';
      if (n.includes('ลำตัว') || n.includes('โยก') || n.includes('หมุน')) return 'fa-sync-alt';
      if (n.includes('สมดุล') || n.includes('ทรงตัว')) return 'fa-balance-scale';
      return iconMap['default'];
    }

    exercises = exercises.map((ex, i) => ({
      ...ex,
      sets:         Number(ex.sets)         || 3,
      reps_per_set: Number(ex.reps_per_set) || 10,
      color: colorList[i % colorList.length],
      icon:  iconMap[ex.exercise_type] || iconFromName(ex.name_th)
    }));

    return res.json({
      success: true, has_plan: true,
      plan: {
        plan_id:     plan.plan_id,
        plan_name:   plan.plan_name,
        physio_name: plan.physio_name || 'นักกายภาพบำบัด',
        start_date:  plan.start_date,
        end_date:    plan.end_date,
        notes:       plan.notes
      },
      exercises
    });

  } catch (error) {
    console.error('❌ Error exercise-plans:', error);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาด', error: error.message });
  } finally {
    if (connection) await connection.end();
  }
});
// GET /api/today-progress — ดูว่าวันนี้ทำท่าไหนไปแล้วบ้าง
app.get('/api/today-progress', authenticateToken, async (req, res) => {
  let connection;
  try {
    const userId = Number(req.user.user_id);
    connection = await createConnection();

    const [pRows] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ? LIMIT 1',
      [userId]
    );
    if (!pRows || pRows.length === 0)
      return res.status(404).json({ success: false, message: 'ไม่พบข้อมูลผู้ป่วย' });

    const patientId = Number(pRows[0].patient_id);

    // นับ session เป็น sets_done (1 session = 1 เซต)
    const [todaySessions] = await connection.execute(
      `SELECT es.exercise_id, e.name_th, e.exercise_type,
              COUNT(*) as sets_done,
              COALESCE(SUM(es.actual_sets), COUNT(*)) as sets_done_alt,
              MAX(es.session_date) as last_done
       FROM Exercise_Sessions es
       LEFT JOIN Exercises e ON es.exercise_id = e.exercise_id
       WHERE es.patient_id = ? AND DATE(es.session_date) = CURDATE()
       GROUP BY es.exercise_id, e.name_th, e.exercise_type`,
      [patientId]
    );

    return res.json({
      success: true,
      date: new Date().toISOString().split('T')[0],
      completed_exercises: todaySessions.map(s => ({
        exercise_id:   s.exercise_id,
        name_th:       s.name_th,
        exercise_type: s.exercise_type,
        sets_done:     Number(s.sets_done_alt) || Number(s.sets_done) || 0,
        last_done:     s.last_done
      }))
    });

  } catch (error) {
    console.error('❌ Error today-progress:', error);
    return res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาด', error: error.message });
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

app.listen(port, '0.0.0.0', () => { // ✅ ถูกต้องแล้ว
    console.log(`Server running on port ${port}`);
});
