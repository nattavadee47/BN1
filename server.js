const express = require('express');
const app = express();
const mysql = require('mysql2/promise');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const hostname = '127.0.0.1';
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = 'stroke_rehab_secret_key_2024';

const createConnection = async () => {
  return await mysql.createConnection({
    host: 'gateway01.ap-northeast-1.prod.aws.tidbcloud.com',
    user: '3HZNLzyS4E2dJfG.root',
    password: '1CmpzXSMTQxYdngG',
    database: 'stroke_rehab_db',
    ssl: { minVersion: 'TLSv1.2' }
  });
};

// Middleware JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'ต้องระบุ Access token' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token ไม่ถูกต้อง' });
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
  res.json({ message: 'เซิร์ฟเวอร์ระบบกายภาพบำบัดทำงานปกติ!', timestamp: new Date().toISOString(), version: '1.0.0' });
});
app.get('/health', (req, res) => {
  res.json({ status: 'OK', server: 'ระบบกายภาพบำบัดสำหรับผู้ป่วยหลังเส้นเลือดสมองแตก', port });
});

// ========================
// ระบบยืนยันตัวตน (Authentication)
// ========================

// เข้าสู่ระบบ
app.post('/api/auth/login', async (req, res) => {
  const connection = await createConnection();
  
  try {
    const { phone, password } = req.body;
    
    console.log('🔍 Login attempt:', { phone, hasPassword: !!password });
    
    if (!phone || !password) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกเบอร์โทรศัพท์และรหัสผ่าน'
      });
    }

    // ค้นหาผู้ใช้จากเบอร์โทรศัพท์
    const [users] = await connection.execute(
      'SELECT user_id, phone, password_hash, full_name, role FROM Users WHERE phone = ?',
      [phone]
    );

    console.log('🔍 User search result:', users.length > 0 ? 'Found user' : 'User not found');

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    const user = users[0];
    
    // ตรวจสอบรหัสผ่าน
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!isValidPassword) {
      // บันทึกการเข้าสู่ระบบล้มเหลว
      await connection.execute(
        'INSERT INTO Login_History (user_id, ip_address, status) VALUES (?, ?, ?)',
        [user.user_id, req.ip, 'Failed']
      );
      
      return res.status(401).json({
        success: false,
        message: 'เบอร์โทรศัพท์หรือรหัสผ่านไม่ถูกต้อง'
      });
    }

    // สร้าง JWT Token
    const token = jwt.sign(
      { 
        user_id: user.user_id, 
        phone: user.phone, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // บันทึกการเข้าสู่ระบบสำเร็จ
    await connection.execute(
      'INSERT INTO Login_History (user_id, ip_address, status) VALUES (?, ?, ?)',
      [user.user_id, req.ip, 'Success']
    );

    console.log('✅ Login successful for user:', user.phone);

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
    console.error('ข้อผิดพลาดในการเข้าสู่ระบบ:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ'
    });
  } finally {
    await connection.end();
  }
});

// ลงทะเบียนผู้ใช้ใหม่ - แก้ไขให้รองรับภาษาไทย
// แทนที่ API POST /api/auth/register ใน server.js ด้วยโค้ดนี้
app.post('/api/auth/register', async (req, res) => {
  const connection = await createConnection();
  
  try {
    console.log('🔍 Registration request received');
    console.log('Request body:', JSON.stringify(req.body, null, 2));
    
    const {
      phone,
      password,
      first_name,
      last_name,
      birth_date,
      gender,
      role,
      // ฟิลด์เฉพาะผู้ป่วย
      weight,
      height,
      injured_side,
      injured_part,
      emergency_contact_name,
      emergency_contact_phone,
      emergency_contact_relation,
      // ฟิลด์เฉพาะนักกายภาพบำบัด
      license_number,
      specialization,
      // ฟิลด์เฉพาะผู้ดูแล
      relationship
    } = req.body;

    // ตรวจสอบข้อมูลจำเป็น
    if (!phone || !password || !first_name || !last_name || !birth_date || !gender || !role) {
      console.log('❌ Missing required fields');
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลที่จำเป็นให้ครบถ้วน'
      });
    }

    // ตรวจสอบรูปแบบเบอร์โทรศัพท์
    const phoneRegex = /^[0-9]{10}$/;
    if (!phoneRegex.test(phone)) {
      console.log('❌ Invalid phone format:', phone);
      return res.status(400).json({
        success: false,
        message: 'รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง (ต้องเป็นตัวเลข 10 หลัก)'
      });
    }

    // ตรวจสอบความแข็งแกร่งของรหัสผ่าน
    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
      });
    }

    // ตรวจสอบวันที่เกิด
    const birthDateObj = new Date(birth_date);
    if (isNaN(birthDateObj.getTime())) {
      return res.status(400).json({
        success: false,
        message: 'รูปแบบวันที่เกิดไม่ถูกต้อง'
      });
    }

    // ตรวจสอบว่าเบอร์โทรซ้ำหรือไม่
    const [existingUsers] = await connection.execute(
      'SELECT user_id FROM Users WHERE phone = ?',
      [phone]
    );

    if (existingUsers.length > 0) {
      console.log('❌ Phone number already exists:', phone);
      return res.status(400).json({
        success: false,
        message: 'เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว'
      });
    }

    // เริ่ม Transaction
    await connection.beginTransaction();
    console.log('🔄 Transaction started');

    try {
      // เข้ารหัสรหัสผ่าน
      const password_hash = await bcrypt.hash(password, 12);
      const full_name = `${first_name} ${last_name}`;

      console.log('🔐 Password hashed successfully');

      // เพิ่มข้อมูลใน�าราง Users
      const [userResult] = await connection.execute(
        'INSERT INTO Users (phone, password_hash, full_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
        [phone, password_hash, full_name, role]
      );

      const user_id = userResult.insertId;
      console.log(`✅ User created with ID: ${user_id}`);

      // เพิ่มข้อมูลเฉพาะตามบทบาท
      if (role === 'Patient' || role === 'ผู้ป่วย') {
        console.log('👤 Creating patient record...');
        
        const patientData = {
          user_id,
          first_name: first_name.substring(0, 50),
          last_name: last_name.substring(0, 50),
          birth_date,
          gender: gender.substring(0, 10),
          weight: weight ? parseFloat(weight) : null,
          height: height ? parseFloat(height) : null, // เปลี่ยนเป็น parseFloat
          patient_phone: phone,
          injured_side: injured_side || 'Left', // ค่า default สำหรับ NOT NULL
          injured_part: injured_part || 'Other', // ค่า default สำหรับ NOT NULL
          emergency_contact_name: emergency_contact_name || null,
          emergency_contact_phone: emergency_contact_phone || null,
          emergency_contact_relation: emergency_contact_relation || null
        };

        console.log('Patient data to insert:', patientData);

        await connection.execute(
          `INSERT INTO Patients (
            user_id, first_name, last_name, birth_date, gender, weight, height, 
            patient_phone, injured_side, injured_part, emergency_contact_name, 
            emergency_contact_phone, emergency_contact_relation
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            patientData.user_id,
            patientData.first_name,
            patientData.last_name,
            patientData.birth_date,
            patientData.gender,
            patientData.weight,
            patientData.height,
            patientData.patient_phone,
            patientData.injured_side,
            patientData.injured_part,
            patientData.emergency_contact_name,
            patientData.emergency_contact_phone,
            patientData.emergency_contact_relation
          ]
        );

        console.log('✅ Patient record created successfully');

      } else if (role === 'Physiotherapist' || role === 'นักกายภาพบำบัด') {
        console.log('🩺 Creating physiotherapist record...');
        
        await connection.execute(
          'INSERT INTO Physiotherapists (user_id, license_number, specialization) VALUES (?, ?, ?)',
          [user_id, license_number || null, specialization || null]
        );

        console.log('✅ Physiotherapist record created successfully');

      } else if (role === 'Caregiver' || role === 'ผู้ดูแล') {
        console.log('👨‍👩‍👧‍👦 Creating caregiver record...');
        
        await connection.execute(
          'INSERT INTO Caregivers (user_id, relationship) VALUES (?, ?)',
          [user_id, relationship || null]
        );

        console.log('✅ Caregiver record created successfully');
      }

      // Commit transaction
      await connection.commit();
      console.log('✅ Transaction committed successfully');

      // สร้าง JWT Token สำหรับผู้ใช้ใหม่
      const token = jwt.sign(
        { 
          user_id: user_id, 
          phone: phone, 
          role: role 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      // บันทึกการสมัครสมาชิกสำเร็จในประวัติ
      try {
        await connection.execute(
          'INSERT INTO Login_History (user_id, ip_address, status, created_at) VALUES (?, ?, ?, NOW())',
          [user_id, req.ip || '0.0.0.0', 'Registration']
        );
      } catch (historyError) {
        console.warn('⚠️ Failed to log registration history:', historyError.message);
      }

      console.log('🎉 Registration completed successfully for:', phone);

      res.status(201).json({
        success: true,
        message: 'ลงทะเบียนสำเร็จ',
        user: {
          user_id: user_id,
          phone: phone,
          full_name: full_name,
          role: role
        },
        token: token
      });

    } catch (transactionError) {
      // Rollback transaction
      await connection.rollback();
      console.error('❌ Transaction rolled back due to error:', transactionError);
      throw transactionError;
    }

  } catch (error) {
    console.error('❌ Registration error:', error);
    
    // ส่งข้อความแสดงข้อผิดพลาดที่ละเอียด
    let errorMessage = 'เกิดข้อผิดพลาดในการลงทะเบียน';
    
    if (error.code === 'ER_DUP_ENTRY') {
      errorMessage = 'เบอร์โทรศัพท์นี้ถูกใช้งานแล้ว';
    } else if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      errorMessage = 'ข้อมูลอ้างอิงไม่ถูกต้อง';
    } else if (error.code === 'ER_BAD_NULL_ERROR') {
      errorMessage = 'ข้อมูลที่จำเป็นไม่ครบถ้วน';
    } else if (error.code === 'ER_DATA_TOO_LONG') {
      errorMessage = 'ข้อมูลยาวเกินไป กรุณาตรวจสอบและลองใหม่';
    } else if (error.message.includes('Data truncated')) {
      errorMessage = 'รูปแบบข้อมูลไม่ถูกต้อง';
    }
    
    res.status(500).json({
      success: false,
      message: errorMessage,
      error_code: error.code,
      debug: process.env.NODE_ENV === 'development' ? error.message : undefined
    });

  } finally {
    await connection.end();
    console.log('🔌 Database connection closed');
  }
});

// ออกจากระบบ
app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: 'ออกจากระบบสำเร็จ'
  });
});

// ฟังก์ชันตรวจสอบค่า ENUM ที่ถูกต้องสำหรับภาษาไทย - อัพเดทให้ตรงกับ Database Schema
function validateThaiEnumValues(data) {
  const errors = [];
  
  // ตรวจสอบ gender
  if (data.gender && !['ชาย', 'หญิง', 'อื่นๆ', 'Male', 'Female', 'Other'].includes(data.gender)) {
    errors.push(`เพศไม่ถูกต้อง: ${data.gender}. ต้องเป็น: ชาย, หญิง, หรือ อื่นๆ`);
  }
  
  // ตรวจสอบ injured_side
  if (data.injured_side && !['ซ้าย', 'ขวา', 'ทั้งสองข้าง', 'Left', 'Right', 'Both'].includes(data.injured_side)) {
    errors.push(`ด้านที่บาดเจ็บไม่ถูกต้อง: ${data.injured_side}. ต้องเป็น: ซ้าย, ขวา, หรือ ทั้งสองข้าง`);
  }
  
  // ตรวจสอบ injured_part
  if (data.injured_part && !['แขน', 'ขา', 'ลำตัว', 'หัว', 'อื่นๆ', 'Arm', 'Leg', 'Trunk', 'Head', 'Other'].includes(data.injured_part)) {
    errors.push(`ส่วนที่บาดเจ็บไม่ถูกต้อง: ${data.injured_part}. ต้องเป็น: แขน, ขา, ลำตัว, หัว, หรือ อื่นๆ`);
  }
  
  return errors;
}

// ========================
// จัดการข้อมูลผู้ใช้ (User Management CRUD)
// ========================

// ดูรายชื่อผู้ใช้ทั้งหมด (เฉพาะผู้ดูแลระบบ)
app.get('/api/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  
  try {
    const [users] = await connection.execute(`
      SELECT user_id, phone, full_name, role, created_at, updated_at 
      FROM Users 
      ORDER BY created_at DESC
    `);

    res.json({
      success: true,
      data: users
    });
  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงข้อมูลผู้ใช้:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้'
    });
  } finally {
    await connection.end();
  }
});

// ดูโปรไฟล์ผู้ใช้
app.get('/api/users/:id', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const userId = req.params.id;
  
  try {
    // ตรวจสอบสิทธิ์ - ผู้ใช้สามารถดูข้อมูลตัวเองหรือผู้ดูแลระบบดูได้ทั้งหมด
    if (req.user.user_id != userId && req.user.role !== 'Admin') {
      return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
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
    let profileData = { ...user };

    // ดึงข้อมูลเพิ่มเติมตามบทบาท
    if (user.role === 'Patient' || user.role === 'ผู้ป่วย') {
      const [patients] = await connection.execute(`
        SELECT * FROM Patients WHERE user_id = ?
      `, [userId]);
      profileData.patient_info = patients[0] || null;
    } else if (user.role === 'Physiotherapist' || user.role === 'นักกายภาพบำบัด') {
      const [physios] = await connection.execute(`
        SELECT * FROM Physiotherapists WHERE user_id = ?
      `, [userId]);
      profileData.physiotherapist_info = physios[0] || null;
    } else if (user.role === 'Caregiver' || user.role === 'ผู้ดูแล') {
      const [caregivers] = await connection.execute(`
        SELECT * FROM Caregivers WHERE user_id = ?
      `, [userId]);
      profileData.caregiver_info = caregivers[0] || null;
    }

    res.json({
      success: true,
      data: profileData
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงโปรไฟล์:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลโปรไฟล์'
    });
  } finally {
    await connection.end();
  }
});

app.put('/api/users/:id', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const userId = req.params.id;
  
  try {
    console.log('🔄 Update profile request for user:', userId);
    console.log('Request data:', JSON.stringify(req.body, null, 2));

    // ตรวจสอบสิทธิ์
    if (req.user.user_id != userId && req.user.role !== 'Admin') {
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

// ลบผู้ใช้ (เฉพาะผู้ดูแลระบบ)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  const userId = req.params.id;
  
  try {
    // ตรวจสอบว่าผู้ใช้มีอยู่หรือไม่
    const [users] = await connection.execute(
      'SELECT user_id FROM Users WHERE user_id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }

    // ลบผู้ใช้ (CASCADE จะลบข้อมูลที่เกี่ยวข้องในตารางอื่นด้วย)
    await connection.execute(
      'DELETE FROM Users WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      message: 'ลบผู้ใช้สำเร็จ'
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการลบผู้ใช้:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการลบผู้ใช้'
    });
  } finally {
    await connection.end();
  }
});

// เปลี่ยนรหัสผ่าน
app.post('/api/users/:id/change-password', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const userId = req.params.id;
  
  try {
    // ตรวจสอบสิทธิ์
    if (req.user.user_id != userId && req.user.role !== 'Admin') {
      return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
    }

    const { currentPassword, newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร'
      });
    }

    // หากไม่ใช่ Admin ต้องตรวจสอบรหัสผ่านเดิม
    if (req.user.role !== 'Admin') {
      if (!currentPassword) {
        return res.status(400).json({
          success: false,
          message: 'กรุณากรอกรหัสผ่านปัจจุบัน'
        });
      }

      // ดึงรหัสผ่านปัจจุบัน
      const [users] = await connection.execute(
        'SELECT password_hash FROM Users WHERE user_id = ?',
        [userId]
      );

      if (users.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'ไม่พบข้อมูลผู้ใช้'
        });
      }

      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, users[0].password_hash);
      if (!isCurrentPasswordValid) {
        return res.status(400).json({
          success: false,
          message: 'รหัสผ่านปัจจุบันไม่ถูกต้อง'
        });
      }
    }

    // เข้ารหัสรหัสผ่านใหม่
    const newPasswordHash = await bcrypt.hash(newPassword, 12);

    // อัพเดทรหัสผ่าน
    await connection.execute(
      'UPDATE Users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?',
      [newPasswordHash, userId]
    );

    res.json({
      success: true,
      message: 'เปลี่ยนรหัสผ่านสำเร็จ'
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการเปลี่ยนรหัสผ่าน:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการเปลี่ยนรหัสผ่าน'
    });
  } finally {
    await connection.end();
  }
});

// ========================
// จัดการข้อมูลผู้ป่วย (Patient CRUD)
// ========================

// ดูรายชื่อผู้ป่วยทั้งหมด
app.get('/api/patients', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    let query = `
      SELECT p.*, u.phone, u.full_name, u.created_at
      FROM Patients p 
      JOIN Users u ON p.user_id = u.user_id 
    `;
    let queryParams = [];

    // หากเป็นผู้ป่วย ให้แสดงเฉพาะข้อมูลตัวเอง
    if (req.user.role === 'Patient' || req.user.role === 'ผู้ป่วย') {
      query += ' WHERE u.user_id = ?';
      queryParams = [req.user.user_id];
    }

    query += ' ORDER BY p.patient_id DESC';

    const [patients] = await connection.execute(query, queryParams);

    res.json({
      success: true,
      data: patients
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงข้อมูลผู้ป่วย:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย'
    });
  } finally {
    await connection.end();
  }
});

// ดูข้อมูลผู้ป่วยรายบุคคล
app.get('/api/patients/:id', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const patientId = req.params.id;
  
  try {
    // ตรวจสอบสิทธิ์
    if (req.user.role === 'Patient' || req.user.role === 'ผู้ป่วย') {
      const [patients] = await connection.execute(
        'SELECT patient_id FROM Patients WHERE user_id = ? AND patient_id = ?',
        [req.user.user_id, patientId]
      );
      
      if (patients.length === 0) {
        return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์ดูรายงานนี้' });
      }
    }

    // สถิติรวม (ใช้ข้อมูลตัวอย่าง เนื่องจากยังไม่มีตาราง Exercise_Sessions)
    const summary = {
      total_plans: 0,
      total_exercises: 0,
      total_sessions: 0,
      avg_accuracy: 0,
      last_session_date: null
    };

    // ข้อมูลผู้ป่วย
    const [patientData] = await connection.execute(
      'SELECT * FROM Patients WHERE patient_id = ?',
      [patientId]
    );

    res.json({
      success: true,
      data: {
        summary,
        patient: patientData[0] || null,
        weeklyProgress: [],
        topExercises: []
      }
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการสร้างรายงาน:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการสร้างรายงาน'
    });
  } finally {
    await connection.end();
  }
});

// ========================
// เส้นทางสำหรับการทดสอบ
// ========================

// ทดสอบการเชื่อมต่อ API
app.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'API ทำงานปกติ',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/auth/*',
      users: '/api/users/*',
      patients: '/api/patients/*',
      reports: '/api/reports/*'
    }
  });
});

// ทดสอบการเชื่อมต่อฐานข้อมูล
app.get('/test-db', async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [result] = await connection.execute('SELECT 1 as test');
    res.json({
      success: true,
      message: 'เชื่อมต่อฐานข้อมูลสำเร็จ',
      data: result[0]
    });
  } catch (error) {
    console.error('ทดสอบฐานข้อมูลล้มเหลว:', error);
    res.status(500).json({
      success: false,
      message: 'ไม่สามารถเชื่อมต่อฐานข้อมูลได้'
    });
  } finally {
    await connection.end();
  }
});

// ดูสถิติการลงทะเบียน
app.get('/api/stats/registration', authenticateToken, async (req, res) => {
  if (req.user.role !== 'Admin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  
  try {
    // นับจำนวนผู้ใช้ตามบทบาท
    const [roleStats] = await connection.execute(`
      SELECT 
        role,
        COUNT(*) as count
      FROM Users 
      GROUP BY role
      ORDER BY count DESC
    `);

    // นับจำนวนการลงทะเบียนรายเดือน
    const [monthlyStats] = await connection.execute(`
      SELECT 
        DATE_FORMAT(created_at, '%Y-%m') as month,
        COUNT(*) as registrations
      FROM Users 
      WHERE created_at >= DATE_SUB(NOW(), INTERVAL 12 MONTH)
      GROUP BY DATE_FORMAT(created_at, '%Y-%m')
      ORDER BY month DESC
    `);

    res.json({
      success: true,
      data: {
        roleStats,
        monthlyStats,
        totalUsers: roleStats.reduce((sum, stat) => sum + stat.count, 0)
      }
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงสถิติ:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงสถิติ'
    });
  } finally {
    await connection.end();
  }
});

// ดึงรายการแบบกึกหัดทั้งหมด
app.get('/api/exercises', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [exercises] = await connection.execute(`
      SELECT exercise_id, name_th, name_en, description, angle_range, 
             hold_time, repetitions, sets, rest_time
      FROM Exercises 
      ORDER BY exercise_id
    `);

    res.json({
      success: true,
      data: exercises
    });

  } catch (error) {
    console.error('ข้อผิดพลาดในการดึงข้อมูลแบบกึกหัด:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลแบบกึกหัด'
    });
  } finally {
    await connection.end();
  }
});

// บันทึกผลการออกกำลังกาย
app.post('/api/exercise-sessions', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const {
      exercise_type,
      exercise_name,
      actual_reps,
      target_reps,
      accuracy_percent,
      session_duration,
      notes
    } = req.body;

    console.log('🔍 Saving exercise session:', {
      user_id: req.user.user_id,
      exercise_type,
      exercise_name,
      actual_reps,
      accuracy_percent
    });

    // หาข้อมูลผู้ป่วยจาก user_id
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

    // หาหรือสร้าง Exercise record
    let exerciseId = null;
    const [existingExercises] = await connection.execute(
      'SELECT exercise_id FROM Exercises WHERE name_en = ? OR name_th = ?',
      [exercise_type, exercise_name]
    );

    if (existingExercises.length > 0) {
      exerciseId = existingExercises[0].exercise_id;
    } else {
      // สร้าง exercise ใหม่
      const [exerciseResult] = await connection.execute(
        'INSERT INTO Exercises (name_th, name_en, description) VALUES (?, ?, ?)',
        [exercise_name, exercise_type, `Auto-created from session: ${exercise_name}`]
      );
      exerciseId = exerciseResult.insertId;
    }

    // หาหรือสร้าง Exercise Plan
    let planId = null;
    const [existingPlans] = await connection.execute(
      `SELECT plan_id FROM ExercisePlans 
       WHERE patient_id = ? AND (end_date IS NULL OR end_date >= CURDATE())
       ORDER BY plan_id DESC LIMIT 1`,
      [patientId]
    );

    if (existingPlans.length > 0) {
      planId = existingPlans[0].plan_id;
    } else {
      // สร้าง plan ใหม่
      const [planResult] = await connection.execute(
        `INSERT INTO ExercisePlans (patient_id, physio_id, plan_name, start_date) 
         VALUES (?, 1, 'Auto Plan', CURDATE())`,
        [patientId]
      );
      planId = planResult.insertId;
    }

    // บันทึก Exercise Session
    const [sessionResult] = await connection.execute(
      `INSERT INTO Exercise_Sessions 
       (patient_id, plan_id, exercise_id, actual_reps, accuracy_percent, notes) 
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        patientId,
        planId,
        exerciseId,
        actual_reps,
        accuracy_percent,
        notes || `Session completed with ${actual_reps} reps, ${accuracy_percent}% accuracy`
      ]
    );

    console.log('✅ Exercise session saved with ID:', sessionResult.insertId);

    res.status(201).json({
      success: true,
      message: 'บันทึกผลการออกกำลังกายสำเร็จ',
      data: {
        session_id: sessionResult.insertId,
        patient_id: patientId,
        exercise_id: exerciseId,
        plan_id: planId
      }
    });

  } catch (error) {
    console.error('❌ Error saving exercise session:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการบันทึกผลการออกกำลังกาย',
      error_details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await connection.end();
  }
});

// ดึงประวัติการออกกำลังกายโดยไม่ระบุ patientId (ใช้ user_id จาก token)
app.get('/api/exercise-sessions', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    // หาข้อมูลผู้ป่วยจาก user_id
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

    // ดึงข้อมูลการออกกำลังกาย
    const [sessions] = await connection.execute(`
      SELECT 
        es.*,
        e.name_th as exercise_name_th,
        e.name_en as exercise_name_en,
        e.description as exercise_description,
        ep.plan_name,
        DATE_FORMAT(es.session_date, '%d/%m/%Y') as session_date_thai,
        TIME_FORMAT(es.session_date, '%H:%i') as session_time
      FROM Exercise_Sessions es
      JOIN Exercises e ON es.exercise_id = e.exercise_id
      JOIN ExercisePlans ep ON es.plan_id = ep.plan_id
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
    console.error('ข้อผิดพลาดในการดึงประวัติการออกกำลังกาย:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงประวัติการออกกำลังกาย'
    });
  } finally {
    await connection.end();
  }
});

// ดึงสถิติการออกกำลังกายโดยไม่ระบุ patientId
app.get('/api/exercise-stats', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    // หาข้อมูลผู้ป่วยจาก user_id
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

    // แบบกึกหัดยอดนิยม
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

// ดึงสถิติการออกกำลังกายของผู้ป่วยที่ระบุ
app.get('/api/exercise-stats/:patientId', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const patientId = req.params.patientId;
    
    // ตรวจสอบสิทธิ์
    if (req.user.role === 'Patient' || req.user.role === 'ผู้ป่วย') {
      const [patientCheck] = await connection.execute(
        'SELECT patient_id FROM Patients WHERE patient_id = ? AND user_id = ?',
        [patientId, req.user.user_id]
      );
      
      if (patientCheck.length === 0) {
        return res.status(403).json({
          success: false,
          message: 'ไม่มีสิทธิ์เข้าถึงข้อมูลนี้'
        });
      }
    }

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

    // แบบกึกหัดยอดนิยม
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

// จัดการข้อผิดพลาด 404 - แก้ไขปัญหา PathError
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: 'ไม่พบเส้นทาง API ที่ระบุ',
    path: req.originalUrl,
    method: req.method
  });
});

// จัดการข้อผิดพลาดทั่วไป
app.use((error, req, res, next) => {
  console.error('ข้อผิดพลาดของเซิร์ฟเวอร์:', error);
  
  // ไม่แสดงรายละเอียดข้อผิดพลาดใน production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(500).json({
    success: false,
    message: 'เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์',
    ...(isDevelopment && { error: error.message, stack: error.stack })
  });
});

// เริ่มเซิร์ฟเวอร์
app.listen(port, hostname, () => {
  console.log(`✅ Server running at http://${hostname}:${port}`);
});
