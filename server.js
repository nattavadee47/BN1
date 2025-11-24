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
    origin: '*', // หรือระบุ domain ที่ชัดเจน
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
    
    // ✅ ตรวจสอบว่า user_id เป็น number
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
    user_id: parseInt(user_id), // ✅ ต้องมี parseInt
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

// ฟังก์ชันแปลงค่าภาษาไทย-อังกฤษ (เพิ่มหลัง const createConnection)
function normalizeEnumValue(value, type) {
  if (!value) return null;
  
  const mappings = {
    role: {
      'ผู้ป่วย': 'Patient',
      'Patient': 'Patient',
      'นักกายภาพบำบัด': 'Physiotherapist',
      'Physiotherapist': 'Physiotherapist',
      'ผู้ดูแล': 'Caregiver',
      'Caregiver': 'Caregiver',
      'Admin': 'Admin'
    },
    gender: {
      'ชาย': 'Male',
      'Male': 'Male',
      'หญิง': 'Female',
      'Female': 'Female',
      'อื่นๆ': 'Other',
      'Other': 'Other'
    },
    injured_side: {
      'ซ้าย': 'Left',
      'Left': 'Left',
      'ขวา': 'Right',
      'Right': 'Right',
      'ทั้งสองข้าง': 'Both',
      'Both': 'Both'
    },
    injured_part: {
      'แขน': 'Arm',
      'Arm': 'Arm',
      'ขา': 'Leg',
      'Leg': 'Leg',
      'ลำตัว': 'Trunk',
      'Trunk': 'Trunk',
      'หัว': 'Head',
      'Head': 'Head',
      'อื่นๆ': 'Other',
      'Other': 'Other'
    }
  };
  
  return mappings[type]?.[value] || value;
}

// ========================
// จัดการข้อมูลผู้ใช้ (User Management CRUD)
// ========================

// ดูรายชื่อผู้ใช้ทั้งหมด (เฉพาะผู้ดูแลระบบ)
app.get('/api/users', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
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
  const userId = parseInt(req.params.id);
  
  try {
    const tokenUserId = parseInt(req.user.user_id);
    const requestedUserId = parseInt(userId);
    
    if (tokenUserId !== requestedUserId && !isAdmin(req.user.role)) {
      console.log('❌ Authorization failed');
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

    if (user.role === 'Patient' || user.role === 'ผู้ป่วย') {
      const [patients] = await connection.execute(
        'SELECT * FROM Patients WHERE user_id = ?',
        [userId]
      );
      profileData.patient_info = patients[0] || null;
    } else if (user.role === 'Physiotherapist' || user.role === 'นักกายภาพบำบัด') {
      const [physios] = await connection.execute(
        'SELECT * FROM Physiotherapists WHERE user_id = ?',
        [userId]
      );
      profileData.physiotherapist_info = physios[0] || null;
    } else if (user.role === 'Caregiver' || user.role === 'ผู้ดูแล') {
      const [caregivers] = await connection.execute(
        'SELECT * FROM Caregivers WHERE user_id = ?',
        [userId]
      );
      profileData.caregiver_info = caregivers[0] || null;
    }

    console.log('✅ Profile loaded successfully for user:', userId);

    res.json({
      success: true,
      data: profileData
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

// ลบผู้ใช้ (เฉพาะผู้ดูแลระบบ)
app.delete('/api/users/:id', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
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
  const userId = parseInt(req.params.id);
  
  try {
    const tokenUserId = Number(req.user.user_id);
    const requestedUserId = Number(userId);
    
    if (tokenUserId !== requestedUserId && !isAdmin(req.user.role)) {
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
    if (!isAdmin(req.user.role)) {
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
  if (!isAdmin(req.user.role)) {
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

// ฟังก์ชันประเมินผลการออกกำลังกาย
async function evaluateExercisePerformance(connection, exerciseId, actualReps, holdTime) {
    const [criteria] = await connection.execute(
        'SELECT * FROM Exercise_Criteria WHERE exercise_id = ?',
        [exerciseId]
    );
    
    if (criteria.length === 0) {
        return { level: 'unknown', message: 'ไม่พบเกณฑ์การประเมิน' };
    }
    
    const standard = criteria[0];
    let level = 'needs_improvement';
    let message = 'ควรพยายามต่อไป';
    
    if (actualReps >= standard.min_reps_excellent) {
        level = 'excellent';
        message = 'ดีเยี่ยม! ทำได้ตามเป้าหมาย';
    } else if (actualReps >= standard.min_reps_good) {
        level = 'good';
        message = 'ดี! ใกล้เป้าหมายแล้ว';
    }
    
    return {
        level,
        message,
        actual_reps: actualReps,
        target_good: standard.min_reps_good,
        target_excellent: standard.min_reps_excellent,
        hold_time_met: holdTime >= standard.min_hold_time
    };
}

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

        // หา plan_id
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
                [patientId, physios[0].physio_id, 'แผนการกึกอัตโนมัติ']
            );
            planId = planResult.insertId;
        }

          // ✅ ถูกต้อง - บันทึกเวลาไทยแล้วแปลงเป็น UTC
          // บันทึก Session ด้วยเวลาไทยปัจจุบัน
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

        // ✅ ตรวจสอบเวลาที่บันทึก
        const [checkTime] = await connection.execute(
            `SELECT 
                session_date,
                CONVERT_TZ(session_date, @@session.time_zone, '+07:00') as thai_time,
                @@session.time_zone as current_tz
            FROM Exercise_Sessions 
            WHERE session_id = ?`,
            [sessionResult.insertId]
        );

        console.log('⏰ Time check:', {
            session_id: sessionResult.insertId,
            saved_time: checkTime[0]?.session_date,
            thai_time: checkTime[0]?.thai_time,
            timezone: checkTime[0]?.current_tz,
            server_time: new Date().toISOString(),
            bangkok_time: new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok' })
        });

        await connection.end();

        res.status(201).json({
            success: true,
            message: 'บันทึกสำเร็จ',
            data: {
                session_id: sessionResult.insertId,
                actual_reps_left: parseInt(actual_reps_left) || 0,
                actual_reps_right: parseInt(actual_reps_right) || 0,
                total: total_reps,
                accuracy_percent: parseFloat(accuracy_percent) || 0,
                duration_seconds: parseInt(duration_seconds) || 0,
                saved_time: checkTime[0]?.saved_time,
                thai_time: checkTime[0]?.thai_time
            }
        });

    } catch (error) {
        console.error('❌ Error:', error);
        if (connection) await connection.end();
        res.status(500).json({ 
            success: false, 
            message: 'เกิดข้อผิดพลาด',
            error: error.message 
        });
    }
});

app.get('/api/exercise-sessions', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [patients] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (patients.length === 0) {
      return res.status(404).json({ success: false, message: 'ไม่พบข้อมูลผู้ป่วย' });
    }
    
    const patientId = patients[0].patient_id;

    // ✅ เพิ่มฟิลด์ชื่อท่าและข้อมูลซ้าย-ขวา
    const [sessions] = await connection.execute(`
      SELECT 
          es.session_id,
          es.patient_id,
          es.exercise_id,
          es.plan_id,
          es.session_date,
          es.actual_reps,
          es.actual_reps_left,
          es.actual_reps_right,
          es.accuracy_percent,
          es.duration_seconds,
          es.notes,
          e.name_th as exercise_name_th,
          e.name_en as exercise_name_en,
          e.description
      FROM Exercise_Sessions es
      JOIN Exercises e ON es.exercise_id = e.exercise_id
      JOIN ExercisePlans ep ON es.plan_id = ep.plan_id
      WHERE es.patient_id = ?
      ORDER BY es.session_date DESC
      LIMIT 50
    `, [patientId]);

    console.log('✅ Loaded sessions:', {
      count: sessions.length,
      sample: sessions[0] ? {
        exercise_name_th: sessions[0].exercise_name_th,
        exercise_name_en: sessions[0].exercise_name_en,
        left: sessions[0].actual_reps_left,
        right: sessions[0].actual_reps_right,
        total: sessions[0].actual_reps,
        date: sessions[0].session_date
      } : null
    });

    res.json({
      success: true,
      data: sessions,
      total: sessions.length
    });

  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาด' });
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
// ========================
// ADMIN DASHBOARD APIs
// ========================

// ดึงสถิติ Dashboard
app.get('/api/admin/dashboard/stats', authenticateToken, async (req, res) => {
  console.log('📊 Dashboard stats request from:', {
    user_id: req.user.user_id,
    role: req.user.role
  });

  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ 
      success: false, 
      message: 'ไม่มีสิทธิ์เข้าถึง - ต้องการบทบาท Admin',
      current_role: req.user.role
    });
  }

  const connection = await createConnection();
  
  try {
    // นับผู้ใช้ทั้งหมด
    const [totalUsers] = await connection.execute(
      'SELECT COUNT(*) as count FROM Users'
    );

    // นับผู้ป่วยใหม่ (30 วันล่าสุด)
    const [newPatients] = await connection.execute(
      `SELECT COUNT(*) as count FROM Users 
       WHERE role = 'Patient' AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)`
    );

    // นับ sessions ทั้งหมด
    const [totalSessions] = await connection.execute(
      'SELECT COUNT(*) as count FROM Exercise_Sessions'
    );

    console.log('✅ Dashboard stats loaded:', {
      totalUsers: totalUsers[0].count,
      newPatients: newPatients[0].count,
      totalSessions: totalSessions[0].count
    });

    res.json({
      success: true,
      data: {
        totalUsers: totalUsers[0].count,
        newPatients: newPatients[0].count,
        totalSessions: totalSessions[0].count
      }
    });

  } catch (error) {
    console.error('❌ Error loading dashboard stats:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสถิติ',
      error: error.message
    });
  } finally {
    await connection.end();
  }
});


// ดูรายชื่อผู้ใช้ทั้งหมด (สำหรับ Admin)
app.get('/api/admin/users', authenticateToken, async (req, res) => {
  console.log('👥 Users list request from:', {
    user_id: req.user.user_id,
    role: req.user.role
  });

  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ 
      success: false, 
      message: 'ไม่มีสิทธิ์เข้าถึง',
      current_role: req.user.role
    });
  }

  const connection = await createConnection();
  
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const [users] = await connection.execute(`
      SELECT user_id, phone, full_name, role, created_at, updated_at 
      FROM Users 
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);

    const [totalCount] = await connection.execute(
      'SELECT COUNT(*) as total FROM Users'
    );

    console.log('✅ Users loaded:', {
      count: users.length,
      total: totalCount[0].total
    });

    res.json({
      success: true,
      data: users,
      pagination: {
        page,
        limit,
        total: totalCount[0].total,
        totalPages: Math.ceil(totalCount[0].total / limit)
      }
    });

  } catch (error) {
    console.error('❌ Error loading users:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ใช้',
      error: error.message
    });
  } finally {
    await connection.end();
  }
});

// ดูข้อมูลผู้ใช้รายบุคคล (Admin)
app.get('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }
  const connection = await createConnection();
  const userId = parseInt(req.params.id);
  
  try {
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

    res.json({
      success: true,
      data: users[0]
    });

  } catch (error) {
    console.error('Error loading user:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล'
    });
  } finally {
    await connection.end();
  }
});

// สร้างผู้ใช้ใหม่ (Admin)
app.post('/api/admin/users', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  
  try {
    const { phone, password, full_name, role } = req.body;

    // ตรวจสอบข้อมูล
    if (!phone || !password || !full_name || !role) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
      });
    }

    // เข้ารหัสรหัสผ่าน
    const password_hash = await bcrypt.hash(password, 12);

    // เพิ่มผู้ใช้
    const [result] = await connection.execute(
      'INSERT INTO Users (phone, password_hash, full_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
      [phone, password_hash, full_name, role]
    );

    res.status(201).json({
      success: true,
      message: 'สร้างผู้ใช้สำเร็จ',
      data: {
        user_id: result.insertId,
        phone,
        full_name,
        role
      }
    });

  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการสร้างผู้ใช้'
    });
  } finally {
    await connection.end();
  }
});

// แก้ไขผู้ใช้ (Admin)
app.put('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  const userId = parseInt(req.params.id);
  
  try {
    const { phone, full_name, role } = req.body;

    const updates = [];
    const values = [];

    if (phone) {
      updates.push('phone = ?');
      values.push(phone);
    }
    if (full_name) {
      updates.push('full_name = ?');
      values.push(full_name);
    }
    if (role) {
      updates.push('role = ?');
      values.push(role);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'ไม่มีข้อมูลที่ต้องการแก้ไข'
      });
    }

    updates.push('updated_at = NOW()');
    values.push(userId);

    await connection.execute(
      `UPDATE Users SET ${updates.join(', ')} WHERE user_id = ?`,
      values
    );

    res.json({
      success: true,
      message: 'แก้ไขข้อมูลสำเร็จ'
    });

  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการแก้ไขข้อมูล'
    });
  } finally {
    await connection.end();
  }
});

// ลบผู้ใช้ (Admin)
app.delete('/api/admin/users/:id', authenticateToken, async (req, res) => {
  if (!isAdmin(req.user.role)) {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง' });
  }

  const connection = await createConnection();
  const userId = parseInt(req.params.id);
  
  try {
    await connection.execute(
      'DELETE FROM Users WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      message: 'ลบผู้ใช้สำเร็จ'
    });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการลบผู้ใช้'
    });
  } finally {
    await connection.end();
  }
});
// ========================
// DEBUG ENDPOINTS (ลบออกหลังแก้ปัญหาเสร็จ)
// ========================

// Debug: ดูข้อมูล Admin ทั้งหมด
app.get('/api/debug/admins', async (req, res) => {
  const connection = await createConnection();
  
  try {
    const [admins] = await connection.execute(
      'SELECT user_id, phone, full_name, role, created_at FROM Users WHERE role = ?',
      ['Admin']
    );

    res.json({
      success: true,
      count: admins.length,
      admins: admins.map(admin => ({
        user_id: admin.user_id,
        phone: admin.phone,
        full_name: admin.full_name,
        role: admin.role,
        created_at: admin.created_at
      }))
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  } finally {
    await connection.end();
  }
});
 // ========================
// Caregiver APIs - ระบบผู้ดูแลผู้ป่วย
// ========================

// ✅ ดึงผู้ป่วยที่ผู้ดูแลดูแล (ผ่านเบอร์ฉุกเฉิน)
app.get('/api/caregiver/patients', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  
  try {
    console.log('👨‍👩‍👧 Loading patients for caregiver:', req.user.user_id);
    
    // ดึงข้อมูล Caregiver
    const [caregivers] = await connection.execute(
      'SELECT * FROM Caregivers WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (caregivers.length === 0) {
      console.log('⚠️ Caregiver record not found');
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ดูแล กรุณาติดต่อเจ้าหน้าที่'
      });
    }
    
    // ดึงเบอร์โทรของผู้ดูแล
    const [users] = await connection.execute(
      'SELECT phone, full_name FROM Users WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }
    
    const caregiverPhone = users[0].phone;
    const caregiverName = users[0].full_name;
    console.log('📞 Caregiver phone:', caregiverPhone);
    console.log('👤 Caregiver name:', caregiverName);
    
    // ✅ ดึงผู้ป่วยที่มีเบอร์ฉุกเฉินตรงกับเบอร์ผู้ดูแล
    const [patients] = await connection.execute(`
      SELECT 
        p.*,
        u.phone as user_phone,
        u.full_name
      FROM Patients p
      JOIN Users u ON p.user_id = u.user_id
      WHERE p.emergency_contact_phone = ?
      ORDER BY p.patient_id DESC
    `, [caregiverPhone]);
    
    console.log(`✅ Found ${patients.length} patient(s) for caregiver: ${caregiverName}`);
    
    res.json({
      success: true,
      data: patients,
      caregiver_info: {
        caregiver_id: caregivers[0].caregiver_id,
        phone: caregiverPhone,
        name: caregiverName,
        relationship: caregivers[0].relationship,
        patients_count: patients.length
      },
      message: patients.length === 0 ? 'ยังไม่มีผู้ป่วยในความดูแล กรุณาติดต่อเจ้าหน้าที่เพื่อเพิ่มเบอร์โทรของคุณเป็นเบอร์ฉุกเฉินในข้อมูลผู้ป่วย' : null
    });
    
  } catch (error) {
    console.error('❌ Error loading caregiver patients:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูลผู้ป่วย',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await connection.end();
  }
});

// ✅ ดึงรายละเอียดผู้ป่วยรายเดียว (ต้องเป็นผู้ป่วยที่ดูแล)
app.get('/api/caregiver/patients/:patientId', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const patientId = parseInt(req.params.patientId);
  
  try {
    console.log('🔍 Loading patient details:', patientId);
    
    // ดึงเบอร์โทรของผู้ดูแล
    const [users] = await connection.execute(
      'SELECT phone FROM Users WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }
    
    const caregiverPhone = users[0].phone;
    console.log('📞 Verifying access for caregiver:', caregiverPhone);
    
    // ตรวจสอบว่าผู้ป่วยนี้อยู่ในความดูแลหรือไม่
    const [patients] = await connection.execute(`
      SELECT 
        p.*,
        u.phone as user_phone,
        u.full_name,
        u.created_at as registration_date
      FROM Patients p
      JOIN Users u ON p.user_id = u.user_id
      WHERE p.patient_id = ? AND p.emergency_contact_phone = ?
    `, [patientId, caregiverPhone]);
    
    if (patients.length === 0) {
      console.log('⚠️ Access denied - patient not under care');
      return res.status(403).json({
        success: false,
        message: 'คุณไม่มีสิทธิ์เข้าถึงข้อมูลผู้ป่วยรายนี้'
      });
    }
    
    console.log('✅ Patient details loaded');
    
    res.json({
      success: true,
      data: {
        patient: patients[0]
      }
    });
    
  } catch (error) {
    console.error('❌ Error loading patient details:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await connection.end();
  }
});

// ✅ ดึงสถิติการฝึกของผู้ป่วย (ต้องเป็นผู้ป่วยที่ดูแล)
app.get('/api/caregiver/patients/:patientId/stats', authenticateToken, async (req, res) => {
  const connection = await createConnection();
  const patientId = parseInt(req.params.patientId);
  
  try {
    console.log('📊 Loading stats for patient:', patientId);
    
    // ตรวจสอบสิทธิ์
    const [users] = await connection.execute(
      'SELECT phone FROM Users WHERE user_id = ?',
      [req.user.user_id]
    );
    
    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'ไม่พบข้อมูลผู้ใช้'
      });
    }
    
    const caregiverPhone = users[0].phone;
    
    // ตรวจสอบว่าเป็นผู้ป่วยที่ดูแล
    const [patients] = await connection.execute(
      'SELECT patient_id FROM Patients WHERE patient_id = ? AND emergency_contact_phone = ?',
      [patientId, caregiverPhone]
    );
    
    if (patients.length === 0) {
      console.log('⚠️ Access denied - patient not under care');
      return res.status(403).json({
        success: false,
        message: 'คุณไม่มีสิทธิ์เข้าถึงข้อมูลผู้ป่วยรายนี้'
      });
    }
    
    // ดึงสถิติรวม
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
      WHERE patient_id = ? 
        AND session_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)
      GROUP BY DATE(session_date)
      ORDER BY session_date ASC
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
    
    console.log('✅ Stats loaded successfully');

    res.json({
      success: true,
      data: {
        total_stats: totalStats[0],
        weekly_progress: weeklyStats,
        popular_exercises: popularExercises
      }
    });

  } catch (error) {
    console.error('❌ Error loading patient stats:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงสถิติ',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  } finally {
    await connection.end();
  }
});

// ========================
// API Endpoint สำหรับค้นหาผู้ป่วยด้วยเบอร์โทรศัพท์
// เพิ่มใน server.js
// ========================

// ค้นหาผู้ใช้ด้วยเบอร์โทรศัพท์ (สำหรับ Caregiver ค้นหาผู้ป่วย)
app.get('/api/users/search-by-phone/:phone', async (req, res) => {
  let connection;
  
  try {
    const { phone } = req.params;
    
    console.log('🔍 Searching for user with phone:', phone);
    
    // ตรวจสอบเบอร์โทรศัพท์
    if (!phone || phone.length !== 10) {
      return res.status(400).json({
        success: false,
        message: 'เบอร์โทรศัพท์ต้องเป็นตัวเลข 10 หลัก'
      });
    }
    
    connection = await createConnection();
    
    // ค้นหาผู้ใช้จากเบอร์โทรศัพท์
    const [users] = await connection.execute(
      `SELECT 
        user_id,
        phone,
        first_name,
        last_name,
        birth_date,
        gender,
        role,
        created_at
      FROM users 
      WHERE phone = ?`,
      [phone]
    );
    
    if (users.length === 0) {
      console.log('❌ User not found with phone:', phone);
      return res.status(404).json({
        success: false,
        message: 'ไม่พบผู้ใช้งานที่มีเบอร์โทรศัพท์นี้'
      });
    }
    
    const user = users[0];
    
    console.log('✅ User found:', {
      user_id: user.user_id,
      name: `${user.first_name} ${user.last_name}`,
      role: user.role
    });
    
    // ไม่ส่งข้อมูลที่ sensitive
    const { password_hash, ...userData } = user;
    
    res.json({
      success: true,
      message: 'พบข้อมูลผู้ใช้งาน',
      data: userData
    });
    
  } catch (error) {
    console.error('❌ Error searching user by phone:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการค้นหา',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// แก้ไข API Register เพื่อรองรับ Caregiver
// ========================

app.post('/api/auth/register', async (req, res) => {
  let connection;
  
  try {
    const {
      phone,
      password,
      first_name,
      last_name,
      birth_date,
      gender,
      role,
      // ข้อมูลผู้ป่วย
      weight,
      height,
      injured_side,
      injured_part,
      emergency_contact_name,
      emergency_contact_phone,
      emergency_contact_relation,
      // ข้อมูล Caregiver
      patient_id,
      patient_phone,
      relationship,
      // ข้อมูลนักกายภาพบำบัด
      license_number,
      specialization
    } = req.body;

    console.log('📝 Registration request:', {
      phone,
      role,
      name: `${first_name} ${last_name}`,
      patient_id: patient_id || 'N/A'
    });

    // Validation
    if (!phone || !password || !first_name || !last_name || !birth_date || !gender || !role) {
      return res.status(400).json({
        success: false,
        message: 'กรุณากรอกข้อมูลให้ครบถ้วน'
      });
    }

    if (!/^[0-9]{10}$/.test(phone)) {
      return res.status(400).json({
        success: false,
        message: 'เบอร์โทรศัพท์ต้องเป็นตัวเลข 10 หลัก'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'รหัสผ่านต้องมีอย่างน้อย 6 ตัวอักษร'
      });
    }

    // ตรวจสอบว่า Caregiver ต้องระบุ patient_id
    if (role === 'ผู้ช่วยผู้ดูแล' && !patient_id) {
      return res.status(400).json({
        success: false,
        message: 'กรุณาค้นหาและเลือกผู้ป่วยที่ต้องการดูแล'
      });
    }

    connection = await createConnection();

    // ตรวจสอบเบอร์โทรซ้ำ
    const [existingUsers] = await connection.execute(
      'SELECT user_id FROM users WHERE phone = ?',
      [phone]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'เบอร์โทรศัพท์นี้มีการลงทะเบียนแล้ว'
      });
    }

    // เข้ารหัสรหัสผ่าน
    const hashedPassword = await bcrypt.hash(password, 10);

    // สร้าง full_name
    const full_name = `${first_name} ${last_name}`;

    // เริ่ม transaction
    await connection.beginTransaction();

    try {
      // Insert user
      const [userResult] = await connection.execute(
        `INSERT INTO users (
          phone, password_hash, first_name, last_name, full_name,
          birth_date, gender, role, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
        [phone, hashedPassword, first_name, last_name, full_name, birth_date, gender, role]
      );

      const userId = userResult.insertId;
      console.log('✅ User created with ID:', userId);

      // ถ้าเป็นผู้ป่วย - บันทึกข้อมูลเพิ่มเติม
      if (role === 'ผู้ป่วย') {
        await connection.execute(
          `INSERT INTO patients (
            user_id, weight, height, injured_side, injured_part,
            emergency_contact_name, emergency_contact_phone, emergency_contact_relation,
            created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            userId,
            weight || null,
            height || null,
            injured_side || null,
            injured_part || null,
            emergency_contact_name || null,
            emergency_contact_phone || null,
            emergency_contact_relation || null
          ]
        );
        console.log('✅ Patient data saved');
      }

      // ถ้าเป็น Caregiver - เชื่อมโยงกับผู้ป่วย
      if (role === 'ผู้ช่วยผู้ดูแล' && patient_id) {
        // ตรวจสอบว่าผู้ป่วยมีอยู่จริง
        const [patients] = await connection.execute(
          'SELECT user_id FROM users WHERE user_id = ? AND role = ?',
          [patient_id, 'ผู้ป่วย']
        );

        if (patients.length === 0) {
          throw new Error('ไม่พบข้อมูลผู้ป่วยในระบบ');
        }

        // บันทึกข้อมูล Caregiver
        await connection.execute(
          `INSERT INTO caregivers (
            user_id, patient_id, relationship, created_at
          ) VALUES (?, ?, ?, NOW())`,
          [userId, patient_id, relationship || null]
        );
        
        // อัพเดทเบอร์ฉุกเฉินของผู้ป่วย (ถ้ายังไม่มี)
        await connection.execute(
          `UPDATE patients 
           SET emergency_contact_phone = COALESCE(emergency_contact_phone, ?),
               emergency_contact_name = COALESCE(emergency_contact_name, ?),
               emergency_contact_relation = COALESCE(emergency_contact_relation, ?)
           WHERE user_id = ?`,
          [phone, full_name, relationship || 'ผู้ช่วยดูแล', patient_id]
        );
        
        console.log('✅ Caregiver linked to patient:', patient_id);
      }

      // ถ้าเป็นนักกายภาพบำบัด - บันทึกข้อมูลใบประกอบวิชาชีพ
      if (role === 'นักกายภาพบำบัด') {
        await connection.execute(
          `INSERT INTO physiotherapists (
            user_id, license_number, specialization, created_at
          ) VALUES (?, ?, ?, NOW())`,
          [userId, license_number || null, specialization || null]
        );
        console.log('✅ Physiotherapist data saved');
      }

      // Commit transaction
      await connection.commit();

      // สร้าง JWT token
      const token = jwt.sign(
        {
          user_id: userId,
          phone: phone,
          role: role,
          full_name: full_name
        },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      console.log('✅ Registration successful for:', full_name);

      res.status(201).json({
        success: true,
        message: 'สมัครสมาชิกสำเร็จ',
        data: {
          user_id: userId,
          phone: phone,
          full_name: full_name,
          role: role,
          token: token
        }
      });

    } catch (error) {
      // Rollback transaction on error
      await connection.rollback();
      throw error;
    }

  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      success: false,
      message: error.message || 'เกิดข้อผิดพลาดในการสมัครสมาชิก',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// ========================
// API สำหรับ Caregiver ดูข้อมูลผู้ป่วยที่ดูแล
// ========================

app.get('/api/caregiver/patients', authenticateToken, async (req, res) => {
  let connection;
  
  try {
    const caregiverId = req.user.user_id;
    
    console.log('👥 Fetching patients for caregiver:', caregiverId);
    
    connection = await createConnection();
    
    // ดึงรายชื่อผู้ป่วยที่ Caregiver ดูแล
    const [patients] = await connection.execute(
      `SELECT 
        u.user_id as patient_id,
        u.phone,
        u.first_name,
        u.last_name,
        u.full_name,
        u.birth_date,
        u.gender,
        p.injured_side,
        p.injured_part,
        c.relationship,
        c.created_at as caregiver_since
      FROM caregivers c
      INNER JOIN users u ON c.patient_id = u.user_id
      LEFT JOIN patients p ON u.user_id = p.user_id
      WHERE c.user_id = ?
      ORDER BY c.created_at DESC`,
      [caregiverId]
    );
    
    console.log('✅ Found', patients.length, 'patients');
    
    // ดึงข้อมูล Caregiver
    const [caregiver] = await connection.execute(
      'SELECT phone, full_name FROM users WHERE user_id = ?',
      [caregiverId]
    );
    
    res.json({
      success: true,
      message: 'ดึงข้อมูลผู้ป่วยสำเร็จ',
      data: patients,
      caregiver_info: caregiver[0] || null
    });
    
  } catch (error) {
    console.error('❌ Error fetching caregiver patients:', error);
    res.status(500).json({
      success: false,
      message: 'เกิดข้อผิดพลาดในการดึงข้อมูล',
      error: error.message
    });
  } finally {
    if (connection) await connection.end();
  }
});

// Debug: สร้าง Admin ทดสอบ
app.post('/api/debug/create-admin', async (req, res) => {
  const connection = await createConnection();
  
  try {
    const phone = '0800000000';
    const password = 'admin123';
    const full_name = 'Admin Test';
    
    // ตรวจสอบว่ามีอยู่แล้วหรือไม่
    const [existing] = await connection.execute(
      'SELECT user_id FROM Users WHERE phone = ?',
      [phone]
    );
    
    if (existing.length > 0) {
      // อัปเดตรหัสผ่านของ Admin ที่มีอยู่
      const password_hash = await bcrypt.hash(password, 12);
      await connection.execute(
        'UPDATE Users SET password_hash = ?, updated_at = NOW() WHERE phone = ?',
        [password_hash, phone]
      );
      
      return res.json({
        success: true,
        message: 'อัปเดตรหัสผ่าน Admin สำเร็จ',
        credentials: {
          phone: phone,
          password: password,
          user_id: existing[0].user_id
        }
      });
    }
    
    // สร้างใหม่
    const password_hash = await bcrypt.hash(password, 12);
    
    const [result] = await connection.execute(
      'INSERT INTO Users (phone, password_hash, full_name, role, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())',
      [phone, password_hash, full_name, 'Admin']
    );

    res.json({
      success: true,
      message: 'สร้าง Admin ทดสอบสำเร็จ',
      credentials: {
        phone: phone,
        password: password,
        user_id: result.insertId
      }
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  } finally {
    await connection.end();
  }
});

// Debug: ทดสอบ Token
app.get('/api/debug/me', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      user_id: req.user.user_id,
      phone: req.user.phone,
      role: req.user.role,
      user_id_type: typeof req.user.user_id
    }
  });
});

// Debug: ตรวจสอบรหัสผ่าน
app.post('/api/debug/check-password', async (req, res) => {
  const connection = await createConnection();
  
  try {
    const { phone, password } = req.body;
    
    const [users] = await connection.execute(
      'SELECT user_id, phone, password_hash, role FROM Users WHERE phone = ?',
      [phone]
    );

    if (users.length === 0) {
      return res.json({
        success: false,
        message: 'ไม่พบเบอร์โทรศัพท์นี้ในระบบ'
      });
    }

    const user = users[0];
    const isValid = await bcrypt.compare(password, user.password_hash);

    res.json({
      success: true,
      phone: user.phone,
      role: user.role,
      password_match: isValid,
      hash_preview: user.password_hash.substring(0, 20) + '...'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.message
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

app.listen(port, '0.0.0.0', () => { // ✅ ถูกต้องแล้ว
    console.log(`Server running on port ${port}`);
});