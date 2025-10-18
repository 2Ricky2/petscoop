const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ✅ MySQL connection (Railway DB = "railway")
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME || 'railway', // <-- fallback for safety
});

db.connect((err) => {
  if (err) console.error('❌ Database connection failed:', err);
  else console.log('✅ MySQL Connected to Railway DB');
});

// ========================= ROUTES =========================

// Signup
app.post('/signup', async (req, res) => {
  const { user_name, user_email, user_pass } = req.body;
  if (!user_name || !user_email || !user_pass)
    return res.json({ success: false, message: 'All fields required' });

  db.query('SELECT * FROM users WHERE user_email = ?', [user_email], async (err, result) => {
    if (err) return res.json({ success: false, message: 'DB error' });
    if (result.length > 0)
      return res.json({ success: false, message: 'Email already exists' });

    const hashed = await bcrypt.hash(user_pass, 10);
    db.query(
      'INSERT INTO users (user_name, user_email, user_pass, role) VALUES (?, ?, ?, ?)',
      [user_name, user_email, hashed, 'user'],
      (err2) => {
        if (err2) return res.json({ success: false, message: 'Insert error' });
        return res.json({ success: true, message: 'User created successfully!' });
      }
    );
  });
});

// Login
app.post('/login', (req, res) => {
  const { user_email, user_pass } = req.body;
  if (!user_email || !user_pass)
    return res.json({ success: false, message: 'All fields required' });

  db.query('SELECT * FROM users WHERE user_email = ?', [user_email], async (err, result) => {
    if (err) return res.json({ success: false, message: 'DB error' });
    if (result.length === 0)
      return res.json({ success: false, message: 'User not found' });

    const user = result[0];
    const isMatch = await bcrypt.compare(user_pass, user.user_pass);
    if (!isMatch)
      return res.json({ success: false, message: 'Invalid password' });

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.user_id,
        username: user.user_name,
        email: user.user_email,
        role: user.role,
      },
    });
  });
});

// Upload image
app.post('/upload', upload.single('image'), (req, res) => {
  if (!req.file)
    return res.json({ success: false, message: 'No file uploaded' });
  const imageUrl = `${process.env.BASE_URL}/uploads/${req.file.filename}`;
  return res.json({ success: true, imageUrl });
});

// Pets management
app.get('/pets', (req, res) => {
  db.query('SELECT * FROM pets ORDER BY pet_id DESC', (err, results) => {
    if (err) return res.json({ success: false, message: 'DB error' });
    return res.json({ success: true, pets: results });
  });
});

app.post('/add-pet', (req, res) => {
  const { pet_name, pet_desc, pet_image } = req.body;
  if (!pet_name || !pet_desc || !pet_image)
    return res.json({ success: false, message: 'All fields required' });

  db.query(
    'INSERT INTO pets (pet_name, pet_desc, pet_image) VALUES (?, ?, ?)',
    [pet_name, pet_desc, pet_image],
    (err) => {
      if (err) return res.json({ success: false, message: 'DB insert error' });
      res.json({ success: true, message: 'Pet added successfully' });
    }
  );
});

// Server listen
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
