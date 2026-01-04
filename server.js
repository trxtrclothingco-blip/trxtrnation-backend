require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

const users = {}; // TEMP memory store

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  if (users[email]) return res.status(400).json({ error: 'User exists' });

  const hash = await bcrypt.hash(password, 10);
  const code = generateCode();

  users[email] = {
    username,
    email,
    password: hash,
    verified: false,
    code,
    paid: false
  };

  await transporter.sendMail({
    to: email,
    subject: 'TRXTRNATION Verification Code',
    text: `Your verification code is: ${code}`
  });

  res.json({ success: true });
});

app.post('/verify', (req, res) => {
  const { email, code } = req.body;
  const user = users[email];
  if (!user || user.code !== code) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  user.verified = true;
  delete user.code;
  res.json({ success: true });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  if (!user || !user.verified) {
    return res.status(400).json({ error: 'Invalid login' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid login' });

  const token = jwt.sign(
    { email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({
    token,
    username: user.username,
    paid: user.paid
  });
});

app.get('/check', auth, (req, res) => {
  const user = users[req.user.email];
  res.json({
    username: user.username,
    paid: user.paid
  });
});

app.post('/pay', auth, (req, res) => {
  users[req.user.email].paid = true;
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Backend running'));
