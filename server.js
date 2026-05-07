const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

const corsOptions = {
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(__dirname));

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const user = await db.verifyUser(username.trim(), password);
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const sessionToken = await db.createSession(user.id);

    res.json({
      success: true,
      message: 'Login successful',
      user,
      sessionToken,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name } = req.body;

    if (!username || !password || !name) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }

    const userId = await db.createUser(username.trim(), password, name.trim());
    res.json({ success: true, message: 'User registered successfully', userId });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Registration failed' });
  }
});

app.post('/api/hash-demo', async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ message: 'Password is required' });
    }
    const hash = await bcrypt.hash(password, 10);
    res.json({ success: true, hash, algorithm: 'bcrypt', saltRounds: 10 });
  } catch (error) {
    console.error('Hash demo error:', error);
    res.status(500).json({ message: 'Hashing failed' });
  }
});

app.get('/api/test-db', async (req, res) => {
  try {
    const connected = await db.testConnection();
    if (!connected) {
      return res.status(500).json({ success: false, message: 'Database connection failed' });
    }
    res.json({ success: true, message: 'Database connection successful' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Database connection failed', error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString(), service: 'SecureAuth API', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(`✅ SecureAuth API running at http://localhost:${PORT}`);
});