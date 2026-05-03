require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const SALT_ROUNDS = 10;

const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME     || 'secureauth',
  waitForConnections: true,
  connectionLimit: 10
});

async function init() {
  try {
    const [rows] = await pool.query('SELECT COUNT(*) AS count FROM users');
    if (rows[0].count === 0) {
      const hash = await bcrypt.hash('SecurePass123!', SALT_ROUNDS);
      await pool.query(
        'INSERT INTO users (username, password_hash, name) VALUES (?, ?, ?)',
        ['student', hash, 'Student']
      );
      console.log('✅ Demo user inserted into MySQL');
    }
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

async function verifyUser(username, password) {
  const sanitized = username.replace(/[^a-zA-Z0-9_]/g, '');
  const [rows] = await pool.query(
    'SELECT * FROM users WHERE username = ?',
    [sanitized]
  );
  if (rows.length === 0) return null;
  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return null;
  return { id: user.id, username: user.username, name: user.name };
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}

async function createUser(username, password, name) {
  const [existing] = await pool.query(
    'SELECT id FROM users WHERE username = ?',
    [username]
  );
  if (existing.length > 0) throw new Error('Username already taken');
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const [result] = await pool.query(
    'INSERT INTO users (username, password_hash, name) VALUES (?, ?, ?)',
    [username, passwordHash, name]
  );
  return result.insertId;
}

async function testConnection() {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

init();

module.exports = { verifyUser, createSession, createUser, testConnection };
