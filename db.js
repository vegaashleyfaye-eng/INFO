require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const SALT_ROUNDS = 10;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

async function init() {
  try {
    const result = await pool.query('SELECT COUNT(*) AS count FROM users');
    if (parseInt(result.rows[0].count, 10) === 0) {
      const hash = await bcrypt.hash('SecurePass123!', SALT_ROUNDS);
      await pool.query(
        'INSERT INTO users (username, password_hash, name) VALUES ($1, $2, $3)',
        ['student', hash, 'Student']
      );
      console.log('✅ Demo user inserted into PostgreSQL');
    }
  } catch (err) {
    console.error('DB init error:', err.message);
  }
}

async function verifyUser(username, password) {
  const sanitized = username.replace(/[^a-zA-Z0-9_]/g, '');
  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [sanitized]
  );
  if (result.rows.length === 0) return null;
  const user = result.rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return null;
  return { id: user.id, username: user.username, name: user.name };
}

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  return token;
}

async function createUser(username, password, name) {
  const existing = await pool.query(
    'SELECT id FROM users WHERE username = $1',
    [username]
  );
  if (existing.rows.length > 0) throw new Error('Username already taken');
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  const result = await pool.query(
    'INSERT INTO users (username, password_hash, name) VALUES ($1, $2, $3) RETURNING id',
    [username, passwordHash, name]
  );
  return result.rows[0].id;
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