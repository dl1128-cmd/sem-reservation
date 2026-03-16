const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();

const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error('ERROR: DATABASE_URL 환경 변수가 설정되지 않았습니다!');
} else {
  console.log('DATABASE_URL 설정됨:', dbUrl.replace(/\/\/.*:.*@/, '//***:***@'));
}

const pool = new Pool({
  connectionString: dbUrl,
  ssl: { rejectUnauthorized: false }
});

// Create tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      phone TEXT NOT NULL DEFAULT '',
      advisor TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      approved INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reservations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      date TEXT NOT NULL,
      start_time TEXT NOT NULL,
      end_time TEXT NOT NULL,
      purpose TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Create or update admin account
  const adminPass = process.env.ADMIN_PASSWORD || 'eeml9117as';
  const hashed = bcrypt.hashSync(adminPass, 10);
  const { rows } = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
  if (rows.length === 0) {
    await pool.query(
      'INSERT INTO users (username, password, name, phone, advisor, role, approved) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      ['admin', hashed, '관리자', '', '-', 'admin', 1]
    );
    console.log('관리자 계정 생성');
  } else {
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [hashed, 'admin']);
    console.log('관리자 비밀번호 업데이트');
  }
}

initDB().catch(console.error);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'sem-reservation-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다.' });
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: '로그인이 필요합니다.' });
  const { rows } = await pool.query('SELECT role FROM users WHERE id = $1', [req.session.userId]);
  if (!rows.length || rows[0].role !== 'admin') return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  next();
}

// ── Auth Routes ──

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name, phone, advisor } = req.body;
    if (!username || !password || !name || !phone || !advisor) {
      return res.status(400).json({ error: '모든 필드를 입력해주세요.' });
    }
    const { rows: existing } = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.length) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });

    const hashed = bcrypt.hashSync(password, 10);
    await pool.query(
      'INSERT INTO users (username, password, name, phone, advisor, role, approved) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [username, hashed, name, phone, advisor, 'user', 0]
    );
    res.json({ success: true, pending: true });
  } catch (err) { res.status(500).json({ error: '서버 오류' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (!rows.length || !bcrypt.compareSync(password, rows[0].password)) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 잘못되었습니다.' });
    }
    const user = rows[0];
    if (!user.approved) return res.status(403).json({ error: '관리자 승인 대기 중입니다.' });

    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, name: user.name, advisor: user.advisor, role: user.role } });
  } catch (err) { res.status(500).json({ error: '서버 오류' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, name, advisor, role FROM users WHERE id = $1', [req.session.userId]);
  if (!rows.length) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  res.json(rows[0]);
});

// ── Admin Routes ──

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, name, phone, advisor, role, approved, created_at FROM users ORDER BY created_at DESC');
  res.json(rows);
});

app.post('/api/admin/users/:id/approve', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM users WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  await pool.query('UPDATE users SET approved = 1 WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/api/admin/users/:id/reject', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, role FROM users WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  if (rows[0].role === 'admin') return res.status(400).json({ error: '관리자는 삭제할 수 없습니다.' });
  await pool.query('DELETE FROM reservations WHERE user_id = $1', [req.params.id]);
  await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/reservations', requireAdmin, async (req, res) => {
  const { advisor, date_from, date_to } = req.query;
  let query = `SELECT r.*, u.name as user_name, u.advisor FROM reservations r JOIN users u ON r.user_id = u.id WHERE 1=1`;
  const params = [];
  let idx = 1;
  if (advisor) { query += ` AND u.advisor = $${idx++}`; params.push(advisor); }
  if (date_from) { query += ` AND r.date >= $${idx++}`; params.push(date_from); }
  if (date_to) { query += ` AND r.date <= $${idx++}`; params.push(date_to); }
  query += ' ORDER BY r.date DESC, r.start_time';
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

app.delete('/api/admin/reservations/:id', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM reservations WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: '예약을 찾을 수 없습니다.' });
  await pool.query('DELETE FROM reservations WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const totalUsers = (await pool.query("SELECT COUNT(*) as cnt FROM users WHERE role != 'admin'")).rows[0].cnt;
  const pendingUsers = (await pool.query('SELECT COUNT(*) as cnt FROM users WHERE approved = 0')).rows[0].cnt;
  const totalReservations = (await pool.query('SELECT COUNT(*) as cnt FROM reservations')).rows[0].cnt;

  const today = new Date().toISOString().split('T')[0];
  const todayReservations = (await pool.query('SELECT COUNT(*) as cnt FROM reservations WHERE date = $1', [today])).rows[0].cnt;

  const d = new Date();
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(d); monday.setDate(diff);
  const weekStart = monday.toISOString().split('T')[0];
  const sunday = new Date(monday); sunday.setDate(monday.getDate() + 6);
  const weekEnd = sunday.toISOString().split('T')[0];

  const { rows: advisorUsage } = await pool.query(`
    SELECT u.advisor,
      COALESCE(SUM(
        (CAST(substring(r.end_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.end_time from 4 for 2) AS INTEGER))
        - (CAST(substring(r.start_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.start_time from 4 for 2) AS INTEGER))
      ), 0) as total_minutes
    FROM reservations r JOIN users u ON r.user_id = u.id
    WHERE r.date >= $1 AND r.date <= $2
    GROUP BY u.advisor ORDER BY total_minutes DESC
  `, [weekStart, weekEnd]);

  // Monthly usage per advisor
  const now = new Date();
  const monthStart = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-01`;
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const monthEnd = `${nextMonth.getFullYear()}-${String(nextMonth.getMonth() + 1).padStart(2, '0')}-01`;

  const { rows: advisorMonthly } = await pool.query(`
    SELECT u.advisor,
      COALESCE(SUM(
        (CAST(substring(r.end_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.end_time from 4 for 2) AS INTEGER))
        - (CAST(substring(r.start_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.start_time from 4 for 2) AS INTEGER))
      ), 0) as total_minutes
    FROM reservations r JOIN users u ON r.user_id = u.id
    WHERE r.date >= $1 AND r.date < $2
    GROUP BY u.advisor ORDER BY total_minutes DESC
  `, [monthStart, monthEnd]);

  res.json({ totalUsers: +totalUsers, pendingUsers: +pendingUsers, totalReservations: +totalReservations, todayReservations: +todayReservations, advisorUsage, advisorMonthly, weekStart, weekEnd, monthStart });
});

// ── Reservation Routes ──

function getWeekStart(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(d); monday.setDate(diff);
  return monday.toISOString().split('T')[0];
}

function getWeekEnd(weekStartStr) {
  const d = new Date(weekStartStr + 'T00:00:00');
  d.setDate(d.getDate() + 6);
  return d.toISOString().split('T')[0];
}

async function getAdvisorWeeklyMinutes(advisor, weekStart, weekEnd, excludeId) {
  let query = `
    SELECT COALESCE(SUM(
      (CAST(substring(r.end_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.end_time from 4 for 2) AS INTEGER))
      - (CAST(substring(r.start_time from 1 for 2) AS INTEGER) * 60 + CAST(substring(r.start_time from 4 for 2) AS INTEGER))
    ), 0) as total_minutes
    FROM reservations r JOIN users u ON r.user_id = u.id
    WHERE u.advisor = $1 AND r.date >= $2 AND r.date <= $3
  `;
  const params = [advisor, weekStart, weekEnd];
  if (excludeId) { query += ' AND r.id != $4'; params.push(excludeId); }
  const { rows } = await pool.query(query, params);
  return +rows[0].total_minutes;
}

app.get('/api/reservations', requireAuth, async (req, res) => {
  const { date, week_start } = req.query;
  let query = `SELECT r.*, u.name as user_name, u.advisor FROM reservations r JOIN users u ON r.user_id = u.id`;
  const params = [];
  if (date) { query += ' WHERE r.date = $1'; params.push(date); }
  else if (week_start) { const we = getWeekEnd(week_start); query += ' WHERE r.date >= $1 AND r.date <= $2'; params.push(week_start, we); }
  query += ' ORDER BY r.date, r.start_time';
  const { rows } = await pool.query(query, params);
  res.json(rows);
});

app.post('/api/reservations', requireAuth, async (req, res) => {
  try {
    const { date, start_time, end_time, purpose } = req.body;
    if (!date || !start_time || !end_time) return res.status(400).json({ error: '날짜와 시간을 입력해주세요.' });

    const today = new Date(); today.setHours(0, 0, 0, 0);
    const resDate = new Date(date + 'T00:00:00');
    const maxDate = new Date(today); maxDate.setDate(maxDate.getDate() + 14);
    if (resDate < today) return res.status(400).json({ error: '과거 날짜에는 예약할 수 없습니다.' });
    if (resDate > maxDate) return res.status(400).json({ error: '현재로부터 최대 2주 이내만 예약 가능합니다.' });

    const [sh, sm] = start_time.split(':').map(Number);
    const [eh, em] = end_time.split(':').map(Number);
    const duration = (eh * 60 + em) - (sh * 60 + sm);
    if (duration <= 0) return res.status(400).json({ error: '종료 시간은 시작 시간보다 뒤여야 합니다.' });

    const { rows: overlap } = await pool.query(
      'SELECT COUNT(*) as cnt FROM reservations WHERE date = $1 AND start_time < $2 AND end_time > $3',
      [date, end_time, start_time]
    );
    if (+overlap[0].cnt > 0) return res.status(400).json({ error: '해당 시간에 이미 예약이 있습니다.' });

    const { rows: userRows } = await pool.query('SELECT advisor FROM users WHERE id = $1', [req.session.userId]);
    const advisor = userRows[0].advisor;
    const weekStart = getWeekStart(date);
    const weekEnd = getWeekEnd(weekStart);
    const currentMinutes = await getAdvisorWeeklyMinutes(advisor, weekStart, weekEnd);

    if (currentMinutes + duration > 180) {
      const remaining = Math.max(0, 180 - currentMinutes);
      return res.status(400).json({ error: `${advisor} 교수님 연구실의 이번 주 잔여 시간: ${remaining}분 (최대 3시간/주). 요청: ${duration}분` });
    }

    const { rows } = await pool.query(
      'INSERT INTO reservations (user_id, date, start_time, end_time, purpose) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [req.session.userId, date, start_time, end_time, purpose || '']
    );
    res.json({ success: true, id: rows[0].id });
  } catch (err) { res.status(500).json({ error: '서버 오류' }); }
});

app.delete('/api/reservations/:id', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM reservations WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: '예약을 찾을 수 없습니다.' });
  if (rows[0].user_id !== req.session.userId) return res.status(403).json({ error: '본인의 예약만 취소할 수 있습니다.' });

  // Block deletion of past reservations for non-admin users
  const today = new Date().toISOString().split('T')[0];
  if (rows[0].date < today) return res.status(403).json({ error: '지난 예약은 삭제할 수 없습니다.' });

  await pool.query('DELETE FROM reservations WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.get('/api/advisor-usage', requireAuth, async (req, res) => {
  const { advisor, week_start } = req.query;
  if (!advisor || !week_start) return res.status(400).json({ error: 'advisor와 week_start가 필요합니다.' });
  const weekEnd = getWeekEnd(week_start);
  const totalMinutes = await getAdvisorWeeklyMinutes(advisor, week_start, weekEnd);
  res.json({ advisor, week_start, week_end: weekEnd, used_minutes: totalMinutes, remaining_minutes: Math.max(0, 180 - totalMinutes), limit_minutes: 180 });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => { console.log(`SEM 예약 시스템이 http://localhost:${PORT} 에서 실행 중입니다.`); });
