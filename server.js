const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const db = new Database(path.join(__dirname, 'sem.db'));

db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    advisor TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    approved INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    purpose TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// Migrate: add columns if missing (for existing DBs)
try { db.exec('ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ""'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT "user"'); } catch {}
try { db.exec('ALTER TABLE users ADD COLUMN approved INTEGER NOT NULL DEFAULT 0'); } catch {}

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  const hashed = bcrypt.hashSync('admin1234', 10);
  db.prepare(
    'INSERT INTO users (username, password, name, advisor, role, approved) VALUES (?, ?, ?, ?, ?, ?)'
  ).run('admin', hashed, '관리자', '-', 'admin', 1);
  console.log('기본 관리자 계정 생성: admin / admin1234');
}

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'sem-reservation-secret-key-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  }
  next();
}

// ── Auth Routes ──

app.post('/api/register', (req, res) => {
  const { username, password, name, phone, advisor } = req.body;

  if (!username || !password || !name || !phone || !advisor) {
    return res.status(400).json({ error: '모든 필드를 입력해주세요.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  db.prepare(
    'INSERT INTO users (username, password, name, phone, advisor, role, approved) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(username, hashed, name, phone, advisor, 'user', 0);

  res.json({ success: true, pending: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 잘못되었습니다.' });
  }

  if (!user.approved) {
    return res.status(403).json({ error: '관리자 승인 대기 중입니다. 승인 후 로그인할 수 있습니다.' });
  }

  req.session.userId = user.id;
  res.json({
    success: true,
    user: { id: user.id, name: user.name, advisor: user.advisor, role: user.role }
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, name, advisor, role FROM users WHERE id = ?')
    .get(req.session.userId);
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  res.json(user);
});

// ── Admin Routes ──

// List all users (for admin)
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(
    'SELECT id, username, name, phone, advisor, role, approved, created_at FROM users ORDER BY created_at DESC'
  ).all();
  res.json(users);
});

// Approve user
app.post('/api/admin/users/:id/approve', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });

  db.prepare('UPDATE users SET approved = 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Reject (delete) user
app.post('/api/admin/users/:id/reject', requireAdmin, (req, res) => {
  const user = db.prepare('SELECT id, role FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
  if (user.role === 'admin') return res.status(400).json({ error: '관리자는 삭제할 수 없습니다.' });

  db.prepare('DELETE FROM reservations WHERE user_id = ?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// All reservations (for admin, with filters)
app.get('/api/admin/reservations', requireAdmin, (req, res) => {
  const { advisor, date_from, date_to } = req.query;

  let query = `
    SELECT r.*, u.name as user_name, u.advisor
    FROM reservations r
    JOIN users u ON r.user_id = u.id
    WHERE 1=1
  `;
  const params = [];

  if (advisor) {
    query += ' AND u.advisor = ?';
    params.push(advisor);
  }
  if (date_from) {
    query += ' AND r.date >= ?';
    params.push(date_from);
  }
  if (date_to) {
    query += ' AND r.date <= ?';
    params.push(date_to);
  }

  query += ' ORDER BY r.date DESC, r.start_time';

  const rows = db.prepare(query).all(...params);
  res.json(rows);
});

// Admin: delete any reservation
app.delete('/api/admin/reservations/:id', requireAdmin, (req, res) => {
  const reservation = db.prepare('SELECT id FROM reservations WHERE id = ?').get(req.params.id);
  if (!reservation) return res.status(404).json({ error: '예약을 찾을 수 없습니다.' });

  db.prepare('DELETE FROM reservations WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Admin: stats summary
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE role != "admin"').get().cnt;
  const pendingUsers = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE approved = 0').get().cnt;
  const totalReservations = db.prepare('SELECT COUNT(*) as cnt FROM reservations').get().cnt;

  const today = new Date().toISOString().split('T')[0];
  const todayReservations = db.prepare('SELECT COUNT(*) as cnt FROM reservations WHERE date = ?').get(today).cnt;

  // Advisor usage summary for this week
  const d = new Date();
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(d);
  monday.setDate(diff);
  const weekStart = monday.toISOString().split('T')[0];
  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);
  const weekEnd = sunday.toISOString().split('T')[0];

  const advisorUsage = db.prepare(`
    SELECT u.advisor,
      COALESCE(SUM(
        (CAST(substr(r.end_time, 1, 2) AS INTEGER) * 60 + CAST(substr(r.end_time, 4, 2) AS INTEGER))
        - (CAST(substr(r.start_time, 1, 2) AS INTEGER) * 60 + CAST(substr(r.start_time, 4, 2) AS INTEGER))
      ), 0) as total_minutes
    FROM reservations r
    JOIN users u ON r.user_id = u.id
    WHERE r.date >= ? AND r.date <= ?
    GROUP BY u.advisor
    ORDER BY total_minutes DESC
  `).all(weekStart, weekEnd);

  res.json({ totalUsers, pendingUsers, totalReservations, todayReservations, advisorUsage, weekStart, weekEnd });
});

// ── Reservation Routes ──

function getWeekStart(dateStr) {
  const d = new Date(dateStr + 'T00:00:00');
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  const monday = new Date(d);
  monday.setDate(diff);
  return monday.toISOString().split('T')[0];
}

function getWeekEnd(weekStartStr) {
  const d = new Date(weekStartStr + 'T00:00:00');
  d.setDate(d.getDate() + 6);
  return d.toISOString().split('T')[0];
}

function calcMinutes(start, end) {
  const [sh, sm] = start.split(':').map(Number);
  const [eh, em] = end.split(':').map(Number);
  return (eh * 60 + em) - (sh * 60 + sm);
}

function getAdvisorWeeklyMinutes(advisor, weekStart, weekEnd, excludeId) {
  let query = `
    SELECT COALESCE(SUM(
      (CAST(substr(r.end_time, 1, 2) AS INTEGER) * 60 + CAST(substr(r.end_time, 4, 2) AS INTEGER))
      - (CAST(substr(r.start_time, 1, 2) AS INTEGER) * 60 + CAST(substr(r.start_time, 4, 2) AS INTEGER))
    ), 0) as total_minutes
    FROM reservations r
    JOIN users u ON r.user_id = u.id
    WHERE u.advisor = ?
    AND r.date >= ? AND r.date <= ?
  `;
  const params = [advisor, weekStart, weekEnd];

  if (excludeId) {
    query += ' AND r.id != ?';
    params.push(excludeId);
  }

  return db.prepare(query).get(...params).total_minutes;
}

function hasOverlap(date, startTime, endTime, excludeId) {
  let query = `
    SELECT COUNT(*) as cnt FROM reservations
    WHERE date = ?
    AND start_time < ? AND end_time > ?
  `;
  const params = [date, endTime, startTime];

  if (excludeId) {
    query += ' AND id != ?';
    params.push(excludeId);
  }

  return db.prepare(query).get(...params).cnt > 0;
}

app.get('/api/reservations', requireAuth, (req, res) => {
  const { date, week_start } = req.query;

  let query = `
    SELECT r.*, u.name as user_name, u.advisor
    FROM reservations r
    JOIN users u ON r.user_id = u.id
  `;
  const params = [];

  if (date) {
    query += ' WHERE r.date = ?';
    params.push(date);
  } else if (week_start) {
    const weekEnd = getWeekEnd(week_start);
    query += ' WHERE r.date >= ? AND r.date <= ?';
    params.push(week_start, weekEnd);
  }

  query += ' ORDER BY r.date, r.start_time';

  const rows = db.prepare(query).all(...params);
  res.json(rows);
});

app.post('/api/reservations', requireAuth, (req, res) => {
  const { date, start_time, end_time, purpose } = req.body;

  if (!date || !start_time || !end_time) {
    return res.status(400).json({ error: '날짜와 시간을 입력해주세요.' });
  }

  // Check: max 2 weeks from today
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const reservationDate = new Date(date + 'T00:00:00');
  const maxDate = new Date(today);
  maxDate.setDate(maxDate.getDate() + 14);

  if (reservationDate < today) {
    return res.status(400).json({ error: '과거 날짜에는 예약할 수 없습니다.' });
  }
  if (reservationDate > maxDate) {
    return res.status(400).json({ error: '현재로부터 최대 2주 이내만 예약 가능합니다.' });
  }

  const duration = calcMinutes(start_time, end_time);
  if (duration <= 0) {
    return res.status(400).json({ error: '종료 시간은 시작 시간보다 뒤여야 합니다.' });
  }

  if (hasOverlap(date, start_time, end_time)) {
    return res.status(400).json({ error: '해당 시간에 이미 예약이 있습니다.' });
  }

  const user = db.prepare('SELECT advisor FROM users WHERE id = ?').get(req.session.userId);
  const weekStart = getWeekStart(date);
  const weekEnd = getWeekEnd(weekStart);
  const currentMinutes = getAdvisorWeeklyMinutes(user.advisor, weekStart, weekEnd);

  if (currentMinutes + duration > 180) {
    const remaining = Math.max(0, 180 - currentMinutes);
    return res.status(400).json({
      error: `${user.advisor} 교수님 연구실의 이번 주 잔여 시간: ${remaining}분 (최대 3시간/주). 요청: ${duration}분`
    });
  }

  const result = db.prepare(
    'INSERT INTO reservations (user_id, date, start_time, end_time, purpose) VALUES (?, ?, ?, ?, ?)'
  ).run(req.session.userId, date, start_time, end_time, purpose || '');

  res.json({ success: true, id: result.lastInsertRowid });
});

app.delete('/api/reservations/:id', requireAuth, (req, res) => {
  const reservation = db.prepare('SELECT * FROM reservations WHERE id = ?').get(req.params.id);

  if (!reservation) {
    return res.status(404).json({ error: '예약을 찾을 수 없습니다.' });
  }
  if (reservation.user_id !== req.session.userId) {
    return res.status(403).json({ error: '본인의 예약만 취소할 수 있습니다.' });
  }

  db.prepare('DELETE FROM reservations WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/advisor-usage', requireAuth, (req, res) => {
  const { advisor, week_start } = req.query;
  if (!advisor || !week_start) {
    return res.status(400).json({ error: 'advisor와 week_start가 필요합니다.' });
  }

  const weekEnd = getWeekEnd(week_start);
  const totalMinutes = getAdvisorWeeklyMinutes(advisor, week_start, weekEnd);

  res.json({
    advisor,
    week_start,
    week_end: weekEnd,
    used_minutes: totalMinutes,
    remaining_minutes: Math.max(0, 180 - totalMinutes),
    limit_minutes: 180
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`SEM 예약 시스템이 http://localhost:${PORT} 에서 실행 중입니다.`);
});
