const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'fitness_tracker_secret_' + Date.now();
const DB_PATH = path.join(__dirname, 'data.json');

// --- JSON File Database ---
function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    return { users: [], records: [] };
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: '未登录' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

// --- Auth Routes ---
app.post('/api/register', (req, res) => {
  const { username, password, nickname } = req.body;
  if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
  if (username.length < 3) return res.status(400).json({ error: '用户名至少3个字符' });
  if (password.length < 4) return res.status(400).json({ error: '密码至少4个字符' });

  const db = readDB();
  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ error: '用户名已存在' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const user = {
    id: Date.now().toString(),
    username,
    nickname: nickname || username,
    password: hash,
    createdAt: new Date().toISOString()
  };
  db.users.push(user);
  writeDB(db);

  const token = jwt.sign({ id: user.id, username: user.username, nickname: user.nickname }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, nickname: user.nickname } });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(400).json({ error: '用户名或密码错误' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, nickname: user.nickname }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, nickname: user.nickname } });
});

// Verify token
app.get('/api/login/verify', auth, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(401).json({ error: '用户不存在' });
  res.json({ user: { id: user.id, username: user.username, nickname: user.nickname } });
});

// --- Records Routes ---
app.get('/api/records', auth, (req, res) => {
  const db = readDB();
  const records = db.records.filter(r => r.userId === req.user.id);
  res.json(records);
});

app.post('/api/records', auth, (req, res) => {
  const db = readDB();
  const record = {
    id: Date.now().toString() + Math.random().toString(36).slice(2, 6),
    userId: req.user.id,
    ...req.body,
    createdAt: new Date().toISOString()
  };
  db.records.push(record);
  writeDB(db);
  res.json(record);
});

app.delete('/api/records/:id', auth, (req, res) => {
  const db = readDB();
  const idx = db.records.findIndex(r => r.id === req.params.id && r.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: '记录不存在' });
  db.records.splice(idx, 1);
  writeDB(db);
  res.json({ ok: true });
});

app.delete('/api/records', auth, (req, res) => {
  const db = readDB();
  db.records = db.records.filter(r => r.userId !== req.user.id);
  writeDB(db);
  res.json({ ok: true });
});

// Export all user data
app.get('/api/export', auth, (req, res) => {
  const db = readDB();
  const records = db.records.filter(r => r.userId === req.user.id);
  res.setHeader('Content-Disposition', 'attachment; filename=fitness-backup.json');
  res.json(records);
});

// Import data
app.post('/api/import', auth, (req, res) => {
  const { records } = req.body;
  if (!Array.isArray(records)) return res.status(400).json({ error: '数据格式错误' });
  const db = readDB();
  // Remove old records for this user
  db.records = db.records.filter(r => r.userId !== req.user.id);
  // Add imported records
  const imported = records.map(r => ({
    ...r,
    id: r.id || Date.now().toString() + Math.random().toString(36).slice(2, 6),
    userId: req.user.id,
  }));
  db.records.push(...imported);
  writeDB(db);
  res.json({ ok: true, count: imported.length });
});

// Community: see all users' recent records (anonymized)
app.get('/api/community', auth, (req, res) => {
  const db = readDB();
  const oneDayAgo = Date.now() - 86400000;
  const recent = db.records
    .filter(r => new Date(r.createdAt).getTime() > oneDayAgo)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 50)
    .map(r => {
      const user = db.users.find(u => u.id === r.userId);
      return {
        nickname: user?.nickname || '匿名',
        type: r.type,
        exercise: r.exercise,
        weight: r.weight, sets: r.sets, reps: r.reps,
        duration: r.duration, distance: r.distance, calories: r.calories,
        createdAt: r.createdAt
      };
    });
  res.json(recent);
});

// Fallback to index.html
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🏋️ 健身记录服务器已启动: http://localhost:${PORT}`);
});
