const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const xss = require('xss');
const multer = require('multer');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 10000;
const SECRET = process.env.JWT_SECRET || 'nc_secret_change_me';
const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(__dirname, 'uploads');
[DATA, UPLOADS].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

function readJSON(file) {
  const p = path.join(DATA, file);
  if (!fs.existsSync(p)) fs.writeFileSync(p, '[]');
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return []; }
}
function writeJSON(file, data) { fs.writeFileSync(path.join(DATA, file), JSON.stringify(data, null, 2)); }

const storage = multer.diskStorage({
  destination: (r, f, cb) => cb(null, UPLOADS),
  filename: (r, f, cb) => cb(null, uuidv4() + path.extname(f.originalname))
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } });

app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io", "https://cdnjs.cloudflare.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      mediaSrc: ["'self'", "data:", "blob:", "https:"],
      connectSrc: ["'self'", "https:"],
    }
  }
}));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(UPLOADS));
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const t = req.headers.authorization?.split(' ')[1];
  if (!t) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin')
      return res.status(403).json({ error: 'Forbidden' });
    next();
  });
}

// ======== AUTH ========
app.post('/api/register', async (req, res) => {
  try {
    let { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Required' });
    username = xss(username.trim().toLowerCase());
    if (username.length < 3) return res.status(400).json({ error: 'Username 3+ chars' });
    let users = readJSON('users.json');
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Taken' });
    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(), username, password: hash, displayName: username, bio: '', avatar: '',
      online: false, lastSeen: new Date().toISOString(), verified: false, verifiedBadge: null,
      premium: false, role: users.length === 0 ? 'superadmin' : 'user', banned: false,
      createdAt: new Date().toISOString()
    };
    users.push(user); writeJSON('users.json', users);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '7d' });
    const { password: p, ...safe } = user;
    res.json({ token, user: safe });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = readJSON('users.json');
    const user = users.find(u => u.username === (username || '').toLowerCase().trim());
    if (!user) return res.status(401).json({ error: 'Invalid' });
    if (user.banned) return res.status(403).json({ error: 'Banned' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid' });
    user.online = true; user.lastSeen = new Date().toISOString();
    writeJSON('users.json', users);
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, SECRET, { expiresIn: '7d' });
    const { password: p, ...safe } = user;
    res.json({ token, user: safe });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ======== USERS ========
app.get('/api/users', auth, (req, res) => {
  res.json(readJSON('users.json').filter(u => !u.banned && u.username !== req.user.username).map(u => ({
    id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar,
    online: u.online, verified: u.verified, verifiedBadge: u.verifiedBadge, premium: u.premium
  })));
});

app.put('/api/profile', auth, upload.single('avatar'), async (req, res) => {
  try {
    let users = readJSON('users.json');
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });
    if (req.body.displayName) users[idx].displayName = xss(req.body.displayName.trim());
    if (req.body.bio !== undefined) users[idx].bio = xss(req.body.bio.trim());
    if (req.file) users[idx].avatar = '/uploads/' + req.file.filename;
    writeJSON('users.json', users);
    const { password: p, ...safe } = users[idx];
    res.json({ success: true, user: safe });
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ======== MESSAGES ========
app.get('/api/messages/:chatId', auth, (req, res) => {
  res.json(readJSON('messages.json').filter(m => m.chatId === req.params.chatId && !m.deletedForEveryone).sort((a, b) => a.timestamp - b.timestamp).slice(-200));
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: '/uploads/' + req.file.filename, name: req.file.originalname, size: req.file.size, type: req.file.mimetype });
});

// ======== GROUPS ========
app.post('/api/groups', auth, (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: 'Name required' });
  const g = readJSON('groups.json');
  const group = { id: uuidv4(), name: xss(req.body.name.trim()), description: xss(req.body.description || ''), owner: req.user.id, admins: [req.user.id], members: [req.user.id], inviteCode: uuidv4().slice(0, 8), isChannel: false, subscribers: [] };
  g.push(group); writeJSON('groups.json', g); res.json({ success: true, group });
});

app.get('/api/groups', auth, (req, res) => {
  res.json(readJSON('groups.json').filter(g => g.members?.includes(req.user.id)).map(g => ({ id: g.id, name: g.name, description: g.description, inviteCode: g.inviteCode, isChannel: g.isChannel, memberCount: g.members?.length || 0 })));
});

app.post('/api/groups/join/:code', auth, (req, res) => {
  const g = readJSON('groups.json');
  const grp = g.find(x => x.inviteCode === req.params.code);
  if (!grp) return res.status(404).json({ error: 'Not found' });
  if (!grp.members.includes(req.user.id)) grp.members.push(req.user.id);
  writeJSON('groups.json', g); res.json({ success: true, groupId: grp.id });
});

app.post('/api/channels', auth, (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: 'Name required' });
  const g = readJSON('groups.json');
  const ch = { id: uuidv4(), name: xss(req.body.name.trim()), description: xss(req.body.description || ''), owner: req.user.id, admins: [req.user.id], members: [], inviteCode: '', isChannel: true, subscribers: [req.user.id] };
  g.push(ch); writeJSON('groups.json', g); res.json({ success: true, channel: ch });
});

app.get('/api/groups/explore', auth, (req, res) => {
  res.json(readJSON('groups.json').filter(g => g.isChannel || g.inviteCode).map(g => ({ id: g.id, name: g.name, description: g.description, memberCount: g.members?.length || 0, isChannel: g.isChannel })));
});

// ======== ADMIN ========
app.get('/admin/stats', adminAuth, (req, res) => {
  const u = readJSON('users.json');
  res.json({ totalUsers: u.length, totalMessages: readJSON('messages.json').length, onlineUsers: u.filter(x => x.online).length, premium: u.filter(x => x.premium).length, verified: u.filter(x => x.verified).length });
});

app.get('/admin/users', adminAuth, (req, res) => {
  res.json(readJSON('users.json').map(u => { const { password: p, ...s } = u; return s; }));
});

app.put('/admin/user/:id', adminAuth, (req, res) => {
  let u = readJSON('users.json');
  const i = u.findIndex(x => x.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'Not found' });
  if (req.body.verified !== undefined) { u[i].verified = req.body.verified; u[i].verifiedBadge = req.body.verified ? (req.body.verifiedBadge || 'blue') : null; }
  if (req.body.premium !== undefined) u[i].premium = req.body.premium;
  if (req.body.banned !== undefined) u[i].banned = req.body.banned;
  writeJSON('users.json', u); res.json({ success: true });
});

// ======== PREMIUM ========
app.post('/api/premium/initiate', auth, (req, res) => {
  const ref = 'NC-' + uuidv4().slice(0, 8).toUpperCase();
  const p = readJSON('payments.json');
  p.push({ id: ref, userId: req.user.id, amount: 500, status: 'pending', createdAt: new Date().toISOString() });
  writeJSON('payments.json', p); res.json({ success: true, paymentId: ref });
});

app.post('/api/premium/confirm', auth, (req, res) => {
  const p = readJSON('payments.json');
  const pay = p.find(x => x.id === req.body.paymentId);
  if (!pay) return res.status(404).json({ error: 'Not found' });
  pay.status = 'completed';
  let u = readJSON('users.json');
  const i = u.findIndex(x => x.id === (pay.userId || req.user.id));
  if (i !== -1) { u[i].premium = true; writeJSON('users.json', u); }
  writeJSON('payments.json', p); res.json({ success: true });
});

// ======== SOCKET.IO ========
io.use((socket, next) => {
  const t = socket.handshake.auth?.token;
  if (!t) return next(new Error('No token'));
  try { socket.user = jwt.verify(t, SECRET); next(); }
  catch { next(new Error('Invalid')); }
});

io.on('connection', (socket) => {
  const uid = socket.user.id;
  const uname = socket.user.username;
  console.log(`[+] ${uname}`);

  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === uid);
  if (idx !== -1) { users[idx].online = true; users[idx].lastSeen = new Date().toISOString(); writeJSON('users.json', users); }
  io.emit('user:online', { id: uid, username: uname });
  socket.join(`user:${uid}`);

  socket.on('message:send', (data) => {
    try {
      if (!data.chatId || !data.content) return;
      const msg = {
        id: uuidv4(), chatId: data.chatId, chatType: data.chatType || 'private',
        senderId: uid, senderUsername: uname,
        senderDisplayName: users[idx]?.displayName || uname,
        senderAvatar: users[idx]?.avatar || '',
        content: xss(data.content), type: data.type || 'text',
        timestamp: Date.now(), edited: false, replyTo: data.replyTo || null,
        reactions: [], readBy: [uid], deleted: false, deletedForEveryone: false
      };
      let msgs = readJSON('messages.json');
      msgs.push(msg);
      if (msgs.length > 50000) msgs.splice(0, msgs.length - 50000);
      writeJSON('messages.json', msgs);
      io.to(`chat:${data.chatId}`).emit('message:new', msg);
    } catch (e) { console.error(e); }
  });

  socket.on('chat:join', (chatId) => {
    socket.join(`chat:${chatId}`);
    let msgs = readJSON('messages.json');
    let upd = false;
    msgs.forEach(m => { if (m.chatId === chatId && !m.readBy.includes(uid)) { m.readBy.push(uid); upd = true; } });
    if (upd) writeJSON('messages.json', msgs);
  });

  socket.on('typing:start', (c) => socket.to(`chat:${c}`).emit('typing:update', { chatId: c, user: uname, typing: true }));
  socket.on('typing:stop', (c) => socket.to(`chat:${c}`).emit('typing:update', { chatId: c, user: uname, typing: false }));

  socket.on('message:react', (data) => {
    try {
      let msgs = readJSON('messages.json');
      const m = msgs.find(x => x.id === data.msgId);
      if (!m) return;
      const ex = m.reactions.findIndex(r => r.userId === uid);
      if (ex !== -1) { if (m.reactions[ex].emoji === data.emoji) m.reactions.splice(ex, 1); else m.reactions[ex].emoji = data.emoji; }
      else m.reactions.push({ userId: uid, username: uname, emoji: data.emoji });
      writeJSON('messages.json', msgs);
      io.to(`chat:${m.chatId}`).emit('message:reacted', { msgId: data.msgId, reactions: m.reactions });
    } catch (e) { console.error(e); }
  });

  socket.on('message:edit', (data) => {
    try {
      let msgs = readJSON('messages.json');
      const m = msgs.find(x => x.id === data.msgId);
      if (!m || m.senderId !== uid) return;
      m.content = xss(data.content); m.edited = true;
      writeJSON('messages.json', msgs);
      io.to(`chat:${m.chatId}`).emit('message:edited', { msgId: data.msgId, content: m.content });
    } catch (e) { console.error(e); }
  });

  socket.on('message:delete', (data) => {
    try {
      let msgs = readJSON('messages.json');
      const m = msgs.find(x => x.id === data.msgId);
      if (!m || (m.senderId !== uid && socket.user.role !== 'admin')) return;
      m.deleted = true; m.deletedForEveryone = !!data.forEveryone;
      if (!data.forEveryone) m.content = 'Deleted';
      writeJSON('messages.json', msgs);
      io.to(`chat:${m.chatId}`).emit('message:deleted', { msgId: data.msgId, forEveryone: !!data.forEveryone });
    } catch (e) { console.error(e); }
  });

  socket.on('disconnect', () => {
    console.log(`[-] ${uname}`);
    let users = readJSON('users.json');
    const i = users.findIndex(u => u.id === uid);
    if (i !== -1) { users[i].online = false; users[i].lastSeen = new Date().toISOString(); writeJSON('users.json', users); }
    io.emit('user:offline', { id: uid, lastSeen: new Date().toISOString() });
  });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
server.listen(PORT, '0.0.0.0', () => console.log(`NovaChat on ${PORT}`));
