const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const helmet = require('helmet');
const compression = require('compression');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const xss = require('xss');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'novachat_secret_change_in_prod_xyz';

const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

[DATA_DIR, UPLOAD_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

function readJSON(file) {
  const p = path.join(DATA_DIR, file);
  if (!fs.existsSync(p)) fs.writeFileSync(p, '[]');
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return []; }
}

function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2));
}

// Multer file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

// Middleware
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(compression());
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 200 });
app.use('/api/', limiter);

// JWT Auth
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  });
}

function superAdminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Super admin only' });
    }
    next();
  });
}

// ======= AUTH ROUTES =======
app.post('/api/register', async (req, res) => {
  try {
    let { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    username = xss(username.trim().toLowerCase());
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username 3-20 chars' });

    let users = readJSON('users.json');
    if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Username taken' });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: uuidv4(),
      username,
      email: email || '',
      password: hash,
      displayName: username,
      bio: '',
      avatar: '',
      online: false,
      lastSeen: new Date().toISOString(),
      verified: false,
      verifiedBadge: null,
      verifiedReason: '',
      premium: false,
      premiumUntil: null,
      coins: 0,
      role: users.length === 0 ? 'superadmin' : 'user',
      banned: false,
      banReason: '',
      suspended: false,
      suspendReason: '',
      deleted: false,
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeJSON('users.json', users);

    const token = jwt.sign({
      id: user.id, username: user.username, role: user.role,
      verified: user.verified, premium: user.premium
    }, JWT_SECRET, { expiresIn: '7d' });

    const { password: pw, ...safe } = user;
    res.json({ token, user: safe });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = readJSON('users.json');
    const user = users.find(u => u.username === (username || '').toLowerCase().trim());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.banned) return res.status(403).json({ error: 'Account is banned: ' + (user.banReason || 'No reason') });
    if (user.suspended) return res.status(403).json({ error: 'Account suspended: ' + (user.suspendReason || 'No reason') });

    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });

    user.online = true;
    user.lastSeen = new Date().toISOString();
    writeJSON('users.json', users);

    const token = jwt.sign({
      id: user.id, username: user.username, role: user.role,
      verified: user.verified, premium: user.premium
    }, JWT_SECRET, { expiresIn: '7d' });

    const { password: pw, ...safe } = user;
    res.json({ token, user: safe });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/logout', auth, (req, res) => {
  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx !== -1) {
    users[idx].online = false;
    users[idx].lastSeen = new Date().toISOString();
    writeJSON('users.json', users);
  }
  res.json({ success: true });
});

// ======= USER ROUTES =======
app.get('/api/user/:id', auth, (req, res) => {
  const users = readJSON('users.json');
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (user.banned || user.deleted) return res.status(404).json({ error: 'Not found' });
  const { password: pw, ...safe } = user;
  res.json({ user: safe });
});

app.put('/api/profile', auth, upload.single('avatar'), async (req, res) => {
  try {
    let users = readJSON('users.json');
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) return res.status(404).json({ error: 'Not found' });

    const { displayName, bio, password: newPass, email: newEmail,
            theme, language, fontSize, customStatus } = req.body;

    if (displayName) users[idx].displayName = xss(displayName.trim());
    if (bio !== undefined) users[idx].bio = xss(bio.trim());
    if (req.file) users[idx].avatar = '/uploads/' + req.file.filename;
    if (newPass) users[idx].password = await bcrypt.hash(newPass, 10);
    if (newEmail !== undefined) users[idx].email = xss(newEmail);
    if (theme !== undefined) users[idx].theme = theme;
    if (language !== undefined) users[idx].language = language;
    if (fontSize !== undefined) users[idx].fontSize = fontSize;
    if (customStatus !== undefined) users[idx].customStatus = xss(customStatus);

    writeJSON('users.json', users);
    const { password: pw, ...safe } = users[idx];
    res.json({ success: true, user: safe });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Update failed' });
  }
});

app.get('/api/users', auth, (req, res) => {
  const users = readJSON('users.json');
  const filtered = users
    .filter(u => !u.banned && !u.deleted && u.username !== req.user.username)
    .map(u => ({
      id: u.id, username: u.username, displayName: u.displayName,
      avatar: u.avatar, online: u.online, lastSeen: u.lastSeen,
      verified: u.verified, verifiedBadge: u.verifiedBadge,
      premium: u.premium, bio: u.bio, customStatus: u.customStatus
    }));
  res.json(filtered);
});

app.get('/api/users/search/:q', auth, (req, res) => {
  const q = req.params.q.toLowerCase();
  const users = readJSON('users.json');
  const filtered = users
    .filter(u => (u.username.includes(q) || (u.displayName || '').toLowerCase().includes(q)))
    .filter(u => !u.banned && !u.deleted && u.username !== req.user.username)
    .map(u => ({
      id: u.id, username: u.username, displayName: u.displayName,
      avatar: u.avatar, online: u.online, verified: u.verified,
      verifiedBadge: u.verifiedBadge, premium: u.premium
    }));
  res.json(filtered);
});

// ======= MESSAGE ROUTES =======
app.get('/api/messages/:chatId', auth, (req, res) => {
  const msgs = readJSON('messages.json');
  const chatMsgs = msgs
    .filter(m => m.chatId === req.params.chatId && !m.deletedForEveryone)
    .sort((a, b) => a.timestamp - b.timestamp);
  res.json(chatMsgs.slice(-200));
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({
    url: '/uploads/' + req.file.filename,
    name: req.file.originalname,
    size: req.file.size,
    type: req.file.mimetype
  });
});

// ======= ADMIN ROUTES =======
app.get('/admin/stats', adminAuth, (req, res) => {
  const users = readJSON('users.json');
  const msgs = readJSON('messages.json');
  res.json({
    totalUsers: users.length,
    totalMessages: msgs.length,
    onlineUsers: users.filter(u => u.online).length,
    bannedUsers: users.filter(u => u.banned).length,
    premium: users.filter(u => u.premium).length,
    verified: users.filter(u => u.verified).length
  });
});

app.get('/admin/users', adminAuth, (req, res) => {
  const users = readJSON('users.json');
  const sanitized = users.map(u => {
    const { password: pw, ...safe } = u;
    return safe;
  });
  res.json(sanitized);
});

app.put('/admin/user/:id', adminAuth, (req, res) => {
  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const { banned, verified, verifiedBadge, premium, premiumUntil, role, suspended, reason } = req.body;

  if (banned !== undefined) {
    users[idx].banned = banned;
    if (banned && reason) users[idx].banReason = reason;
    if (!banned) users[idx].banReason = '';
  }
  if (suspended !== undefined) {
    users[idx].suspended = suspended;
    if (suspended && reason) users[idx].suspendReason = reason;
    if (!suspended) users[idx].suspendReason = '';
  }
  if (verified !== undefined) {
    users[idx].verified = verified;
    users[idx].verifiedBadge = verified ? (verifiedBadge || 'blue') : null;
    if (!verified) users[idx].verifiedBadge = null;
  }
  if (verifiedBadge && verified === undefined) {
    users[idx].verified = true;
    users[idx].verifiedBadge = verifiedBadge;
  }
  if (premium !== undefined) {
    users[idx].premium = premium;
    if (premium && !users[idx].premiumUntil) {
      users[idx].premiumUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    }
    if (!premium) users[idx].premiumUntil = null;
  }
  if (premiumUntil !== undefined) users[idx].premiumUntil = premiumUntil;
  if (role !== undefined && req.user.role === 'superadmin') {
    if (users[idx].role !== 'superadmin') users[idx].role = role;
  }

  writeJSON('users.json', users);
  res.json({ success: true });
});

app.delete('/admin/user/:id', adminAuth, (req, res) => {
  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  if (users[idx].role === 'superadmin') return res.status(403).json({ error: 'Cannot delete superadmin' });

  users[idx].banned = true;
  users[idx].deleted = true;
  writeJSON('users.json', users);
  res.json({ success: true });
});

app.post('/admin/announce', adminAuth, (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });
  io.emit('announcement', {
    text: xss(message),
    from: req.user.username,
    timestamp: Date.now()
  });
  res.json({ success: true });
});

app.get('/admin/reports', adminAuth, (req, res) => {
  const reports = readJSON('reports.json');
  const users = readJSON('users.json');
  const enriched = reports.slice(-100).reverse().map(r => {
    const reporter = users.find(u => u.id === r.reporter);
    const target = users.find(u => u.id === r.target);
    return {
      id: r.id,
      reporterName: reporter ? reporter.username : '[Deleted]',
      targetName: target ? target.username : '[Deleted]',
      targetId: r.target,
      reason: r.reason,
      timestamp: r.timestamp
    };
  });
  res.json(enriched);
});

// ======= USER REPORTS =======
app.post('/api/report-user', auth, (req, res) => {
  const { userId, reason } = req.body;
  if (!userId || !reason) return res.status(400).json({ error: 'Missing data' });

  const reports = readJSON('reports.json');
  reports.push({
    id: uuidv4(),
    reporter: req.user.id,
    target: userId,
    reason: xss(reason),
    timestamp: Date.now()
  });
  if (reports.length > 500) reports.splice(0, reports.length - 500);
  writeJSON('reports.json', reports);

  // Notify admins
  const users = readJSON('users.json');
  users.filter(u => u.role === 'admin' || u.role === 'superadmin').forEach(a => {
    io.to(`user:${a.id}`).emit('admin:report', {
      from: req.user.username,
      reason: xss(reason)
    });
  });

  res.json({ success: true });
});

// ======= COMPLAINTS =======
app.post('/api/complaint', auth, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Text required' });
  const complaints = readJSON('complaints.json');
  complaints.push({
    id: uuidv4(),
    userId: req.user.id,
    username: req.user.username,
    text: xss(text),
    createdAt: new Date().toISOString()
  });
  if (complaints.length > 200) complaints.splice(0, complaints.length - 200);
  writeJSON('complaints.json', complaints);
  res.json({ success: true });
});

// ======= PREMIUM =======
app.post('/api/premium/initiate', auth, (req, res) => {
  const price = 500;
  const ref = 'NCP-' + uuidv4().slice(0, 8).toUpperCase();
  const payment = {
    id: ref,
    userId: req.user.id,
    username: req.user.username,
    amount: price,
    currency: 'NGN',
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  let payments = readJSON('payments.json');
  payments.push(payment);
  if (payments.length > 200) payments.splice(0, payments.length - 200);
  writeJSON('payments.json', payments);

  res.json({
    success: true,
    paymentId: ref,
    amount: price,
    message: 'Premium checkout created'
  });
});

app.post('/api/premium/confirm', auth, (req, res) => {
  const { paymentId } = req.body;
  let payments = readJSON('payments.json');
  const payment = payments.find(p => p.id === paymentId);
  if (!payment) return res.status(404).json({ error: 'Payment not found' });

  payment.status = 'completed';
  payment.confirmedAt = new Date().toISOString();

  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === (payment.userId || req.user.id));
  if (idx !== -1) {
    users[idx].premium = true;
    const prev = users[idx].premiumUntil ? new Date(users[idx].premiumUntil).getTime() : 0;
    const now = Date.now();
    const base = prev > now ? prev : now;
    users[idx].premiumUntil = new Date(base + 30 * 24 * 60 * 60 * 1000).toISOString();
    writeJSON('users.json', users);
  }

  writeJSON('payments.json', payments);
  res.json({ success: true, message: 'Premium activated' });
});

// ======= SOCKET.IO =======
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error('Invalid token'));
  }
});

io.on('connection', (socket) => {
  const uid = socket.user.id;
  const username = socket.user.username;
  const role = socket.user.role;
  console.log(`[+] ${username} connected`);

  // Online status
  let users = readJSON('users.json');
  const uIdx = users.findIndex(u => u.id === uid);
  if (uIdx !== -1) {
    users[uIdx].online = true;
    users[uIdx].lastSeen = new Date().toISOString();
    writeJSON('users.json', users);
  }
  io.emit('user:online', { id: uid, username });
  socket.join(`user:${uid}`);

  // Send message
  socket.on('message:send', (data) => {
    try {
      const { chatId, chatType, content, type, replyTo } = data;
      if (!chatId || !content) return;

      const msg = {
        id: uuidv4(),
        chatId,
        chatType: chatType || 'private',
        senderId: uid,
        senderUsername: username,
        senderDisplayName: users[uIdx]?.displayName || username,
        senderAvatar: users[uIdx]?.avatar || '',
        content: xss(content),
        type: type || 'text',
        timestamp: Date.now(),
        edited: false,
        replyTo: replyTo || null,
        reactions: [],
        readBy: [uid],
        deleted: false,
        deletedForEveryone: false,
        starred: false,
        pinned: false
      };

      let msgs = readJSON('messages.json');
      msgs.push(msg);
      if (msgs.length > 50000) msgs.splice(0, msgs.length - 50000);
      writeJSON('messages.json', msgs);

      io.to(`chat:${chatId}`).emit('message:new', msg);
    } catch (e) { console.error('msg error:', e); }
  });

  // Join chat
  socket.on('chat:join', (chatId) => {
    socket.join(`chat:${chatId}`);
    let msgs = readJSON('messages.json');
    let updated = false;
    msgs.forEach(m => {
      if (m.chatId === chatId && !m.readBy.includes(uid)) {
        m.readBy.push(uid);
        updated = true;
      }
    });
    if (updated) writeJSON('messages.json', msgs);
  });

  socket.on('chat:leave', (chatId) => socket.leave(`chat:${chatId}`));

  // Typing
  socket.on('typing:start', (chatId) => {
    socket.to(`chat:${chatId}`).emit('typing:update', { chatId, user: username, typing: true });
  });
  socket.on('typing:stop', (chatId) => {
    socket.to(`chat:${chatId}`).emit('typing:update', { chatId, user: username, typing: false });
  });

  // Voice recording
  socket.on('voice:start', (chatId) => {
    socket.to(`chat:${chatId}`).emit('voice:update', { chatId, user: username, recording: true });
  });
  socket.on('voice:stop', (chatId) => {
    socket.to(`chat:${chatId}`).emit('voice:update', { chatId, user: username, recording: false });
  });

  // Reactions
  socket.on('message:react', (data) => {
    try {
      const { msgId, emoji } = data;
      let msgs = readJSON('messages.json');
      const msg = msgs.find(m => m.id === msgId);
      if (!msg) return;
      const existing = msg.reactions.findIndex(r => r.userId === uid);
      if (existing !== -1) {
        if (msg.reactions[existing].emoji === emoji) msg.reactions.splice(existing, 1);
        else msg.reactions[existing].emoji = emoji;
      } else {
        msg.reactions.push({ userId: uid, username, emoji });
      }
      writeJSON('messages.json', msgs);
      io.to(`chat:${msg.chatId}`).emit('message:reacted', { msgId, reactions: msg.reactions });
    } catch (e) { console.error(e); }
  });

  // Edit message
  socket.on('message:edit', (data) => {
    try {
      const { msgId, content } = data;
      let msgs = readJSON('messages.json');
      const msg = msgs.find(m => m.id === msgId);
      if (!msg || msg.senderId !== uid) return;
      msg.content = xss(content);
      msg.edited = true;
      writeJSON('messages.json', msgs);
      io.to(`chat:${msg.chatId}`).emit('message:edited', { msgId, content: msg.content });
    } catch (e) { console.error(e); }
  });

  // Delete message
  socket.on('message:delete', (data) => {
    try {
      const { msgId, forEveryone } = data;
      let msgs = readJSON('messages.json');
      const msg = msgs.find(m => m.id === msgId);
      if (!msg) return;
      if (msg.senderId !== uid && role !== 'admin') return;

      if (forEveryone) {
        msg.deletedForEveryone = true;
        msg.deleted = true;
        writeJSON('messages.json', msgs);
        io.to(`chat:${msg.chatId}`).emit('message:deleted', { msgId, forEveryone: true });
      } else {
        msg.deleted = true;
        msg.content = 'This message was deleted';
        writeJSON('messages.json', msgs);
        io.to(`chat:${msg.chatId}`).emit('message:deleted', { msgId, forEveryone: false });
      }
    } catch (e) { console.error(e); }
  });

  // Star message
  socket.on('message:star', (msgId) => {
    let msgs = readJSON('messages.json');
    const msg = msgs.find(m => m.id === msgId);
    if (msg && msg.senderId === uid) {
      msg.starred = !msg.starred;
      writeJSON('messages.json', msgs);
      io.to(`chat:${msg.chatId}`).emit('message:starred', { msgId, starred: msg.starred });
    }
  });

  // Pin message
  socket.on('message:pin', (data) => {
    const { msgId } = data;
    let msgs = readJSON('messages.json');
    const msg = msgs.find(m => m.id === msgId);
    if (msg) {
      msg.pinned = !msg.pinned;
      writeJSON('messages.json', msgs);
      io.to(`chat:${msg.chatId}`).emit('message:pinned', { msgId, pinned: msg.pinned });
    }
  });

  // Disconnect
  socket.on('disconnect', () => {
    console.log(`[-] ${username} disconnected`);
    let users = readJSON('users.json');
    const idx = users.findIndex(u => u.id === uid);
    if (idx !== -1) {
      users[idx].online = false;
      users[idx].lastSeen = new Date().toISOString();
      writeJSON('users.json', users);
    }
    io.emit('user:offline', { id: uid, lastSeen: new Date().toISOString() });
  });
});

// Fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`NovaChat running on port ${PORT}`);
});
