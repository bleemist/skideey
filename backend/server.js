require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');

// Models
const User = require('./models/User');
const Post = require('./models/Post');
const Room = require('./models/Room');
const Message = require('./models/Message');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

// File upload (photos, videos, docs)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + file.originalname.replace(/\s+/g, '_');
    cb(null, uniqueName);
  }
});
const upload = multer({ storage });

// Connect MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
};

// ------------------- ROUTES -------------------

// ✅ Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ msg: 'Username and password required' });

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ msg: 'Username already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ✅ Login user
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ msg: 'User not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ msg: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, username }, process.env.JWT_SECRET);
  res.json({ token, user });
});

// ✅ Upload file (photo/video/document)
app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ url: `/uploads/${req.file.filename}` });
});

// ✅ Create post (text + media)
app.post('/api/posts', auth, async (req, res) => {
  try {
    const post = await Post.create({
      author: req.user.id,
      text: req.body.text,
      media: req.body.media || []
    });
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ Fetch posts
app.get('/api/posts', async (req, res) => {
  const posts = await Post.find()
    .populate('author', 'username avatarUrl')
    .sort({ createdAt: -1 });
  res.json(posts);
});

// ✅ Update profile picture
app.post('/api/profile/avatar', auth, upload.single('avatar'), async (req, res) => {
  const user = await User.findById(req.user.id);
  user.avatarUrl = `/uploads/${req.file.filename}`;
  await user.save();
  res.json(user);
});

// ✅ Create chat room
app.post('/api/rooms', auth, async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ msg: 'Name & password required' });

  if (await Room.findOne({ name })) return res.status(400).json({ msg: 'Room already exists' });

  const passwordHash = await bcrypt.hash(password, 10);
  const room = await Room.create({ name, passwordHash, createdBy: req.user.id });
  res.json(room);
});

// ✅ Join chat room
app.post('/api/rooms/join', auth, async (req, res) => {
  const { name, password } = req.body;
  const room = await Room.findOne({ name });
  if (!room) return res.status(404).json({ msg: 'Room not found' });

  const match = await bcrypt.compare(password, room.passwordHash);
  if (!match) return res.status(401).json({ msg: 'Incorrect password' });

  res.json(room);
});

// ✅ Get list of all chat rooms
app.get('/api/rooms', auth, async (req, res) => {
  const rooms = await Room.find().sort({ createdAt: -1 });
  res.json(rooms);
});

// ✅ Real-time messaging (Socket.IO)
io.on('connection', socket => {
  console.log('🟢 User connected');

  socket.on('joinRoom', roomName => {
    socket.join(roomName);
    console.log(`User joined room: ${roomName}`);
  });

  socket.on('chatMessage', async data => {
    const { room, encryptedText, sender, attachments } = data;
    const roomObj = await Room.findOne({ name: room });
    if (!roomObj) return;

    await Message.create({
      room: roomObj._id,
      sender,
      encryptedText,
      attachments
    });

    io.to(room).emit('message', data);
  });

  socket.on('disconnect', () => console.log('🔴 User disconnected'));
});

// ✅ Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SKIDEEY Backend running on http://localhost:${PORT}`);
});
