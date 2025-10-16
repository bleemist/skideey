require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const { Server } = require("socket.io");
const http = require("http");

const User = require("./models/User");
const Post = require("./models/Post");
const Message = require("./models/Message");
const Room = require("./models/Room");

const app = express();
app.use(express.json());
app.use(cors());

// 🌤 Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ⚙️ Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

// 🧩 MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("MongoDB Error:", err));

// 🔐 Middleware for token authentication
function auth(req, res, next) {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Access denied" });
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(400).json({ error: "Invalid token" });
  }
}

// 🧑 Register User
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const userExists = await User.findOne({ username });
  if (userExists) return res.status(400).json({ error: "Username already exists" });

  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  await user.save();
  res.json({ message: "User registered successfully" });
});

// 🔑 Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: "User not found" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET);
  res.json({ token, user });
});

// 🧍 Update Profile Picture
app.post("/api/profile/image", auth, upload.single("image"), async (req, res) => {
  try {
    const uploadRes = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ resource_type: "image" }, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
      stream.end(req.file.buffer);
    });

    await User.findByIdAndUpdate(req.user._id, { profileImage: uploadRes.secure_url });
    res.json({ imageUrl: uploadRes.secure_url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📰 Create Post
app.post("/api/posts", auth, upload.array("media", 5), async (req, res) => {
  try {
    const mediaUrls = [];

    for (const file of req.files) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ resource_type: "auto" }, (err, r) => {
          if (err) reject(err);
          else resolve(r);
        });
        stream.end(file.buffer);
      });
      mediaUrls.push(result.secure_url);
    }

    const post = new Post({
      author: req.user._id,
      content: req.body.content,
      mediaUrls
    });
    await post.save();
    res.json(post);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 💬 Create or Join Room
app.post("/api/room", auth, async (req, res) => {
  const { name } = req.body;
  let room = await Room.findOne({ name });
  if (!room) room = await Room.create({ name, createdBy: req.user._id, members: [req.user._id] });
  res.json(room);
});

// 💬 Send Message
app.post("/api/message", auth, upload.array("media", 5), async (req, res) => {
  const mediaUrls = [];

  for (const file of req.files) {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ resource_type: "auto" }, (err, r) => {
        if (err) reject(err);
        else resolve(r);
      });
      stream.end(file.buffer);
    });
    mediaUrls.push(result.secure_url);
  }

  const message = new Message({
    room: req.body.room,
    sender: req.user._id,
    text: req.body.text,
    mediaUrls
  });
  await message.save();
  io.to(req.body.room).emit("newMessage", message);
  res.json(message);
});

// 🧠 Fetch All Posts
app.get("/api/posts", async (req, res) => {
  const posts = await Post.find().populate("author", "username profileImage").sort({ timestamp: -1 });
  res.json(posts);
});

// ⚙️ Socket.io setup
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

io.on("connection", (socket) => {
  console.log("🟢 Connected:", socket.id);

  socket.on("joinRoom", (room) => {
    socket.join(room);
    console.log(`Joined room: ${room}`);
  });

  socket.on("disconnect", () => {
    console.log("🔴 Disconnected:", socket.id);
  });
});

// 🚀 Start Server
server.listen(process.env.PORT || 5000, () =>
  console.log(`🚀 Server running on port ${process.env.PORT}`)
);
