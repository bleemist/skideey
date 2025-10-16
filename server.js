import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import multer from "multer";
import { Server } from "socket.io";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { 
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Fix for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Create uploads directory if it doesn't exist
import fs from "fs";
if (!fs.existsSync("public/uploads")) {
  fs.mkdirSync("public/uploads", { recursive: true });
}

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// -------------------------------
// 🔗 Database Connection
// -------------------------------
const MONGODB_URI = process.env.MONGO_URI || "mongodb://localhost:27017/skideey";
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ DB error:", err));

// -------------------------------
// 📦 Mongoose Models
// -------------------------------
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  profileImage: { type: String, default: "https://cdn-icons-png.flaticon.com/512/847/847969.png" },
  createdAt: { type: Date, default: Date.now }
});

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  content: String,
  mediaUrls: [String],
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  views: { type: Number, default: 0 },
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    text: String,
    createdAt: { type: Date, default: Date.now }
  }],
  createdAt: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  room: String,
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: String,
  mediaUrls: [String],
  createdAt: { type: Date, default: Date.now }
});

const roomSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  description: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  isPrivate: { type: Boolean, default: false },
  password: String,
  maxUsers: { type: Number, default: 100 },
  userCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);
const Message = mongoose.model("Message", messageSchema);
const Room = mongoose.model("Room", roomSchema);

// -------------------------------
// 🔐 Authentication Middleware
// -------------------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// -------------------------------
// 📁 File Upload Setup
// -------------------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
});
const upload = multer({ storage });

// -------------------------------
// 👤 Auth Routes
// -------------------------------
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ error: "Username already taken" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashedPassword });

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        profileImage: user.profileImage 
      } 
    });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET);
    res.json({ 
      token, 
      user: { 
        id: user._id, 
        username: user.username, 
        profileImage: user.profileImage 
      } 
    });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

app.post("/api/profile/image", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.profileImage = `/uploads/${req.file.filename}`;
    await user.save();
    
    res.json({ 
      imageUrl: user.profileImage,
      user: {
        id: user._id,
        username: user.username,
        profileImage: user.profileImage
      }
    });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// -------------------------------
// 💬 Room Management
// -------------------------------
// Get all public rooms
app.get("/api/rooms", async (req, res) => {
  try {
    const rooms = await Room.find({ isPrivate: false })
      .populate("createdBy", "username profileImage")
      .sort({ userCount: -1, createdAt: -1 });
    res.json(rooms);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Create new room
app.post("/api/rooms", authenticateToken, async (req, res) => {
  try {
    const { name, description, isPrivate, password, maxUsers } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: "Room name is required" });
    }

    // Room name validation
    if (name.length < 3 || name.length > 20) {
      return res.status(400).json({ error: "Room name must be 3-20 characters" });
    }

    if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
      return res.status(400).json({ error: "Room name can only contain letters, numbers, hyphens, and underscores" });
    }

    const existingRoom = await Room.findOne({ name });
    if (existingRoom) {
      return res.status(400).json({ error: "Room name already exists" });
    }

    const user = await User.findById(req.user.userId);
    
    const roomData = {
      name,
      description: description || "",
      createdBy: user._id,
      isPrivate: isPrivate || false,
      maxUsers: Math.min(maxUsers || 100, 500) // Cap at 500 users
    };

    // Add password if room is private
    if (isPrivate && password) {
      if (password.length < 4) {
        return res.status(400).json({ error: "Room password must be at least 4 characters" });
      }
      roomData.password = await bcrypt.hash(password, 10);
    }

    const room = await Room.create(roomData);
    const populatedRoom = await room.populate("createdBy", "username profileImage");

    io.emit("newRoom", populatedRoom);
    res.json(populatedRoom);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Join room with password check
app.post("/api/rooms/:roomId/join", authenticateToken, async (req, res) => {
  try {
    const { password } = req.body;
    const room = await Room.findById(req.params.roomId);
    
    if (!room) {
      return res.status(404).json({ error: "Room not found" });
    }

    // Check if room is full
    if (room.userCount >= room.maxUsers) {
      return res.status(400).json({ error: "Room is full" });
    }

    // Check password for private rooms
    if (room.isPrivate) {
      if (!password) {
        return res.status(400).json({ error: "Password required for this room" });
      }
      const validPassword = await bcrypt.compare(password, room.password);
      if (!validPassword) {
        return res.status(400).json({ error: "Invalid room password" });
      }
    }

    // Update user count
    room.userCount += 1;
    await room.save();

    res.json({ success: true, room });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Leave room
app.post("/api/rooms/:roomId/leave", authenticateToken, async (req, res) => {
  try {
    const room = await Room.findById(req.params.roomId);
    
    if (room && room.userCount > 0) {
      room.userCount -= 1;
      await room.save();
      io.emit("roomUpdated", room);
    }

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// -------------------------------
// 📰 Posts Routes
// -------------------------------
app.post("/api/posts", authenticateToken, upload.array("media"), async (req, res) => {
  try {
    const { content } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const mediaUrls = req.files?.map(f => `/uploads/${f.filename}`) || [];
    const post = await Post.create({ 
      author: user._id, 
      content, 
      mediaUrls 
    });
    
    const populated = await post.populate("author", "username profileImage");
    populated.views = 0;
    populated.likes = [];
    populated.comments = [];

    io.emit("newPost", populated);
    res.json(populated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

app.get("/api/posts", async (req, res) => {
  try {
    const posts = await Post.find()
      .populate("author", "username profileImage")
      .populate("comments.user", "username profileImage")
      .sort({ createdAt: -1 });
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Like/Unlike post
app.post("/api/posts/:postId/like", authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ error: "Post not found" });

    const userId = req.user.userId;
    const likeIndex = post.likes.indexOf(userId);

    if (likeIndex > -1) {
      post.likes.splice(likeIndex, 1);
    } else {
      post.likes.push(userId);
    }

    await post.save();
    const updatedPost = await Post.findById(req.params.postId)
      .populate("author", "username profileImage")
      .populate("comments.user", "username profileImage");

    io.emit("postUpdated", updatedPost);
    res.json(updatedPost);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Add comment
app.post("/api/posts/:postId/comment", authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: "Comment text required" });

    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.comments.push({
      user: req.user.userId,
      text
    });

    await post.save();
    const updatedPost = await Post.findById(req.params.postId)
      .populate("author", "username profileImage")
      .populate("comments.user", "username profileImage");

    io.emit("postUpdated", updatedPost);
    res.json(updatedPost);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Increment views
app.post("/api/posts/:postId/view", async (req, res) => {
  try {
    const post = await Post.findById(req.params.postId);
    if (!post) return res.status(404).json({ error: "Post not found" });

    post.views += 1;
    await post.save();
    
    const updatedPost = await Post.findById(req.params.postId)
      .populate("author", "username profileImage")
      .populate("comments.user", "username profileImage");

    io.emit("postUpdated", updatedPost);
    res.json(updatedPost);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// -------------------------------
// 💬 Chat Routes
// -------------------------------
app.post("/api/room", authenticateToken, (req, res) => res.json({ ok: true }));

app.post("/api/message", authenticateToken, upload.array("media"), async (req, res) => {
  try {
    const { room, text } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    const mediaUrls = req.files?.map(f => `/uploads/${f.filename}`) || [];
    const message = await Message.create({ 
      room, 
      sender: user._id, 
      text, 
      mediaUrls 
    });
    
    const populated = await message.populate("sender", "username profileImage");

    io.emit("newMessage", populated);
    res.json(populated);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

app.get("/api/messages/:room", authenticateToken, async (req, res) => {
  try {
    const messages = await Message.find({ room: req.params.room })
      .populate("sender", "username profileImage")
      .sort({ createdAt: 1 });
    res.json(messages);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// -------------------------------
// Socket.io Connection Handling
// -------------------------------
const roomUsers = new Map();

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  socket.on("joinRoom", (roomName) => {
    socket.join(roomName);
    console.log(`User ${socket.id} joined room: ${roomName}`);
    
    // Track room users
    if (!roomUsers.has(roomName)) {
      roomUsers.set(roomName, new Set());
    }
    roomUsers.get(roomName).add(socket.id);
    
    io.to(roomName).emit("userJoined", {
      room: roomName,
      userCount: roomUsers.get(roomName).size
    });
  });

  socket.on("leaveRoom", (roomName) => {
    socket.leave(roomName);
    
    if (roomUsers.has(roomName)) {
      roomUsers.get(roomName).delete(socket.id);
      io.to(roomName).emit("userLeft", {
        room: roomName,
        userCount: roomUsers.get(roomName).size
      });
    }
  });

  socket.on("disconnect", () => {
    console.log("User disconnected:", socket.id);
    // Clean up room user tracking
    for (const [roomName, users] of roomUsers.entries()) {
      if (users.has(socket.id)) {
        users.delete(socket.id);
        io.to(roomName).emit("userLeft", {
          room: roomName,
          userCount: users.size
        });
      }
    }
  });
});

// -------------------------------
// 🧭 Serve frontend
// -------------------------------
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// -------------------------------
// 🚀 Start Server
// -------------------------------
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`🚀 SKIDEEY running on http://localhost:${PORT}`)); 
