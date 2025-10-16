const mongoose = require("mongoose");

const postSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  content: { type: String, required: true },
  mediaUrls: [String],
  timestamp: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 }
});

module.exports = mongoose.model("Post", postSchema);
