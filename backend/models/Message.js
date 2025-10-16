const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  room: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  text: { type: String },
  mediaUrls: [String],
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Message", messageSchema);
