const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  avatarUrl: { type: String, default: null },
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('User', userSchema);
