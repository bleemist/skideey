const mongoose = require('mongoose');
const roomSchema = new mongoose.Schema({
  name: { type: String, unique: true },
  passwordHash: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Room', roomSchema);
