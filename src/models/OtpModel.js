const mongoose = require("mongoose");

const otpSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  otp: {
    type: String, 
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

module.exports = mongoose.model("Otp", otpSchema);

