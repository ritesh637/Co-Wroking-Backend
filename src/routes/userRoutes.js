const express = require("express");
const router = express.Router();
const axios = require("axios");
const {
  authMiddleware,
  adminMiddleware,
} = require("../middlewares/authMiddleware");
const {
  registerUser,
  loginUser,
  sendOTP,
  verifyOTP,
  otpGenerate,
  resetPassword,
  verifyOtp,
  getUserProfile,
  updateUserProfile,
} = require("../controllers/userController");

// Register a new user
router.post("/register", registerUser);

// User login
router.post("/login", loginUser);

// Send OTP
router.post("/send-otp", sendOTP);

// Verify OTP and login
router.post("/verify-otp", verifyOTP);

// Generate OTP
router.post("/generateotp", otpGenerate);

//Verffy otp
router.post("/verifyotp", verifyOtp);

// Reset Password
router.post("/forgotpassword", resetPassword);

//update-user
router.get("/profile", authMiddleware ,getUserProfile);

router.put("/update-profile",authMiddleware,updateUserProfile);
// router
//   .route("/profile")
//   .get(authMiddleware, getUserProfile)
//   .put(authMiddleware, updateUserProfile);

module.exports = router;
