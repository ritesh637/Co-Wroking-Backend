const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/UserModel");

const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ role: "admin" });

    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);

      const admin = new User({
        email: "200101120103@cutm.ac.in",
        password: hashedPassword,
        username: "Admin",
        phoneNumber: "7707076831",
        role: "admin",
      });

      await admin.save();
      console.log("✅ Default admin created!");
    } else {
      console.log("⚡ Admin already exists.");
    }
  } catch (error) {
    console.error("❌ Error creating admin:", error);
  }
};
module.exports = { createDefaultAdmin };
