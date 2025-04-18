const express = require("express");
const router = express.Router();
const {
  createPromoCode,
  getAllPromoCodes,
  validatePromoCode,
  getPromoCodeById,
  updatePromoCode,
  deletePromoCode,
} = require("../controllers/promoController");
const {
  authMiddleware,
  adminMiddleware,
} = require("../middlewares/authMiddleware");

// Create promo code (only admin)
router.post("/create", authMiddleware, adminMiddleware, createPromoCode);

// Get all promo codes
router.get("/all", getAllPromoCodes);

// Validate promo code
router.post("/validate", validatePromoCode);

// Get promo by ID
router.get("/:id", getPromoCodeById);

// Update promo code
router.put("/:id", authMiddleware, adminMiddleware, updatePromoCode);

// Delete promo code
router.delete("/:id", authMiddleware, adminMiddleware, deletePromoCode);

module.exports = router;
