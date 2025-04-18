const PromoCode = require("../models/PromoCode");

// ✅ Create promo code
const createPromoCode = async (req, res) => {
  const { code, discount, expiry } = req.body;

  if (!code || !discount || !expiry) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existing = await PromoCode.findOne({ code });
    if (existing) {
      return res.status(400).json({ message: "Promo code already exists" });
    }

    const newPromo = new PromoCode({
      code: code.trim(),
      discount,
      expiry,
    });

    await newPromo.save();
    res.status(201).json({ message: "Promo code created", promo: newPromo });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ✅ Get all promo codes
const getAllPromoCodes = async (req, res) => {
  try {
    const promos = await PromoCode.find().sort({ createdAt: -1 });
    res.json(promos);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ✅ Validate promo code
const validatePromoCode = async (req, res) => {
  const { code } = req.body;
  try {
    const promo = await PromoCode.findOne({ code });
    if (!promo || new Date(promo.expiry) < new Date()) {
      return res.status(400).json({ message: "Invalid or expired promo code" });
    }
    res.json(promo);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ✅ Get promo code by ID
const getPromoCodeById = async (req, res) => {
  const { id } = req.params;
  try {
    const promo = await PromoCode.findById(id);
    if (!promo) {
      return res.status(404).json({ message: "Promo code not found" });
    }
    res.json(promo);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ✅ Update promo code
const updatePromoCode = async (req, res) => {
  const { id } = req.params;
  const { code, discount, expiry } = req.body;

  try {
    const promo = await PromoCode.findByIdAndUpdate(
      id,
      { code, discount, expiry },
      { new: true }
    );
    if (!promo) {
      return res.status(404).json({ message: "Promo code not found" });
    }
    res.json(promo);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ✅ Delete promo code
const deletePromoCode = async (req, res) => {
  const { id } = req.params;
  try {
    const promo = await PromoCode.findByIdAndDelete(id);
    if (!promo) {
      return res.status(404).json({ message: "Promo code not found" });
    }
    res.json({ message: "Promo code deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  createPromoCode,
  getAllPromoCodes,
  validatePromoCode,
  getPromoCodeById,
  updatePromoCode,
  deletePromoCode,
};
