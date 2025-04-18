const express = require("express");
const {
  createOrder,
  verifyPayment,
  getUserBookings,
  getAllUsersBookings,
  viewInvoiceData, 
  downloadInvoice,
} = require("../controllers/paymentContoller");
const {
  authMiddleware,
  adminMiddleware,
} = require("../middlewares/authMiddleware");
const router = express.Router();

router.post("/create-order", authMiddleware, createOrder);
router.post("/verify-payment", authMiddleware, verifyPayment);
router.get("/my-bookings", authMiddleware, getUserBookings);
router.get("/invoice/:bookingId", authMiddleware, viewInvoiceData);
router.get("/download-invoice/:bookingId", authMiddleware, downloadInvoice);
router.get(
  "/my-all-users-bookings",
  authMiddleware,
  adminMiddleware,
  getAllUsersBookings
);

module.exports = router;
