const Razorpay = require("razorpay");
const crypto = require("crypto");
const Payment = require("../models/PaymentModel");
const PDFDocument = require("pdfkit");
const fs = require("fs");
const path = require("path");
const User = require("../models/UserModel");
require("dotenv").config();

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// 📦 Create Razorpay Order
exports.createOrder = async (req, res) => {
  const { userId, cartItems, totalAmount } = req.body;

  // 🧠 Validate input
  if (!userId || !cartItems || !totalAmount) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields: userId, cartItems, totalAmount",
    });
  }

  try {
    const options = {
      amount: totalAmount * 100,
      currency: "INR",
      receipt: `receipt_order_${Math.random().toString(36).substring(2, 10)}`,
      payment_capture: 1,
    };

    let order;
    try {
      order = await razorpay.orders.create(options);
    } catch (razorErr) {
      console.error("❌ Razorpay order creation error:", razorErr);
      return res.status(500).json({
        success: false,
        message: "Razorpay order creation failed",
        error: razorErr.message,
      });
    }

    const payment = new Payment({
      userId,
      cartItems,
      totalAmount,
      paymentStatus: "Pending",
      razorpayOrderId: order.id,
    });

    await payment.save();

    res.status(201).json({
      success: true,
      order: {
        id: order.id,
        amount: order.amount,
        currency: order.currency,
      },
    });
  } catch (error) {
    console.error("❌ Backend error creating order:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create order.",
    });
  }
};

// ✅ Verify Razorpay Payment
exports.verifyPayment = async (req, res) => {
  const paymentResponse = req.body;

  try {
    const payment = await Payment.findOne({
      razorpayOrderId: paymentResponse.razorpay_order_id,
    });

    if (!payment) {
      return res
        .status(404)
        .json({ success: false, message: "Payment not found." });
    }

    payment.paymentStatus = "Completed";
    await payment.save();

    res
      .status(200)
      .json({ success: true, message: "Payment verified successfully." });
  } catch (error) {
    console.error("❌ Payment verification error:", error);
    res
      .status(500)
      .json({ success: false, message: "Payment verification failed." });
  }
};

// 🧾 Generate PDF Invoice
const generateInvoice = (booking, user, outputPath) => {
  const dir = path.dirname(outputPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  const doc = new PDFDocument();
  doc.pipe(fs.createWriteStream(outputPath));

  doc.fontSize(22).text("Space Hub Coworking Pvt. Ltd.", { align: "center" });
  doc.moveDown(0.5);
  doc.fontSize(20).text("Invoice", { align: "center" });
  doc.moveDown();

  const name = user?.username || "N/A";
  const email = user?.email || "N/A";
  const bookingId = booking?._id || "N/A";
  const amount = booking?.totalAmount || 0;
  const date = booking?.createdAt
    ? new Date(booking.createdAt).toLocaleString()
    : "N/A";
  const status = booking?.paymentStatus || "N/A";

  const firstItem = booking?.cartItems?.[0] || {};
  const plan = firstItem.plan || "N/A";

  const startDate = firstItem.startDate
    ? new Date(firstItem.startDate).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "long",
        year: "numeric",
      })
    : "N/A";

  const endDate = firstItem.endDate
    ? new Date(firstItem.endDate).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "long",
        year: "numeric",
      })
    : "N/A";

  doc.fontSize(12).text(`Name: ${name}`);
  doc.text(`Email: ${email}`);
  doc.moveDown();
  doc.text(`Booking ID: ${bookingId}`);
  doc.text(`Amount Paid: ₹${amount}`);
  doc.text(`Booking Date: ${date}`);
  doc.text(`Plan: ${plan}`);
  doc.text(`Start Date: ${startDate}`);
  doc.text(`End Date: ${endDate}`);
  doc.text(`Payment Status: ${status}`);
  doc.moveDown();
  doc.text("Thank you for your Booking!", { align: "center" });

  doc.end();
};

// 📥 Download Invoice as PDF
exports.downloadInvoice = async (req, res) => {
  const { bookingId } = req.params;
  const userId = req.user.id;

  try {
    const booking = await Payment.findById(bookingId);
    const user = await User.findById(userId);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    const invoicePath = path.join(
      __dirname,
      `../invoices/invoice_${booking._id}.pdf`
    );

    if (!fs.existsSync(invoicePath)) {
      generateInvoice(booking, user, invoicePath);
      setTimeout(() => {
        res.download(invoicePath);
      }, 1000);
    } else {
      res.download(invoicePath);
    }
  } catch (error) {
    console.error("❌ Invoice download error:", error);
    res.status(500).json({ message: "Failed to download invoice." });
  }
};

// 👁 View Static Invoice Data
exports.viewInvoiceData = async (req, res) => {
  const { bookingId } = req.params;
  const userId = req.user.id;

  try {
    const booking = await Payment.findById(bookingId);
    const user = await User.findById(userId);

    if (!booking) {
      return res.status(404).json({ message: "Booking not found" });
    }

    const firstItem = booking?.cartItems?.[0] || {};
    const plan = firstItem.plan || "N/A";

    const response = {
      username: user?.username || "N/A",
      email: user?.email || "N/A",
      bookingId: booking._id,
      amount: booking.totalAmount || 0,
      createdAt: booking.createdAt,
      status: booking.paymentStatus,
      plan,
      startDate: firstItem.startDate,
      endDate: firstItem.endDate,
    };

    res.status(200).json(response);
  } catch (error) {
    console.error("❌ Invoice fetch error:", error);
    res.status(500).json({ message: "Failed to load invoice." });
  }
};

// 📋 Get Logged-in User Bookings
exports.getUserBookings = async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId);

    if (!user) return res.status(404).json({ message: "User not found" });

    const bookings = await Payment.find({ userId }).sort({ createdAt: -1 });

    res.status(200).json({ bookings });
  } catch (err) {
    console.error("❌ Error fetching user bookings:", err);
    res.status(500).json({ message: "Server error" });
  }
};

// 📋 Admin: Get All Bookings
exports.getAllUsersBookings = async (req, res) => {
  try {
    const bookings = await Payment.find()
      .populate("userId", "username email")
      .exec();

    res.status(200).json({
      success: true,
      count: bookings.length,
      data: bookings,
    });
  } catch (error) {
    console.error("❌ Error fetching all bookings:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
    });
  }
};
