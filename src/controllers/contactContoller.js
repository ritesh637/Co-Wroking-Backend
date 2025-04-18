const Contact = require("../models/ContactModel");

// Create a new contact submission
exports.createContact = async (req, res) => {
  try {
    const { firstName, lastName, email, subject, message } = req.body;

    // Validation check
    if (!firstName || !lastName || !email || !subject || !message) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const newContact = new Contact({ firstName, lastName, email, subject, message });
    await newContact.save();

    res.status(201).json({ success: true, message: "Contact form submitted successfully", data: newContact });
  } catch (error) {
    console.error("Error in createContact:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Get all contact submissions
exports.getContacts = async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: contacts });
  } catch (error) {
    console.error("Error in getContacts:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};
