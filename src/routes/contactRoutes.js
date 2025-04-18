const express = require("express");
const router = express.Router();
const {
  createContact,
  getContacts,
} = require("../controllers/contactContoller");

router.post("/submit", createContact);

router.get("/all", getContacts);

module.exports = router;
