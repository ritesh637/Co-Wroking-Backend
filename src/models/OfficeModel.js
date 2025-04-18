

const mongoose = require("mongoose");

const officeSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  image: { type: String, required: true },
  location: { type: String, required: true },
  description: { type: String, required: true },
  pricing: {
    Conference_Room: { type: String, required: true },
    Meeting_Room: { type: String, required: true },
    Day_Pass: { type: String, required: true },
  },
});

const Office = mongoose.model("Office", officeSchema);
module.exports = Office;
