const Office = require("../models/OfficeModel");

const getOfficeById = async (req, res) => {
  try {
    const office = await Office.findOne({ id: req.params.id });
    if (!office) return res.status(404).json({ message: "Office not found" });
    res.json(office);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const getAllOffices = async (req, res) => {
  try {
    const { search = "", page = 1, limit = 6 } = req.query;
    const query = {
      $or: [
        { name: new RegExp(search, "i") },
        { location: new RegExp(search, "i") },
      ],
    };
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const total = await Office.countDocuments(query);
    const offices = await Office.find(query).skip(skip).limit(parseInt(limit));

    res.json({ total, page: +page, limit: +limit, offices });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const createOffice = async (req, res) => {
  try {
    const office = new Office(req.body);
    const newOffice = await office.save();
    res.status(201).json(newOffice);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const updateOffice = async (req, res) => {
  try {
    const office = await Office.findOneAndUpdate(
      { id: req.params.id },
      req.body,
      { new: true }
    );
    if (!office) return res.status(404).json({ message: "Office not found" });
    res.json(office);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

const deleteOffice = async (req, res) => {
  try {
    const office = await Office.findOneAndDelete({ id: req.params.id });
    if (!office) return res.status(404).json({ message: "Office not found" });
    res.json({ message: "Office deleted" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  getOfficeById,
  getAllOffices,
  createOffice,
  updateOffice,
  deleteOffice,
};
