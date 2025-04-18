const express = require("express");
const router = express.Router();
const officeController = require("../controllers/officeController");
const {
  authMiddleware,
  adminMiddleware,
} = require("../middlewares/authMiddleware");

router.get("/:id", officeController.getOfficeById);
router.get("/", officeController.getAllOffices);
router.post(
  "/create",
  authMiddleware,
  adminMiddleware,
  officeController.createOffice
);
router.put(
  "/:id",
  authMiddleware,
  adminMiddleware,
  officeController.updateOffice
);
router.delete(
  "/:id",
  authMiddleware,
  adminMiddleware,
  officeController.deleteOffice
);

module.exports = router;
