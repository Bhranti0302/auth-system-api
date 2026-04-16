const express = require("express");
const router = express.Router();

const { signup, login, logout, googleLogin } = require("../controllers/authController");

router.post("/signup", signup);
router.post("/login", login);
router.post("/logout", logout);
router.post("/google-login", googleLogin);


module.exports = router;
