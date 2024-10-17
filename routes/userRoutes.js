const express = require("express");
const { RegisterUser, LoginUser,ForgotPassword, ResetPassword } = require("../controller/userController");
const router = express.Router();


router.post("/register", RegisterUser);
router.post("/login", LoginUser);
router.post("/forgot-password", ForgotPassword);  
router.post("/reset-password/:token", ResetPassword);

module.exports = router;
