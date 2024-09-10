"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const userController_1 = require("../Controller/userController");
const router = express_1.default.Router();
router.post('/create', userController_1.createUser);
router.post('/sendotp', userController_1.sendOtp);
router.post('/verify-otp', userController_1.verifyOtp);
router.post('/login', userController_1.loginUser);
router.post('/forgot-password', userController_1.forgotpass);
router.post('/verifyotpforgot', userController_1.verifyOtpForgot);
router.post('/resetOtp', userController_1.resetOtp);
router.post('/verifyResetOtp', userController_1.verifyResetOtp);
router.post('/reset-password', userController_1.resetPassword);
router.post('/logout', userController_1.logout);
exports.default = router;
