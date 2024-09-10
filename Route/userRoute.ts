import express, { Router } from 'express';
import authenticate from '../middleware/cookie';
import {
  createUser,
  loginUser,
  verifyOtp,
  logout,
  sendOtp,
  forgotpass,
  resetOtp,
  verifyResetOtp,
  resetPassword,
  verifyOtpForgot
} from '../Controller/userController';

const router: Router = express.Router();

router.post('/create', createUser);
router.post('/sendotp',sendOtp);
router.post('/verify-otp', verifyOtp);
router.post('/login', loginUser);
router.post('/forgot-password',forgotpass);
router.post('/verifyotpforgot',verifyOtpForgot);
router.post('/resetOtp',resetOtp);
router.post('/verifyResetOtp',verifyResetOtp);
router.post('/reset-password',resetPassword);
router.post('/logout', logout);

export default router;
