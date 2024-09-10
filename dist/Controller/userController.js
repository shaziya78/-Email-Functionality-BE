"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logout = exports.resetPassword = exports.verifyResetOtp = exports.resetOtp = exports.loginUser = exports.verifyOtpForgot = exports.forgotpass = exports.verifyOtp = exports.sendOtp = exports.createUser = void 0;
const bcrypt_1 = __importDefault(require("bcrypt"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const nodemailer_1 = __importDefault(require("nodemailer"));
const usermodel_1 = __importDefault(require("../Model/usermodel"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
;
const transporter = nodemailer_1.default.createTransport({
    host: 'smtp.gmail.com',
    port: 587, // Default port for TLS
    secure: false, // Use TLS
    auth: {
        user: process.env.EMAIL_USER, // Your Gmail address
        pass: process.env.EMAIL_PASS, // Your Gmail password or App Password
    },
});
// const sendOtp = async (email: string, otp: string): Promise<void> => {
//   const mailOptions = {
//     from: process.env.EMAIL_USER, 
//     to: email,
//     subject: "OTP for Verification",
//     text: `Your OTP is ${otp}`,
//   };
//   try {
//     console.log(`Sending OTP to ${email}`);
//     await transporter.sendMail(mailOptions);
//     console.log("OTP sent successfully");
//   } catch (error) {
//     console.error("Error sending OTP:", error);
//   }
// };
const createUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { name, phone, email, password } = req.body;
        if (!name || !phone || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }
        if (password.length !== 8) {
            return res.status(400).json({ error: "Password must be exactly 8 characters long" });
        }
        if (!/^\d{10}$/.test(phone)) {
            return res.status(400).json({ error: "Phone number must be exactly 10 digits long" });
        }
        const emailCharRegex = /[!@#$%^&*(),.?":{}|<>]/;
        if (!emailCharRegex.test(email)) {
            return res.status(400).json({ error: "Email must contain at least one special character" });
        }
        const specialCharRegex = /[!@#$%^&*(),.?":{}|<>]/;
        if (!specialCharRegex.test(password)) {
            return res.status(400).json({ error: "Password must contain at least one special character" });
        }
        const existingUser = yield usermodel_1.default.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ error: "User already exists" });
        }
        const hashedPassword = yield bcrypt_1.default.hash(password, 10);
        const newUser = new usermodel_1.default({
            name,
            phone,
            email,
            password: hashedPassword,
            isVerified: false, // Initially, the user is not verified
        });
        const savedUser = yield newUser.save();
        console.log("User created:", savedUser);
        // Create JWT and store user info in a cookie
        const token = jsonwebtoken_1.default.sign({ userId: savedUser._id, name: savedUser.name, isVerified: savedUser.isVerified }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
        });
        res.cookie("email", email, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000
        });
        return res
            .status(201)
            .json({ message: "User created, please verify OTP", userId: savedUser._id, name: savedUser.name, isVerified: savedUser.isVerified });
    }
    catch (error) {
        console.error("Error creating user:", error);
        return res.status(500).json({ error: "Failed to create user" });
    }
});
exports.createUser = createUser;
// send otp
const sendOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    console.log('Cookies:', req.cookies); // Log cookies to see their names and values
    const userCookie = req.cookies.email; // Use the correct cookie name based on the log
    if (!userCookie) {
        return res.status(400).json({ message: 'No email found in cookie' });
    }
    // Find the user by email
    const user = yield usermodel_1.default.findOne({ email: userCookie }).exec();
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp; // Save the OTP in the user's record
    yield user.save(); // Save the user with the updated OTP
    // Set up the Nodemailer transporter
    const transporter = nodemailer_1.default.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, // Ensure this is set in your environment variables
            pass: process.env.EMAIL_PASS, // Ensure this is set in your environment variables
        },
    });
    // Set up the mail options
    const mailOptions = {
        from: process.env.EMAIL_USER, // Sender address
        to: user.email, // Recipient address
        subject: 'OTP For Verification',
        text: `Your OTP code is ${otp}`, // Proper template literal usage
    };
    try {
        // Send the email
        yield transporter.sendMail(mailOptions);
        return res.json({ message: 'OTP sent successfully' });
    }
    catch (error) {
        console.error('Error sending OTP:', error); // Added error logging
        return res.status(500).json({ message: 'Failed to send OTP' });
    }
});
exports.sendOtp = sendOtp;
const verifyOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { otp } = req.body;
        if (!otp) {
            return res.status(400).json({ error: "OTP are required" });
        }
        const userCookie = req.cookies.email;
        if (!userCookie) {
            return res.status(400).json({ status: "No Email Found for this user" });
        }
        const user = yield usermodel_1.default.findOne({ email: userCookie }).exec();
        if (!user) {
            return res.status(400).json({ status: "No user Found" });
        }
        if (user.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }
        if (user.otpExpires && user.otpExpires.getTime() < Date.now()) {
            return res.status(400).json({ error: "OTP has expired" });
        }
        user.otp = undefined;
        user.otpExpires = undefined;
        user.isVerified = true;
        yield user.save();
        // Update JWT token to reflect the verified status
        const token = jsonwebtoken_1.default.sign({ userId: user._id, name: user.name, isVerified: true }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
        });
        return res.status(200).json({ message: "OTP verified successfully" });
    }
    catch (error) {
        return res.status(500).json({ error: "Failed to verify OTP" });
    }
});
exports.verifyOtp = verifyOtp;
const loginUser = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: "Please fill out all the details" });
        }
        const user = yield usermodel_1.default.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        const isMatch = yield bcrypt_1.default.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Incorrect password" });
        }
        const token = jsonwebtoken_1.default.sign({ userId: user._id, name: user.name, isVerified: user.isVerified }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
        });
        res.cookie('email', user.email, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
        const _a = user.toObject(), { password: _ } = _a, userWithoutPassword = __rest(_a, ["password"]);
        return res.status(200).json(userWithoutPassword);
    }
    catch (error) {
        console.error("Error logging in user:", error);
        return res.status(500).json({ error: "Failed to log in user" });
    }
});
exports.loginUser = loginUser;
const forgotpass = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        const user = yield usermodel_1.default.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "No user found with this email" });
        }
        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp; // Save the OTP in the user's record
        yield user.save(); // Save the user with the updated OTP
        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
        // Set up the Nodemailer transporter
        const transporter = nodemailer_1.default.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER, // Ensure this is set in your environment variables
                pass: process.env.EMAIL_PASS, // Ensure this is set in your environment variables
            },
        });
        // Set up the mail options
        const mailOptions = {
            from: process.env.EMAIL_USER, // Sender address
            to: user.email, // Recipient address
            subject: 'OTP For Verification',
            text: `Your OTP code is ${otp}`, // Proper template literal usage
        };
        // Send the email
        yield transporter.sendMail(mailOptions);
        return res.json({ message: 'OTP sent successfully' });
    }
    catch (error) {
        console.error('Error sending OTP:', error); // Detailed error logging
        if (error) {
            console.error('SMTP Response:', error); // SMTP server response
        }
        return res.status(500).json({ message: 'Failed to send OTP', error });
    }
});
exports.forgotpass = forgotpass;
// for forgot password otp verify
const verifyOtpForgot = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { otp, email } = req.body; // Extract both otp and email from req.body
        if (!otp || !email) { // Check if both otp and email are provided
            return res.status(400).json({ error: "OTP and email are required" });
        }
        const user = yield usermodel_1.default.findOne({ email }).exec(); // Use the email to find the user
        if (!user) {
            return res.status(400).json({ status: "No user found" });
        }
        if (user.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // Set expiration time to 10 minutes from now
        user.otpExpires = otpExpires;
        // Clear the OTP and mark the user as verified
        user.otp = undefined;
        user.otpExpires = undefined;
        user.isVerified = true;
        yield user.save();
        // Update JWT token to reflect the verified status
        const token = jsonwebtoken_1.default.sign({ userId: user._id, name: user.name, isVerified: true }, process.env.JWT_SECRET, { expiresIn: "1h" });
        // Set the token in a cookie
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
        });
        return res.status(200).json({ message: "OTP verified successfully" });
    }
    catch (error) {
        return res.status(500).json({ error: "Failed to verify OTP" });
    }
});
exports.verifyOtpForgot = verifyOtpForgot;
// for reset
const resetOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    console.log('Cookies:', req.cookies); // Log cookies to see their names and values
    const userCookie = req.cookies.email; // Use the correct cookie name based on the log
    if (!userCookie) {
        return res.status(400).json({ message: 'No email found in cookie' });
    }
    // Find the user by email
    const user = yield usermodel_1.default.findOne({ email: userCookie }).exec();
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    if (!user.isVerified) {
        return res.status(400).json({ message: "User is not verified" });
    }
    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp; // Save the OTP in the user's record
    yield user.save(); // Save the user with the updated OTP
    // Set up the Nodemailer transporter
    const transporter = nodemailer_1.default.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER, // Ensure this is set in your environment variables
            pass: process.env.EMAIL_PASS, // Ensure this is set in your environment variables
        },
    });
    // Set up the mail options
    const mailOptions = {
        from: process.env.EMAIL_USER, // Sender address
        to: user.email, // Recipient address
        subject: 'OTP For Verification',
        text: `Your OTP code is ${otp}`, // Proper template literal usage
    };
    try {
        // Send the email
        yield transporter.sendMail(mailOptions);
        return res.json({ message: 'OTP sent successfully' });
    }
    catch (error) {
        console.error('Error sending OTP:', error); // Added error logging
        return res.status(500).json({ message: 'Failed to send OTP' });
    }
});
exports.resetOtp = resetOtp;
const verifyResetOtp = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { otp } = req.body;
        if (!otp) {
            return res.status(400).json({ error: "OTP are required" });
        }
        const userCookie = req.cookies.email;
        if (!userCookie) {
            return res.status(400).json({ status: "No Email Found for this user" });
        }
        const user = yield usermodel_1.default.findOne({ email: userCookie }).exec();
        if (!user) {
            return res.status(400).json({ status: "No user Found" });
        }
        if (user.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP" });
        }
        if (user.otpExpires && user.otpExpires.getTime() < Date.now()) {
            return res.status(400).json({ error: "OTP has expired" });
        }
        user.otp = undefined;
        user.otpExpires = undefined;
        user.isVerified = true;
        yield user.save();
        // Update JWT token to reflect the verified status
        const token = jsonwebtoken_1.default.sign({ userId: user._id, name: user.name, isVerified: true }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 3600000, // 1 hour
        });
        return res.status(200).json({ message: "OTP verified successfully,Now you can reset your password" });
    }
    catch (error) {
        return res.status(500).json({ error: "Failed to verify OTP" });
    }
});
exports.verifyResetOtp = verifyResetOtp;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { oldPassword, newPassword, confirmPassword } = req.body;
        // Validate input
        if (!oldPassword || !newPassword || !confirmPassword) {
            return res.status(400).json({ error: "All fields are required" });
        }
        // Check if the user is authenticated (you might need to use middleware for this)
        const userCookie = req.cookies.email;
        if (!userCookie) {
            return res.status(400).json({ error: "User not authenticated" });
        }
        // Find the user from the database
        const user = yield usermodel_1.default.findOne({ email: userCookie }).exec();
        if (!user) {
            return res.status(400).json({ error: "User not found" });
        }
        // Verify old password
        const isMatch = yield bcrypt_1.default.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: "Old password is incorrect" });
        }
        // Validate new passwords
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ error: "New passwords do not match" });
        }
        // Hash the new password
        const hashedPassword = yield bcrypt_1.default.hash(newPassword, 10);
        // Update user password and clear OTP
        user.password = hashedPassword;
        user.otp = undefined;
        user.otpExpires = undefined;
        yield user.save();
        return res.status(200).json({ message: "Password has been reset successfully" });
    }
    catch (error) {
        console.error("Error resetting password:", error);
        return res.status(500).json({ error: "Failed to reset password" });
    }
});
exports.resetPassword = resetPassword;
const logout = (req, res) => {
    try {
        res.cookie("token", "", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 0, // Expire the cookie immediately
        });
        return res.status(200).json({ message: "Logged out successfully" });
    }
    catch (error) {
        console.error("Error logging out user:", error);
        return res.status(500).json({ error: "Failed to log out" });
    }
};
exports.logout = logout;
