import bcrypt from "bcrypt";
import { Request, Response } from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { emailTemplate } from '../emailTemplate';
import Form from "../Model/usermodel";
import dotenv from 'dotenv';
dotenv.config();


interface ICreateUserRequest extends Request {
  body: {
    name: string;
    phone: string;
    email: string;
    password: string;
  };
}

interface IVerifyOtpRequest extends Request {
  body: {
    email: string;
    otp: string;
  };
}

interface ILoginRequest extends Request {
  body: {
    email: string;
    password: string;
  };
}

interface IForgotPasswordRequest extends Request {
  body: {
    email: string;
  };
}

interface IResetPasswordRequest extends Request {
  body: {
    oldPassword:string;
    newPassword: string;
    confirmPassword: string;
  };
}
interface ISendOtpRequest extends Request {
  cookies: {
    email?: string;
    [key: string]: any; // To accommodate other potential cookies
  };
};



const transporter = nodemailer.createTransport({
  
  host: process.env.EMAIL_HOST,
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


const createUser = async (req: ICreateUserRequest, res: Response): Promise<Response> => {
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

    const existingUser = await Form.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new Form({
      name,
      phone,
      email,
      password: hashedPassword,
      isVerified: false, // Initially, the user is not verified
    });
    const savedUser = await newUser.save();
    console.log("User created:", savedUser);

    // Create JWT and store user info in a cookie
    const token = jwt.sign(
      { userId: savedUser._id, name: savedUser.name, isVerified: savedUser.isVerified },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000, // 1 hour
    });
 
    res.cookie("email",email,{
      httpOnly:true,
      secure:process.env.NODE_ENV==="production",
      maxAge:3600000
    });
    return res
      .status(201)
      .json({ message: "User created, please verify OTP", userId: savedUser._id, name: savedUser.name, isVerified: savedUser.isVerified });
  } catch (error) {
    console.error("Error creating user:", error);
    return res.status(500).json({ error: "Failed to create user" });
  }
};
// send otp
const sendOtp = async (req: ISendOtpRequest, res: Response): Promise<Response> => {
  console.log('Cookies:', req.cookies); // Log cookies to see their names and values

  const userCookie = req.cookies.email; // Use the correct cookie name based on the log

  if (!userCookie) {
    return res.status(400).json({ message: 'No email found in cookie' });
  }

  // Find the user by email
  const user = await Form.findOne({ email: userCookie }).exec();

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  user.otp = otp; // Save the OTP in the user's record
  await user.save(); // Save the user with the updated OTP

  // Set up the Nodemailer transporter
  const transporter = nodemailer.createTransport({
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
    await transporter.sendMail(mailOptions);
    return res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error); // Added error logging
    return res.status(500).json({ message: 'Failed to send OTP' });
  }
};

const verifyOtp = async (req: IVerifyOtpRequest, res: Response): Promise<Response> => {
  try {
    const {otp } = req.body;

    if (!otp) {
      return res.status(400).json({ error: "OTP are required" });
    }

  const userCookie=req.cookies.email;
  if(!userCookie){
    return res.status(400).json({status:"No Email Found for this user"})
  }

  const user=await Form.findOne({email:userCookie}).exec();

  if(!user){
    return res.status(400).json({status:"No user Found"})
  }

  if(user.otp !== otp){
return res.status(400).json({error:"Invalid OTP"})
  }

if(user.otpExpires && user.otpExpires.getTime()< Date.now()){
  return res.status(400).json({error:"OTP has expired"})
}
    user.otp = undefined;
    user.otpExpires = undefined;
    user.isVerified = true;
    await user.save();

    // Update JWT token to reflect the verified status
    const token = jwt.sign(
      { userId: user._id, name: user.name, isVerified: true },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000, // 1 hour
    });

    return res.status(200).json({ message: "OTP verified successfully" });
  } catch (error) {
    return res.status(500).json({ error: "Failed to verify OTP" });
  }
};

const loginUser = async (req: ILoginRequest, res: Response): Promise<Response> => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Please fill out all the details" });
    }

    const user = await Form.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    const token = jwt.sign(
      { userId: user._id, name: user.name, isVerified: user.isVerified },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000, // 1 hour
    });

    res.cookie('email', user.email, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

    const { password: _, ...userWithoutPassword } = user.toObject();
    return res.status(200).json(userWithoutPassword);
  } catch (error) {
    console.error("Error logging in user:", error);
    return res.status(500).json({ error: "Failed to log in user" });
  }
};
const forgotpass = async (req: IForgotPasswordRequest, res: Response): Promise<Response> => {
  try {
    const { email } = req.body;

    const user = await Form.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "No user found with this email" });
    }

    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = otp; // Save the OTP in the user's record
    await user.save(); // Save the user with the updated OTP

       if (user.otp !== otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Set up the Nodemailer transporter
    const transporter = nodemailer.createTransport({
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
    await transporter.sendMail(mailOptions);
    return res.json({ message: 'OTP sent successfully' });


  } catch (error) {
    console.error('Error sending OTP:', error); // Detailed error logging
    return res.status(500).json({ message: 'Failed to send OTP',error});
  }
};

// for forgot password otp verify

const verifyOtpForgot = async (req: Request, res: Response): Promise<Response> => {
  try {
    const { otp, email } = req.body; // Extract both otp and email from req.body

    if (!otp || !email) { // Check if both otp and email are provided
      return res.status(400).json({ error: "OTP and email are required" });
    }

    const user = await Form.findOne({ email }).exec(); // Use the email to find the user

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
    await user.save();

    // Update JWT token to reflect the verified status
    const token = jwt.sign(
      { userId: user._id, name: user.name, isVerified: true },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    // Set the token in a cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000, // 1 hour
    });

    return res.status(200).json({ message: "OTP verified successfully" });
  } catch (error) {
    return res.status(500).json({ error: "Failed to verify OTP" });
  }
};



// for reset
const resetOtp=async(req:Request,res:Response):Promise<Response>=>{
  console.log('Cookies:', req.cookies); // Log cookies to see their names and values

  const userCookie = req.cookies.email; // Use the correct cookie name based on the log

  if (!userCookie) {
    return res.status(400).json({ message: 'No email found in cookie' });
  }

  // Find the user by email
  const user = await Form.findOne({ email: userCookie }).exec();

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  if(!user.isVerified){
    return res.status(400).json({message:"User is not verified"})
  }
  // Generate a 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  user.otp = otp; // Save the OTP in the user's record
  await user.save(); // Save the user with the updated OTP

  // Set up the Nodemailer transporter
  const transporter = nodemailer.createTransport({
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
    await transporter.sendMail(mailOptions);
    return res.json({ message: 'OTP sent successfully' });
  } catch (error) {
    console.error('Error sending OTP:', error); // Added error logging
    return res.status(500).json({ message: 'Failed to send OTP' });
  }
};

const verifyResetOtp = async (req: Request, res: Response): Promise<Response> => {
  try {
    const {otp } = req.body;

    if (!otp) {
      return res.status(400).json({ error: "OTP are required" });
    }

  const userCookie=req.cookies.email;
  if(!userCookie){
    return res.status(400).json({status:"No Email Found for this user"})
  }

  const user=await Form.findOne({email:userCookie}).exec();

  if(!user){
    return res.status(400).json({status:"No user Found"})
  }

  if(user.otp !== otp){
return res.status(400).json({error:"Invalid OTP"})
  }

if(user.otpExpires && user.otpExpires.getTime()< Date.now()){
  return res.status(400).json({error:"OTP has expired"})
}
    user.otp = undefined;
    user.otpExpires = undefined;
    user.isVerified = true;
    await user.save();

    // Update JWT token to reflect the verified status
    const token = jwt.sign(
      { userId: user._id, name: user.name, isVerified: true },
      process.env.JWT_SECRET as string,
      { expiresIn: "1h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 3600000, // 1 hour
    });

    return res.status(200).json({ message: "OTP verified successfully,Now you can reset your password" });
  } catch (error) {
    return res.status(500).json({ error: "Failed to verify OTP" });
  }
};
const resetPassword = async (req: IResetPasswordRequest, res: Response): Promise<Response> => {
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
    const user = await Form.findOne({ email: userCookie }).exec();
    if (!user) {
      return res.status(400).json({ error: "User not found" });
    }

    // Verify old password
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Old password is incorrect" });
    }

    // Validate new passwords
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: "New passwords do not match" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and clear OTP
    user.password = hashedPassword;
    user.otp = undefined;
    user.otpExpires = undefined;

    await user.save();

    return res.status(200).json({ message: "Password has been reset successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ error: "Failed to reset password" });
  }
};


const logout = (req: Request, res: Response): Response => {
  try {
    res.cookie("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 0, // Expire the cookie immediately
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Error logging out user:", error);
    return res.status(500).json({ error: "Failed to log out" });
  }
};

export { createUser,sendOtp, verifyOtp, forgotpass, verifyOtpForgot, loginUser,resetOtp,verifyResetOtp, resetPassword, logout };


