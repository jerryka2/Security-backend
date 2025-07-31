import axios from "axios";
import bcrypt from "bcrypt";
import { v2 as cloudinary } from "cloudinary";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import stripe from "stripe";
import validator from "validator";
import appointmentModel from "../models/appointmentModel.js";
import doctorModel from "../models/eventModel.js";
import tempLoginModel from "../models/tempLoginModel.js";
import tempUserModel from "../models/tempUserModel.js";
import userModel from "../models/userModel.js";
import sendOtpEmail from "../utils/sendOtpEmail.js";
import sendPasswordResetEmail from "../utils/sendPasswordResetEmail.js";

// Stripe initialization
const stripeInstance = new stripe(process.env.STRIPE_SECRET_KEY);

/* ------------------ Core APIs ------------------ */

// Register user (with OTP)
const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.json({ success: false, message: "Missing Details" });
    }

    if (!validator.isEmail(email)) {
      return res.json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    // Password validation: at least 6 chars, at least one number
    const passwordRegex = /^(?=.*\d).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.json({
        success: false,
        message:
          "Password must be at least 6 characters and contain at least one number.",
      });
    }

    // Check if user already exists
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.json({ success: false, message: "User already exists" });
    }
    const tempExists = await tempUserModel.findOne({ email });
    if (tempExists) {
      return res.json({
        success: false,
        message: "Please verify OTP sent to your email",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Store in tempUserModel
    await tempUserModel.create({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpires,
    });

    // Send OTP via email
    try {
      await sendOtpEmail(email, otp);
    } catch (err) {
      await tempUserModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "Failed to send OTP email. Please try again.",
      });
    }

    res.json({
      success: true,
      message:
        "OTP sent to your email. Please verify to complete registration.",
    });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// OTP verification and final registration
const verifyUserOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const tempUser = await tempUserModel.findOne({ email });
    if (!tempUser) {
      return res.json({
        success: false,
        message: "No registration found for this email.",
      });
    }
    if (tempUser.otp !== otp) {
      return res.json({ success: false, message: "Invalid OTP." });
    }
    if (tempUser.otpExpires < new Date()) {
      await tempUserModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "OTP expired. Please register again.",
      });
    }

    // Move user to main userModel
    const { name, password } = tempUser;
    const newUser = new userModel({ name, email, password });
    await newUser.save();
    await tempUserModel.deleteOne({ email });

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour
    });
    res.json({ success: true, message: "Registration successful!" });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// const verifyCaptcha = async (token) => {
//   const secret = process.env.RECAPTCHA_SECRET_KEY;
//   const response = await axios.post(
//     `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${token}`
//   );
//   return response.data.success;
// };

const verifyCaptcha = async (token) => {
  const secret = process.env.RECAPTCHA_SECRET_KEY;

  try {
    const response = await axios.post(
      `https://www.google.com/recaptcha/api/siteverify`,
      new URLSearchParams({
        secret: secret,
        response: token,
      }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
    );

    if (!response.data.success) {
      console.error("❌ CAPTCHA Verification Failed", response.data);
    }

    return response.data.success;
  } catch (err) {
    console.error("Error verifying CAPTCHA:", err);
    return false;
  }
};

// Login user - Step 1: Verify credentials and send OTP
const loginUser = async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;

    // CAPTCHA verification
    if (!captchaToken || !(await verifyCaptcha(captchaToken))) {
      return res.json({ success: false, message: "Please verify you are a human." });
    }

    if (!email || !password) {
      return res.json({
        success: false,
        message: "Email and password are required",
      });
    }

    // First, check if user is in tempUserModel (not fully registered)
    const tempUser = await tempUserModel.findOne({ email });
    if (tempUser) {
      // User is not fully registered, send OTP for registration (reuse registration OTP logic)
      // Password validation: at least 6 chars, at least one number
      const passwordRegex = /^(?=.*\d).{6,}$/;
      if (!passwordRegex.test(password)) {
        return res.json({
          success: false,
          message:
            "Password must be at least 6 characters and contain at least one number.",
        });
      }
      // Check password matches tempUser password
      const isMatch = await bcrypt.compare(password, tempUser.password);
      if (!isMatch) {
        return res.json({ success: false, message: "Invalid credentials" });
      }
      // Generate OTP for login
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry
      tempUser.otp = otp;
      tempUser.otpExpires = otpExpires;
      await tempUser.save();
      try {
        await sendOtpEmail(email, otp);
        return res.json({
          success: true,
          message: "OTP sent to your email. Please verify to complete registration.",
          requiresOtp: true,
        });
      } catch (err) {
        return res.json({
          success: false,
          message: "Failed to send OTP email. Please try again.",
        });
      }
    }

    // User is fully registered, proceed with normal login
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User does not exist" });
    }

    // Check for lockout
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const wait = Math.ceil((user.lockUntil - Date.now()) / 1000);
      return res.json({
        success: false,
        message: `Too many failed attempts. Please try again after ${wait} seconds.`,
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 3) {
        user.lockUntil = Date.now() + 10 * 1000; // 10 seconds
        user.loginAttempts = 0;
      }
      await user.save();
      if (user.lockUntil && user.lockUntil > Date.now()) {
        return res.json({
          success: false,
          message:
            "Too many failed attempts. Please try again after 10 seconds.",
        });
      }
      return res.json({ success: false, message: "Invalid credentials" });
    }

    // Credentials are correct, log in directly
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour
    });
    return res.json({
      success: true,
      message: "Login successful!"
    });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Login user - Step 2: Verify OTP and complete login
const verifyLoginOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.json({
        success: false,
        message: "Email and OTP are required",
      });
    }

    const tempLogin = await tempLoginModel.findOne({ email });
    if (!tempLogin) {
      return res.json({
        success: false,
        message:
          "No login attempt found for this email. Please try logging in again.",
      });
    }

    if (tempLogin.otp !== otp) {
      return res.json({ success: false, message: "Invalid OTP." });
    }

    if (tempLogin.otpExpires < new Date()) {
      await tempLoginModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "OTP expired. Please try logging in again.",
      });
    }

    // OTP is valid, complete the login
    const user = await userModel.findById(tempLogin.userId);
    if (!user) {
      await tempLoginModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "User not found. Please try logging in again.",
      });
    }

    // Generate JWT token
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Clean up temp login record
    await tempLoginModel.deleteOne({ email });

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60 * 60 * 1000 // 1 hour
    });
    res.json({
      success: true,
      message: "Login successful!"
    });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Get user profile
const getProfile = async (req, res) => {
  try {
    const { userId } = req.body;
    const userData = await userModel.findById(userId).select("-password");
    res.json({ success: true, userData });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Update user profile
const updateProfile = async (req, res) => {
  console.log('updateProfile req.body:', req.body);
  console.log('updateProfile req.file:', req.file);
  try {
    const { userId, name, phone, address, dob, gender } = req.body;
    const imageFile = req.file;

    if (!name || !phone || !dob || !gender) {
      return res.json({ success: false, message: "Data Missing" });
    }

    await userModel.findByIdAndUpdate(userId, {
      name,
      phone,
      address: JSON.parse(address),
      dob,
      gender,
    });

    if (imageFile) {
      const imageUpload = await cloudinary.uploader.upload(imageFile.path, {
        resource_type: "image",
      });
      const imageURL = imageUpload.secure_url;
      await userModel.findByIdAndUpdate(userId, { image: imageURL });
    }

    res.json({ success: true, message: "Profile Updated" });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Book appointment
const bookAppointment = async (req, res) => {
  try {
    const { userId, docId, slotDate, slotTime } = req.body;
    const docData = await doctorModel.findById(docId).select("-password");

    if (!docData.available) {
      return res.json({ success: false, message: "Doctor Not Available" });
    }

    let slots_booked = docData.slots_booked;

    if (slots_booked[slotDate]) {
      if (slots_booked[slotDate].includes(slotTime)) {
        return res.json({ success: false, message: "Slot Not Available" });
      } else {
        slots_booked[slotDate].push(slotTime);
      }
    } else {
      slots_booked[slotDate] = [slotTime];
    }

    const userData = await userModel.findById(userId).select("-password");

    delete docData.slots_booked;

    const appointmentData = {
      userId,
      docId,
      userData,
      docData,
      amount: docData.fees,
      slotTime,
      slotDate,
      date: Date.now(),
    };

    const newAppointment = new appointmentModel(appointmentData);
    await newAppointment.save();

    await doctorModel.findByIdAndUpdate(docId, { slots_booked });

    res.json({ success: true, message: "Appointment Booked" });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Cancel appointment
const cancelAppointment = async (req, res) => {
  try {
    const { userId, appointmentId } = req.body;
    const appointmentData = await appointmentModel.findById(appointmentId);

    if (appointmentData.userId.toString() !== userId) {
      return res.json({ success: false, message: "Unauthorized action" });
    }

    await appointmentModel.findByIdAndUpdate(appointmentId, {
      cancelled: true,
    });

    const { docId, slotDate, slotTime } = appointmentData;
    const doctorData = await doctorModel.findById(docId);

    let slots_booked = doctorData.slots_booked;
    slots_booked[slotDate] = slots_booked[slotDate].filter(
      (e) => e !== slotTime
    );

    await doctorModel.findByIdAndUpdate(docId, { slots_booked });

    res.json({ success: true, message: "Appointment Cancelled" });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// List user's appointments
const listAppointment = async (req, res) => {
  try {
    const { userId } = req.body;
    const appointments = await appointmentModel.find({ userId });
    res.json({ success: true, appointments });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

/* ------------------ Password Reset APIs ------------------ */

// Forgot Password - Generate reset token and send email
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email) {
      return res.json({ 
        success: false, 
        message: "Email is required" 
      });
    }

    if (!validator.isEmail(email)) {
      return res.json({ 
        success: false, 
        message: "Please enter a valid email address" 
      });
    }

    // Check if user exists
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ 
        success: false, 
        message: "No account found with this email address" 
      });
    }

    // Generate secure reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Set token and expiry (1 hour from now)
    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    try {
      // Send reset email
      await sendPasswordResetEmail(email, resetToken);
      
      res.json({
        success: true,
        message: "Password reset link has been sent to your email address"
      });
    } catch (error) {
      // Clear the reset token if email fails
      user.passwordResetToken = null;
      user.passwordResetExpires = null;
      await user.save();

      console.error("Password reset email error:", error);
      res.json({
        success: false,
        message: "Failed to send reset email. Please try again later."
      });
    }
  } catch (error) {
    console.error("Forgot password error:", error);
    res.json({
      success: false,
      message: "An error occurred. Please try again later."
    });
  }
};

// Verify Reset Token - Check if token is valid and not expired
const verifyResetToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.json({
        success: false,
        message: "Reset token is required"
      });
    }

    // Hash the token to compare with stored hash
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid token and check expiry
    const user = await userModel.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.json({
        success: false,
        message: "Invalid or expired reset token. Please request a new password reset."
      });
    }

    res.json({
      success: true,
      message: "Reset token is valid",
      email: user.email
    });
  } catch (error) {
    console.error("Verify reset token error:", error);
    res.json({
      success: false,
      message: "An error occurred while verifying the token"
    });
  }
};

// Reset Password - Update password with new one
const resetPassword = async (req, res) => {
  try {
    const { token, password, confirmPassword } = req.body;

    // Validate inputs
    if (!token || !password || !confirmPassword) {
      return res.json({
        success: false,
        message: "All fields are required"
      });
    }

    if (password !== confirmPassword) {
      return res.json({
        success: false,
        message: "Passwords do not match"
      });
    }

    // Password validation
    const passwordRegex = /^(?=.*\d).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.json({
        success: false,
        message: "Password must be at least 6 characters and contain at least one number"
      });
    }

    // Hash the token to compare with stored hash
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    // Find user with valid token and check expiry
    const user = await userModel.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.json({
        success: false,
        message: "Invalid or expired reset token. Please request a new password reset."
      });
    }

    // Check if new password is same as current password
    const isSamePassword = await bcrypt.compare(password, user.password);
    if (isSamePassword) {
      return res.json({
        success: false,
        message: "New password cannot be the same as your current password. Please choose a different password."
      });
    }

    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Update password and clear reset token
    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    user.loginAttempts = 0; // Reset login attempts
    user.lockUntil = null; // Clear any account locks
    await user.save();

    res.json({
      success: true,
      message: "Password has been successfully reset. You can now login with your new password."
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.json({
      success: false,
      message: "An error occurred while resetting your password. Please try again."
    });
  }
};

/* ------------------ Logout API ------------------ */

// Logout User - Clear CSRF token and other session data
const logoutUser = async (req, res) => {
  try {
    // Clear the CSRF cookie
    res.clearCookie('_csrf', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });
    
    // Clear any other auth-related cookies if they exist
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    // Clear any session cookies
    res.clearCookie('connect.sid', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/'
    });

    // Log the user ID if available (from auth middleware)
    const userId = req.body.userId || 'unknown';
    console.log(`User ${userId} logged out successfully`);

    res.json({
      success: true,
      message: "Logged out successfully. CSRF token and session cleared.",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error("Logout error:", error);
    res.json({
      success: false,
      message: "An error occurred during logout. Please try again."
    });
  }
};

/* ------------------ Stripe Payment APIs ------------------ */

// Create Stripe session
const paymentStripe = async (req, res) => {
  try {
    const { appointmentId } = req.body;
    const { origin } = req.headers;

    const appointmentData = await appointmentModel.findById(appointmentId);

    if (!appointmentData || appointmentData.cancelled) {
      return res.json({
        success: false,
        message: "Appointment Cancelled or not found",
      });
    }

    const currency = (process.env.CURRENCY || "usd").toLowerCase();

    const line_items = [
      {
        price_data: {
          currency,
          product_data: {
            name: "Appointment Fees",
          },
          unit_amount: appointmentData.amount * 100,
        },
        quantity: 1,
      },
    ];

    const session = await stripeInstance.checkout.sessions.create({
      success_url: `${origin}/verify?success=true&appointmentId=${appointmentData._id}`,
      cancel_url: `${origin}/verify?success=false&appointmentId=${appointmentData._id}`,
      line_items: line_items,
      mode: "payment",
    });

    res.json({ success: true, session_url: session.url });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

// Verify Stripe payment
const verifyStripe = async (req, res) => {
  try {
    const { appointmentId, success } = req.body;

    if (success === "true") {
      await appointmentModel.findByIdAndUpdate(appointmentId, {
        payment: true,
      });
      return res.json({ success: true, message: "Payment Successful" });
    }

    res.json({ success: false, message: "Payment Failed" });
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

/* ------------------ Final Export ------------------ */

export {
  bookAppointment,
  cancelAppointment,
  forgotPassword,
  getProfile,
  listAppointment,
  loginUser,
  logoutUser,
  paymentStripe,
  registerUser,
  resetPassword,
  updateProfile,
  verifyLoginOtp,
  verifyResetToken,
  verifyStripe,
  verifyUserOtp
};

