import express from "express";
import {
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
  verifyUserOtp,
} from "../controllers/userController.js";
import authUser from "../middleware/authUser.js";
import upload from "../middleware/multer.js";
import { loginRateLimiter, passwordResetRateLimiter } from "../middleware/rateLimiter.js";

const userRouter = express.Router();

// Auth routes
userRouter.post("/register", registerUser);
userRouter.post("/login", loginRateLimiter, loginUser);
userRouter.post("/verify-login-otp", loginRateLimiter, verifyLoginOtp);
userRouter.post("/logout", authUser, logoutUser);
userRouter.get("/profile", authUser, getProfile);
userRouter.post("/update-profile", authUser, upload.single('image'), updateProfile);
userRouter.post("/verify-otp", verifyUserOtp);

// Password Reset routes
userRouter.post("/forgot-password", passwordResetRateLimiter, forgotPassword);
userRouter.post("/verify-reset-token", verifyResetToken);
userRouter.post("/reset-password", resetPassword);

// Appointments
userRouter.post("/book-appointment", authUser, bookAppointment);
userRouter.get("/my-appointments", authUser, listAppointment);
userRouter.post("/cancel-appointment", authUser, cancelAppointment);

// Stripe routes only
userRouter.post("/payment-stripe", authUser, paymentStripe);
userRouter.post("/verify-stripe", authUser, verifyStripe);

export default userRouter;
