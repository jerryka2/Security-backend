import cookieParser from "cookie-parser";
import cors from "cors";
import csrf from "csurf";
import "dotenv/config";
import express from "express";
import fs from "fs";
import helmet from "helmet";
import https from "https";

import "./config/cloudinary.js";
import connectDB from "./config/mongodb.js";

import { handleCsrfError } from "./middleware/csrfProtection.js";
import adminRouter from "./routes/adminRoute.js";
import csrfRouter from "./routes/csrfRoute.js";
import doctorRouter from "./routes/eventRoute.js";
import stripeRouter from "./routes/stripeRoute.js";
import userRouter from "./routes/userRoute.js";

// App config
const app = express();
const port = process.env.PORT || 4000;

// Connect DB
connectDB();

// Middlewares
app.use(helmet());
app.use(express.json());
app.use(cookieParser());

// ✅ CORS (must be configured BEFORE CSRF)
const corsOptions = {
  origin: [
    "https://localhost:5173", // user frontend
    "https://localhost:5174", // admin frontend
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "token",
    "atoken",
    "X-CSRF-Token",
  ],
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions)); // Preflight support

// ✅ Conditional CSRF protection middleware
app.use((req, res, next) => {
  const userAgent = req.headers["user-agent"] || "";
  if (userAgent.includes("PostmanRuntime")) {
    // Skip CSRF for Postman requests
    return next();
  }
  // Apply CSRF protection for all other requests
  return csrf({
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    },
  })(req, res, next);
});

// ✅ Route to send CSRF token
app.get("/api/csrf-token", (req, res) => {
  res.cookie("XSRF-TOKEN", req.csrfToken(), {
    httpOnly: false, // must be accessible by frontend JS or Postman
    secure: true,
    sameSite: "strict",
  });
  res.json({
    success: true,
    csrfToken: req.csrfToken(),
  });
});

// ✅ Main API routes (these now receive CSRF protection automatically unless skipped)
app.use("/api/csrf", csrfRouter);
app.use("/api/user", userRouter);
app.use("/api/admin", adminRouter);
app.use("/api/doctor", doctorRouter);
app.use("/api/stripe", stripeRouter);

// ✅ CSRF error handler
app.use(handleCsrfError);

// ✅ Default route
app.get("/", (req, res) => {
  res.send("API Working");
});

// ✅ HTTPS server with fallback
try {
  const key = fs.readFileSync("./.cert/key.pem");
  const cert = fs.readFileSync("./.cert/cert.pem");
  https.createServer({ key, cert }, app).listen(port, () => {
    console.log(`HTTPS Server started on PORT:${port}`);
  });
} catch (err) {
  console.warn("Could not start HTTPS server, falling back to HTTP:", err.message);
  app.listen(port, () => console.log(`HTTP Server started on PORT:${port}`));
}
