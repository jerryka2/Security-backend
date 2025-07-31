🔐 OTP-Based Login Implementation
🧾 Overview
The login process has been enhanced to support two-step verification using OTP (One-Time Password) for added security.

🔄 Two-Step Flow:
Step 1: Verify email and password

Step 2: Verify OTP sent to user’s email

🔗 API Endpoints
1️⃣ Login (Step 1) – Verify Credentials and Send OTP
📨 Endpoint:
POST /api/user/login

📝 Request Body:

json
Copy
Edit
{
  "email": "user@example.com",
  "password": "password123"
}
✅ Success Response:

json
Copy
Edit
{
  "success": true,
  "message": "Credentials verified. OTP sent to your email for secure login.",
  "requiresOtp": true
}
❌ Error Response:

json
Copy
Edit
{
  "success": false,
  "message": "Invalid credentials"
}
2️⃣ Verify Login OTP (Step 2) – Complete Login
📨 Endpoint:
POST /api/user/verify-login-otp

📝 Request Body:

json
Copy
Edit
{
  "email": "user@example.com",
  "otp": "123456"
}
✅ Success Response:

json
Copy
Edit
{
  "success": true,
  "message": "Login successful!",
  "token": "jwt_token_here"
}
❌ Error Response:

json
Copy
Edit
{
  "success": false,
  "message": "Invalid OTP"
}
⚙️ How It Works
User submits credentials
→ Calls /api/user/login

Backend verifies credentials
→ Sends OTP if valid

User enters OTP
→ Calls /api/user/verify-login-otp

Backend verifies OTP
→ Sends JWT token on success

🌟 Features
🔐 Two-Factor Authentication (2FA) via Email OTP

⏱️ OTP expires in 10 minutes

🧹 Auto-deletes expired OTPs

🚫 Account lock after 3 failed password attempts (10 sec)

🚦 Rate-limited login attempts

🖥️ Frontend Implementation Example
javascript
Copy
Edit
// Step 1: Login with credentials
const loginStep1 = async (email, password) => {
  try {
    const response = await axios.post("/api/user/login", { email, password });
    if (response.data.success && response.data.requiresOtp) {
      // Show OTP input form
      return { requiresOtp: true };
    }
  } catch (error) {
    console.error("Login error:", error);
  }
};

// Step 2: Verify OTP
const loginStep2 = async (email, otp) => {
  try {
    const response = await axios.post("/api/user/verify-login-otp", {
      email,
      otp,
    });
    if (response.data.success) {
      // Store token and redirect to dashboard
      localStorage.setItem("token", response.data.token);
      return { success: true, token: response.data.token };
    }
  } catch (error) {
    console.error("OTP verification error:", error);
  }
};
🗃️ Database Models
🆕 tempLoginModel.js
Used to temporarily store login OTPs:

javascript
Copy
Edit
{
  email: String,
  userId: ObjectId,
  otp: String,
  otpExpires: Date,
  createdAt: Date (auto-expires after 10 minutes)
}
🔒 Security Considerations
✅ OTPs are 6-digit secure random numbers

🕐 OTP expires after 10 minutes

🔁 Only one active OTP per email

🚫 Rate limiting on login attempts

🔐 Password verified before OTP is sent

🔒 Account lockout after multiple failed attempts