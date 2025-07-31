import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,      // Your Gmail address
    pass: process.env.EMAIL_PASS,      // Your Gmail app password
  },
});

const sendOtpEmail = async (email, otp) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `
Hello,

Thank you for using our service.

Your One-Time Password (OTP) is: ${otp}

Please use this code to complete your verification. It is valid for the next 5 minutes.

⚠️ Do not share this code with anyone for security reasons.

If you did not request this, please ignore this email.

Best regards,  
Your Security Team
    `,
    html: `
      <div style="font-family: Arial, sans-serif; color: #333;">
        <h2>🔐 Your OTP Code</h2>
        <p>Thank you for using our service.</p>
        <p><strong>Your One-Time Password (OTP) is:</strong></p>
        <h1 style="color: #2E86C1;">${otp}</h1>
        <p>This code is valid for the next <strong>5 minutes</strong>.</p>
        <p style="color: red;">⚠️ Do not share this code with anyone for security reasons.</p>
        <p>If you did not request this, please ignore this email.</p>
        <br>
        <p>Best regards,<br><strong>Your Security Team</strong></p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};

export default sendOtpEmail;
