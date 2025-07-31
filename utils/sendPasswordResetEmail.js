import nodemailer from "nodemailer";

const sendPasswordResetEmail = async (email, resetToken) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST || "smtp.gmail.com",
      port: process.env.EMAIL_PORT || 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request - EventVibe",
      html: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0" />
            <title>Password Reset - EventVibe</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #fff9f3;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background: #ffffff;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    border-radius: 10px;
                    overflow: hidden;
                }
                .header {
                    background-color: #ff5e57;
                    color: white;
                    padding: 25px;
                    text-align: center;
                }
                .header h1 {
                    margin: 0;
                    font-size: 24px;
                }
                .content {
                    padding: 30px;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 24px;
                    background-color: #ff5e57;
                    color: white;
                    text-decoration: none;
                    border-radius: 6px;
                    font-weight: bold;
                    transition: background-color 0.3s ease;
                }
                .btn:hover {
                    background-color: #e0483f;
                }
                .highlight {
                    background-color: #fdf1ec;
                    padding: 10px;
                    border-radius: 6px;
                    font-family: monospace;
                    word-break: break-word;
                }
                .warning, .security-note {
                    margin: 20px 0;
                    padding: 15px;
                    border-radius: 6px;
                    font-size: 14px;
                }
                .warning {
                    background-color: #fff3cd;
                    border-left: 5px solid #ffc107;
                }
                .security-note {
                    background-color: #e9f7ef;
                    border-left: 5px solid #28a745;
                }
                .footer {
                    background-color: #f1f1f1;
                    text-align: center;
                    padding: 20px;
                    font-size: 12px;
                    color: #777;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 Reset Your EventVibe Password</h1>
                </div>

                <div class="content">
                    <p>Hello,</p>
                    <p>We received a request to reset the password for your EventVibe account associated with <strong>${email}</strong>.</p>

                    <p>Click the button below to reset your password:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" class="btn">Reset Password</a>
                    </div>

                    <p>Or copy and paste this link into your browser:</p>
                    <p class="highlight">${resetUrl}</p>

                    <div class="warning">
                        <strong>⚠️ Important:</strong>
                        <ul>
                            <li>This link expires in <strong>1 hour</strong>.</li>
                            <li>It can only be used once.</li>
                            <li>If you didn’t request this, ignore this email.</li>
                        </ul>
                    </div>

                    <div class="security-note">
                        <strong>✅ Security Tips:</strong>
                        <ul>
                            <li>Use a strong, unique password</li>
                            <li>Never share your password</li>
                            <li>Enable two-factor authentication (if available)</li>
                        </ul>
                    </div>

                    <p>If you have any issues, feel free to contact EventVibe support.</p>
                    <p>Best regards,<br><strong>The EventVibe Team</strong></p>
                </div>

                <div class="footer">
                    <p>This is an automated message. Please do not reply.</p>
                    <p>If you didn’t request a password reset, no action is needed.</p>
                    <p>&copy; ${new Date().getFullYear()} EventVibe. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
      `,
    };

    const result = await transporter.sendMail(mailOptions);
    console.log("Password reset email sent:", result.messageId);
    return true;
  } catch (error) {
    console.error("Error sending password reset email:", error);
    throw new Error("Failed to send password reset email");
  }
};

export default sendPasswordResetEmail;
