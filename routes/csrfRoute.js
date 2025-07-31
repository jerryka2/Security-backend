import express from "express";

const csrfRouter = express.Router();

// Get CSRF token - this endpoint is excluded from CSRF protection
csrfRouter.get("/token", (req, res) => {
    try {
        res.json({
            success: true,
            csrfToken: req.csrfToken(),
            message: "CSRF token generated successfully"
        });
    } catch (error) {
        console.error("Error generating CSRF token:", error);
        res.status(500).json({
            success: false,
            message: "Failed to generate CSRF token"
        });
    }
});

// Test endpoint to verify CSRF protection is working
csrfRouter.post("/test", (req, res) => {
    res.json({
        success: true,
        message: "CSRF protection is working correctly!",
        receivedData: req.body
    });
});

export default csrfRouter;
