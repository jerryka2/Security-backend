import rateLimit from "express-rate-limit";

export const loginRateLimiter = rateLimit({
    windowMs: 10 * 1000, // 10 seconds
    max: 4, // limit each IP to 4 requests per windowMs
    message: {
        success: false,
        message: "Too many login attempts, please try again after 10 seconds."
    },
    standardHeaders: true,
    legacyHeaders: false,
});

export const passwordResetRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 3 requests per 15 minutes
    message: {
        success: false,
        message: "Too many password reset attempts. Please try again after 15 minutes."
    },
    standardHeaders: true,
    legacyHeaders: false,
}); 