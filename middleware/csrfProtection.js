// csrf.js

import csrf from 'csurf';

/**
 * Setup CSRF protection middleware with cookie options
 */
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Only secure in production
        sameSite: 'strict',                            // Protect against CSRF attacks
        maxAge: 3600000                                // 1 hour expiration
    },
    ignoreMethods: ['GET', 'HEAD', 'OPTIONS']          // Only protect write methods
});

/**
 * Conditionally apply CSRF protection
 * Skips protection for specific routes like token fetch, health checks, etc.
 */
const conditionalCsrfProtection = (req, res, next) => {
    const skipRoutes = [
        '/api/csrf-token',
        '/api/csrf/token',
        '/api/health',
        '/'
    ];

    if (skipRoutes.includes(req.path) || req.method === 'GET') {
        return next(); // Skip CSRF check for safe routes
    }

    return csrfProtection(req, res, next); // Apply CSRF check
};

/**
 * Provide CSRF token to client in response local
 * Can be used in templates or sent via API
 */
const provideCsrfToken = (req, res, next) => {
    try {
        res.locals.csrfToken = req.csrfToken();
    } catch (_) {
        // Safe to skip if CSRF middleware isn't applied on this route
    }
    next();
};

/**
 * Error handler for CSRF-related failures
 */
const handleCsrfError = (err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({
            success: false,
            message: 'Invalid CSRF token. Please refresh the page and try again.',
            error: 'CSRF_TOKEN_INVALID'
        });
    }
    next(err); // Pass to next error handler
};

export {
    conditionalCsrfProtection as csrfProtection,
    provideCsrfToken,
    handleCsrfError
};
