// Utility functions for CSRF token management

/**
 * Extract CSRF token from request headers
 * @param {Object} req - Express request object
 * @returns {string|null} - CSRF token or null if not found
 */
export const getCsrfTokenFromRequest = (req) => {
    // Check for CSRF token in various places
    return req.get('X-CSRF-Token') || 
           req.get('X-XSRF-Token') || 
           req.body._csrf || 
           req.query._csrf ||
           null;
};

/**
 * Middleware to validate CSRF token manually (if needed)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Next middleware function
 */
export const validateCsrfToken = (req, res, next) => {
    const token = getCsrfTokenFromRequest(req);
    
    if (!token) {
        return res.status(403).json({
            success: false,
            message: 'CSRF token missing',
            error: 'CSRF_TOKEN_MISSING'
        });
    }
    
    // The actual CSRF validation is handled by the csurf middleware
    // This is just for additional checks if needed
    next();
};

/**
 * Add CSRF token to response data
 * @param {Object} data - Response data object
 * @param {Object} req - Express request object
 * @returns {Object} - Data with CSRF token added
 */
export const addCsrfTokenToResponse = (data, req) => {
    return {
        ...data,
        csrfToken: req.csrfToken()
    };
};

/**
 * Clear CSRF token from response cookies
 * @param {Object} res - Express response object
 */
export const clearCsrfToken = (res) => {
    res.clearCookie('_csrf', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        path: '/'
    });
};
