import jwt from 'jsonwebtoken';

// Admin authentication middleware
const authAdmin = async (req, res, next) => {
  try {
    let atoken = null;

    // Get token from cookies or headers
    if (req.cookies?.atoken) {
      atoken = req.cookies.atoken;
    } else {
      atoken = req.headers.aToken || req.headers.atoken;
    }

    // If token is missing
    if (!atoken) {
      return res.json({
        success: false,
        message: 'Not Authorized Login Again'
      });
    }

    // Verify token and check admin email
    const token_decode = jwt.verify(atoken, process.env.JWT_SECRET);
    if (token_decode.email !== process.env.ADMIN_EMAIL) {
      return res.json({
        success: false,
        message: 'Not Authorized Login Again'
      });
    }

    // Authorized
    next();

  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: error.message
    });
  }
};

export default authAdmin;
