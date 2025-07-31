import jwt from 'jsonwebtoken';

// Doctor authentication middleware
const authDoctor = async (req, res, next) => {
  let token = null;

  // Retrieve token from cookies or headers
  if (req.cookies?.dtoken) {
    token = req.cookies.dtoken;
  } else if (req.headers.dtoken) {
    token = req.headers.dtoken;
  }

  // No token found
  if (!token) {
    return res.json({
      success: false,
      message: 'Not Authorized Login Again'
    });
  }

  try {
    // Verify token and attach doctor ID to request body
    const token_decode = jwt.verify(token, process.env.JWT_SECRET);
    req.body.docId = token_decode.id;
    next();
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: error.message
    });
  }
};

export default authDoctor;
