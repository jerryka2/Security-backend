import mongoose from 'mongoose';

const tempUserSchema = new mongoose.Schema({
  name:       { type: String },
  email:      { type: String, unique: true },
  password:   { type: String },
  otp:        { type: String },
  otpExpires: { type: Date }
});

export default mongoose.model('tempUser', tempUserSchema);
