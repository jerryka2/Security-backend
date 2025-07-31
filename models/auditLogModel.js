import mongoose from 'mongoose';

const auditLogSchema = new mongoose.Schema({
  user:      { type: String, required: true },
  action:    { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});

const auditLogModel =
  mongoose.models.auditlog ||
  mongoose.model('auditlog', auditLogSchema);

export default auditLogModel;
