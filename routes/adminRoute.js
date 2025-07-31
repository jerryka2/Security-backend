import express from 'express';
import {
  addDoctor,
  adminDashboard,
  allDoctors,
  appointmentCancel,
  appointmentsAdmin,
  getAuditLog,
  loginAdmin
} from '../controllers/adminController.js';

import { changeAvailablity } from '../controllers/eventController.js';
import authAdmin from '../middleware/authAdmin.js';
import upload from '../middleware/multer.js';

const adminRouter = express.Router();

// Authentication
adminRouter.post('/login', loginAdmin);

// Doctor Management
adminRouter.post(
  '/add-doctor',
  authAdmin,
  upload.single('image'),
  addDoctor
);
adminRouter.get('/all-doctors', authAdmin, allDoctors);
adminRouter.post('/change-availability', authAdmin, changeAvailablity);

// Appointment Management
adminRouter.get('/appointments', authAdmin, appointmentsAdmin);
adminRouter.post('/cancel-appointment', authAdmin, appointmentCancel);

// Admin Features
adminRouter.get('/dashboard', authAdmin, adminDashboard);
adminRouter.get('/audit-log', authAdmin, getAuditLog);

export default adminRouter;
