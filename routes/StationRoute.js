import express from 'express';
import {
  loginDoctor,
  appointmentsDoctor,
  appointmentCancel,
  doctorList,
  changeAvailablity,
  appointmentComplete,
  doctorDashboard,
  doctorProfile,
  updateDoctorProfile
} from '../controllers/eventController.js';

import authDoctor from '../middleware/authEvent.js';

const doctorRouter = express.Router();

// Authentication
doctorRouter.post('/login', loginDoctor);

// Appointment Management
doctorRouter.get('/appointments', authDoctor, appointmentsDoctor);
doctorRouter.post('/cancel-appointment', authDoctor, appointmentCancel);
doctorRouter.post('/complete-appointment', authDoctor, appointmentComplete);

// Availability
doctorRouter.post('/change-availability', authDoctor, changeAvailablity);

// Doctor Info
doctorRouter.get('/list', doctorList);
doctorRouter.get('/dashboard', authDoctor, doctorDashboard);

// Profile Management
doctorRouter.get('/profile', authDoctor, doctorProfile);
doctorRouter.post('/update-profile', authDoctor, updateDoctorProfile);

export default doctorRouter;


