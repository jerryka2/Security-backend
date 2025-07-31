import bcrypt from "bcrypt";
import { v2 as cloudinary } from "cloudinary";
import jwt from "jsonwebtoken";
import validator from "validator";
import appointmentModel from "../models/appointmentModel.js";
import auditLogModel from "../models/auditLogModel.js";
// import doctorModel from "../models/eventModel.js";
import doctorModel from "../models/eventModel.js";
import userModel from "../models/userModel.js";

// API for admin login
const loginAdmin = async (req, res) => {
    try {

        const { email, password } = req.body

        if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
            const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
            res.cookie('atoken', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 60 * 60 * 1000 // 1 hour
            });
            res.json({ success: true })
        } else {
            res.json({ success: false, message: "Invalid credentials" })
        }

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }

}

// const loginAdmin = async (req, res) => {
//     try {
//         const { email, password } = req.body;

//         // ✅ Validate Input Fields
//         if (!email || !password) {
//             return res.status(400).json({ success: false, message: "Email and password are required." });
//         }

//         // ✅ Check Admin Credentials
//         if (email === process.env.ADMIN_EMAIL && password === process.env.ADMIN_PASSWORD) {
//             // ✅ Ensure `expiresIn` is correctly formatted
//             const expiresIn = process.env.JWT_EXPIRES_IN || "7d"; // Default to 7 days

//             // ✅ Generate JWT Token
//             const token = jwt.sign(
//                 { email, role: "admin" },
//                 process.env.JWT_SECRET,
//                 { expiresIn } // ✅ Correct format
//             );

//             return res.status(200).json({
//                 success: true,
//                 message: "Admin login successful!",
//                 token
//             });
//         } else {
//             return res.status(401).json({ success: false, message: "Invalid admin credentials." });
//         }
//     } catch (error) {
//         console.error("Error in loginAdmin:", error);
//         res.status(500).json({ success: false, message: "Internal Server Error", error: error.message });
//     }
// };

// API to get all appointments list
const appointmentsAdmin = async (req, res) => {
    try {

        const appointments = await appointmentModel.find({})
        res.json({ success: true, appointments })

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }

}

// API for appointment cancellation
const appointmentCancel = async (req, res) => {
    try {

        const { appointmentId } = req.body
        await appointmentModel.findByIdAndUpdate(appointmentId, { cancelled: true })

        res.json({ success: true, message: 'Appointment Cancelled' })

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }

}

// API for adding Doctor
const addDoctor = async (req, res) => {

    try {

        const { name, email, password, speciality, degree, experience, about, fees, address } = req.body
        const imageFile = req.file

        // checking for all data to add doctor
        if (!name || !email || !password || !speciality || !degree || !experience || !about || !fees || !address) {
            return res.json({ success: false, message: "Missing Details" })
        }

        // validating email format
        if (!validator.isEmail(email)) {
            return res.json({ success: false, message: "Please enter a valid email" })
        }

        // validating strong password
        if (password.length < 8) {
            return res.json({ success: false, message: "Please enter a strong password" })
        }

        // hashing user password
        const salt = await bcrypt.genSalt(10); // the more no. round the more time it will take
        const hashedPassword = await bcrypt.hash(password, salt)

        // upload image to cloudinary
        const imageUpload = await cloudinary.uploader.upload(imageFile.path, { resource_type: "image" })
        const imageUrl = imageUpload.secure_url

        const doctorData = {
            name,
            email,
            image: imageUrl,
            password: hashedPassword,
            speciality,
            degree,
            experience,
            about,
            fees,
            address: JSON.parse(address),
            date: Date.now()
        }

        const newDoctor = new doctorModel(doctorData)
        await newDoctor.save()
        res.json({ success: true, message: 'Doctor Added' })

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
}

// API to get all doctors list for admin panel
const allDoctors = async (req, res) => {
    try {

        const doctors = await doctorModel.find({}).select('-password')
        res.json({ success: true, doctors })

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
}

// API to get dashboard data for admin panel
const adminDashboard = async (req, res) => {
    try {

        const doctors = await doctorModel.find({})
        const users = await userModel.find({})
        const appointments = await appointmentModel.find({})

        const dashData = {
            doctors: doctors.length,
            appointments: appointments.length,
            patients: users.length,
            latestAppointments: appointments.reverse()
        }

        res.json({ success: true, dashData })

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }
}

// GET /api/admin/audit-log - Only for authenticated admins
const getAuditLog = async (req, res) => {
    try {
        const logs = await auditLogModel.find({}, { __v: 0 }).sort({ timestamp: -1 });
        const formatted = logs.map((log, idx) => ({
            id: log._id,
            user: log.user,
            action: log.action,
            timestamp: log.timestamp,
        }));
        res.json(formatted);
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

export {
    addDoctor, adminDashboard, allDoctors, appointmentCancel, appointmentsAdmin, getAuditLog, loginAdmin
};

