import express from 'express';
import { createCheckoutSession } from '../controllers/stripeController.js';

const router = express.Router();

// Stripe Checkout endpoint
router.post('/create-checkout-session', createCheckoutSession);

export default router;
