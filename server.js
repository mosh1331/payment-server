// server.js (Node.js/Express Backend with Production-Level Practices)

const Razorpay = require('razorpay');
const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const helmet = require('helmet'); // For securing HTTP headers
const rateLimit = require('express-rate-limit'); // For limiting requests
const morgan = require('morgan'); // For logging
const dotenv = require('dotenv');
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Add security headers
app.use(morgan('combined')); // Log requests

// Rate limiter to avoid DDOS attacks (optional)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Razorpay instance with your key_id and key_secret from environment variables
const razorpayInstance = new Razorpay({
  key_id: process.env.KEY_ID,
  key_secret: process.env.KEY_SECRET,
});

// API to create an order
app.post('/create-order', async (req, res) => {
  const { amount, currency } = req.body;

  // Validate request data
  if (!amount || !currency) {
    return res.status(400).json({ success: false, message: 'Amount and currency are required' });
  }

  // Ensure the amount is a number
  if (isNaN(amount)) {
    return res.status(400).json({ success: false, message: 'Amount must be a valid number' });
  }

  const options = {
    amount: amount * 100, // Amount in smallest currency unit (paisa for INR)
    currency: currency,
    receipt: `receipt_order_${Date.now()}`, // Unique receipt ID for each transaction
  };

  try {
    const order = await razorpayInstance.orders.create(options);
    return res.status(200).json({
      success: true,
      order,
    });
  } catch (error) {
    console.error('Error creating Razorpay order:', error);
    return res.status(500).json({ success: false, message: 'Unable to create order' });
  }
});

// API to verify payment signature
app.post('/verify-payment', (req, res) => {
  const { razorpay_payment_id, razorpay_order_id, razorpay_signature } = req.body;

  // Input validation
  if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature) {
    return res.status(400).json({ success: false, message: 'Invalid payment details' });
  }

  try {
    // Generating signature using Razorpay's secret key
    const hmac = crypto.createHmac('sha256', process.env.KEY_SECRET);
    hmac.update(razorpay_order_id + '|' + razorpay_payment_id);
    const generated_signature = hmac.digest('hex');

    if (generated_signature === razorpay_signature) {
      // TODO: Update order status in your database to "Payment Successful"
      return res.status(200).json({ success: true, message: 'Payment verified successfully' });
    } else {
      // TODO: Update order status in your database to "Payment Failed"
      return res.status(400).json({ success: false, message: 'Payment verification failed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    return res.status(500).json({ success: false, message: 'Server error in payment verification' });
  }
});

// Custom error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong! Please try again later.',
  });
});

// Handle invalid routes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'API route not found',
  });
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});
