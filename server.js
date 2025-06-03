const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { MongoClient, ObjectId } = require('mongodb');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const mongoUri = process.env.MONGO_URI;
const jwtSecret = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// MongoDB setup
let db;
MongoClient.connect(mongoUri)
  .then(client => {
    db = client.db();
    console.log('connected MongoDB ');

    // Root route
    app.get('/', (req, res) => {
      res.send('Hello niloy! Server is running');
    });

    // Start server after DB is connected
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  });

// JWT Authentication middleware
const authenticate = (roles = []) => (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Missing token' });

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    if (roles.length && !roles.includes(user.role)) return res.status(403).json({ message: 'Access denied' });
    req.user = user;
    next();
  });
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, ticketMakerId } = req.body;

    // Check required fields
    if (!name || !email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    // Only allow Ticket Maker to register via this route
    if (role !== 'Ticket Maker') {
      return res.status(403).json({ message: 'Only Ticket Maker can register from this form' });
    }

    // Ensure Ticket Maker ID is provided
    if (!ticketMakerId) {
      return res.status(400).json({ message: 'Ticket Maker ID is required' });
    }

    const usersCollection = db.collection('users');

    // Check if email already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'Email already exists' });
    }

    // Check if Ticket Maker ID is unique
    const existingId = await usersCollection.findOne({ ticketMakerId });
    if (existingId) {
      return res.status(409).json({ message: 'Ticket Maker ID already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    await usersCollection.insertOne({
      name,
      email,
      password: hashedPassword,
      role,
      ticketMakerId,
      createdAt: new Date(),
    });

    res.status(201).json({ message: 'Ticket Maker registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Error registering user' });
  }
});


// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, jwtSecret, { expiresIn: '1d' });
    res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Get all users (Admin only)
app.get('/api/users', authenticate(['Admin']), async (req, res) => {
  const users = await db.collection('users').find().toArray();
  res.json(users);
});

// Delete user (Admin only)
app.delete('/api/users/:id', authenticate(['Admin']), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.collection('users').deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ message: 'Failed to delete user' });
  }
});


// Create ticket
app.post('/api/tickets', authenticate(['Ticket Maker']), upload.array('attachments'), async (req, res) => {
  try {
    const { title, description, priority } = req.body;

    // Safely handle file uploads (if any)
    const attachments = req.files?.map(file => file.path) || [];

    const ticket = {
      title,
      description,
      priority,
      status: 'Pending',
      assignedTo: null,
      createdBy: req.user.id,
      attachments,
      createdAt: new Date()
    };

    await db.collection('tickets').insertOne(ticket);
    res.status(201).json({ message: 'Ticket submitted' });
  } catch (err) {
    console.error('Error creating ticket:', err); // log the error for debugging
    res.status(500).json({ message: 'Error creating ticket' });
  }
});


// Get tickets
app.get('/api/tickets', authenticate(), async (req, res) => {
  const filter = req.user.role === 'Ticket Maker'
    ? { createdBy: req.user.id }
    : req.user.role === 'Checker'
      ? { status: 'Pending' }
      : {};
  const tickets = await db.collection('tickets').find(filter).toArray();
  res.json(tickets);
});

// Get ticket by ID
app.get('/api/tickets/:id', authenticate(), async (req, res) => {
  const { id } = req.params;
  const ticket = await db.collection('tickets').findOne({ _id: new ObjectId(id) });
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
  res.json(ticket);
});

// Update ticket
app.put('/api/tickets/:id', authenticate(['Checker', 'DFS Team', 'IT Team']), async (req, res) => {
  const { id } = req.params;
  const update = req.body;

  if (update.status === 'Rejected' && !update.remarks) {
    return res.status(400).json({ message: 'Remarks required for rejection' });
  }

  await db.collection('tickets').updateOne({ _id: new ObjectId(id) }, { $set: update });
  res.json({ message: 'Ticket updated' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ message: 'Internal server error' });
});
