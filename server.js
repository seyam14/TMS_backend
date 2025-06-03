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

// Multer setup for file uploads
const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|pdf/;
  const ext = path.extname(file.originalname).toLowerCase();
  const mime = file.mimetype;

  if (allowedTypes.test(ext) && (mime.startsWith('image/') || mime === 'application/pdf')) {
    cb(null, true);
  } else {
    cb(new Error('Only images (jpeg, jpg, png, gif) and PDFs are allowed'));
  }
};
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB limit
  fileFilter: fileFilter,
});

// MongoDB setup
let db;
MongoClient.connect(mongoUri)
  .then(client => {
    db = client.db();
    console.log('Connected to MongoDB');

    // Start server after DB is connected
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  });

// Root test route
app.get('/', (req, res) => {
  res.send('Hello niloy! Server is running');
});

// JWT auth middleware
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

// ===== AUTH ROUTES =====

// Register Ticket Maker
// 
// Only allow Ticket Maker to register from frontend
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, ticketId } = req.body;
    if (!name || !email || !password || !ticketId) {
      return res.status(400).json({ message: 'Name, email, password, and Ticket ID are required' });
    }

    // Check if email or ticketId already exists
    const existingEmail = await db.collection('users').findOne({ email });
    if (existingEmail) return res.status(400).json({ message: 'Email already exists' });

    const existingTicketId = await db.collection('users').findOne({ ticketId });
    if (existingTicketId) return res.status(400).json({ message: 'Ticket ID already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      name,
      email,
      password: hashedPassword,
      ticketId,
      role: 'Ticket Maker', // hardcoded role
      createdAt: new Date(),
    };

    await db.collection('users').insertOne(newUser);

    res.status(201).json({ message: 'Registration successful' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error' });
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

    const token = jwt.sign(
      { id: user._id, role: user.role, name: user.name },
      jwtSecret,
      { expiresIn: '1d' }
    );

    res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// ===== USER ROUTES =====

// Get all users (Admin only)
app.get('/api/users', authenticate(['Admin']), async (req, res) => {
  const users = await db.collection('users').find().toArray();
  res.json(users);
});

// Delete a user (Admin only)
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

// ===== TICKET ROUTES =====

// Create a ticket
app.post('/api/tickets', authenticate(['Ticket Maker']), upload.array('attachments'), async (req, res) => {
  try {
    const { title, description, priority } = req.body;
    const attachments = req.files?.map(file => file.path) || [];

    const ticket = {
      title,
      description,
      priority,
      status: 'Pending',
      assignedTo: null,
      assignedToRole: null,
      createdBy: req.user.id,
      attachments,
      createdAt: new Date()
    };

    await db.collection('tickets').insertOne(ticket);
    res.status(201).json({ message: 'Ticket submitted' });
  } catch (err) {
    console.error('Error creating ticket:', err);
    res.status(500).json({ message: 'Error creating ticket' });
  }
});

// Get tickets (filtered by user role)
app.get('/api/tickets', authenticate(), async (req, res) => {
  const user = req.user;
  const ticketsCollection = db.collection('tickets');
  let filter = {};

  switch (user.role) {
    case 'Ticket Maker':
      filter = { createdBy: user.id };
      break;
    case 'Checker':
      filter = { status: 'Pending' };
      break;
    case 'DFS Team':
    case 'IT Team':
      filter = { assignedTo: user.id };
      break;
    case 'Admin':
      filter = {};
      break;
    default:
      return res.status(403).json({ message: 'Unauthorized role' });
  }

  try {
    const tickets = await ticketsCollection.find(filter).toArray();
    res.json(tickets);
  } catch (err) {
    console.error('Error fetching tickets:', err);
    res.status(500).json({ message: 'Error retrieving tickets' });
  }
});

// Get ticket by ID
app.get('/api/tickets/:id', authenticate(), async (req, res) => {
  const { id } = req.params;
  try {
    const ticket = await db.collection('tickets').findOne({ _id: new ObjectId(id) });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching ticket' });
  }
});

// Update ticket (Checker, DFS Team, IT Team)

app.put('/api/tickets/:id', authenticate(['Checker', 'DFS Team', 'IT Team']), async (req, res) => {
  const { id } = req.params;
  const update = req.body;

  console.log('Update request from user role:', req.user.role, 'Update data:', update);

  if (update.status === 'Rejected' && !update.remarks) {
    return res.status(400).json({ message: 'Remarks required for rejection' });
  }

  try {
    if (req.user.role === 'Checker') {
      if (update.status === 'Forwarded to DFS') {
        const dfs = await db.collection('users').findOne({ role: 'DFS Team' });
        if (!dfs) return res.status(400).json({ message: 'No DFS team user found' });

        update.status = 'Assigned';
        update.assignedTo = dfs._id.toString();
      } else if (update.status === 'Forwarded to IT') {
        const it = await db.collection('users').findOne({ role: 'IT Team' });
        if (!it) return res.status(400).json({ message: 'No IT team user found' });

        update.status = 'Assigned';
        update.assignedTo = it._id.toString();
      } else {
        return res.status(400).json({ message: 'Invalid assignment status from Checker' });
      }
    }

    await db.collection('tickets').updateOne(
      { _id: new ObjectId(id) },
      { $set: update }
    );

    // Notification to ticket creator (placeholder)
    const ticket = await db.collection('tickets').findOne({ _id: new ObjectId(id) });
    if (ticket) {
      const creator = await db.collection('users').findOne({ _id: new ObjectId(ticket.createdBy) });
      if (creator && creator.email) {
        // Here you can implement email or real-time socket notification
        console.log(`Notify creator (${creator.email}) about ticket update.`);
      }
    }

    res.json({ message: 'Ticket updated' });
  } catch (err) {
    console.error('Error updating ticket:', err);
    res.status(500).json({ message: 'Failed to update ticket' });
  }
});




// Global error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message.includes('Only images')) {
    return res.status(400).json({ message: err.message });
  }
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ message: 'Internal server error' });
});

