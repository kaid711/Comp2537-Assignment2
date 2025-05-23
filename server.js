require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');
const fs = require('fs');

const app = express();
//const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const client = new MongoClient(process.env.MONGODB_URI);
let usersCollection;

async function connectToDatabase() {
  await client.connect();
  const db = client.db(process.env.MONGODB_DATABASE);
  usersCollection = db.collection('users');
  console.log('✅ Connected to MongoDB');
}

connectToDatabase().catch(console.error);

app.use(session({
  secret: process.env.NODE_SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    dbName: process.env.MONGODB_DATABASE,
    crypto: { secret: process.env.MONGODB_SESSION_SECRET },
    ttl: 3600
  })
}));

// Middleware checks if user is logged in
function isAuthenticated(req, res, next) {
  if (!req.session.username) {
    return res.redirect('/login');
  }
  next();
}

// Middleware checks if user is admin
function isAdmin(req, res, next) {
  if (req.session.user_type !== 'admin') {
    return res.status(403).render('403', { username: req.session.username, user_type: req.session.user_type });
  }
  next();
}


// Home
app.get('/', (req, res) => {
  res.render('index', { username: req.session.username, user_type: req.session.user_type });
});

// Signup
app.get('/signup', (req, res) => {
  res.render('signup', { username: req.session.username, user_type: req.session.user_type });
});

// Signup POST
app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const signupSchema = Joi.object({
    name: Joi.string().min(1).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });

  const validation = signupSchema.validate({ name, email, password });
  if (validation.error) {
  const errorField = validation.error.details[0].context.key;
  
  let errorMessage;
  if (errorField === 'name') {
    errorMessage = 'Please enter your name.';
  } else if (errorField === 'email') {
    errorMessage = 'Please provide a valid email address.';
  } else if (errorField === 'password') {
    errorMessage = 'Please enter a password.';
  } else {
    errorMessage = 'Invalid input.';
  }

  return res.send(`
    <h3>${errorMessage}</h3>
    <a href="/signup">Back to Sign Up</a>
  `);
}


  const existingUser = await usersCollection.findOne({ email });
  if (existingUser) {
    return res.send(`<p>Email already registered.</p><a href="/login">Login</a>`);
  }

  const hashedPassword = await bcrypt.hash(password, 12);

  const result = await usersCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    user_type: "user"
  });

  req.session.username = name;
  req.session.email = email;
  req.session.user_type = "user";
  res.redirect('/members');
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { username: req.session.username, user_type: req.session.user_type });
});

// Login POST
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
  });

  const validation = loginSchema.validate({ email, password });
  if (validation.error) {
    return res.send(`<p>Validation error: ${validation.error.details[0].message}</p><a href="/login">Back</a>`);
  }

  const user = await usersCollection.findOne({ email });
  if (!user) {
    return res.send(`<p>User not found.</p><a href="/login">Back</a>`);
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.send(`<p>Incorrect password.</p><a href="/login">Back</a>`);
  }

  req.session.username = user.name;
  req.session.email = user.email;
  req.session.user_type = user.user_type;
  res.redirect('/members');
});

// Members
app.get('/members', isAuthenticated, (req, res) => {
  const imageDir = path.join(__dirname, 'public/images');
  const images = fs.readdirSync(imageDir);
  res.render('members', { username: req.session.username, user_type: req.session.user_type, images });
});

// Admin Page
app.get('/admin', isAuthenticated, isAdmin, async (req, res) => {
  const users = await usersCollection.find({}).toArray();
  
  res.render('admin', { 
    username: req.session.username, 
    user_type: req.session.user_type, 
    users 
  });
});


// Promote user
app.get('/promote/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;
  await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "admin" } });
  res.redirect('/admin');
});

// Demote user
app.get('/demote/:id', isAuthenticated, isAdmin, async (req, res) => {
  const userId = req.params.id;
  await usersCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { user_type: "user" } });
  res.redirect('/admin');
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.send("Error logging out");
    }
    res.redirect('/');
  });
});

// 404
app.use((req, res) => {
  res.status(404).render('404', { username: req.session.username, user_type: req.session.user_type });
});

app.listen(process.env.PORT, () => console.log(`🚀 Server running on port ${process.env.PORT}`));

