require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(passport.initialize());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  }).then(() => {
    console.log('Connected to MongoDB');
  }).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
  });
  

// User model
const User = mongoose.model('User', new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
}));

// Passport local strategy
passport.use(new LocalStrategy(
  function(username, password, done) {
    User.findOne({ username: username }, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false, { message: 'Incorrect username' }); }

      bcrypt.compare(password, user.password, function(err, result) {
        if (result) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password' });
        }
      });
    });
  }
));

// Routes
app.post('/register', async function(req, res) {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username: username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user' });
  }
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) { return next(err); }
    if (!user) { return res.status(401).json({ message: 'Invalid username or password' }); }

    req.logIn(user, function(err) {
      if (err) { return next(err); }
      const token = jwt.sign({ userId: user._id }, process.env.SECRET_KEY);
      return res.json({ token });
    });
  })(req, res, next);
});

// Protected route
app.get('/protected', passport.authenticate('local', { session: false }), function(req, res) {
  res.json({ message: 'Protected route accessed successfully' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
