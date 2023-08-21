require('dotenv').config()

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pg = require('pg');

const app = express();
const port = process.env.PORT || 3000;

const path = require('path'); // Added this line for front-end

// Middleware
app.use(bodyParser.json());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (like your HTML, CSS, and JavaScript)
app.use(express.static(__dirname));


// PostgreSQL setup
const pool = new pg.Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'postgres',
  password: 'qwe123',
  port: 5432,
});


// JWT Verification Middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, process.env.SECRETKEY , (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token' });
    }
    req.userId = decoded.userId;
    next();
  });
}

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const client = await pool.connect();
    const result = await client.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hashedPassword]
    );
    const userId = result.rows[0].id;
    client.release();

    res.status(201).json({ message: 'User registered successfully', userId });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { name, password } = req.body;

    if (!name || !password) {
      return res.status(400).json({ message: 'name and password are required' });
    }

    const client = await pool.connect();
    const result = await client.query('SELECT * FROM users WHERE name = $1', [name]);
    const user = result.rows[0];
    client.release();

    if (!user) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Authentication failed' });
    }

    const token = jwt.sign({ userId: user.id },  process.env.SECRETKEY , { expiresIn: '1h' });


    // Redirect to facebook.com after successful login
    res.redirect('https://pasha-holding.az/');
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'An error occurred' });
  }
});

// Protected Route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'This is a protected route', userId: req.userId });
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
