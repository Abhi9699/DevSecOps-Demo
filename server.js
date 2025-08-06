const express = require('express');
require('dotenv').config();
const next = require('next');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;
const dev = process.env.NODE_ENV !== 'production';

// Initialize Next.js
const nextApp = next({ dev });
const handle = nextApp.getRequestHandler();

// Middleware
app.use(cors());

app.use(express.static(path.join(__dirname, 'public')));

// Custom routes with XSS vulnerability
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  
  // VULNERABILITY: Directly reflecting user input without sanitization
  // This creates a Reflected XSS vulnerability
  res.send(`
    <html>
      <head>
        <title>Search Results</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${query}</p>
        <div id="results">
          <p>No results found for "${query}"</p>
        </div>
        <a href="/">Back to Home</a>
      </body>
    </html>
  `);
});

// Feedback endpoint with XSS vulnerability
app.post('/api/feedback', bodyParser.json(), bodyParser.urlencoded({ extended: true }), (req, res) => {
  const { name, message } = req.body;
  
  // VULNERABILITY: Directly reflecting user input without sanitization
  res.send(`
    <html>
      <head>
        <title>Feedback Submitted</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Thank you for your feedback!</h1>
        <div class="feedback-confirmation">
          <p>From: ${name}</p>
          <p>Message: ${message}</p>
        </div>
        <a href="/">Back to Home</a>
      </body>
    </html>
  `);
});



// Start the server
nextApp.prepare().then(() => {
  // Let Next.js handle all other routes
  app.all('*', (req, res) => {
    return handle(req, res);
  });

  app.listen(port, (err) => {
    if (err) throw err;
    console.log(`> Server running on http://localhost:${port}`);
  });
});