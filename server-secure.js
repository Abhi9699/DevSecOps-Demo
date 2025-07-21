const express = require('express');
const next = require('next');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// Import DOMPurify for sanitization
// Note: In a real implementation, you would need to install this package:
// npm install dompurify jsdom
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;
const dev = process.env.NODE_ENV !== 'production';

// Initialize Next.js
const nextApp = next({ dev });
const handle = nextApp.getRequestHandler();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Helper function to encode HTML entities
function encodeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Fixed search endpoint with proper sanitization
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  
  // SECURE: Sanitize and encode user input before rendering
  // Method 1: HTML encoding
  const encodedQuery = encodeHTML(query);
  
  // Method 2: Using DOMPurify (more robust for complex HTML)
  // const sanitizedQuery = DOMPurify.sanitize(query);
  
  // Set Content-Security-Policy header to prevent XSS
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  );
  
  res.send(`
    <html>
      <head>
        <title>Search Results</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${encodedQuery}</p>
        <div id="results">
          <p>No results found for "${encodedQuery}"</p>
        </div>
        <a href="/">Back to Home</a>
      </body>
    </html>
  `);
});

// Fixed feedback endpoint with proper sanitization
app.post('/api/feedback', (req, res) => {
  const { name, message } = req.body;
  
  // SECURE: Sanitize and encode user input before rendering
  const encodedName = encodeHTML(name);
  const encodedMessage = encodeHTML(message);
  
  // Set Content-Security-Policy header to prevent XSS
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  );
  
  res.send(`
    <html>
      <head>
        <title>Feedback Submitted</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <h1>Thank you for your feedback!</h1>
        <div class="feedback-confirmation">
          <p>From: ${encodedName}</p>
          <p>Message: ${encodedMessage}</p>
        </div>
        <a href="/">Back to Home</a>
      </body>
    </html>
  `);
});

// Chatbot endpoint
app.post('/api/chatbot', (req, res) => {
  const { message } = req.body;
  const sanitizedMessage = DOMPurify.sanitize(message);

  let reply = "I'm not sure how to respond to that. Can you ask something else?";

  if (sanitizedMessage.toLowerCase().includes('hello')) {
    reply = 'Hi there! How can I assist you?';
  } else if (sanitizedMessage.toLowerCase().includes('help')) {
    reply = 'You can ask me about our services, pricing, or contact information.';
  } else if (sanitizedMessage.toLowerCase().includes('pricing')) {
    reply = 'Our pricing is very competitive. Please visit our pricing page for more details.';
  } else if (sanitizedMessage.toLowerCase().includes('contact')) {
    reply = 'You can contact us at support@example.com.';
  }

  res.json({ reply });
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