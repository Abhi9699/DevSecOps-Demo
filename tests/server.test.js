/**
 * Server API Tests
 * 
 * These tests verify the functionality of the server endpoints,
 * including the vulnerable endpoints that contain XSS issues.
 */

const request = require('supertest');
const express = require('express');
const bodyParser = require('body-parser');

// Mock Express app for testing
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Import the routes from server.js
// Note: In a real test, you would import the actual routes
// For this demo, we'll recreate the vulnerable endpoints

// Search endpoint with XSS vulnerability
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  
  // VULNERABILITY: Directly reflecting user input without sanitization
  res.send(`
    <html>
      <head>
        <title>Search Results</title>
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
app.post('/api/feedback', (req, res) => {
  const { name, message } = req.body;
  
  // VULNERABILITY: Directly reflecting user input without sanitization
  res.send(`
    <html>
      <head>
        <title>Feedback Submitted</title>
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

describe('Server API Tests', () => {
  describe('GET /api/search', () => {
    it('should return search results with the query parameter', async () => {
      const response = await request(app)
        .get('/api/search')
        .query({ q: 'test query' });
      
      expect(response.status).toBe(200);
      expect(response.text).toContain('You searched for: test query');
    });
    
    it('should be vulnerable to XSS in the query parameter', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      const response = await request(app)
        .get('/api/search')
        .query({ q: xssPayload });
      
      expect(response.status).toBe(200);
      // The XSS payload should be present unmodified in the response
      expect(response.text).toContain(`You searched for: ${xssPayload}`);
    });
  });
  
  describe('POST /api/feedback', () => {
    it('should return feedback confirmation with the submitted data', async () => {
      const response = await request(app)
        .post('/api/feedback')
        .send({ name: 'Test User', message: 'This is a test message' });
      
      expect(response.status).toBe(200);
      expect(response.text).toContain('From: Test User');
      expect(response.text).toContain('Message: This is a test message');
    });
    
    it('should be vulnerable to XSS in the name and message fields', async () => {
      const xssPayload = '<script>alert("XSS")</script>';
      const response = await request(app)
        .post('/api/feedback')
        .send({ name: xssPayload, message: 'Normal message' });
      
      expect(response.status).toBe(200);
      // The XSS payload should be present unmodified in the response
      expect(response.text).toContain(`From: ${xssPayload}`);
    });
  });
});