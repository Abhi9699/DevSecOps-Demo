'use client';

import { useState } from 'react';
import Chatbot from './Chatbot'; // Import the Chatbot component

export default function Home() {
  const [searchQuery, setSearchQuery] = useState('');
  const [feedbackName, setFeedbackName] = useState('');
  const [feedbackMessage, setFeedbackMessage] = useState('');
  
  // Handle search form submission
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    // Redirect to the vulnerable search endpoint
    window.location.href = `/api/search?q=${searchQuery}`;
  };
  
  // Handle feedback form submission
  const handleFeedback = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const response = await fetch('/api/feedback', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ name: feedbackName, message: feedbackMessage }),
      });
      
      const html = await response.text();
      
      // Create a new window with the response HTML
      const newWindow = window.open('', '_blank');
      if (newWindow) {
        newWindow.document.write(html);
        newWindow.document.close();
      }
    } catch (error) {
      console.error('Error submitting feedback:', error);
    }
  };

  return (
    <div className="min-h-screen p-8 font-[family-name:var(--font-geist-sans)]">
      <header className="mb-8 text-center">
        <h1 className="text-3xl font-bold mb-2">Vulnerable Demo App</h1>
        <p className="text-gray-600">A demonstration of XSS vulnerabilities for security training</p>
      </header>
      
      <main className="max-w-2xl mx-auto">
        {/* Search Form with XSS Vulnerability */}
        <section className="search-form mb-10 p-6 bg-gray-50 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Search</h2>
          <form onSubmit={handleSearch}>
            <div className="mb-4">
              <label htmlFor="search" className="block mb-2">Enter search term:</label>
              <input 
                type="text" 
                id="search" 
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full p-2 border rounded"
                placeholder="Try: <script>alert('XSS')</script>"
              />
            </div>
            <button 
              type="submit" 
              className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
            >
              Search
            </button>
          </form>
          <div className="mt-4 text-sm text-gray-500">
            <p><strong>Note:</strong> This search endpoint contains a reflected XSS vulnerability.</p>
          </div>
        </section>
        
        {/* Feedback Form with XSS Vulnerability */}
        <section className="feedback-form p-6 bg-gray-50 rounded-lg">
          <h2 className="text-xl font-semibold mb-4">Submit Feedback</h2>
          <form onSubmit={handleFeedback}>
            <div className="mb-4">
              <label htmlFor="name" className="block mb-2">Your Name:</label>
              <input 
                type="text" 
                id="name" 
                value={feedbackName}
                onChange={(e) => setFeedbackName(e.target.value)}
                className="w-full p-2 border rounded"
                placeholder="Try: <script>alert('XSS')</script>"
              />
            </div>
            <div className="mb-4">
              <label htmlFor="message" className="block mb-2">Your Message:</label>
              <textarea 
                id="message" 
                value={feedbackMessage}
                onChange={(e) => setFeedbackMessage(e.target.value)}
                className="w-full p-2 border rounded"
                rows={4}
                placeholder="Your feedback here..."
              ></textarea>
            </div>
            <button 
              type="submit" 
              className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600"
            >
              Submit Feedback
            </button>
          </form>
          <div className="mt-4 text-sm text-gray-500">
            <p><strong>Note:</strong> This feedback endpoint contains a reflected XSS vulnerability.</p>
          </div>
        </section>
      </main>
      
      <Chatbot />

      <footer className="mt-12 text-center text-gray-500 text-sm">
        <p>DevSecOps Demo Application - For Security Training Purposes Only</p>
      </footer>
    </div>
  );
}
