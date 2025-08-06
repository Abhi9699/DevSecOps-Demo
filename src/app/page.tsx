'use client';

import { useState } from 'react';
import Image from 'next/image';
import Chatbot from './Chatbot';
import { FiSearch, FiUser, FiMessageSquare, FiSend } from 'react-icons/fi';

export default function Home() {
  const [searchQuery, setSearchQuery] = useState('');
  const [feedbackName, setFeedbackName] = useState('');
  const [feedbackMessage, setFeedbackMessage] = useState('');

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    window.location.href = `/api/search?q=${searchQuery}`;
  };

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
    <div className="min-h-screen bg-gray-50 font-sans text-gray-800">
      <div className="container mx-auto px-4 py-12">
        <header className="text-center mb-16">
          <div className="flex justify-center items-center mb-4">
            <Image src="/TESTRIG_Logo.png" alt="TestRig Logo" width="776" height="145" className="h-16 w-auto mr-4" />
            <h1 className="text-5xl font-bold text-gray-900">DevSecOps Webinar</h1>
          </div>
          <p className="text-lg text-gray-600">by TestRig Technologies Pvt Ltd - A demonstration of XSS vulnerabilities for security training</p>
        </header>

        <main className="grid md:grid-cols-2 gap-12">
          <section className="bg-white p-8 rounded-xl shadow-md hover:shadow-lg transition-shadow duration-300">
            <h2 className="text-3xl font-semibold mb-6 text-gray-800 flex items-center"><FiSearch className="mr-3" />Search</h2>
            <form onSubmit={handleSearch}>
              <div className="mb-6">
                <label htmlFor="search" className="block mb-2 text-sm font-medium text-gray-600">Enter search term:</label>
                <div className="relative">
                  <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    id="search" 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full p-3 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition"
                    placeholder='Try: <script>alert("XSS")</script>'
                  />
                </div>
              </div>
              <button 
                type="submit" 
                className="w-full bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors duration-300 font-semibold flex items-center justify-center"
              >
                <FiSearch className="mr-2" /> Search
              </button>
            </form>
            <div className="mt-6 text-sm text-gray-500 bg-gray-100 p-4 rounded-lg">
              <p><strong>Note:</strong> This search endpoint contains a reflected XSS vulnerability.</p>
            </div>
          </section>

          <section className="bg-white p-8 rounded-xl shadow-md hover:shadow-lg transition-shadow duration-300">
            <h2 className="text-3xl font-semibold mb-6 text-gray-800 flex items-center"><FiMessageSquare className="mr-3" />Submit Feedback</h2>
            <form onSubmit={handleFeedback}>
              <div className="mb-6">
                <label htmlFor="name" className="block mb-2 text-sm font-medium text-gray-600">Your Name:</label>
                <div className="relative">
                  <FiUser className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                  <input 
                    type="text" 
                    id="name" 
                    value={feedbackName}
                    onChange={(e) => setFeedbackName(e.target.value)}
                    className="w-full p-3 pl-10 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition"
                    placeholder='Try: <script>alert("XSS")</script>'
                  />
                </div>
              </div>
              <div className="mb-6">
                <label htmlFor="message" className="block mb-2 text-sm font-medium text-gray-600">Your Message:</label>
                <textarea 
                  id="message" 
                  value={feedbackMessage}
                  onChange={(e) => setFeedbackMessage(e.target.value)}
                  className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-green-500 transition"
                  rows={5}
                  placeholder="Your feedback here..."
                ></textarea>
              </div>
              <button 
                type="submit" 
                className="w-full bg-green-600 text-white px-6 py-3 rounded-lg hover:bg-green-700 transition-colors duration-300 font-semibold flex items-center justify-center"
              >
                <FiSend className="mr-2" /> Submit Feedback
              </button>
            </form>
            <div className="mt-6 text-sm text-gray-500 bg-gray-100 p-4 rounded-lg">
              <p><strong>Note:</strong> This feedback endpoint contains a reflected XSS vulnerability.</p>
            </div>
          </section>
        </main>

        <Chatbot />

        <footer className="mt-20 text-center text-gray-500 text-sm">
          <p>DevSecOps Demo Application - For Security Training Purposes Only</p>
        </footer>
      </div>
    </div>
  );
}