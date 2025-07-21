# DevSecOps Demo Application

## Overview

This project demonstrates a web application with integrated security scanning in a DevSecOps pipeline. It showcases how to implement automated security testing and vulnerability detection as part of the development workflow.

## 🚨 Security Warning

This application contains **intentional security vulnerabilities** for educational purposes. Do not deploy it in a production environment or expose it to the public internet.

## Features

- Next.js frontend with React components
- Express.js backend API
- Automated security scanning with OWASP ZAP
- GitHub Actions CI/CD pipeline
- ESLint security plugin integration
- SonarCloud static code analysis
- Secure and insecure implementation examples

## Project Structure

```
├── .github/workflows/   # GitHub Actions workflows
├── public/              # Static assets
├── src/                 # Source code
│   └── app/             # Next.js app
└── tests/               # Test files
```

## Getting Started

### Prerequisites

- Node.js 18 or higher
- npm 9 or higher

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd demo-app

# Install dependencies
npm install
```

## Usage

### Development Mode

```bash
npm run dev
```
### Production Mode

```bash
npm run build
npm start
```

### Secure Implementation

```bash
npm run start:secure
```
### Static Analysis
```bash
# Run ESLint security checks
npm run lint
```
The project also integrates with SonarCloud for comprehensive static code analysis, automatically performed in the CI/CD pipeline.

## CI/CD Pipeline

The GitHub Actions workflow in `.github/workflows/devsecops-pipeline.yml` includes:

1. **Build and Test**: Builds the application and runs tests
2. **Dynamic Security Scan**: Runs OWASP ZAP to detect runtime vulnerabilities
3. **Static Code Analysis**: Uses SonarCloud to analyze code quality and security

All scan results are saved as workflow artifacts and can be accessed through their respective dashboards.

## Security Implementation

The application demonstrates security best practices including input sanitization with DOMPurify, output encoding, Content Security Policy headers, and framework-specific protections.

Key security implementations in `server-secure.js`:

```javascript
// Encode HTML entities and set Content-Security-Policy headers
function encodeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
);
```

## Resources

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [SonarCloud Documentation](https://docs.sonarcloud.io/)
- [DevSecOps Best Practices](https://owasp.org/www-project-devsecops-guideline/)

## 📝 License

This project is licensed for educational purposes only. Do not use in production environments.