# 🔍 Link Fraud & Risk Score Detector

A simple, lightweight web application and backend to check whether any website link is fraudulent or safe, and evaluate its risk score with clear explanations.

---

## ✨ Features

- **Instant Fraud Check**: Enter any link or domain (e.g. `https://google.com` or `http://fake-bank-login.xyz`) to determine if it is:
  - 🟢 **Safe / Legitimate**
  - 🟡 **Suspicious**
  - 🔴 **Fraud / Malicious**
- **Risk Score (0 - 100)**: Color-coded score bar reflecting risk level.
- **Clear Reasons & Findings**: Explains why the link was flagged:
  - Insecure HTTP connections
  - Common scam or phishing keywords (`bank`, `login`, `verify`, `refund`, etc.)
  - High-risk / abused top-level domains (`.xyz`, `.top`, `.info`, etc.)
  - Raw IP address usage
  - Brand impersonation patterns (excessive hyphens, suspicious length)
  - Matches against known malicious portals in `db.json`
- **Minimal & Clean UI**: No complicated diagrams, charts, or feeds. Clean, fast, and responsive interface.
- **Offline / Local Fallback**: If the Node.js backend is not running, the frontend includes a client-side evaluator that still works directly in the browser!

---

## 🏗️ Project Structure

```text
ioc-aggregator/
├── public/                 # Simple Frontend
│   ├── index.html          # Clean single-card UI
│   ├── app.js              # Fetch logic & DOM updates
│   └── styles.css          # Minimal clean styling (~150 lines)
├── db.json                 # Known fraud patterns & verified safe domains
├── server.js               # Lightweight Express backend (single /api/check route)
├── package.json            # Node.js dependencies (express, cors)
└── README.md               # Project documentation
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Backend Server
```bash
npm start
```
The server will start at:
```text
http://localhost:3000
```

### 3. Open in Browser
Open `http://localhost:3000` in your web browser. You can enter any link or click the example buttons.

*(Optional)* You can also simply open `public/index.html` directly in any web browser without running the server, and the built-in local evaluator will check your links.

---

## 🔌 API Endpoint

### `POST /api/check`
- **Body**:
  ```json
  {
    "url": "http://refund-tax-support.in/pay.html"
  }
  ```
- **Response**:
  ```json
  {
    "url": "http://refund-tax-support.in/pay.html",
    "host": "refund-tax-support.in",
    "isFraud": true,
    "status": "Fraud",
    "riskScore": 98,
    "reasons": [
      "Matches known malicious threat database: Reported tax refund scam portal."
    ]
  }
  ```
