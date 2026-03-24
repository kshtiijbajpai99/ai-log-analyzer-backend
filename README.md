# 🔐 AI Log Security Analyzer

## 🚀 Overview
AI Log Security Analyzer is a full-stack application that detects sensitive data exposure and security risks in logs. It analyzes logs in real-time, assigns risk scores, and generates actionable insights.

---

## ⚡ Features
- Detects:
  - Emails, passwords, API keys, tokens  
  - Errors and suspicious patterns  
- Risk scoring system (0–10)  
- AI-generated insights  
- Sensitive data masking  
- Policy engine (BLOCK / MASK / WARN)  
- Chunk-based processing for large logs  
- Rate limiting  
- Downloadable report  

---

## 🛠️ Tech Stack
- Backend: Node.js, Express  
- Frontend: HTML, CSS, JavaScript  
- File Parsing: pdf-parse, mammoth  

---

## 📂 Input Support
- `.txt`, `.log`, `.pdf`, `.docx`  
- Direct text input  

---

## 📊 Output
- Risk level and score  
- Structured findings  
- Masked logs  
- AI insights  

---

## 🌐 Live Demo
- Frontend: https://ai-log-analyzer-frontend.vercel.app/  
- Backend: https://ai-log-analyzer-backend-zbho.onrender.com/  

---

## ⚙️ Setup Instructions

### Backend
```bash
npm install
npm start
