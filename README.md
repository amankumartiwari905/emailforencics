# AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

An AI-powered cybersecurity platform for detecting, analyzing, and investigating malicious or suspicious emails using **email header forensics, AI/ML phishing detection, NLP-based threat analysis, URL and domain intelligence, IP geolocation, relay-path analysis, identity correlation, and automated forensic reporting**.

The platform is designed to help security analysts move from simply identifying a suspicious email to understanding **where it came from, how it travelled, what indicators are involved, and how severe the threat is**.

---

## 🚨 Problem Statement

Email-based attacks continue to be one of the most common entry points for cyber threats.

Traditional email analysis often requires investigators to manually inspect:

- Email headers
- Sender and recipient information
- IP addresses
- DNS/domain information
- URLs
- Authentication results
- Mail relay paths
- Attachments
- Suspicious language
- Threat indicators

This process can be time-consuming and requires significant cybersecurity expertise.

There is a need for an automated platform that can combine these different forensic signals and provide investigators with a **centralized threat analysis and intelligence workflow**.

---

# 💡 Proposed Solution

Our platform automatically analyzes an uploaded `.eml` email and generates a comprehensive forensic investigation.

The system combines:

**Email Parsing → Header Forensics → IP Intelligence → Geolocation → Domain Intelligence → URL Analysis → NLP Analysis → ML Phishing Detection → Threat Scoring → Identity Correlation → Forensic Report**

This allows investigators to quickly determine whether an email is legitimate, suspicious, or potentially malicious.

---

# ✨ Key Features

## 📧 Email Header Forensics

Extracts and analyzes important email metadata including:

- Sender
- Recipient
- Subject
- Reply-To
- Return-Path
- Message-ID
- Received headers
- Sending IP addresses
- Relay information

The system reconstructs available mail-server hops to understand the email's transmission path.

---

## 🤖 AI/ML Phishing Detection

The platform uses a machine-learning phishing classifier based on:

- TF-IDF text representation
- Logistic Regression classification
- Email subject analysis
- Email body analysis

The model produces a phishing probability that contributes to the overall threat assessment.

---

## 🧠 NLP Threat Analysis

Natural Language Processing is used to identify potential social-engineering indicators.

The analysis can detect patterns such as:

- Urgency
- Credential harvesting
- Payment requests
- Fake invoices
- Executive impersonation
- Account suspension threats
- Suspicious requests
- Social-engineering language

This provides additional context beyond traditional header analysis.

---

# 🌐 URL & Domain Intelligence

Suspicious URLs and domains are extracted from emails and analyzed for potential threats.

The platform examines indicators such as:

- Suspicious URLs
- Domain characteristics
- Domain reputation
- Lookalike domains
- Sender-domain relationships
- Domain risk

This helps identify phishing infrastructure and impersonation attempts.

---

# 🔐 SPF, DKIM & DMARC Analysis

Email authentication information can be used to evaluate whether the sender infrastructure aligns with the claimed domain.

Authentication signals help investigators understand potential:

- Sender spoofing
- Domain impersonation
- Authentication failures
- Email-origin inconsistencies

---

# 🌍 IP Geolocation & Intelligence

Extracted public IP addresses are investigated using external intelligence services.

The platform provides information such as:

- IP address
- Approximate geographic location
- Organization/provider
- Proxy/VPN indicators
- Network intelligence

> **Important:** IP geolocation represents an approximate network location. It should not be interpreted as the physical identity or exact location of an individual.

---

# 🔄 Email Relay Path Analysis

The system reconstructs the email's available relay chain from the `Received` headers.

This allows investigators to visualize:

```
Source
  ↓
Mail Relay
  ↓
Intermediate Server
  ↓
Recipient Mail Server
```

The platform also attempts to identify the **earliest reliable public IP** available from the email headers.

---

# 🕵️ Identity & Campaign Correlation

The platform correlates investigation indicators to identify relationships between:

- Email cases
- Domains
- IP addresses
- URLs
- Campaign indicators

This can help investigators identify whether multiple suspicious emails may be connected to the same campaign or infrastructure.

---

# 📎 Attachment Analysis

Email attachments are extracted and analyzed as part of the forensic pipeline.

The system can identify attachment-related indicators that may contribute to the overall threat assessment.

---

# 📊 Threat Scoring

Multiple signals are combined into an overall threat assessment.

Signals may include:

- Domain risk
- URL indicators
- IP intelligence
- NLP threat indicators
- ML phishing probability
- Attachment indicators
- Authentication information
- Lookalike-domain detection

The final result provides an analyst-friendly threat classification such as:

```
LOW
MEDIUM
HIGH
CRITICAL
```

---

# 📑 Automated Forensic Reports

The platform can generate a downloadable **PDF forensic report** containing the analysis results.

Reports can be useful for:

- Security investigations
- Incident documentation
- SOC workflows
- Evidence preservation
- Case records
- Presentation/demo purposes

---

# 📁 Case Management

Investigations can be organized into cases.

A case can contain information such as:

- Case ID
- Threat score
- Threat classification
- Severity
- Indicators
- Related analysis
- Investigation details

This helps transform individual email analyses into a structured investigation workflow.

---

# 🖥️ Dashboard

The frontend provides a centralized cybersecurity investigation interface.

Major areas include:

- Dashboard
- Analyze Email
- Header Forensics
- URL & Domain Intelligence
- IP Geolocation
- Relay Path
- Threat Intelligence
- Cases
- Case Details
- Forensic Reports
- Alerts
- Analysis History
- Spam Tracker
- Server Trace
- Settings

---

# 🏗️ System Architecture

```
                    ┌──────────────────────┐
                    │      Analyst         │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   React Frontend     │
                    │      Vite + TS       │
                    └──────────┬───────────┘
                               │
                         REST API
                               │
                               ▼
                    ┌──────────────────────┐
                    │    FastAPI Backend   │
                    └──────────┬───────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   Email Parser          Threat Analysis       ML/NLP Engine
          │                    │                    │
          ▼                    ▼                    ▼
   Header Forensics      Threat Scoring      Phishing Detection
          │
          ├───────────────┐
          ▼               ▼
     IP Intelligence   Domain Intelligence
          │               │
          ▼               ▼
     Geolocation       URL Analysis
          │               │
          └───────┬───────┘
                  ▼
          Identity Correlation
                  │
                  ▼
          Forensic Investigation
                  │
                  ▼
          PDF Report Generation
```

---

# 🛠️ Technology Stack

## Frontend

- React
- TypeScript
- Vite
- Tailwind CSS
- Bootstrap
- HTML5
- CSS3
- JavaScript

## Backend

- Python
- FastAPI
- Pydantic
- Uvicorn

## AI / Machine Learning

- Scikit-learn
- TF-IDF
- Logistic Regression
- NLP-based threat analysis

## Cybersecurity / Intelligence

- Email header analysis
- DNS/domain intelligence
- URL analysis
- IP intelligence
- IP geolocation
- Proxy/VPN detection
- Lookalike-domain detection
- Identity correlation

## Reporting

- ReportLab
- PDF forensic report generation

## Deployment

- GitHub
- Render
- REST API

---

# 📂 Project Structure

```
AI-Powered-Email-Threat-Detection-GeoLocation-and-Forensic-Intelligence-Platform/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── email.py
│   │   │
│   │   ├── schemas/
│   │   │
│   │   ├── services/
│   │   │   ├── email_parser.py
│   │   │   ├── domain_analyzer.py
│   │   │   ├── domain_intelligence.py
│   │   │   ├── domain_risk_analyzer.py
│   │   │   ├── url_analyzer.py
│   │   │   ├── threat_analyzer.py
│   │   │   ├── attachment_analyzer.py
│   │   │   ├── nlp_threat_analyzer.py
│   │   │   ├── phishing_classifier.py
│   │   │   ├── ip_geolocation.py
│   │   │   ├── proxy_check.py
│   │   │   ├── identity_correlator.py
│   │   │   └── ...
│   │   │
│   │   ├── main.py
│   │   └── proxy.py
│   │
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── screens/
│   │   ├── services/
│   │   │   └── api.ts
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   │
│   ├── index.html
│   ├── package.json
│   └── vite.config.ts
│
└── README.md
```

---

# 🔄 Application Workflow

### Step 1 — Upload Email

The analyst uploads an `.eml` file through the web interface.

### Step 2 — Email Parsing

The backend extracts:

- Headers
- Body
- URLs
- IP addresses
- Attachments
- Sender/recipient information

### Step 3 — Infrastructure Analysis

Extracted domains and IP addresses are analyzed.

### Step 4 — AI Analysis

The email content is evaluated using:

- NLP threat detection
- ML phishing classification

### Step 5 — Correlation

Indicators are correlated to identify relationships between domains, IPs, URLs, and cases.

### Step 6 — Threat Scoring

All available signals are combined into a threat assessment.

### Step 7 — Visualization

Results are presented through the investigation dashboard.

### Step 8 — Forensic Report

The analyst can generate a downloadable PDF report.

---

# 🔌 API Endpoints

## Analyze Email

```
POST /analyze
```

Accepts an `.eml` file and returns the complete forensic analysis.

---

## Generate Forensic Report

```
POST /analyze/report
```

Generates a PDF forensic report from the email analysis.

---

## Case Campaign Cluster

```
GET /cases/{case_id}/cluster
```

Returns the campaign correlation graph associated with a case.

---

## Global Correlation Graph

```
GET /cases/graph
```

Returns the available correlation graph across analyzed emails.

---

# 🚀 Local Setup

## Clone Repository

```
git clone https://github.com/pranav-n29/AI-Powered-Email-Threat-Detection-GeoLocation-and-Forensic-Intelligence-Platform.git
```

```
cd AI-Powered-Email-Threat-Detection-GeoLocation-and-Forensic-Intelligence-Platform
```

---

# ⚙️ Backend Setup

```
cd backend
```

Create a virtual environment:

```
python -m venv venv
```

Activate it on Windows:

```
venv\Scripts\activate
```

Install dependencies:

```
pip install -r requirements.txt
```

Start the backend:

```
uvicorn app.main:app --reload
```

The API will run locally at:

```
http://localhost:8000
```

---

# 🎨 Frontend Setup

Open another terminal:

```
cd frontend
```

Install dependencies:

```
npm install
```

Start the development server:

```
npm run dev
```

The frontend will run using the Vite development server.

---

# 🔑 Environment Variables

The frontend uses:

```
VITE_API_URL
```

For local development:

```
VITE_API_URL=http://localhost:8000
```

For the deployed application:

```
VITE_API_URL=https://mailtrace-ai-backend-lx6h.onrender.com
```

External intelligence API credentials should be configured as environment variables and **must not be committed to GitHub**.

---

# ☁️ Deployment

The application is deployed using **Render**.

## Backend

Backend configuration:

```
Root Directory:
backend

Build Command:
pip install -r requirements.txt

Start Command:
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

## Frontend

Frontend configuration:

```
Root Directory:
frontend

Build Command:
npm install && npm run build

Publish Directory:
dist
```

---

# 🔐 Security Considerations

The platform is designed as a cybersecurity investigation tool.

Important security practices include:

- Never expose API keys in frontend code.
- Store secrets using environment variables.
- Do not commit credentials to GitHub.
- Treat uploaded emails as potentially malicious input.
- Validate uploaded files.
- Do not execute email attachments.
- Treat IP geolocation as approximate intelligence.
- External threat-intelligence results should be independently verified before making operational decisions.

---

# 🎯 Use Cases

The platform can assist:

### SOC Analysts

Quickly investigate suspicious emails and extract threat indicators.

### Incident Response Teams

Analyze email-based incidents and generate forensic documentation.

### Cybersecurity Students

Learn practical email forensics and threat intelligence.

### Digital Forensics Investigators

Investigate email headers, relay paths, domains, URLs, and IP infrastructure.

### Organizations

Improve visibility into phishing and social-engineering attempts.

---

# 🌟 Advantages

Traditional workflow:

```
Email
  ↓
Manual Header Inspection
  ↓
Manual IP Lookup
  ↓
Manual Domain Lookup
  ↓
Manual URL Analysis
  ↓
Manual Threat Assessment
  ↓
Manual Report
```

Our workflow:

```
Email
  ↓
┌───────────────────────────────┐
│      Automated Analysis       │
├───────────────────────────────┤
│ Header Forensics              │
│ IP Intelligence               │
│ Geolocation                   │
│ Domain Intelligence           │
│ URL Analysis                  │
│ NLP Threat Detection          │
│ ML Phishing Detection         │
│ Identity Correlation          │
│ Threat Scoring                │
└───────────────────────────────┘
  ↓
Investigation Dashboard
  ↓
Forensic Report
```

This significantly reduces the amount of manual analysis required during an investigation.

---

# 🔮 Future Enhancements

Potential future improvements include:

- Real-time threat-intelligence feeds
- VirusTotal integration
- Advanced attachment sandboxing
- YARA-based malware detection
- Expanded SIEM integration
- Automated IOC extraction
- STIX/TAXII support
- Advanced graph-based campaign detection
- Real-time alerting
- Historical threat analytics
- Explainable AI for threat scoring
- Organization-wide email security monitoring

---

# 🧪 Prototype Status

The current implementation is a **working cybersecurity prototype** demonstrating an end-to-end email investigation workflow.

Implemented capabilities include:

- `.eml` upload
- Email parsing
- Header analysis
- IP extraction
- IP intelligence
- IP geolocation
- Relay-chain analysis
- Domain analysis
- URL analysis
- Lookalike-domain detection
- NLP threat analysis
- ML phishing classification
- Threat scoring
- Identity correlation
- Attachment analysis
- Case management
- Forensic PDF generation
- Web-based investigation dashboard
- Cloud deployment

---

# 🌐 Live Demo

**Frontend**

[Frontend](https://ai-powered-email-threat-detection-aj43.onrender.com/)

**Backend**

[Backend](https://mailtrace-ai-backend-lxh6.onrender.com/)

**GitHub Repository**

[GitHub Repository](https://github.com/pranav-n29/AI-Powered-Email-Threat-Detection-GeoLocation-and-Forensic-Intelligence-Platform)

---

# 👥 Team

**Project:** AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

**Domain:** Cybersecurity / Artificial Intelligence / Digital Forensics

**Built for:** Smart India Hackathon (SIH)

---

# ⚠️ Disclaimer

This platform is intended for **authorized cybersecurity analysis, research, education, and defensive security purposes**.

Threat intelligence, IP geolocation, domain reputation, and AI/ML predictions should be treated as investigative indicators rather than definitive proof of malicious activity.

Always perform appropriate human verification before taking security or legal action based on automated results.

---

## ⭐ Project Vision

> **From a suspicious email to actionable forensic intelligence — faster, smarter, and in one platform.**