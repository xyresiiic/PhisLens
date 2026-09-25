# PhishLens 🔍

**Explainable Phishing Email Investigation Platform**

PhishLens is an email security analysis tool designed to detect phishing attacks and provide clear, transparent, explainable evidence for analysts and end-users alike.

---

## 🚀 Features

- **Multi-Vector Threat Detection**:
  - **Sender & Domain Inspection**: Flags spoofed display names, lookalike/typosquatted domains, and mismatched `From` vs `Reply-To`.
  - **URL & Link Analysis**: Detects IP-based links, suspicious TLDs, URL shorteners, hidden targets, and lookalike brand impersonation.
  - **Email Authentication**: Inspects SPF, DKIM, and DMARC status.
  - **Content & Urgency Analysis**: Identifies credential harvesting language, high-pressure urgency patterns, and financial coercion tactics.
- **Explainable Scoring Engine**: Transparent 0–100 risk scoring with prioritized evidence breakdowns and actionable recommendations.
- **Interactive UI**: Built-in test cases (`Legitimate`, `Suspicious`, `Phishing`) for rapid demonstration and manual `.eml` raw input.

---

## 🛠️ Getting Started

### Prerequisites
- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- npm

### Installation
```bash
npm install
```

### Running Locally
```bash
npm start
# or
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000) in your browser.

---

## 📂 Project Structure

```text
phishlens/
├── lib/
│   ├── constants.js          # Weights, known brands, TLDs, thresholds
│   ├── parser.js             # RFC 822 email and MIME header/body parser
│   ├── scoring.js            # Aggregation and risk classification logic
│   └── detectors/
│       ├── auth.js           # SPF, DKIM, DMARC validation
│       ├── content.js        # Urgency & credential harvesting keywords
│       ├── sender.js         # Domain impersonation and spoofing detectors
│       └── url.js            # URL structure, IP regex, and Levenshtein lookalike
├── public/
│   ├── index.html            # Primary web interface
│   ├── style.css             # UI styling
│   ├── app.js                # Frontend client logic & API interaction
│   └── samples/              # Preloaded .eml test samples
├── server.js                 # Express server & API endpoints
└── .gitignore                # Ignored files for version control
```

---

## 🛡️ License
ISC / Domain Verse 1.0 Project
