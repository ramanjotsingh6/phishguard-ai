# 🛡️ PhishGuard AI — Phishing Detection Platform

> A production-grade AI-powered phishing email detection platform with a professional cybersecurity dashboard, real-time threat analysis, and explainable AI.

---

## 📁 Project Structure

```
phishing-platform/
├── backend/
│   ├── app.py                    # Flask REST API server
│   ├── requirements.txt          # Python dependencies
│   ├── model/
│   │   ├── train_model.py        # Model training script
│   │   ├── phishing_model.pkl    # Trained model (auto-generated)
│   │   └── metrics.json          # Model performance metrics
│   └── utils/
│       └── email_analyzer.py     # Feature extraction & analysis engine
├── frontend/
│   └── index.html                # Complete React SPA (standalone)
├── SAMPLE_EMAILS.txt             # Test phishing/legitimate emails
└── README.md
```

---

## 🚀 Quick Start

### Option A: Frontend Only (Demo Mode)
Simply open `frontend/index.html` in your browser. The app runs in intelligent demo mode with realistic simulated analysis.

### Option B: Full Stack (AI Backend + Frontend)

#### Step 1: Install Python dependencies
```bash
cd backend
pip install -r requirements.txt
```

#### Step 2: Train the AI model
```bash
cd backend
python3 model/train_model.py
```
Expected output:
```
✓ Dataset loaded: 100 samples
⚙  Training model...
  Accuracy:  1.0000 (100.00%)
  5-Fold CV Accuracy: 0.8800 ± 0.0510
✓ Model saved to: backend/model/phishing_model.pkl
```

#### Step 3: Start Flask API
```bash
cd backend
python3 app.py
```
API running at: `http://localhost:5000`

#### Step 4: Open the Frontend
Open `frontend/index.html` in your browser.
The navbar will show **"API Online"** when connected.

---

## 🔌 API Reference

### `POST /api/analyze-email`
Analyze email content for phishing.

**Request:**
```json
{
  "email_text": "URGENT: Your account has been suspended...",
  "email_header": "From: ...\nReply-To: ..."
}
```

**Response:**
```json
{
  "scan_id": "A1B2C3D4E5F6",
  "prediction": {
    "label": "PHISHING",
    "is_phishing": true,
    "confidence": 94.2,
    "risk_score": 87
  },
  "explanation": {
    "summary": "This email shows strong indicators...",
    "details": ["• Urgency language detected", "..."],
    "risk_label": "CRITICAL — Almost certainly malicious",
    "recommendation": "DO NOT click any links..."
  },
  "indicators": [...],
  "threat_flags": [...],
  "urls": [...],
  "features": {...},
  "highlighted_keywords": ["urgent", "verify", "suspended"],
  "processing_time_ms": 45.2
}
```

### `POST /api/scan-links`
Scan URLs for phishing indicators.

**Request:**
```json
{
  "urls": ["http://paypal-verify.xyz", "https://google.com"]
}
```

### `GET /api/dashboard-stats`
Get platform statistics and model metrics.

### `GET /health`
API health check.

---

## 🤖 AI Model Details

| Property | Value |
|----------|-------|
| Model Type | Voting Ensemble (Soft) |
| Base Models | Logistic Regression + Random Forest |
| Feature Extraction | TF-IDF (1-3 grams, max 5000 features) |
| Training Samples | 100 (50 phishing / 50 legitimate) |
| Test Accuracy | 100% (small test set) |
| CV Accuracy (5-fold) | 88.0% ± 5.1% |
| Precision | 89.2% |
| Recall | 87.4% |
| F1 Score | 88.3% |

### Feature Engineering
- **NLP:** TF-IDF n-grams with stop word removal
- **Patterns:** 18 urgency patterns, 14 threat phrases, 13 financial lures
- **Technical:** URL analysis, domain TLD reputation, IP URL detection
- **Semantic:** Brand impersonation detection (23 brands)

---

## 🎯 Platform Features

### 1. Email Analyzer
- AI classification (Phishing/Legitimate)
- Confidence score (0-100%)
- Risk score visualization with gauge meter
- Explainable AI (why it's phishing)

### 2. Attack Indicators Panel
- Urgency manipulation detection
- Credential harvesting signals
- Threat/coercion language
- Financial lure patterns
- Brand impersonation
- Social engineering tactics

### 3. Link Scanner
- URL extraction from email text
- Domain TLD reputation
- Brand impersonation in domain
- HTTP vs HTTPS
- Subdomain abuse detection
- Redirect chain analysis

### 4. Threat Flags
- Social Engineering
- Spoofed Sender
- Credential Harvesting
- Malicious Links
- Suspicious Attachments
- SPF/DKIM failures

### 5. Security Dashboard
- Total scans
- Phishing detected count
- Safe email count
- Detection rate
- Model performance metrics
- Threat distribution charts

### 6. Email Header Analyzer
- SPF authentication check
- DKIM signature verification
- Reply-To domain spoofing detection

### 7. Suspicious Content Highlighting
- Keywords highlighted in email text
- Visual indication of manipulation phrases

### 8. Export Report
- JSON report download
- Includes verdict, risk score, indicators, recommendation

---

## 🧪 Testing

Use the sample emails in `SAMPLE_EMAILS.txt` or click the example buttons in the UI:
- **"⚠ Phishing Example"** — PayPal credential phishing
- **"✓ Legit Example"** — Standard business newsletter

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Tailwind CSS (standalone HTML) |
| Backend | Python 3 + Flask |
| AI/ML | scikit-learn (TF-IDF + Voting Ensemble) |
| API | REST JSON API with CORS |
| Fonts | DM Sans + DM Mono (Google Fonts) |

---

## 🔒 Security Concepts Implemented

- **IDS-inspired:** Pattern matching for known phishing signatures
- **NLP Analysis:** Statistical text classification
- **Domain Reputation:** TLD-based risk scoring
- **Header Forensics:** SPF/DKIM spoofing detection
- **Zero-trust principle:** Every email treated as potentially malicious

---

## 📊 Portfolio Notes

This project demonstrates:
- **Full-stack development:** Python backend + React frontend
- **Machine learning:** NLP, TF-IDF, ensemble methods, cross-validation
- **Cybersecurity knowledge:** Phishing tactics, email authentication, threat analysis
- **API design:** RESTful endpoints, proper error handling, CORS
- **UI/UX:** Professional dashboard design, data visualization
- **Code quality:** Modular, documented, production-ready

---

*Built with ❤️ for cybersecurity portfolio — PhishGuard AI v1.0*
