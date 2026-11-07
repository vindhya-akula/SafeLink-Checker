# 🔐 SafeLink Checker

A web-based URL security analysis application that checks website URLs for suspicious indicators and assigns a risk score to help users identify potentially unsafe links.

## 🚀 Project Overview

SafeLink Checker is a full-stack application built with Python, FastAPI, HTML, CSS, and JavaScript. It analyzes submitted URLs, identifies suspicious patterns, and displays a risk assessment through an interactive dashboard.

The application also integrates VirusTotal for external threat intelligence checks.

## ✨ Features

- **URL Scanning:** Analyze HTTP and HTTPS URLs.
- **Risk Assessment:** Generate a risk score from 0 to 100.
- **Risk Classification:** Categorize URLs as Low, Medium, or High Risk.
- **Security Findings:** Display suspicious indicators identified during local analysis.
- **Scan History:** Store and view previously scanned URLs.
- **VirusTotal Integration:** Request external threat intelligence analysis.
- **Interactive Dashboard:** View scan results through a responsive web interface.
- **URL Validation:** Validate submitted URLs before analysis.

## 🛠️ Tech Stack

| Component | Technologies |
|---|---|
| Frontend | HTML, CSS, JavaScript |
| Backend | Python, FastAPI |
| Database | SQLite, SQLAlchemy |
| Security Analysis | Custom URL analysis |
| External Threat Intelligence | VirusTotal API |
| Testing | Pytest |
| Development Tools | VS Code, Git, GitHub |

## 📁 Project Structure

```text
SafeLink-Checker/
│
├── backend/
│   ├── app/
│   │   ├── routes/
│   │   │   └── scanner.py
│   │   ├── services/
│   │   │   ├── url_analyzer.py
│   │   │   └── virustotal.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── main.py
│   │   └── models.py
│   │
│   ├── tests/
│   │   └── test_url_analyzer.py
│   └── requirements.txt
│
├── frontend/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── app.js
│   └── index.html
│
├── .gitignore
└── README.md
```

## ⚙️ Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/vindhya-akula/SafeLink-Checker.git
cd SafeLink-Checker
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 5. Configure environment variables

Configure your VirusTotal API key using the environment variable expected by your backend configuration.

Keep your API key in a local `.env` file and never commit credentials to GitHub.

### 6. Start the FastAPI backend

From the `backend` directory:

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend API:

```text
http://127.0.0.1:8000
```

Interactive API documentation:

```text
http://127.0.0.1:8000/docs
```

### 7. Run the frontend

Open `frontend/index.html` using the VS Code Live Server extension.

## 🔌 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Check backend health |
| POST | `/api/scan` | Scan and analyze a URL |
| GET | `/api/history` | Retrieve scan history |
| POST | `/api/threat-intel` | Request VirusTotal analysis |

## 🧪 Testing

Run the backend tests from the project root:

```bash
python -m pytest backend/tests -v
```

## 🔒 Security Notes

- Do not expose API keys or credentials in source code.
- Do not submit private, confidential, or sensitive URLs to external scanning services.
- A low risk score does not guarantee that a website is completely safe.
- Local analysis is an indicator-based assessment, not a full malware or vulnerability scan.

## 🎯 Future Enhancements

- Improve URL threat detection techniques.
- Add domain reputation analysis.
- Enhance phishing detection.
- Introduce additional threat intelligence sources.
- Improve dashboard visualizations.
- Add user authentication and personalized scan history.

## 👩‍💻 Author

**Vindhya Akula**

GitHub: [vindhya-akula](https://github.com/vindhya-akula)

---

*SafeLink Checker – Analyze URLs. Identify Risks. Browse Safer.*
