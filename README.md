# PhishGuard — URL & Email Threat Analyzer

A defensive cybersecurity web application that classifies URLs and email messages as **legitimate**, **suspicious**, or **phishing** using a scikit-learn Random Forest classifier blended with transparent rule-based indicators.

## Technology stack
- Python 3.10+
- Flask REST API
- scikit-learn `RandomForestClassifier`
- pandas and NumPy for tabular feature preparation
- HTML, CSS, JavaScript frontend

## Folder structure
```text
phishing_analyzer.py/
├── backend/
│   ├── app.py                 # Flask routes and JSON API
│   ├── features.py            # URL/email engineered features + rules
│   ├── ml_model.py            # dataset, Random Forest, predictions, evaluation
│   ├── evaluate.py            # prints metrics as JSON
│   ├── requirements.txt
│   ├── data/                  # place vetted datasets here
│   └── models/                # optional saved model artifacts
└── frontend/
    ├── templates/index.html   # UI template
    └── static/
        ├── css/style.css
        └── js/app.js
```

## Features
- Analyze a single URL or email (sender, subject, body, optional HTML and attachment filenames).
- Three classes: legitimate, suspicious, phishing.
- Random Forest probability estimates blended with a 0–100 rule-based risk score.
- Engineered indicators: URL/email length, IP-based domains, subdomain count, dots/hyphens/digits/special characters, HTTPS, URL shorteners, punycode, suspicious keywords, query/path length, urgency/credential terms, risky attachment extensions, uppercase ratio and exclamation marks.
- Explains rule indicators and shows per-class probabilities.
- Evaluation page displays accuracy, macro precision, macro recall, macro F1-score and confusion matrix for URL and email models.

## Setup (Windows PowerShell)
1. Extract the ZIP. Open a terminal in the extracted `phishing_analyzer.py` folder.
2. Create and activate a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   py -m pip install --upgrade pip
   py -m pip install -r backend\requirements.txt
   ```
4. Start Flask:
   ```powershell
   py backend\app.py
   ```
5. Open `http://127.0.0.1:5000` in your browser.
6. Optional: print evaluation JSON from the project root:
   ```powershell
   py backend\evaluate.py
   ```

## API
- `GET /api/health` — status and supported classes.
- `POST /api/analyze` — JSON request.
  - URL: `{"type":"url","url":"https://example.com"}`
  - Email: `{"type":"email","sender":"name@example.com","subject":"Hello","body":"Message text","email_html":"","attachments":"file.pdf,update.exe"}`
- `GET /api/evaluation` — holdout evaluation metrics and confusion matrices.

## Model evaluation and limitations
The repository includes a small, deterministic **synthetic teaching dataset** so the project runs without downloading data or exposing the user to unsafe files. Reported metrics are only a demonstration of the evaluation pipeline and are not a reliable estimate of real-world phishing detection. Synthetic examples are limited and may not represent real traffic. For a credible evaluation, collect a sufficiently large, legally obtained, independently labeled dataset; split by source/time to avoid leakage; tune thresholds on validation data; and report per-class precision/recall, macro-F1, confusion matrix and class balance.

This is a defensive educational project, not a substitute for email gateway protection, browser reputation services, sandboxing, or expert review. Never open suspicious links or attachments just to test them. A legitimate prediction is not a safety guarantee.
