# Email Risk Analyzer

Python tool for local analysis of raw `.eml` files for phishing indicators.

## Features
- Parses raw headers and body
- Reviews SPF/DKIM/DMARC-related results present in headers
- Checks From / Return-Path mismatch
- Detects urgent lure language
- Extracts and checks suspicious URL patterns
- Produces a 0–100 heuristic risk score
- Classifies risk as LOW, MEDIUM, or HIGH

## Run
```bash
python email_risk_analyzer.py sample_email.eml
```

No external packages are required for the analyzer.

## Safety
Use only with email data you are authorized to inspect. This is an educational heuristic and does not cryptographically verify DKIM or perform DNS/reputation checks. The included sample is synthetic and uses example domains.
