# Phishing Triage Tool (Python)

This project simulates phishing email analysis by identifying malicious indicators such as suspicious domains, links, and attachments. It evaluates emails using rule-based detection and risk scoring to classify potential threats.

---

## Features

- Detects spoofed and suspicious sender domains  
- Identifies phishing keywords (urgent, verify, reset, etc.)  
- Flags malicious links and URL shorteners  
- Detects dangerous attachments (.zip, .docm, etc.)  
- Identifies mismatched sender names and domains  
- Applies risk scoring and severity classification (Low / Medium / High)  

---

## How to Run

### Option 1 (Windows)
Double click:
run_phishing.bat  

### Option 2 (Command Line)
py phishing_triage.py  

---

## Input

phishing_emails.csv  

This file can be modified to simulate:
- Phishing emails  
- Legitimate emails  
- Suspicious but non-malicious activity  

---

## Output

phishing_triage_report.txt  

The report includes:
- Risk score and severity level  
- Detection reasoning  
- Suspicious indicators (domain, link, attachment)  
- Recommended analyst response actions  

---

## Sample Output

Example alert report:
sample_output/phishing_triage_report.txt

This output demonstrates:

- Risk scoring and severity classification  
- Detection reasoning (why an alert was triggered)  
- Identification of suspicious domains and links  
- Detection of malicious attachments  
- Indicators of Compromise (IOCs)  
- Recommended analyst response actions  

---

## Purpose

This project demonstrates phishing detection, email triage, and threat classification. It reflects how security analysts evaluate suspicious emails and prioritize potential threats.
