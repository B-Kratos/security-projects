# Cyber Security Mini Projects

This repository contains two beginner-friendly **ethical hacking** and **cybersecurity** projects, built using **C** and **Python**.  
They demonstrate basic concepts in password security and log analysis.

---

## 🔒 1. Password Breach Checker (C)

**Goal:**  
Check if a given password exists in a list of breached passwords.

**How it works:**
- Reads a file called `breached.txt` containing leaked passwords.
- Asks the user to enter a password.
- Compares it against the breached list.
- Tells the user if it’s safe or has been leaked.

**Example usage:**

Enter your password: 123456

**Result:**

⚠️ This password has been breached! Choose a stronger one.


---

## 2. SSH Log Analyzer (Python)

**Goal:**  
Analyze authentication logs and find suspicious IPs that had too many failed login attempts.

**How it works:**
- Reads `sample_auth.log`.
- Finds repeated failed login attempts.
- Flags IPs that exceed a threshold (e.g., 2 attempts).
- Outputs the results to `report.csv`.

**Run example:**

python analyzer.py sample_auth.log --threshold 2 --csv report.csv

**Result:**

192.168.1.45 - 5 failed attempts
203.0.113.22 - 3 failed attempts

‍💻 Author

Abdel Hadi Boualem

🌐 https://github.com/B-Kratos

⚠️ Disclaimer

These projects are for educational purposes only.
They do not perform any unauthorized actions and are meant to demonstrate security awareness and coding ability.
