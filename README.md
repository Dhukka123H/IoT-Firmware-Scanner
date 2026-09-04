# 🛡️ IoT Firmware Vulnerability Scanner & Security Auditor
**Author:** Dhukka Haris | [GitHub](https://github.com/Dhukka123H) • [LinkedIn](https://www.linkedin.com/in/dhukka-haris-6716992ba/)  
**Port:** `5000` | **Tech Stack:** Python 3, Flask, ReportLab PDF, Vanilla CSS, JetBrains Mono

---

## 📌 Project Overview
The **IoT Firmware Vulnerability Scanner** is an automated reverse-engineering and security audit tool built to discover hardcoded vulnerabilities, cryptographic secrets, backdoors, and insecure services embedded inside IoT device firmware packages (`.bin`, `.tar`, `.zip`, `.tar.gz`, `.fw`, `.img`).

Many IoT manufacturers release firmware updates without sanitizing root credentials or removing debug daemon services (such as unauthenticated Telnet, outdated Dropbear SSH, or default admin keys). This tool automates the firmware analysis pipeline and produces professional compliance PDF reports.

---

## 🚀 Key Features

- **Multi-Format Extraction Pipeline** — ZIP, TAR, TAR.GZ, BIN with Binwalk fallback
- **6-Vector Heuristic Engine** — Credentials, Private Keys, API Tokens, Daemons, Shadow Files, Backdoor IPs
- **Risk Score Engine (0–100)** — Severity-weighted with floors (see scoring section below)
- **Scan History Log** — Last 10 scans at `/history` with aggregate stats
- **In-Memory PDF Export** — No file written to disk; each export is isolated and fresh
- **Full Security Hardening** — Auto-wipe on startup and post-scan, file validation, session isolation
- **Premium Dark UI** — Collapsible finding cards, animated results, loading overlay

---

## 🔢 Risk Score — How It Works

> The score is **NOT** a simple count. It uses **weighted points + severity floors** to avoid underreporting serious vulnerabilities.

### Point Weights Per Finding
| Severity | Points | Minimum Floor (if any exist) |
|----------|--------|------------------------------|
| **Critical** | 25 pts | Floor = **60** — always HIGH or above |
| **High** | 10 pts | Floor = **30** — at least MODERATE |
| **Medium** | 4 pts | Floor = **10** |
| No findings | — | 0 — SECURE |

### Formula
```
raw   = (critical × 25) + (high × 10) + (medium × 4)
score = max(severity_floor, raw),  capped at 100
```

### Examples
| Findings | Raw | Floor | Final | Label |
|----------|-----|-------|-------|-------|
| 0 findings | 0 | — | **0** | 🟢 SECURE |
| 1 Medium | 4 | 10 | **10** | 🟡 LOW |
| 1 High | 10 | 30 | **30** | 🟠 MODERATE |
| **1 Critical + 1 High** *(sample firmware)* | 35 | 60 | **60** | 🔴 HIGH |
| 3 Critical + 2 High | 95 | 60 | **95** | 🔴 CRITICAL |
| 4+ Critical | 100+ | 60 | **100** | 🔴 CRITICAL |

### Label Thresholds
| Score | Label | Meaning |
|-------|-------|---------|
| 0 | 🟢 SECURE | Clean — no vectors found |
| 1–29 | 🟡 LOW | Minor findings |
| 30–59 | 🟠 MODERATE | Needs attention before deployment |
| 60–79 | 🔴 HIGH | Critical vulnerabilities — do not ship |
| 80–100 | 🔴 CRITICAL | Severely compromised firmware |

---

## 🛠️ System Architecture

```
[ User Firmware Upload (.bin / .zip / .tar / .fw) ]
                     │
                     ▼
       [ Security Validation Layer ]
        ├── File extension whitelist
        ├── Max file size: 50 MB
        └── werkzeug.secure_filename() sanitization
                     │
                     ▼
       [ Extraction Controller ]
        ├── Stage 1: ZIP (zipfile)
        ├── Stage 2: TAR (tarfile)
        ├── Stage 3: Binwalk (Linux/WSL, optional)
        └── Stage 4: Raw binary fallback
                     │
                     ▼
     [ Heuristic Multi-Vector Analyzer ]
        ├── Hardcoded Credential Keys
        ├── Private RSA/SSH/EC Keys
        ├── Cloud API Tokens & JWT Secrets
        ├── Vulnerable Daemons (telnetd, dropbear, vsftpd)
        ├── Shadow/Hash File Exposures
        └── Embedded Backdoor IPs
                     │
                     ▼
          [ Risk Score Engine (0–100) ]
        ├── Weighted scoring: Critical×25, High×10, Medium×4
        └── Severity floors: Critical≥60, High≥30, Medium≥10
                     │
                     ▼
     [ Security Cleanup — Zero Persistence ]
        ├── Upload file deleted immediately after extraction
        └── Extracted tree wiped after analysis
                     │
                     ▼
          [ Output Layer ]
        ├── Real-Time Dashboard (http://127.0.0.1:5000)
        ├── Scan History (/history) — last 10 scans
        └── In-Memory PDF Report (/export/pdf) — no disk file
```

---

## 📥 Installation & Setup

### Prerequisites
- Python 3.8+
- *(Optional on Linux/Kali)*: `sudo apt install binwalk` for native binary unpacking.

> **Note:** The `uploads/` and `extracted_firmware/` folders are **auto-created** by the app at runtime and **auto-deleted** after each scan. You do not need to create them manually, and they are excluded from Git.

### Step 1: Install Dependencies
```bash
cd IoT-Firmware-Scanner
pip install -r requirements.txt
```

### Step 2: Start the Server
```bash
python app.py
```

### Step 3: Open the Dashboard
```
http://127.0.0.1:5000
```

---

## 🧪 Testing with Sample Firmware

A ready-to-use `sample_firmware.zip` is included. It contains:
```ini
root_pass="SuperSecretPassword123!"
api_key="AKIAIOSFODNN7EXAMPLE_KEY"
```

**Expected result:**
- 1 × 🔴 **Critical** — Hardcoded Credential Key (`root_pass`)
- 1 × 🔶 **High** — Active Token / Cloud API Secret (`api_key`)
- Risk Score: **60/100 — HIGH**

**Steps:**
1. Go to `http://127.0.0.1:5000`
2. Drag & drop `sample_firmware.zip` into the upload zone
3. Click **"⚡ Execute Deconstruction Loop"**
4. Click any finding card to expand its raw telemetry
5. Click **"📥 Export PDF Report"** to download the audit PDF
6. Visit `/history` to review past scan records

---

## 🔒 Security Implementation

| Feature | How It Works |
|---------|-------------|
| **No persistent uploads** | File deleted from disk immediately after extraction |
| **No persistent extraction** | `extracted_firmware/` wiped after analysis |
| **Workspace purge on boot** | Both folders deleted & recreated clean on every `python app.py` |
| **Blank page on load** | GET `/` shows empty dashboard — no stale data ever shown |
| **In-memory PDF** | PDF built with `io.BytesIO`, never written to disk |
| **File type whitelist** | Only `.zip .tar .gz .bin .bz2 .img .fw` accepted |
| **File size limit** | Max 50 MB — oversized files rejected before processing |
| **Secure filename** | `werkzeug.secure_filename()` blocks path traversal attacks |
| **Session isolation** | Scan results stored in Flask session — not shared global state |
| **Git clean** | `uploads/`, `extracted_firmware/`, `scan_history.json`, `*.pdf` all in `.gitignore` |

---

## 💼 Resume Bullet Points

- **Engineered an automated IoT firmware security auditing tool** using Python, Flask, and heuristic pattern-matching to identify embedded vulnerabilities before device deployment.
- **Designed a weighted risk scoring engine (0–100)** with severity floors — ensuring a single hardcoded credential always scores HIGH or above, never misleadingly LOW.
- **Implemented in-memory PDF generation** with ReportLab's `BytesIO` pipeline, eliminating disk write vulnerabilities and producing isolated per-scan compliance reports.
- **Built a zero-persistence security architecture**: uploads auto-deleted, extraction trees wiped, workspace purged on startup — no firmware data ever lingers.
- **Automated detection of 6 vulnerability classes** across firmware trees: credentials, private keys, API tokens, vulnerable daemons, shadow files, and backdoor IP addresses.

---

## 💬 Technical Interview Cheat Sheet

> **Q: How does the tool deconstruct proprietary firmware binaries?**  
> **A:** *"The system runs a 4-stage extraction pipeline: ZIP → TAR → Binwalk (recursive `-e -M` with magic byte parsing for SquashFS/CramFS) → raw binary fallback. This handles virtually any firmware archive format."*

> **Q: Why does the risk score show 60/100 for just one hardcoded password?**  
> **A:** *"The scoring uses severity floors — any Critical finding sets a minimum of 60, so the tool never downplays serious vulnerabilities. A single hardcoded root password is always classified HIGH regardless of finding count. 100/100 is reserved for firmware with multiple severe findings across all categories."*

> **Q: How do you prevent uploaded firmware from being exposed?**  
> **A:** *"The upload is deleted immediately after extraction. The extracted tree is wiped after analysis. Both folders are purged clean on server startup. The PDF is generated in RAM using `BytesIO` — never written to disk. Results are stored in Flask's server-side session, so nothing sensitive is ever in global state or on disk."*

> **Q: What is the attack surface reduction achieved by this architecture?**  
> **A:** *"Zero persistent artifacts means no exfiltration window for uploaded firmware, no residual data between users, and no static report file that could be accessed by an unauthorized party. Each request is fully isolated."*