import os
import re
import io
import json
import shutil
import zipfile
import tarfile
import subprocess
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session

# ReportLab imports for premium PDF
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch, mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)

# ─────────────────────────────────────────
# App Bootstrap
# ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "haris_cyber_iot_firmware_scanner_SECURE_2026_xK9#mP$vQ"

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
UPLOAD_FOLDER       = 'uploads'
EXTRACT_FOLDER      = 'extracted_firmware'
HISTORY_FILE        = 'scan_history.json'
MAX_FILE_SIZE_MB    = 50
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_EXTENSIONS  = {'.zip', '.tar', '.gz', '.bin', '.bz2', '.img', '.fw'}
# NOTE: No REPORT_PATH — PDFs are generated in-memory (BytesIO) per request

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────
# Security: Purge workspace on startup
# ─────────────────────────────────────────
def purge_workspace():
    """Wipe uploads and extracted firmware folders for a clean security posture."""
    for folder in [UPLOAD_FOLDER, EXTRACT_FOLDER]:
        if os.path.exists(folder):
            shutil.rmtree(folder, ignore_errors=True)
        os.makedirs(folder, exist_ok=True)

purge_workspace()

# ─────────────────────────────────────────
# Severity & Scoring Engine
# ─────────────────────────────────────────
SEVERITY_MAP = {
    "Hardcoded Credential Key":          "Critical",
    "Private Cryptographic Material":    "Critical",
    "Active Token / Cloud API Secret":   "High",
    "Vulnerable Remote Terminal Daemon": "High",
    "Insecure Shadow/Hash Exposure":     "Medium",
    "Embedded Default IP / Backdoor URI": "Medium",
}

# Point weights per finding
SEVERITY_WEIGHTS = {"Critical": 25, "High": 10, "Medium": 4}

# Minimum floor: even 1 finding of this severity guarantees this floor score
SEVERITY_FLOORS  = {"Critical": 60, "High": 30, "Medium": 10}

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#ef4444"),
    "High":     colors.HexColor("#f97316"),
    "Medium":   colors.HexColor("#eab308"),
}

def classify_severity(risk_category):
    return SEVERITY_MAP.get(risk_category, "Medium")

def calculate_risk_score(findings):
    """Returns a 0–100 risk score with severity-based floors.

    Formula:
      raw = (critical×25) + (high×10) + (medium×4)
      floor = 60 if any Critical, 30 if any High, 10 if any Medium
      score = max(floor, raw), capped at 100

    This ensures 1 Critical credential = min 60/100 (HIGH) —
    never misleadingly LOW regardless of total count.
    """
    if not findings:
        return 0
    c = sum(1 for f in findings if f["severity"] == "Critical")
    h = sum(1 for f in findings if f["severity"] == "High")
    m = sum(1 for f in findings if f["severity"] == "Medium")
    raw = (c * 25) + (h * 10) + (m * 4)
    if c > 0:   floor = SEVERITY_FLOORS["Critical"]
    elif h > 0: floor = SEVERITY_FLOORS["High"]
    else:       floor = SEVERITY_FLOORS["Medium"]
    return min(100, max(floor, raw))

def get_risk_label(score):
    if score == 0:   return "SECURE",   "#22c55e"
    if score <= 29:  return "LOW",      "#84cc16"
    if score <= 59:  return "MODERATE", "#eab308"
    if score <= 79:  return "HIGH",     "#f97316"
    return "CRITICAL", "#ef4444"

# ─────────────────────────────────────────
# Validation
# ─────────────────────────────────────────
def validate_file(file):
    """Returns (ok: bool, error_msg: str)."""
    filename = secure_filename(file.filename)
    if not filename:
        return False, "No file selected."
    # Check extension
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"File type '{ext}' is not supported. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
    # Check size
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_FILE_SIZE_BYTES:
        return False, f"File too large ({size // (1024*1024)}MB). Max allowed: {MAX_FILE_SIZE_MB}MB."
    return True, ""

# ─────────────────────────────────────────
# Extraction Engine
# ─────────────────────────────────────────
def extract_firmware(target_binary):
    """Multi-stage extraction: ZIP → TAR → Binwalk → Raw fallback."""
    if os.path.exists(EXTRACT_FOLDER):
        shutil.rmtree(EXTRACT_FOLDER, ignore_errors=True)
    os.makedirs(EXTRACT_FOLDER, exist_ok=True)

    extracted = False

    # Stage 1: ZIP
    if zipfile.is_zipfile(target_binary):
        try:
            with zipfile.ZipFile(target_binary, 'r') as zf:
                zf.extractall(EXTRACT_FOLDER)
            extracted = True
        except Exception:
            pass

    # Stage 2: TAR
    if not extracted:
        try:
            if tarfile.is_tarfile(target_binary):
                with tarfile.open(target_binary, 'r:*') as tf:
                    tf.extractall(EXTRACT_FOLDER)
                extracted = True
        except Exception:
            pass

    # Stage 3: Binwalk (Linux/WSL)
    if not extracted or not os.listdir(EXTRACT_FOLDER):
        try:
            subprocess.run(
                ["binwalk", "-e", "-M", "--directory", EXTRACT_FOLDER, target_binary],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120
            )
            if os.path.exists(EXTRACT_FOLDER) and os.listdir(EXTRACT_FOLDER):
                extracted = True
        except Exception:
            pass

    # Stage 4: Raw copy fallback
    if not os.path.exists(EXTRACT_FOLDER) or not os.listdir(EXTRACT_FOLDER):
        dest = os.path.join(EXTRACT_FOLDER, os.path.basename(target_binary))
        shutil.copy(target_binary, dest)

    return True

# ─────────────────────────────────────────
# Heuristic Analysis Engine
# ─────────────────────────────────────────
HEURISTICS = {
    "Hardcoded Credential Key": (
        r"(?:password|passwd|pwd|root_pass|admin_pass|root_password)"
        r"\s*[:=]\s*['\"]([a-zA-Z0-9_@#$!%^*()\-+]{4,})['\"]"
    ),
    "Private Cryptographic Material": (
        r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"
    ),
    "Active Token / Cloud API Secret": (
        r"(?:secret_key|api_key|oauth_token|jwt_secret|aws_access_key_id|auth_token|shared_secret_key)"
        r"\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.~]{8,})['\"]"
    ),
    "Vulnerable Remote Terminal Daemon": (
        r"(telnetd|dropbear(?:\s+v[0-9\.]+)?|vsftpd\s+2\.3\.4|in\.tftpd|rshd|rexecd)"
    ),
    "Insecure Shadow/Hash Exposure": (
        r"(root:[^:]+:[0-9]+:[0-9]+:[^:]*:[^:]*:[^:]*)"
    ),
    "Embedded Default IP / Backdoor URI": (
        r"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[a-zA-Z0-9_\-\.~]*)*)"
    ),
}

def analyze_extracted():
    """Walk extraction tree and apply all heuristic patterns."""
    findings = []
    if not os.path.exists(EXTRACT_FOLDER):
        return findings

    for root_dir, _, files in os.walk(EXTRACT_FOLDER):
        for fname in files:
            fpath = os.path.join(root_dir, fname)
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    content = fh.read()
                for category, pattern in HEURISTICS.items():
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        rel_path = os.path.relpath(fpath, EXTRACT_FOLDER)
                        matched  = match.group(0).strip()
                        findings.append({
                            "risk_category":    category,
                            "severity":         classify_severity(category),
                            "source_file_path": rel_path,
                            "raw_leak_telemetry": matched[:150],
                        })
            except Exception:
                continue

    return findings

# ─────────────────────────────────────────
# Scan History
# ─────────────────────────────────────────
def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:10]  # Keep last 10 scans
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def scanner_dashboard():
    if request.method == 'POST':
        if 'firmware_file' not in request.files:
            flash("No file part in the request.", "error")
            return redirect(request.url)

        uploaded = request.files['firmware_file']
        if uploaded.filename == '':
            flash("No file selected.", "error")
            return redirect(request.url)

        # Validate file
        ok, err = validate_file(uploaded)
        if not ok:
            flash(err, "error")
            return redirect(request.url)

        safe_name   = secure_filename(uploaded.filename)
        store_path  = os.path.join(UPLOAD_FOLDER, safe_name)
        uploaded.save(store_path)

        # Scan metadata
        scan_meta = {
            "filename":  safe_name,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "filesize":  f"{os.path.getsize(store_path) / 1024:.1f} KB",
        }

        # Extract & analyse
        extract_firmware(store_path)
        findings = analyze_extracted()

        # Security: wipe upload immediately
        if os.path.exists(store_path):
            os.remove(store_path)

        # Security: wipe extracted tree
        shutil.rmtree(EXTRACT_FOLDER, ignore_errors=True)
        os.makedirs(EXTRACT_FOLDER, exist_ok=True)

        # Risk score
        score = calculate_risk_score(findings)
        label, color = get_risk_label(score)

        # Persist in session for PDF export
        session['scan_findings'] = findings
        session['scan_meta']     = scan_meta
        session['risk_score']    = score
        session['risk_label']    = label

        # Save to history
        save_history({
            "filename":      safe_name,
            "timestamp":     scan_meta["timestamp"],
            "total_findings": len(findings),
            "risk_score":    score,
            "risk_label":    label,
            "critical": sum(1 for f in findings if f["severity"] == "Critical"),
            "high":     sum(1 for f in findings if f["severity"] == "High"),
            "medium":   sum(1 for f in findings if f["severity"] == "Medium"),
        })

        return render_template(
            'index.html',
            telemetry=findings,
            meta=scan_meta,
            risk_score=score,
            risk_label=label,
            risk_color=color,
            history=load_history(),
            mode="executed"
        )

    # GET — show clean dashboard, no stale data
    return render_template(
        'index.html',
        telemetry=[], meta={}, risk_score=0,
        risk_label="", risk_color="",
        history=load_history(),
        mode="idle"
    )


@app.route('/history')
def scan_history():
    return render_template('history.html', history=load_history())


@app.route('/clear-history', methods=['POST'])
def clear_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)
    flash("Scan history cleared.", "success")
    return redirect(url_for('scanner_dashboard'))


# ─────────────────────────────────────────
# Premium PDF Export
# ─────────────────────────────────────────
BRAND_DARK   = colors.HexColor("#0f172a")
BRAND_BLUE   = colors.HexColor("#0ea5e9")
BRAND_SLATE  = colors.HexColor("#334155")
BRAND_LIGHT  = colors.HexColor("#f1f5f9")
BRAND_WHITE  = colors.white
SEV_CRITICAL = colors.HexColor("#ef4444")
SEV_HIGH     = colors.HexColor("#f97316")
SEV_MEDIUM   = colors.HexColor("#eab308")
SEV_OK       = colors.HexColor("#22c55e")

def build_premium_pdf(findings, meta, risk_score, risk_label):
    """Build a multi-page PDF in memory and return a BytesIO buffer."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.75 * inch,
        title="IoT Firmware Security Audit Report",
        author="Haris — CSE-IOTCSBCT",
    )

    styles = getSampleStyleSheet()

    # Custom styles
    def S(name, **kwargs):
        base = styles.get(name, styles["Normal"])
        return ParagraphStyle(name + "_custom", parent=base, **kwargs)

    title_style   = S("Title",    fontSize=16, textColor=BRAND_BLUE,  fontName="Helvetica-Bold", spaceAfter=4)
    sub_style     = S("Normal",   fontSize=9,  textColor=BRAND_SLATE, fontName="Helvetica",      spaceAfter=2)
    h2_style      = S("Heading2", fontSize=13, textColor=BRAND_DARK,  fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6)
    body_style    = S("Normal",   fontSize=9,  textColor=BRAND_DARK,  fontName="Helvetica",      leading=14)
    mono_style    = S("Normal",   fontSize=7.5,textColor=colors.HexColor("#1e293b"), fontName="Courier", leading=11)
    caption_style = S("Normal",   fontSize=8,  textColor=BRAND_SLATE, fontName="Helvetica-Oblique")

    story = []

    # ── Header Banner ──────────────────────────────────────────────────
    def header_table():
        header_data = [[
            Paragraph("IoT FIRMWARE SECURITY AUDIT", title_style),
            Paragraph("COMPLIANCE REPORT", S("Normal", fontSize=10, textColor=BRAND_BLUE,
                                              fontName="Helvetica-Bold", alignment=TA_RIGHT)),
        ]]
        t = Table(header_data, colWidths=[4.5 * inch, 2.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), BRAND_DARK),
            ("TOPPADDING",   (0, 0), (-1, -1), 14),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 14),
            ("LEFTPADDING",  (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ]))
        return t

    story.append(header_table())
    story.append(Spacer(1, 8))

    # ── Auditor Meta Strip ──────────────────────────────────────────────
    meta_rows = [[
        Paragraph(f"<b>Auditor:</b> Dhukka Haris | CSE-IoTCSBCT", body_style),
        Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", S("Normal", fontSize=9, textColor=BRAND_SLATE, fontName="Helvetica", alignment=TA_RIGHT)),
    ]]
    meta_t = Table(meta_rows, colWidths=[4.5 * inch, 2.5 * inch])
    meta_t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), colors.HexColor("#e2e8f0")),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(meta_t)
    story.append(Spacer(1, 10))

    # ── Scan Info Table ─────────────────────────────────────────────────
    scan_file = meta.get("filename", "Unknown")
    scan_time = meta.get("timestamp", "—")
    scan_size = meta.get("filesize", "—")

    info_data = [
        [Paragraph("<b>SCAN INFORMATION</b>", S("Normal", fontSize=9, textColor=BRAND_WHITE, fontName="Helvetica-Bold"))],
        ["Firmware Target", scan_file, "Scan Timestamp", scan_time],
        ["File Size",       scan_size, "Total Findings", str(len(findings))],
    ]
    info_t = Table(info_data, colWidths=[1.5*inch, 2.2*inch, 1.5*inch, 1.8*inch])
    info_t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), BRAND_SLATE),
        ("TEXTCOLOR",    (0, 0), (-1, 0), BRAND_WHITE),
        ("SPAN",         (0, 0), (-1, 0)),
        ("FONTNAME",     (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTNAME",     (2, 1), (2, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8.5),
        ("BACKGROUND",   (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",        (0, 0), (-1, 0), "CENTER"),
    ]))
    story.append(info_t)
    story.append(Spacer(1, 14))

    # ── Risk Score Panel ────────────────────────────────────────────────
    sev_color_map = {"CRITICAL": SEV_CRITICAL, "HIGH": SEV_HIGH, "MODERATE": SEV_MEDIUM,
                     "LOW": SEV_OK, "SECURE": SEV_OK}
    risk_color = sev_color_map.get(risk_label, SEV_OK)

    critical_c = sum(1 for f in findings if f["severity"] == "Critical")
    high_c     = sum(1 for f in findings if f["severity"] == "High")
    medium_c   = sum(1 for f in findings if f["severity"] == "Medium")

    risk_data = [[
        Paragraph(f"<b>RISK SCORE</b>", S("Normal", fontSize=8, textColor=BRAND_SLATE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<b>CRITICAL</b>",   S("Normal", fontSize=8, textColor=SEV_CRITICAL, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<b>HIGH</b>",       S("Normal", fontSize=8, textColor=SEV_HIGH,     fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<b>MEDIUM</b>",     S("Normal", fontSize=8, textColor=SEV_MEDIUM,   fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<b>STATUS</b>",     S("Normal", fontSize=8, textColor=BRAND_SLATE,  fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ],[
        Paragraph(f"<font size=20><b>{risk_score}/100</b></font>", S("Normal", fontSize=20, textColor=risk_color, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<font size=18><b>{critical_c}</b></font>",     S("Normal", fontSize=18, textColor=SEV_CRITICAL, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<font size=18><b>{high_c}</b></font>",         S("Normal", fontSize=18, textColor=SEV_HIGH,     fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<font size=18><b>{medium_c}</b></font>",       S("Normal", fontSize=18, textColor=SEV_MEDIUM,   fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"<font size=13><b>{risk_label}</b></font>",     S("Normal", fontSize=13, textColor=risk_color,   fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]]
    risk_t = Table(risk_data, colWidths=[1.4*inch]*5)
    risk_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("BACKGROUND",    (0, 1), (-1, 1), colors.HexColor("#ffffff")),
        ("BOX",           (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
        ("INNERGRID",     (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("TOPPADDING",    (0, 1), (-1, 1), 14),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 14),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(risk_t)
    story.append(Spacer(1, 16))

    # ── Overall Status Banner ──────────────────────────────────────────
    if not findings:
        status_text = "✔  AUDIT RESULT: PASSED — ZERO HIGH-RISK VECTORS IDENTIFIED"
        status_bg   = colors.HexColor("#dcfce7")
        status_fg   = SEV_OK
    else:
        status_text = f"✘  AUDIT RESULT: FAILED — {len(findings)} EXPOSURE VECTOR(S) DETECTED"
        status_bg   = colors.HexColor("#fef2f2")
        status_fg   = SEV_CRITICAL

    status_data = [[Paragraph(f"<b>{status_text}</b>",
                              S("Normal", fontSize=10, textColor=status_fg,
                                fontName="Helvetica-Bold", alignment=TA_CENTER))]]
    status_t = Table(status_data, colWidths=[7 * inch])
    status_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), status_bg),
        ("BOX",           (0, 0), (-1, -1), 1.5, status_fg),
        ("TOPPADDING",    (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(status_t)
    story.append(Spacer(1, 20))

    # ── Findings Table ─────────────────────────────────────────────────
    if findings:
        story.append(Paragraph("DETAILED EXPOSURE FINDINGS", h2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
        story.append(Spacer(1, 8))

        # Table header
        tbl_header = [
            Paragraph("<b>#</b>",        S("Normal", fontSize=8, textColor=BRAND_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph("<b>SEVERITY</b>", S("Normal", fontSize=8, textColor=BRAND_WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
            Paragraph("<b>RISK CATEGORY</b>",    S("Normal", fontSize=8, textColor=BRAND_WHITE, fontName="Helvetica-Bold")),
            Paragraph("<b>FILE PATH</b>",        S("Normal", fontSize=8, textColor=BRAND_WHITE, fontName="Helvetica-Bold")),
            Paragraph("<b>EXTRACTED TELEMETRY</b>", S("Normal", fontSize=8, textColor=BRAND_WHITE, fontName="Helvetica-Bold")),
        ]
        tbl_rows = [tbl_header]

        sev_bg_map = {
            "Critical": colors.HexColor("#fef2f2"),
            "High":     colors.HexColor("#fff7ed"),
            "Medium":   colors.HexColor("#fefce8"),
        }
        sev_label_colors = {
            "Critical": SEV_CRITICAL,
            "High":     SEV_HIGH,
            "Medium":   SEV_MEDIUM,
        }

        row_styles = []
        for i, item in enumerate(findings, start=1):
            sev    = item["severity"]
            sev_c  = sev_label_colors.get(sev, BRAND_SLATE)
            row_bg = sev_bg_map.get(sev, colors.HexColor("#f8fafc"))

            tbl_rows.append([
                Paragraph(str(i), S("Normal", fontSize=8, textColor=BRAND_SLATE, alignment=TA_CENTER)),
                Paragraph(f"<b>{sev.upper()}</b>", S("Normal", fontSize=7.5, textColor=sev_c, fontName="Helvetica-Bold", alignment=TA_CENTER)),
                Paragraph(item["risk_category"],    body_style),
                Paragraph(item["source_file_path"], S("Normal", fontSize=7.5, textColor=BRAND_SLATE, fontName="Courier")),
                Paragraph(item["raw_leak_telemetry"][:80].encode('latin-1','replace').decode('latin-1') + "…", mono_style),
            ])
            row_styles.append(("BACKGROUND", (0, i), (-1, i), row_bg))

        col_widths = [0.28*inch, 0.9*inch, 2.0*inch, 1.28*inch, 2.54*inch]
        findings_t = Table(tbl_rows, colWidths=col_widths, repeatRows=1)

        base_style = [
            ("BACKGROUND",    (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), BRAND_WHITE),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("ALIGN",         (0, 0), (1, -1),  "CENTER"),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.HexColor("#f1f5f9")]),
        ] + row_styles

        findings_t.setStyle(TableStyle(base_style))
        story.append(findings_t)
        story.append(Spacer(1, 20))

    # ── Recommendations Section ────────────────────────────────────────
    if findings:
        story.append(PageBreak())
        story.append(Paragraph("REMEDIATION RECOMMENDATIONS", h2_style))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
        story.append(Spacer(1, 8))

        recs = [
            ("Hardcoded Credentials",   "Remove all hardcoded passwords. Implement secure secret management (e.g., HashiCorp Vault, AWS Secrets Manager). Use environment variables for runtime secrets."),
            ("Private Key Exposure",     "Rotate all exposed private keys immediately. Use Hardware Security Modules (HSMs) and never embed private keys in firmware images."),
            ("Cloud API Tokens",        "Revoke all exposed API keys and tokens. Rotate and implement IAM role-based access controls. Apply the principle of least privilege."),
            ("Vulnerable Daemons",       "Disable telnetd, rshd, rexecd permanently. Replace Dropbear/vsftpd with hardened alternatives. Apply all vendor security patches."),
            ("Shadow File Exposure",     "Ensure shadow files are not embedded in firmware. Use PAM with remote auth instead of local password hashes."),
            ("Embedded IP Addresses",    "Remove all hardcoded IP endpoints. Use DNS-based service discovery and configuration management."),
        ]

        rec_data = [[
            Paragraph(f"<b>{title}</b>", S("Normal", fontSize=9, textColor=BRAND_DARK, fontName="Helvetica-Bold")),
            Paragraph(desc, body_style),
        ] for title, desc in recs]

        rec_t = Table(rec_data, colWidths=[1.8*inch, 5.2*inch])
        rec_t.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
            ("TOPPADDING",     (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 7),
            ("LEFTPADDING",    (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",   (0, 0), (-1, -1), 8),
            ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rec_t)
        story.append(Spacer(1, 20))

    # ── Footer ─────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 6))
    footer_data = [[
        Paragraph("IoT Firmware Security Audit — CONFIDENTIAL", caption_style),
        Paragraph(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Auditor: Dhukka Haris",
                  S("Normal", fontSize=8, textColor=BRAND_SLATE, fontName="Helvetica-Oblique", alignment=TA_RIGHT)),
    ]]
    footer_t = Table(footer_data, colWidths=[3.5*inch, 3.5*inch])
    footer_t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(footer_t)

    doc.build(story)
    buffer.seek(0)
    return buffer


@app.route('/export/pdf')
def export_pdf():
    findings   = session.get('scan_findings', [])
    meta       = session.get('scan_meta', {"filename": "Unknown", "timestamp": "—", "filesize": "—"})
    risk_score = session.get('risk_score', 0)
    risk_label = session.get('risk_label', 'SECURE')

    if not findings and not meta.get("filename"):
        flash("No scan results available to export. Run a scan first.", "error")
        return redirect(url_for('scanner_dashboard'))

    pdf_buffer = build_premium_pdf(findings, meta, risk_score, risk_label)
    return send_file(pdf_buffer, as_attachment=True, mimetype='application/pdf',
                     download_name=f"IoT_Audit_{meta.get('filename','report')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf")


# ─────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000, use_reloader=False)