# ══════════════════════════════════════════════════════════════
# AI Security Auditor PRO — FINAL (POWERFUL SCAN)
# ══════════════════════════════════════════════════════════════

import streamlit as st
from transformers import pipeline
import re
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter

# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AI Security Auditor PRO",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.title("🛡️ AI Security Auditor ")
st.markdown("### 👨‍💻 Developed by:Ahmed Al-hadi, Ahmed amjad, Hussein osama ")

# ══════════════════════════════════════════════════════════════
# MODEL
# ══════════════════════════════════════════════════════════════
@st.cache_resource
def load_model():
    return pipeline(
        "text-classification",
        model="mrm8488/codebert-base-finetuned-detect-insecure-code"
    )

ai_engine = load_model()

def analyze_with_ai(code):
    try:
        return ai_engine(code[:400])[0]
    except:
        return {"label": "LABEL_1", "score": 0.5}

# ══════════════════════════════════════════════════════════════
# SESSION STATE
# ══════════════════════════════════════════════════════════════
if "files_data" not in st.session_state:
    st.session_state.files_data = []

if "scan_done" not in st.session_state:
    st.session_state.scan_done = False

if "fixed_results" not in st.session_state:
    st.session_state.fixed_results = {}

if "all_issues" not in st.session_state:
    st.session_state.all_issues = []

if "scan_results" not in st.session_state:
    st.session_state.scan_results = {}

# ══════════════════════════════════════════════════════════════
# SEVERITY
# ══════════════════════════════════════════════════════════════
def get_severity(desc):
    if any(x in desc for x in ["Injection", "Deserialization", "Traversal"]):
        return "CRITICAL"
    if any(x in desc for x in ["Secret", "SSL", "Command", "Shell"]):
        return "HIGH"
    if any(x in desc for x in ["eval", "exec", "Random", "Debug"]):
        return "MEDIUM"
    return "LOW"

# ══════════════════════════════════════════════════════════════
# SMART SCAN (🔥 قوي) — Hardened Regex Patterns
# ══════════════════════════════════════════════════════════════
def smart_scan(code):
    issues = []
    lines = code.split("\n")

    rules = [
        # SQL Injection — catches string concat, format, f-strings
        (r"(SELECT|INSERT|UPDATE|DELETE)\b.*?(\+\s*\w|\.format\s*\(|f['\"].*\{)", "SQL Injection"),

        # eval / exec
        (r"\beval\s*\(", "eval() usage"),
        (r"\bexec\s*\(", "exec() usage"),

        # OS Command Injection
        (r"\bos\.system\s*\(", "Command Injection"),
        (r"\bsubprocess\.(run|Popen|call|check_output)\b.*\bshell\s*=\s*True", "Shell Injection"),

        # Insecure deserialization / parsing
        (r"\bpickle\.loads?\s*\(", "Insecure Deserialization"),
        (r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)", "Unsafe YAML Load"),

        # Path traversal
        (r"\.\./|\.\.\\\\", "Path Traversal"),

        # Hardcoded secrets — advanced patterns
        (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}", "Hardcoded Password"),
        (r"(?i)(api[_\-]?key|apikey)\s*=\s*['\"][A-Za-z0-9\-_]{8,}", "Hardcoded API Key"),
        (r"(?i)(secret[_\-]?key|secret)\s*=\s*['\"][^'\"]{6,}", "Hardcoded Secret"),
        (r"(?i)(token|auth[_\-]?token|bearer)\s*=\s*['\"][A-Za-z0-9\-_.]{8,}", "Hardcoded Token"),

        # Insecure HTTP endpoints
        (r"http://(?!localhost|127\.0\.0\.1)[^\s'\",]{5,}", "Insecure HTTP Endpoint"),

        # TLS / SSL disabled
        (r"\bverify\s*=\s*False\b", "SSL Verification Disabled"),

        # Weak randomness
        (r"\brandom\.(random|randint|choice|seed)\s*\(", "Insecure Randomness"),

        # Debug mode
        (r"\bDEBUG\s*=\s*True\b", "Debug Mode Enabled"),

        # Unvalidated user input
        (r"\brequest\.(args|form|data|json|values|files)\b", "Unvalidated User Input"),

        # XSS
        (r"\binnerHTML\s*=", "XSS Risk (innerHTML)"),
        (r"\bdocument\.write\s*\(", "XSS Risk (document.write)"),

        # Sensitive data in logs
        (r"(?i)(print|log|logger)\s*\(.*?(password|token|secret|api_key)", "Sensitive Data in Logs"),
    ]

    seen = set()  # prevent duplicate hits on same line

    for i, line in enumerate(lines):
        for pattern, desc in rules:
            key = (i, desc)
            if key in seen:
                continue
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "line": i + 1,
                    "desc": desc,
                    "severity": get_severity(desc),
                    "code": line.strip()
                })
                seen.add(key)
                break  # one issue per line per rule pass

    return issues

# ══════════════════════════════════════════════════════════════
# AUTO FIX
# ══════════════════════════════════════════════════════════════
def auto_fix(code):
    lines = code.split("\n")
    fixed = []

    for line in lines:
        # Fix SSL
        if re.search(r"\bverify\s*=\s*False\b", line):
            line = re.sub(r"\bverify\s*=\s*False\b", "verify=True", line)

        # Fix unsafe yaml.load → yaml.safe_load
        if re.search(r"\byaml\.load\s*\(", line):
            line = re.sub(r"\byaml\.load\s*\(", "yaml.safe_load(", line)

        # Warn on eval
        if re.search(r"\beval\s*\(", line):
            line = "# ⚠️ SECURITY: avoid eval() — use safer alternatives\n" + line

        # Warn on exec
        if re.search(r"\bexec\s*\(", line):
            line = "# ⚠️ SECURITY: avoid exec() — refactor logic\n" + line

        # Warn on shell=True
        if re.search(r"\bshell\s*=\s*True\b", line):
            line = "# ⚠️ SECURITY: shell=True is dangerous — pass args as list\n" + line

        # Warn on insecure HTTP
        if re.search(r"http://(?!localhost|127\.0\.0\.1)", line):
            line = "# ⚠️ SECURITY: use HTTPS instead of HTTP\n" + line

        fixed.append(line)

    return "\n".join(fixed)

# ══════════════════════════════════════════════════════════════
# DASHBOARD CHARTS (Plotly)
# ══════════════════════════════════════════════════════════════
SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH": "#e67e22",
    "MEDIUM": "#f1c40f",
    "LOW": "#2ecc71"
}

def render_dashboard(all_issues):
    if not all_issues:
        return

    st.markdown("## 📊 Vulnerability Dashboard")

    severity_counts = Counter(i["severity"] for i in all_issues)
    desc_counts = Counter(i["desc"] for i in all_issues)

    ordered_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    sev_labels = [s for s in ordered_severities if s in severity_counts]
    sev_values = [severity_counts[s] for s in sev_labels]
    sev_colors = [SEVERITY_COLORS[s] for s in sev_labels]

    col1, col2, col3 = st.columns(3)

    # ── Metric Cards ────────────────────────────────────────
    total = len(all_issues)
    critical_count = severity_counts.get("CRITICAL", 0)
    high_count = severity_counts.get("HIGH", 0)

    with col1:
        st.metric("🔍 Total Issues", total)
    with col2:
        st.metric("🔴 Critical", critical_count)
    with col3:
        st.metric("🟠 High", high_count)

    st.markdown("---")
    chart_col1, chart_col2 = st.columns(2)

    # ── Donut Chart — Severity Distribution ─────────────────
    with chart_col1:
        fig_donut = go.Figure(data=[go.Pie(
            labels=sev_labels,
            values=sev_values,
            hole=0.55,
            marker=dict(colors=sev_colors, line=dict(color="#1a1a2e", width=2)),
            textinfo="label+percent",
            textfont=dict(size=13),
        )])
        fig_donut.update_layout(
            title="Severity Distribution",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f0f0f0"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
            margin=dict(t=50, b=20, l=20, r=20),
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    # ── Bar Chart — Top Vulnerability Types ─────────────────
    with chart_col2:
        top_descs = desc_counts.most_common(8)
        bar_labels = [d[0] for d in top_descs]
        bar_values = [d[1] for d in top_descs]

        fig_bar = go.Figure(go.Bar(
            x=bar_values,
            y=bar_labels,
            orientation="h",
            marker=dict(
                color=bar_values,
                colorscale=[[0, "#2ecc71"], [0.5, "#f1c40f"], [1, "#e74c3c"]],
                showscale=False,
            ),
            text=bar_values,
            textposition="outside",
        ))
        fig_bar.update_layout(
            title="Top Vulnerability Types",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#f0f0f0"),
            xaxis=dict(showgrid=False, zeroline=False),
            yaxis=dict(autorange="reversed"),
            margin=dict(t=50, b=20, l=20, r=60),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

# ══════════════════════════════════════════════════════════════
# UI — Upload + Run (2-column layout)
# ══════════════════════════════════════════════════════════════
st.markdown("---")
upload_col, info_col = st.columns([2, 1])

with upload_col:
    uploaded_files = st.file_uploader(
        "📁 Upload Files (.py, .js, .txt, etc.)",
        accept_multiple_files=True,
        help="Upload one or more source files to scan for vulnerabilities."
    )
    run_audit = st.button("🚀 Start Audit", use_container_width=True)

with info_col:
    st.markdown("#### 🔎 What We Scan For")
    st.markdown("""
- 🔴 SQL / Shell / Command Injection
- 🔴 Insecure Deserialization
- 🟠 Hardcoded Passwords, Keys & Tokens
- 🟠 Insecure HTTP Endpoints
- 🟡 eval / exec / Unsafe YAML
- 🟡 Debug Mode / Weak Randomness
- 🟢 XSS Risks / Unvalidated Input
""")

# ══════════════════════════════════════════════════════════════
# START — حفظ الملفات في session_state فوراً عند الضغط
# ══════════════════════════════════════════════════════════════
if run_audit:
    if uploaded_files:
        # ✅ الإصلاح الرئيسي: نقرأ الملفات ونحفظها في session_state مباشرة
        st.session_state.files_data = [
            (f.name, f.read().decode("utf-8", errors="ignore"))
            for f in uploaded_files
        ]
        # ✅ نحسب النتائج مرة واحدة ونحفظها
        st.session_state.scan_results = {}
        collected_issues = []
        for name, code in st.session_state.files_data:
            issues = smart_scan(code)
            st.session_state.scan_results[name] = issues
            collected_issues.extend(issues)
        st.session_state.all_issues = collected_issues
        st.session_state.scan_done = True
        st.session_state.fixed_results = {}
    else:
        st.warning("⚠️ Please upload at least one file to scan.")
        st.session_state.scan_done = False

# ══════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════
if st.session_state.scan_done and st.session_state.files_data:

    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }

    # ── Render Dashboard ─────────────────────────────────────
    render_dashboard(st.session_state.all_issues)

    st.markdown("---")
    st.markdown("## 📂 File-by-File Results")

    # ── Per-file breakdown — يستخدم النتائج المحفوظة مسبقاً ───
    for name, code in st.session_state.files_data:

        st.markdown("---")

        file_col, stats_col = st.columns([3, 1])

        # ✅ استخدام النتائج المحفوظة بدلاً من إعادة الحساب
        issues = st.session_state.scan_results.get(name, [])

        with file_col:
            st.subheader(f"📄 {name}")

        with stats_col:
            crit = sum(1 for i in issues if i["severity"] == "CRITICAL")
            high = sum(1 for i in issues if i["severity"] == "HIGH")
            st.markdown(f"**Issues:** {len(issues)} &nbsp;|&nbsp; 🔴 {crit} &nbsp; 🟠 {high}")

        if issues:
            st.error("🚨 Vulnerabilities Detected")

            for issue in issues:
                icon = colors.get(issue["severity"], "⚪")
                st.write(
                    f"{icon} Line {issue['line']} "
                    f"[{issue['severity']}] **{issue['desc']}**"
                )
                st.code(issue["code"])

            if st.button(f"🔧 Auto-Fix {name}", key=f"fix_{name}_{hash(code)}"):
                st.session_state.fixed_results[name] = auto_fix(code)

        else:
            st.success("✅ No issues found — file looks clean")

        # ── Show fixed code + download ───────────────────────
        if name in st.session_state.fixed_results:
            fixed_code = st.session_state.fixed_results[name]

            st.markdown("#### 🛠️ Fixed Code Preview")
            st.code(fixed_code)

            st.download_button(
                "⬇️ Download Fixed File",
                fixed_code,
                file_name=name.replace(".py", "_fixed.py"),
                key=f"dl_{name}"
            )

# ══════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(
    "<center><b>Ahmed Al-hadi, Ahmed amjad, Hussein osama | AI Security Auditor PRO</b></center>",
    unsafe_allow_html=True
)