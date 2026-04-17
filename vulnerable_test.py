"""
AI Security Auditor PRO — النسخة الكاملة الموحّدة
تصميم وتطوير: Ahmed Al-Hadi Jassim

يشمل:
  ✅ تقليل البلاغات الكاذبة (فحص السياق + استثناءات + تصنيف الخطورة)
  ✅ الإصلاح التلقائي (AutoFixer) مدمج مباشرةً
  ✅ واجهة Streamlit محسّنة مع Diff وتحميل الكود المُصلَح
"""

# ══════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════
import streamlit as st
from transformers import pipeline
import re, ast, difflib, os, zipfile, io, shutil, requests
from fpdf import FPDF
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ══════════════════════════════════════════════════════════════
#  PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AI Security Auditor PRO",
    layout="wide",
    page_icon="🛡️",
)
st.title("🛡️ AI Security Auditor PRO")

# ══════════════════════════════════════════════════════════════
#  AI MODEL
# ══════════════════════════════════════════════════════════════
@st.cache_resource
def load_model():
    return pipeline(
        "text-classification",
        model="mrm8488/codebert-base-finetuned-detect-insecure-code"
    )

ai_engine = load_model()

def analyze_with_ai(code: str) -> dict:
    chunks = [code[i:i+400] for i in range(0, len(code), 400)]
    results = []
    for c in chunks:
        try:
            results.append(ai_engine(c)[0])
        except Exception:
            pass
    for r in results:
        if r["label"] == "LABEL_0":
            return r
    return results[0] if results else {"label": "LABEL_1", "score": 0.5}


# ══════════════════════════════════════════════════════════════
#  SEVERITY CLASSIFIER
# ══════════════════════════════════════════════════════════════
def get_severity(desc: str) -> str:
    critical = [
        "SQL Injection", "Command Injection", "Insecure Deserialization",
        "XSS / SSTI", "Path Traversal", "JWT None Algorithm",
    ]
    high = [
        "Hardcoded Secret", "SSL Disabled", "SSL Verification Disabled",
        "SSRF Risk", "eval() usage",
    ]
    medium = [
        "Weak Hashing", "Debug Mode", "CSRF Risk",
        "Open Redirect", "Insecure Randomness",
    ]
    if any(c in desc for c in critical): return "CRITICAL"
    if any(h in desc for h in high):     return "HIGH"
    if any(m in desc for m in medium):   return "MEDIUM"
    return "LOW"


# ══════════════════════════════════════════════════════════════
#  SMART SCAN  — مع فحص السياق وتقليل False Positives
# ══════════════════════════════════════════════════════════════
def smart_scan(code: str) -> List[dict]:
    """
    يفحص الكود سطراً سطراً.
    كل rule: (pattern, description, [exclusion_patterns])
    الاستثناءات تُفحص على السطر + سطرين قبله + سطرين بعده.
    """
    issues = []
    lines = code.split("\n")

    rules = [
        # ── SQL Injection ──────────────────────────────────────────
        (
            r"(SELECT|INSERT|UPDATE|DELETE).*(\{|\+|format\(|%[sd])",
            "SQL Injection",
            [r"\?", r":%\w+", r"cursor\.execute\(.+,\s*[\(\[]"],
        ),
        (
            r"execute\s*\(.*(\+|\{|format\(|%)",
            "SQL Injection",
            [r"\?", r"params\s*=", r",\s*\("],
        ),
        (
            r"f['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{",
            "SQL Injection (f-string)",
            [],
        ),
        # ── eval / exec ────────────────────────────────────────────
        (
            r"\beval\s*\(",
            "eval() usage",
            [r"#.*eval", r"eval\s*\(\s*['\"][^'\"]*['\"]\s*\)"],
        ),
        (r"\bexec\s*\(", "exec() usage", [r"#.*exec"]),
        # ── Command Injection ──────────────────────────────────────
        (
            r"os\.(system|popen|spawn)\s*\(",
            "Command Injection",
            [],
        ),
        (
            r"subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True",
            "Command Injection (subprocess)",
            [],
        ),
        (r"shell\s*=\s*True", "Shell Injection Risk", [r"shell\s*=\s*False"]),
        # ── Deserialization ────────────────────────────────────────
        (r"pickle\.loads?\s*\(", "Insecure Deserialization", []),
        (
            r"allow_dangerous_deserialization\s*=\s*True",
            "Insecure Deserialization",
            [],
        ),
        (
            r"yaml\.load\s*\([^,)]*\)",
            "Insecure YAML Load",
            [r"yaml\.load\s*\(.*Loader\s*="],
        ),
        # ── Path Traversal ─────────────────────────────────────────
        (
            r"open\s*\(.*request\.|open\s*\(.*input\(",
            "Path Traversal",
            [],
        ),
        (r"\.\.(\/|\\)", "Path Traversal (../)", []),
        (r"send_file\s*\(.*request\.", "Path Traversal (send_file)", []),
        # ── Hardcoded Secrets ──────────────────────────────────────
        (
            r"(password|secret|api_key|token|private_key)\s*=\s*['\"][^'\"]{4,}",
            "Hardcoded Secret",
            [
                r"(password|secret|api_key|token)\s*=\s*['\"](\s*|\<.*\>|your_|example|test|dummy)",
                r"os\.environ",
                r"getenv",
            ],
        ),
        (
            r"SECRET_KEY\s*=\s*['\"][^'\"]{1,10}['\"]",
            "Weak Secret Key",
            [r"os\.environ", r"getenv"],
        ),
        # ── User Input ─────────────────────────────────────────────
        (
            r"request\.(args|form|json|data|values)\s*\[",
            "Unvalidated User Input",
            [],
        ),
        (r"\binput\s*\(", "User Input", []),
        # ── XSS / SSTI ─────────────────────────────────────────────
        (
            r"render_template_string\s*\(.*request\.",
            "XSS / SSTI",
            [],
        ),
        (r"Markup\s*\(.*request\.", "XSS (Unsafe Markup)", []),
        (
            r"innerHTML\s*=.*\+",
            "XSS (innerHTML)",
            [r"DOMPurify\.sanitize", r"escapeHtml"],
        ),
        (r"document\.write\s*\(", "XSS (document.write)", []),
        # ── Crypto ─────────────────────────────────────────────────
        (
            r"hashlib\.(md5|sha1)\s*\(",
            "Weak Hashing (MD5/SHA1)",
            [r"hmac\.", r"checksum", r"#.*non.security"],
        ),
        (r"(DES|RC2|RC4|Blowfish)\s*\(", "Weak Encryption", []),
        # ── Randomness ─────────────────────────────────────────────
        (
            r"random\.(random|randint|choice)\s*\(",
            "Insecure Randomness",
            [r"import\s+secrets", r"secrets\."],
        ),
        # ── SSL ────────────────────────────────────────────────────
        (r"SSL_VERIFY\s*=\s*False|verify\s*=\s*False", "SSL Verification Disabled", []),
        (
            r"requests\.(get|post|put|delete)\s*\(.*verify\s*=\s*False",
            "SSL Verification Disabled",
            [],
        ),
        # ── Debug ──────────────────────────────────────────────────
        (
            r"DEBUG\s*=\s*True",
            "Debug Mode Enabled",
            [r"#.*DEBUG", r"if\s+DEBUG"],
        ),
        (
            r"app\.run\s*\(.*debug\s*=\s*True",
            "Debug Mode Enabled",
            [],
        ),
        # ── Redirects / SSRF / CSRF ────────────────────────────────
        (r"redirect\s*\(.*request\.", "Open Redirect", []),
        (r"requests\.(get|post)\s*\(.*request\.(args|form)", "SSRF Risk", []),
        (r"csrf_exempt", "CSRF Risk", []),
        # ── JWT ────────────────────────────────────────────────────
        (
            r"jwt\.decode\s*\(.*algorithms\s*=\s*\[.*none.*\]",
            "JWT None Algorithm",
            [],
        ),
        # ── Logging ────────────────────────────────────────────────
        (
            r"print\s*\(.*password|print\s*\(.*secret|print\s*\(.*token",
            "Sensitive Data in Logs",
            [],
        ),
        (
            r"logging\.(info|debug|warning)\s*\(.*password",
            "Sensitive Data in Logs",
            [],
        ),
        # ── File / Temp ────────────────────────────────────────────
        (r"chmod\s*\(\s*['\"]?0?777", "Insecure File Permissions", []),
        (r"tempfile\.mktemp\s*\(", "Insecure Temp File", []),
        # ── XML ────────────────────────────────────────────────────
        (r"xml\.etree|minidom|expat", "XXE Risk (XML Parsing)", []),
    ]

    for i, line in enumerate(lines):
        stripped = line.strip()

        # تجاهل التعليقات
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # نافذة السياق (سطرين قبل + سطرين بعد)
        ctx_start = max(0, i - 2)
        ctx_end   = min(len(lines), i + 3)
        context   = "\n".join(lines[ctx_start:ctx_end])

        for pattern, desc, exclusions in rules:
            if not re.search(pattern, line, re.IGNORECASE):
                continue

            # فحص الاستثناءات على السطر والسياق
            excluded = any(
                re.search(ex, context, re.IGNORECASE) for ex in exclusions
            )
            if excluded:
                continue

            issues.append({
                "line":     i + 1,
                "desc":     desc,
                "code":     stripped,
                "severity": get_severity(desc),
            })
            break   # rule واحدة لكل سطر

    return issues


# ══════════════════════════════════════════════════════════════
#  AST ANALYSIS
# ══════════════════════════════════════════════════════════════
def ast_analysis(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except Exception:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = ""
            if hasattr(func, "id"):    name = func.id
            elif hasattr(func, "attr"): name = func.attr
            if name in ["eval", "exec", "compile", "pickle", "__import__"]:
                return True
    return False


# ══════════════════════════════════════════════════════════════
#  DATA FLOW — تتبع حقيقي للمتغيرات
# ══════════════════════════════════════════════════════════════
def data_flow(code: str) -> bool:
    lines = code.split("\n")
    input_vars: set = set()

    input_patterns = [
        r"(\w+)\s*=\s*request\.(args|form|json|values)",
        r"(\w+)\s*=\s*input\s*\(",
    ]
    for line in lines:
        for p in input_patterns:
            m = re.search(p, line)
            if m:
                input_vars.add(m.group(1))

    if not input_vars:
        return False

    query_patterns    = [r"execute\s*\(", r"\.raw\s*\(", r"\.query\s*\("]
    sanitize_patterns = [r"parameterized", r"\.escape\(", r"sanitize", r"bleach\.clean"]

    for line in lines:
        has_query = any(
            re.search(qp, line, re.IGNORECASE) for qp in query_patterns
        )
        if not has_query:
            continue
        has_user_var = any(var in line for var in input_vars)
        is_sanitized = any(
            re.search(sp, line, re.IGNORECASE) for sp in sanitize_patterns
        )
        if has_user_var and not is_sanitized:
            return True

    return False


# ══════════════════════════════════════════════════════════════
#  AUTO-FIXER — هياكل البيانات
# ══════════════════════════════════════════════════════════════
@dataclass
class Fix:
    line: int
    vuln_type: str
    original: str
    fixed: str
    explanation: str
    severity: str  = "HIGH"
    confidence: float = 1.0
    requires_review: bool = False
    _import_line: Optional[str] = field(default=None, repr=False)


@dataclass
class FixResult:
    original_code: str
    fixed_code: str
    fixes: List[Fix]   = field(default_factory=list)
    skipped: List[Tuple[int, str, str]] = field(default_factory=list)

    @property
    def fix_count(self): return len(self.fixes)

    @property
    def diff(self):
        return list(difflib.unified_diff(
            self.original_code.splitlines(keepends=True),
            self.fixed_code.splitlines(keepends=True),
            fromfile="original",
            tofile="fixed",
            lineterm="",
        ))


# ══════════════════════════════════════════════════════════════
#  AUTO-FIXER — المحرك
# ══════════════════════════════════════════════════════════════
class AutoFixer:
    """
    يمرّ على الكود سطراً سطراً ويطبّق الإصلاحات الآمنة تلقائياً.
    الإصلاحات المعمارية تُعلَّم requires_review=True.
    """

    def __init__(self):
        self._rules = [
            (r"hashlib\.(md5|sha1)\s*\(",                          "_fix_weak_hash",       "MEDIUM"),
            (r"(DES|RC2|RC4|Blowfish)\s*\(",                       "_fix_weak_cipher",     "HIGH"),
            (r"random\.(random|randint|choice|shuffle|sample)\s*\(","_fix_insecure_random", "MEDIUM"),
            (r"yaml\.load\s*\(([^,)]+)\)",                         "_fix_yaml_load",       "HIGH"),
            (r"pickle\.loads?\s*\(",                               "_skip_pickle",         "CRITICAL"),
            (r"(xml\.etree|minidom|expat)",                        "_fix_xml",             "HIGH"),
            (r"subprocess\.(call|run|Popen)\s*\((.+?)shell\s*=\s*True", "_fix_shell_true", "HIGH"),
            (r"os\.(system|popen)\s*\(",                           "_fix_os_system",       "HIGH"),
            (r"\beval\s*\(",                                        "_fix_eval",            "HIGH"),
            (r"requests\.(get|post|put|delete|patch)\s*\((.+?)verify\s*=\s*False", "_fix_ssl_verify", "HIGH"),
            (r"DEBUG\s*=\s*True",                                  "_fix_debug",           "MEDIUM"),
            (r"app\.run\s*\((.*)debug\s*=\s*True",                 "_fix_app_debug",       "MEDIUM"),
            (r"(SECRET_KEY|password|api_key|token|secret)\s*=\s*['\"]([^'\"]{4,})['\"]", "_fix_hardcoded_secret", "HIGH"),
            (r"tempfile\.mktemp\s*\(",                             "_fix_mktemp",          "MEDIUM"),
            (r"os\.chmod\s*\(.+?,\s*0?o?777\)",                   "_fix_chmod",           "MEDIUM"),
            (r"(execute|query)\s*\(\s*['\"].*\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\+|\.format\(|f['\"])", "_skip_sql", "CRITICAL"),
        ]

    # ── نقطة الدخول ────────────────────────────────────────────
    def fix(self, code: str) -> FixResult:
        lines = code.split("\n")
        fixes: List[Fix]  = []
        skipped: List[Tuple[int, str, str]] = []
        added_imports: set = set()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, handler_name, severity in self._rules:
                m = re.search(pattern, line, re.IGNORECASE | re.DOTALL)
                if not m:
                    continue
                handler  = getattr(self, handler_name)
                fix_obj  = handler(i + 1, line, m, severity)
                if fix_obj is None:
                    continue
                if fix_obj.requires_review:
                    skipped.append((fix_obj.line, fix_obj.vuln_type, fix_obj.explanation))
                else:
                    fixes.append(fix_obj)
                break

        fixed_lines = code.split("\n")

        # جمع الـ imports المطلوبة
        import_lines = []
        for fix in fixes:
            imp = fix._import_line
            if imp and imp not in added_imports:
                import_lines.append(imp)
                added_imports.add(imp)

        if import_lines:
            insert_at = 0
            for idx, l in enumerate(fixed_lines):
                if l.startswith("import ") or l.startswith("from "):
                    insert_at = idx + 1
            for imp in reversed(import_lines):
                fixed_lines.insert(insert_at, imp)
            offset = len(import_lines)
            for fix in fixes:
                fix.line += offset

        # تطبيق التعديلات (من الأسفل للأعلى)
        for fix in sorted(fixes, key=lambda x: x.line, reverse=True):
            idx = fix.line - 1
            if 0 <= idx < len(fixed_lines):
                indent = len(fixed_lines[idx]) - len(fixed_lines[idx].lstrip())
                fixed_lines[idx] = " " * indent + fix.fixed.lstrip()

        return FixResult(
            original_code=code,
            fixed_code="\n".join(fixed_lines),
            fixes=fixes,
            skipped=skipped,
        )

    # ── معالجات ────────────────────────────────────────────────
    def _fix_weak_hash(self, ln, line, m, sev):
        algo  = m.group(1)
        fixed = re.sub(r"hashlib\." + algo, "hashlib.sha256", line).strip()
        f = Fix(ln, "Weak Hashing", line.strip(), fixed,
                f"استبدال {algo.upper()} بـ SHA-256", sev, 0.95)
        f._import_line = None
        return f

    def _fix_weak_cipher(self, ln, line, m, sev):
        f = Fix(ln, "Weak Cipher", line.strip(), line.strip(),
                "استبدل بـ AES-256-GCM — يحتاج مراجعة يدوية", sev, 0.6, True)
        f._import_line = None
        return f

    def _fix_insecure_random(self, ln, line, m, sev):
        func = m.group(1)
        mapping = {
            "random":  "secrets.SystemRandom().random",
            "randint": "secrets.randbelow",
            "choice":  "secrets.choice",
            "shuffle": "secrets.SystemRandom().shuffle",
            "sample":  "secrets.SystemRandom().sample",
        }
        rep   = mapping.get(func, "secrets.token_bytes")
        fixed = re.sub(r"random\." + func, rep, line).strip()
        f = Fix(ln, "Insecure Randomness", line.strip(), fixed,
                f"استبدال random.{func} بـ {rep} من وحدة secrets", sev, 0.9)
        f._import_line = "import secrets"
        return f

    def _fix_yaml_load(self, ln, line, m, sev):
        fixed = re.sub(r"yaml\.load\s*\(", "yaml.safe_load(", line).strip()
        f = Fix(ln, "Insecure YAML Load", line.strip(), fixed,
                "استبدال yaml.load() بـ yaml.safe_load()", sev, 0.99)
        f._import_line = None
        return f

    def _skip_pickle(self, ln, line, m, sev):
        f = Fix(ln, "Insecure Deserialization (pickle)", line.strip(), line.strip(),
                "pickle غير آمن — استبدله بـ json أو msgpack", sev, 0.0, True)
        f._import_line = None
        return f

    def _fix_xml(self, ln, line, m, sev):
        fixed = re.sub(r"xml\.etree\.ElementTree", "defusedxml.ElementTree", line)
        fixed = re.sub(r"import xml", "import defusedxml", fixed).strip()
        f = Fix(ln, "XXE Risk", line.strip(), fixed,
                "استبدال مكتبة XML بـ defusedxml لحماية من XXE", sev, 0.85)
        f._import_line = "import defusedxml.ElementTree"
        return f

    def _fix_shell_true(self, ln, line, m, sev):
        fixed = re.sub(r"shell\s*=\s*True", "shell=False", line).strip()
        f = Fix(ln, "Shell Injection", line.strip(), fixed,
                "تعيين shell=False — تأكد من تمرير الأمر كـ list", sev, 0.8, True)
        f._import_line = None
        return f

    def _fix_os_system(self, ln, line, m, sev):
        f = Fix(ln, "Command Injection (os.system)", line.strip(), line.strip(),
                "استبدل os.system/popen بـ subprocess.run مع shell=False", sev, 0.5, True)
        f._import_line = None
        return f

    def _fix_eval(self, ln, line, m, sev):
        if re.search(r"eval\s*\(\s*['\"][^'\"]*['\"]\s*\)", line):
            return None
        f = Fix(ln, "eval() Usage", line.strip(), line.strip(),
                "استبدل eval() بـ ast.literal_eval() إن كنت تُقيّم بيانات فقط",
                sev, 0.4, True)
        f._import_line = None
        return f

    def _fix_ssl_verify(self, ln, line, m, sev):
        fixed = re.sub(r"verify\s*=\s*False", "verify=True", line).strip()
        f = Fix(ln, "SSL Verification Disabled", line.strip(), fixed,
                "تفعيل التحقق من شهادة SSL (verify=True)", sev, 0.99)
        f._import_line = None
        return f

    def _fix_debug(self, ln, line, m, sev):
        fixed = re.sub(r"DEBUG\s*=\s*True", "DEBUG = False", line).strip()
        f = Fix(ln, "Debug Mode Enabled", line.strip(), fixed,
                "تعطيل وضع Debug في بيئة الإنتاج", sev, 0.95)
        f._import_line = None
        return f

    def _fix_app_debug(self, ln, line, m, sev):
        fixed = re.sub(r"debug\s*=\s*True", "debug=False", line).strip()
        f = Fix(ln, "Debug Mode in app.run()", line.strip(), fixed,
                "تعطيل debug=True في app.run()", sev, 0.99)
        f._import_line = None
        return f

    def _fix_hardcoded_secret(self, ln, line, m, sev):
        var_name = m.group(1)
        val      = m.group(2) if m.lastindex >= 2 else ""
        if re.search(r"(example|test|dummy|your_|<|>|xxx)", val, re.I):
            return None
        fixed = re.sub(
            r"(SECRET_KEY|password|api_key|token|secret)\s*=\s*['\"][^'\"]+['\"]",
            rf'{var_name} = os.environ.get("{var_name.upper()}", "")',
            line, flags=re.IGNORECASE,
        ).strip()
        f = Fix(ln, "Hardcoded Secret", line.strip(), fixed,
                f"نقل {var_name} إلى متغير بيئة عبر os.environ.get()", sev, 0.9)
        f._import_line = "import os"
        return f

    def _fix_mktemp(self, ln, line, m, sev):
        fixed = re.sub(r"tempfile\.mktemp\s*\(", "tempfile.mkstemp(", line).strip()
        f = Fix(ln, "Insecure Temp File", line.strip(), fixed,
                "استبدال mktemp() بـ mkstemp() الآمن", sev, 0.9)
        f._import_line = None
        return f

    def _fix_chmod(self, ln, line, m, sev):
        fixed = re.sub(r"0?o?777", "0o640", line).strip()
        f = Fix(ln, "Insecure File Permissions", line.strip(), fixed,
                "تغيير الصلاحيات من 777 إلى 640", sev, 0.85)
        f._import_line = None
        return f

    def _skip_sql(self, ln, line, m, sev):
        f = Fix(ln, "SQL Injection", line.strip(), line.strip(),
                "استخدم Parameterized Queries: cursor.execute('SELECT...WHERE id=?', (uid,))",
                sev, 0.0, True)
        f._import_line = None
        return f


def apply_auto_fixes(code: str) -> FixResult:
    return AutoFixer().fix(code)


# ══════════════════════════════════════════════════════════════
#  واجهة الإصلاح التلقائي
# ══════════════════════════════════════════════════════════════
def render_auto_fix_section(name: str, code: str):
    st.markdown("#### 🔧 الإصلاح التلقائي")

    btn_key = f"fix_{name}"
    if not st.button(f"🔧 تطبيق الإصلاحات — {name}", key=btn_key, type="primary"):
        return

    with st.spinner("⚙️ جارٍ تطبيق الإصلاحات..."):
        result = apply_auto_fixes(code)

    # ── ملخص ──────────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    c1.metric("✅ إصلاحات مُطبَّقة",   result.fix_count)
    c2.metric("⚠️ تحتاج مراجعة",      len(result.skipped))
    c3.metric("📉 نسبة التغطية",
              f"{result.fix_count}/{result.fix_count + len(result.skipped)}")

    severity_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    # ── إصلاحات تلقائية ───────────────────────────────────────
    if result.fixes:
        with st.expander("✅ الإصلاحات المُطبَّقة تلقائياً", expanded=True):
            for fix in result.fixes:
                icon = severity_icon.get(fix.severity, "⚪")
                st.markdown(
                    f"{icon} **السطر {fix.line} — {fix.vuln_type}**  \n"
                    f"_{fix.explanation}_  \n"
                    f"`ثقة الإصلاح: {fix.confidence * 100:.0f}%`"
                )
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**قبل:**")
                    st.code(fix.original, language="python")
                with col2:
                    st.markdown("**بعد:**")
                    st.code(fix.fixed, language="python")
                st.markdown("---")

    # ── مراجعة يدوية ──────────────────────────────────────────
    if result.skipped:
        with st.expander("⚠️ ثغرات تحتاج مراجعة يدوية", expanded=False):
            for line_no, vtype, explanation in result.skipped:
                st.warning(f"**السطر {line_no} — {vtype}**\n\n💡 {explanation}")

    # ── Diff كامل ─────────────────────────────────────────────
    if result.diff:
        with st.expander("🔍 عرض الـ Diff الكامل"):
            st.code("\n".join(result.diff), language="diff")

    # ── تحميل ─────────────────────────────────────────────────
    if result.fix_count > 0:
        st.success("✅ الكود المُصلَح جاهز للتحميل")
        st.download_button(
            label=f"⬇️ تحميل {name.replace('.py', '_fixed.py')}",
            data=result.fixed_code.encode("utf-8"),
            file_name=name.replace(".py", "_fixed.py"),
            mime="text/x-python",
            key=f"dl_{name}",
        )
    else:
        st.info("ℹ️ لم يُطبَّق أي إصلاح تلقائي — راجع التوصيات اليدوية أعلاه")


# ══════════════════════════════════════════════════════════════
#  SCORE CALCULATOR  — نظام نقاط مرجّح
# ══════════════════════════════════════════════════════════════
def calculate_score(issues, flow_flag, ast_flag, ai_label, ai_confidence):
    """
    يُعيد (score, reasons, severity_counts)
    """
    score  = 0
    reasons = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    if issues:
        for issue in issues:
            sev = issue.get("severity", "LOW")
            severity_counts[sev] += 1

        score += severity_counts["CRITICAL"] * 4
        score += severity_counts["HIGH"]     * 3
        score += severity_counts["MEDIUM"]   * 2
        score += severity_counts["LOW"]      * 1

        reasons.append(
            f"Pattern scan: {severity_counts['CRITICAL']} Critical / "
            f"{severity_counts['HIGH']} High / "
            f"{severity_counts['MEDIUM']} Medium / "
            f"{severity_counts['LOW']} Low"
        )

    if flow_flag:
        score += 3
        reasons.append("مدخل المستخدم يتدفق إلى استعلام قاعدة البيانات مباشرةً")

    if ai_label == "LABEL_0" and ai_confidence > 0.55:
        score += 3
        reasons.append(f"نموذج AI صنّف الكود خطراً ({ai_confidence * 100:.1f}%)")

    if ast_flag:
        score += 2
        reasons.append("AST كشف دالة خطرة (eval/exec/pickle)")

    return score, reasons, severity_counts


# ══════════════════════════════════════════════════════════════
#  PDF REPORT
# ══════════════════════════════════════════════════════════════
def generate_report(results_summary, confidences):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "AI Security Auditor PRO - Report", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.ln(5)
    if confidences:
        avg = sum(confidences) / len(confidences)
        pdf.cell(0, 10, f"Project Risk Score: {avg * 100:.1f}%", ln=True)
    pdf.ln(5)
    for name, score, reasons in results_summary:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"File: {name}  |  Score: {score}", ln=True)
        pdf.set_font("Arial", size=11)
        for r in reasons:
            safe_r = r.encode("latin-1", errors="replace").decode("latin-1")
            pdf.cell(0, 8, f"  - {safe_r}", ln=True)
        pdf.ln(3)
    path = "/tmp/report.pdf"
    pdf.output(path)
    return path


# ══════════════════════════════════════════════════════════════
#  GITHUB DOWNLOADER
# ══════════════════════════════════════════════════════════════
def download_repo(url: str):
    try:
        zip_url = url.rstrip("/") + "/archive/refs/heads/main.zip"
        r = requests.get(zip_url, timeout=15)
        r.raise_for_status()
        if os.path.exists("repo"):
            shutil.rmtree("repo")
        zipfile.ZipFile(io.BytesIO(r.content)).extractall("repo")
        return "repo"
    except Exception:
        return None


def load_files(folder: str):
    files = []
    for root, _, fs in os.walk(folder):
        for f in fs:
            if f.endswith((".py", ".js", ".php")):
                path = os.path.join(root, f)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        files.append((f, fh.read()))
                except Exception:
                    pass
    return files


# ══════════════════════════════════════════════════════════════
#  SESSION STATE
# ══════════════════════════════════════════════════════════════
if "results_summary" not in st.session_state:
    st.session_state.results_summary = []
if "confidences" not in st.session_state:
    st.session_state.confidences = []

# ══════════════════════════════════════════════════════════════
#  UI — رفع الملفات / GitHub
# ══════════════════════════════════════════════════════════════
st.markdown("### 📁 رفع الملفات")
uploaded_files = st.file_uploader(
    "ارفع ملفات Python / JS / PHP",
    accept_multiple_files=True,
)

st.markdown("### 🔗 فحص مستودع GitHub")
repo_url = st.text_input("أدخل رابط المستودع")

# ══════════════════════════════════════════════════════════════
#  MAIN AUDIT LOOP
# ══════════════════════════════════════════════════════════════
if st.button("🚀 بدء التدقيق", type="primary"):
    files = []

    if uploaded_files:
        files = [(f.name, f.read().decode("utf-8", errors="ignore"))
                 for f in uploaded_files]
    elif repo_url:
        folder = download_repo(repo_url)
        if folder:
            files = load_files(folder)
        else:
            st.error("❌ تعذّر تحميل المستودع — تحقق من الرابط")
            st.stop()
    else:
        st.warning("⚠️ ارفع ملفات أو أدخل رابط مستودع")
        st.stop()

    st.session_state.results_summary = []
    st.session_state.confidences     = []

    for name, code in files:
        st.markdown("---")
        st.subheader(f"📄 {name}")

        # ── التحليل ──────────────────────────────────────────
        issues     = smart_scan(code)
        ast_flag   = ast_analysis(code)
        flow_flag  = data_flow(code)
        ai         = analyze_with_ai(code)
        ai_label   = ai["label"]
        confidence = ai["score"]

        st.session_state.confidences.append(confidence)

        score, reasons, severity_counts = calculate_score(
            issues, flow_flag, ast_flag, ai_label, confidence
        )

        # عتبة الخطر المرجّحة
        danger = score >= 4

        # ── مقاييس ───────────────────────────────────────────
        confidence_label = (
            "عالية جداً ⚠️" if confidence >= 0.9 else
            "عالية"          if confidence >= 0.7 else
            "متوسطة"         if confidence >= 0.5 else
            "منخفضة"
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("الخطورة",   "عالية 🔴" if danger else "منخفضة 🟢")
        c2.metric("ثقة AI",    f"{confidence * 100:.1f}% — {confidence_label}")
        c3.metric("النقاط",    score)
        c4.metric("ثغرات وُجدت", len(issues))

        # ── نتائج التفصيل ─────────────────────────────────────
        if danger:
            st.error("🚨 الملف يحتوي على ثغرات")
            for r in reasons:
                st.write("•", r)

            if issues:
                sev_colors = {
                    "CRITICAL": "🔴", "HIGH": "🟠",
                    "MEDIUM":   "🟡", "LOW":  "🟢",
                }
                for issue in issues:
                    icon = sev_colors.get(issue["severity"], "⚪")
                    st.error(
                        f"{icon} السطر {issue['line']} [{issue['severity']}]: "
                        f"{issue['desc']}"
                    )
                    st.code(issue["code"], language="python")
            else:
                st.warning("⚠️ AI اكتشف خطراً لكن لم يُحدَّد سطر بعينه")
                keywords = ["SELECT","input(","request.","eval(","exec("]
                suspicious = [
                    l for l in code.split("\n")
                    if any(k in l for k in keywords)
                ]
                for s in suspicious[:5]:
                    st.warning(f"⚠️ مشبوه: {s.strip()}")

            st.info("💡 نصيحة: استخدم Prepared Statements، تحقق من المدخلات، تجنّب eval/exec")
            st.session_state.results_summary.append((name, score, reasons))

            # ✨ قسم الإصلاح التلقائي
            render_auto_fix_section(name, code)

        else:
            st.success("✅ الملف آمن")

    # ── مجموع المشروع ─────────────────────────────────────────
    if st.session_state.confidences:
        avg = sum(st.session_state.confidences) / len(st.session_state.confidences)
        st.markdown("---")
        st.metric("🔥 مستوى خطورة المشروع الكلي", f"{avg * 100:.1f}%")

    if st.session_state.results_summary:
        worst = max(st.session_state.results_summary, key=lambda x: x[1])
        st.error(f"🔥 الملف الأكثر خطورة: **{worst[0]}** (نقاط: {worst[1]})")

# ══════════════════════════════════════════════════════════════
#  توليد التقرير PDF
# ══════════════════════════════════════════════════════════════
if st.session_state.results_summary:
    st.markdown("---")
    if st.button("📄 توليد تقرير PDF"):
        path = generate_report(
            st.session_state.results_summary,
            st.session_state.confidences,
        )
        with open(path, "rb") as f:
            st.download_button(
                "⬇️ تحميل التقرير",
                f,
                file_name="security_report.pdf",
            )

# ══════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(
    "<center><b>تصميم وتطوير: Ahmed Al-Hadi Jassim | AI Security Auditor PRO</b></center>",
    unsafe_allow_html=True,
)