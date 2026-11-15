import math
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: str
    title: str
    pattern: re.Pattern
    fix: str
    extensions: frozenset[str] = frozenset()


RULES = (
    Rule(
        "SEC-001", "Secrets", "CRITICAL", "AI provider API key",
        re.compile(r"\bsk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{32,}\b"),
        "Remove the provider key, load it from a server-side environment variable, and rotate it.",
    ),
    Rule(
        "SEC-002", "Secrets", "CRITICAL", "Stripe live secret key",
        re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
        "Revoke this live key, remove it from source control, and use server-side secret storage.",
    ),
    Rule(
        "SEC-003", "Secrets", "CRITICAL", "AWS access key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Disable and rotate this AWS access key. Prefer short-lived IAM role credentials.",
    ),
    Rule(
        "SEC-004", "Secrets", "HIGH", "Hardcoded JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "Remove the hardcoded JWT and rotate it. Load service credentials only in trusted server code.",
    ),
    Rule(
        "SEC-005", "Secrets", "CRITICAL", "GitHub personal access token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b"),
        "Revoke this GitHub token, remove it from history, and replace it with a least-privilege secret.",
    ),
    Rule(
        "SEC-006", "Secrets", "CRITICAL", "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Remove the private key from the repository and rotate or replace the exposed key pair.",
    ),
    Rule(
        "SEC-008", "Secrets", "CRITICAL", "Slack access token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
        "Revoke this Slack token and replace it with a least-privilege token stored outside source control.",
    ),
    Rule(
        "SEC-009", "Secrets", "CRITICAL", "npm access token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "Revoke this npm token and replace it with a narrowly scoped token stored outside source control.",
    ),
    Rule(
        "SEC-010", "Secrets", "CRITICAL", "Shopify private app token",
        re.compile(r"\bshpat_[A-Fa-f0-9]{32}\b"),
        "Rotate this Shopify token and keep it in a server-side secret store.",
    ),
    Rule(
        "ENV-001", "Exposure", "CRITICAL", "Secret exposed through a public client variable",
        re.compile(
            r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|DATABASE_URL)\b",
            re.IGNORECASE,
        ),
        "Remove the public client prefix and move secret-dependent operations to a server-side endpoint.",
    ),
    Rule(
        "DB-001", "Database", "CRITICAL", "Open Firebase security rule",
        re.compile(r"\ballow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true\b", re.IGNORECASE),
        "Replace the unconditional rule with authenticated, per-user authorization checks.",
        frozenset({".rules"}),
    ),
    Rule(
        "DB-002", "Database", "HIGH", "SQL string interpolation",
        re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,240}(?:\$\{|f['\"]|['\"]\s*\+\s*[A-Za-z_])", re.IGNORECASE),
        "Use parameterized queries or prepared statements instead of interpolating data into SQL.",
        frozenset({".sql", ".py", ".js", ".jsx", ".ts", ".tsx"}),
    ),
    Rule(
        "DB-003", "Database", "HIGH", "Database privileges granted to PUBLIC",
        re.compile(r"\bGRANT\s+ALL\b.{0,160}\bTO\s+PUBLIC\b", re.IGNORECASE),
        "Grant only the minimum required privileges to an explicit application role.",
        frozenset({".sql"}),
    ),
    Rule(
        "INJ-001", "Injection", "HIGH", "Unsafe HTML injection",
        re.compile(r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=)", re.IGNORECASE),
        "Sanitize untrusted HTML with a vetted sanitizer or render it as text.",
    ),
    Rule(
        "INJ-002", "Injection", "HIGH", "Dynamic code execution",
        re.compile(r"\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\("),
        "Remove dynamic code execution and replace it with explicit, validated operations.",
    ),
    Rule(
        "INJ-003", "Injection", "HIGH", "Shell command execution with shell mode",
        re.compile(r"\b(?:subprocess\.(?:run|Popen|call|check_output)|exec)\s*\([^)]{0,240}\bshell\s*=\s*True", re.IGNORECASE),
        "Pass an argument array with shell=False and validate any user-controlled arguments.",
        frozenset({".py"}),
    ),
    Rule(
        "INJ-004", "Deserialization", "HIGH", "Unsafe pickle deserialization",
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "Do not deserialize untrusted pickle data. Use a constrained data format such as JSON.",
        frozenset({".py"}),
    ),
    Rule(
        "API-002", "API Security", "MEDIUM", "Wildcard CORS origin",
        re.compile(r"(?:Access-Control-Allow-Origin\s*[:=]\s*['\"]?\*|allow_origins\s*=\s*\[[^\]]*['\"]\*['\"])", re.IGNORECASE),
        "Restrict cross-origin access to the exact trusted origins required by the application.",
    ),
    Rule(
        "CRYPTO-001", "Cryptography", "HIGH", "TLS certificate verification disabled",
        re.compile(r"(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)", re.IGNORECASE),
        "Enable TLS certificate verification to prevent man-in-the-middle attacks.",
    ),
    Rule(
        "CRYPTO-002", "Cryptography", "MEDIUM", "Weak cryptographic hash",
        re.compile(r"\b(?:md5|sha1)\s*\(", re.IGNORECASE),
        "Use a modern cryptographic hash for integrity, or a password-hashing function for passwords.",
    ),
    Rule(
        "CRYPTO-003", "Cryptography", "MEDIUM", "Non-cryptographic randomness used for a credential",
        re.compile(r"\brandom\.(?:choice|randint|randrange)\s*\([^)]{0,120}(?:token|secret|password|key)", re.IGNORECASE),
        "Use a cryptographically secure random source such as Python's secrets module.",
        frozenset({".py"}),
    ),
    Rule(
        "CONFIG-001", "Configuration", "MEDIUM", "Debug mode enabled",
        re.compile(r"\b(?:DEBUG|debug)\s*[:=]\s*True\b"),
        "Disable debug mode in deployments and configure it through an environment-specific setting.",
        frozenset({".py"}),
    ),
)

ALLOWED_EXTENSIONS: frozenset[str] = frozenset({
    ".c", ".cjs", ".cpp", ".cs", ".css", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".json", ".kt", ".mjs", ".php", ".py", ".rb",
    ".rules", ".rs", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx",
    ".vue", ".yaml", ".yml",
})
SKIP_DIRS = frozenset({
    ".git", ".idea", ".mypy_cache", ".next", ".pytest_cache", ".venv",
    ".vscode", "__pycache__", "build", "coverage", "dist", "node_modules",
    "target", "vendor", "venv",
})
ENTROPY_ASSIGNMENT = re.compile(
    r"\b(?:api[_-]?key|secret|token|password|passwd|auth[_-]?key|private[_-]?key)"
    r"\s*[:=]\s*(['\"])([A-Za-z0-9_+/=-]{24,})\1",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = ("example", "your_", "changeme", "placeholder", "dummy", "sample")
SQL_CREATE_TABLE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_.\"]+)",
    re.IGNORECASE,
)
NEXT_MUTATION = re.compile(r"\bexport\s+async\s+function\s+(POST|PUT|PATCH|DELETE)\b")
NEXT_AUTH = re.compile(
    r"\b(?:getUser|getSession|currentUser|verifyIdToken|requireAuth|auth\s*\()"
    r"|headers\s*\(\s*\)\s*\.get\s*\(\s*['\"]authorization",
    re.IGNORECASE,
)
FASTAPI_MUTATION = re.compile(r"@\s*(?:app|router)\.(?:post|put|patch|delete)\s*\(", re.IGNORECASE)
FASTAPI_AUTH = re.compile(r"\b(?:Depends\s*\(|current_user|require_user|verify_token|auth_required)\b", re.IGNORECASE)


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0
    frequencies = {}
    for character in value:
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def redact_snippet(line: str, secret: str | None = None) -> str:
    snippet = line.strip()
    if secret:
        snippet = snippet.replace(secret, secret[:4] + "…" + secret[-3:])
    if len(snippet) > 110:
        snippet = snippet[:107] + "..."
    return snippet


def _finding(rule_id: str, category: str, severity: str, title: str, path: str, line: int, snippet: str, fix: str) -> dict:
    return {
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
        "title": title,
        "file_path": path,
        "line_number": line,
        "snippet": snippet,
        "fix_prompt": f"{fix} File: {path}, line {line}.",
    }


def analyze_file(path: Path, root: Path) -> tuple[list[dict], int]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise OSError(f"Could not read source file {path}: {exc}") from exc

    relative_path = path.relative_to(root).as_posix()
    lines = content.splitlines()
    findings = []
    suffix = path.suffix.lower()
    basename = path.name.lower()

    if basename.startswith(".env") and basename not in {
        ".env.example", ".env.sample", ".env.template", ".env.example.local",
    }:
        findings.append(_finding(
            "ENV-002", "Exposure", "HIGH", "Environment file present in project tree",
            relative_path, 1, basename,
            "Confirm this environment file is excluded from version control, remove any committed copy, and rotate exposed values.",
        ))

    for line_number, line in enumerate(lines, start=1):
        matched_secret = False
        for rule in RULES:
            if rule.extensions and suffix not in rule.extensions:
                continue
            match = rule.pattern.search(line)
            if not match:
                continue
            matched_secret = matched_secret or rule.rule_id.startswith("SEC-")
            findings.append(_finding(
                rule.rule_id, rule.category, rule.severity, rule.title,
                relative_path, line_number, redact_snippet(line, match.group(0)), rule.fix,
            ))

        if not matched_secret:
            entropy_match = ENTROPY_ASSIGNMENT.search(line)
            if entropy_match:
                candidate = entropy_match.group(2)
                if (
                    calculate_entropy(candidate) >= 4.2
                    and not any(value in candidate.lower() for value in PLACEHOLDER_VALUES)
                ):
                    findings.append(_finding(
                        "SEC-007", "Secrets", "HIGH", "High-entropy hardcoded credential",
                        relative_path, line_number, redact_snippet(line, candidate),
                        "Move this credential to a server-side secret store and rotate it.",
                    ))

    if suffix == ".sql":
        for match in SQL_CREATE_TABLE.finditer(content):
            table = match.group(1).replace('"', "")
            table_name = table.rsplit(".", 1)[-1]
            rls_pattern = re.compile(
                rf"\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:[\w\"]+\.)?\"?{re.escape(table_name)}\"?"
                r"\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY\b",
                re.IGNORECASE,
            )
            if not rls_pattern.search(content):
                line_number = content.count("\n", 0, match.start()) + 1
                findings.append(_finding(
                    "DB-004", "Database", "HIGH", f"Table {table_name} has no visible RLS enablement",
                    relative_path, line_number, f"CREATE TABLE {table}",
                    "Enable row-level security and define explicit policies for this table.",
                ))

    if suffix in {".ts", ".tsx", ".js", ".jsx"} and "/app/api/" in f"/{relative_path}":
        mutation = NEXT_MUTATION.search(content)
        if mutation and not NEXT_AUTH.search(content):
            line_number = content.count("\n", 0, mutation.start()) + 1
            findings.append(_finding(
                "API-001", "API Security", "HIGH", "Next.js mutation route has no visible authentication check",
                relative_path, line_number, mutation.group(0),
                "Add server-side authentication and authorization checks before performing this mutation.",
            ))

    if suffix == ".py" and FASTAPI_MUTATION.search(content) and not FASTAPI_AUTH.search(content):
        match = FASTAPI_MUTATION.search(content)
        line_number = content.count("\n", 0, match.start()) + 1
        findings.append(_finding(
            "API-003", "API Security", "MEDIUM", "FastAPI mutation route has no visible auth dependency",
            relative_path, line_number, match.group(0),
            "Require an authentication dependency and authorize the requested resource in this route.",
        ))

    if re.search(r"\b(?:set_cookie|Set-Cookie)\b", content, re.IGNORECASE):
        if not re.search(r"\bhttponly\s*=\s*true\b", content, re.IGNORECASE):
            match = re.search(r"\b(?:set_cookie|Set-Cookie)\b", content, re.IGNORECASE)
            line_number = content.count("\n", 0, match.start()) + 1
            findings.append(_finding(
                "AUTH-001", "Session Security", "MEDIUM", "Cookie may be missing HttpOnly",
                relative_path, line_number, lines[line_number - 1] if lines else "",
                "Set HttpOnly, Secure, and an appropriate SameSite policy on session cookies.",
            ))

    return findings, len(lines)
