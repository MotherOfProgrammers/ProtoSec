#pragma once

#include <array>
#include <cmath>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

struct Rule {
    std::string id;
    std::string category;
    std::string severity;
    std::string title;
    std::regex pattern;
    std::vector<std::string> extensions;
    std::string fix;
};

inline double calculateShannonEntropy(std::string_view value) noexcept {
    if (value.empty()) {
        return 0.0;
    }
    std::array<std::size_t, 256> frequencies{};
    for (const unsigned char character : value) {
        ++frequencies[character];
    }

    const double length = static_cast<double>(value.size());
    double entropy = 0.0;
    for (const auto count : frequencies) {
        if (count != 0) {
            const double probability = static_cast<double>(count) / length;
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}

inline const std::vector<Rule>& securityRules() {
    static const std::vector<Rule> rules = {
        {"SEC-001", "Secrets", "CRITICAL", "AI provider API key",
         std::regex(R"(\bsk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{32,}\b)"), {},
         "Remove the provider key, load it from a server-side environment variable, and rotate it."},
        {"SEC-002", "Secrets", "CRITICAL", "Stripe live secret key",
         std::regex(R"(\bsk_live_[A-Za-z0-9]{24,}\b)"), {},
         "Revoke this live key, remove it from source control, and use server-side secret storage."},
        {"SEC-003", "Secrets", "CRITICAL", "AWS access key ID",
         std::regex(R"(\bAKIA[0-9A-Z]{16}\b)"), {},
         "Disable and rotate this AWS access key. Prefer short-lived IAM role credentials."},
        {"SEC-004", "Secrets", "HIGH", "Hardcoded JWT",
         std::regex(R"(\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)"), {},
         "Remove the hardcoded JWT and rotate it. Load service credentials only in trusted server code."},
        {"SEC-005", "Secrets", "CRITICAL", "GitHub personal access token",
         std::regex(R"(\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b)"), {},
         "Revoke this GitHub token, remove it from history, and replace it with a least-privilege secret."},
        {"SEC-006", "Secrets", "CRITICAL", "Private key material",
         std::regex(R"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"), {},
         "Remove the private key from the repository and rotate or replace the exposed key pair."},
        {"SEC-008", "Secrets", "CRITICAL", "Slack access token",
         std::regex(R"(\bxox[baprs]-[A-Za-z0-9-]{10,48}\b)"), {},
         "Revoke this Slack token and replace it with a least-privilege token stored outside source control."},
        {"SEC-009", "Secrets", "CRITICAL", "npm access token",
         std::regex(R"(\bnpm_[A-Za-z0-9]{36}\b)"), {},
         "Revoke this npm token and replace it with a narrowly scoped token stored outside source control."},
        {"SEC-010", "Secrets", "CRITICAL", "Shopify private app token",
         std::regex(R"(\bshpat_[A-Fa-f0-9]{32}\b)"), {},
         "Rotate this Shopify token and keep it in a server-side secret store."},
        {"ENV-001", "Exposure", "CRITICAL", "Secret exposed through a public client variable",
         std::regex(R"(\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|DATABASE_URL)\b)", std::regex::icase), {},
         "Remove the public client prefix and move secret-dependent operations to a server-side endpoint."},
        {"DB-001", "Database", "CRITICAL", "Open Firebase security rule",
         std::regex(R"(\ballow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true\b)", std::regex::icase), {".rules"},
         "Replace the unconditional rule with authenticated, per-user authorization checks."},
        {"DB-002", "Database", "HIGH", "SQL string interpolation",
         std::regex(R"(\b(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,240}(?:\$\{|f['"]|['"]\s*\+\s*[A-Za-z_]))", std::regex::icase), {".sql", ".py", ".js", ".jsx", ".ts", ".tsx"},
         "Use parameterized queries or prepared statements instead of interpolating data into SQL."},
        {"DB-003", "Database", "HIGH", "Database privileges granted to PUBLIC",
         std::regex(R"(\bGRANT\s+ALL\b.{0,160}\bTO\s+PUBLIC\b)", std::regex::icase), {".sql"},
         "Grant only the minimum required privileges to an explicit application role."},
        {"INJ-001", "Injection", "HIGH", "Unsafe HTML injection",
         std::regex(R"((?:dangerouslySetInnerHTML|\.innerHTML\s*=))", std::regex::icase), {},
         "Sanitize untrusted HTML with a vetted sanitizer or render it as text."},
        {"INJ-002", "Injection", "HIGH", "Dynamic code execution",
         std::regex(R"(\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\()"), {},
         "Remove dynamic code execution and replace it with explicit, validated operations."},
        {"INJ-003", "Injection", "HIGH", "Shell command execution with shell mode",
         std::regex(R"(\b(?:subprocess\.(?:run|Popen|call|check_output)|exec)\s*\([^)]{0,240}\bshell\s*=\s*True)", std::regex::icase), {".py"},
         "Pass an argument array with shell=False and validate any user-controlled arguments."},
        {"INJ-004", "Deserialization", "HIGH", "Unsafe pickle deserialization",
         std::regex(R"(\bpickle\.(?:load|loads)\s*\()"), {".py"},
         "Do not deserialize untrusted pickle data. Use a constrained data format such as JSON."},
        {"API-002", "API Security", "MEDIUM", "Wildcard CORS origin",
         std::regex(R"((?:Access-Control-Allow-Origin\s*[:=]\s*['"]?\*|allow_origins\s*=\s*\[[^\]]*['"]\*['"]))", std::regex::icase), {},
         "Restrict cross-origin access to the exact trusted origins required by the application."},
        {"CRYPTO-001", "Cryptography", "HIGH", "TLS certificate verification disabled",
         std::regex(R"((?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0))", std::regex::icase), {},
         "Enable TLS certificate verification to prevent man-in-the-middle attacks."},
        {"CRYPTO-002", "Cryptography", "MEDIUM", "Weak cryptographic hash",
         std::regex(R"(\b(?:md5|sha1)\s*\()", std::regex::icase), {},
         "Use a modern cryptographic hash for integrity, or a password-hashing function for passwords."},
        {"CRYPTO-003", "Cryptography", "MEDIUM", "Non-cryptographic randomness used for a credential",
         std::regex(R"(\brandom\.(?:choice|randint|randrange)\s*\([^)]{0,120}(?:token|secret|password|key))", std::regex::icase), {".py"},
         "Use a cryptographically secure random source such as Python's secrets module."},
        {"CONFIG-001", "Configuration", "MEDIUM", "Debug mode enabled",
         std::regex(R"(\b(?:DEBUG|debug)\s*[:=]\s*True\b)"), {".py"},
         "Disable debug mode in deployments and configure it through an environment-specific setting."},
    };
    return rules;
}
