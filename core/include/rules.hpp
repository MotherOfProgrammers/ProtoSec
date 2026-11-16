#pragma once

#include <array>
#include <cmath>
#include <regex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct Rule {
    std::string id;
    std::string category;
    std::string severity;
    std::string title;
    std::string pattern_source;
    std::regex pattern;
    std::regex::flag_type pattern_flags;
    std::vector<std::string> extensions;
    std::string fix;
};

inline constexpr unsigned int kRuleEngineVersion = 2;

inline Rule makeRule(
    std::string id,
    std::string category,
    std::string severity,
    std::string title,
    std::string pattern_source,
    std::vector<std::string> extensions,
    std::string fix,
    std::regex::flag_type pattern_flags = std::regex::ECMAScript
) {
    const auto pattern = std::regex(pattern_source, pattern_flags);
    return {
        std::move(id),
        std::move(category),
        std::move(severity),
        std::move(title),
        std::move(pattern_source),
        pattern,
        pattern_flags,
        std::move(extensions),
        std::move(fix),
    };
}

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
        makeRule("SEC-001", "Secrets", "CRITICAL", "AI provider API key",
                 R"(\bsk-(?:proj-|ant-api03-)?[A-Za-z0-9_-]{32,}\b)", {},
                 "Remove the provider key, load it from a server-side environment variable, and rotate it."),
        makeRule("SEC-002", "Secrets", "CRITICAL", "Stripe live secret key",
                 R"(\bsk_live_[A-Za-z0-9]{24,}\b)", {},
                 "Revoke this live key, remove it from source control, and use server-side secret storage."),
        makeRule("SEC-003", "Secrets", "CRITICAL", "AWS access key ID",
                 R"(\bAKIA[0-9A-Z]{16}\b)", {},
                 "Disable and rotate this AWS access key. Prefer short-lived IAM role credentials."),
        makeRule("SEC-004", "Secrets", "HIGH", "Hardcoded JWT",
                 R"(\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b)", {},
                 "Remove the hardcoded JWT and rotate it. Load service credentials only in trusted server code."),
        makeRule("SEC-005", "Secrets", "CRITICAL", "GitHub personal access token",
                 R"(\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b)", {},
                 "Revoke this GitHub token, remove it from history, and replace it with a least-privilege secret."),
        makeRule("SEC-006", "Secrets", "CRITICAL", "Private key material",
                 R"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", {},
                 "Remove the private key from the repository and rotate or replace the exposed key pair."),
        makeRule("SEC-008", "Secrets", "CRITICAL", "Slack access token",
                 R"(\bxox[baprs]-[A-Za-z0-9-]{10,48}\b)", {},
                 "Revoke this Slack token and replace it with a least-privilege token stored outside source control."),
        makeRule("SEC-009", "Secrets", "CRITICAL", "npm access token",
                 R"(\bnpm_[A-Za-z0-9]{36}\b)", {},
                 "Revoke this npm token and replace it with a narrowly scoped token stored outside source control."),
        makeRule("SEC-010", "Secrets", "CRITICAL", "Shopify private app token",
                 R"(\bshpat_[A-Fa-f0-9]{32}\b)", {},
                 "Rotate this Shopify token and keep it in a server-side secret store."),
        makeRule("ENV-001", "Exposure", "CRITICAL", "Secret exposed through a public client variable",
                 R"(\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|DATABASE_URL)\b)", {},
                 "Remove the public client prefix and move secret-dependent operations to a server-side endpoint.",
                 std::regex::icase),
        makeRule("DB-001", "Database", "CRITICAL", "Open Firebase security rule",
                 R"(\ballow\s+(?:read|write|read\s*,\s*write)\s*:\s*if\s+true\b)", {".rules"},
                 "Replace the unconditional rule with authenticated, per-user authorization checks.",
                 std::regex::icase),
        makeRule("DB-002", "Database", "HIGH", "SQL string interpolation",
                 R"(\b(?:SELECT|INSERT|UPDATE|DELETE)\b.{0,240}(?:\$\{|f['"]|['"]\s*\+\s*[A-Za-z_]))",
                 {".sql", ".py", ".js", ".jsx", ".ts", ".tsx"},
                 "Use parameterized queries or prepared statements instead of interpolating data into SQL.",
                 std::regex::icase),
        makeRule("DB-003", "Database", "HIGH", "Database privileges granted to PUBLIC",
                 R"(\bGRANT\s+ALL\b.{0,160}\bTO\s+PUBLIC\b)", {".sql"},
                 "Grant only the minimum required privileges to an explicit application role.",
                 std::regex::icase),
        makeRule("INJ-001", "Injection", "HIGH", "Unsafe HTML injection",
                 R"((?:dangerouslySetInnerHTML|\.innerHTML\s*=))", {},
                 "Sanitize untrusted HTML with a vetted sanitizer or render it as text.",
                 std::regex::icase),
        makeRule("INJ-002", "Injection", "HIGH", "Dynamic code execution",
                 R"(\b(?:eval|exec)\s*\(|\bnew\s+Function\s*\()", {},
                 "Remove dynamic code execution and replace it with explicit, validated operations."),
        makeRule("INJ-003", "Injection", "HIGH", "Shell command execution with shell mode",
                 R"(\b(?:subprocess\.(?:run|Popen|call|check_output)|exec)\s*\([^)]{0,240}\bshell\s*=\s*True)",
                 {".py"},
                 "Pass an argument array with shell=False and validate any user-controlled arguments.",
                 std::regex::icase),
        makeRule("INJ-004", "Deserialization", "HIGH", "Unsafe pickle deserialization",
                 R"(\bpickle\.(?:load|loads)\s*\()", {".py"},
                 "Do not deserialize untrusted pickle data. Use a constrained data format such as JSON."),
        makeRule("API-002", "API Security", "MEDIUM", "Wildcard CORS origin",
                 R"((?:Access-Control-Allow-Origin\s*[:=]\s*['"]?\*|allow_origins\s*=\s*\[[^\]]*['"]\*['"]))", {},
                 "Restrict cross-origin access to the exact trusted origins required by the application.",
                 std::regex::icase),
        makeRule("CRYPTO-001", "Cryptography", "HIGH", "TLS certificate verification disabled",
                 R"((?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0))", {},
                 "Enable TLS certificate verification to prevent man-in-the-middle attacks.",
                 std::regex::icase),
        makeRule("CRYPTO-002", "Cryptography", "MEDIUM", "Weak cryptographic hash",
                 R"(\b(?:md5|sha1)\s*\()", {},
                 "Use a modern cryptographic hash for integrity, or a password-hashing function for passwords.",
                 std::regex::icase),
        makeRule("CRYPTO-003", "Cryptography", "MEDIUM", "Non-cryptographic randomness used for a credential",
                 R"(\brandom\.(?:choice|randint|randrange)\s*\([^)]{0,120}(?:token|secret|password|key))",
                 {".py"},
                 "Use a cryptographically secure random source such as Python's secrets module.",
                 std::regex::icase),
        makeRule("CONFIG-001", "Configuration", "MEDIUM", "Debug mode enabled",
                 R"(\b(?:DEBUG|debug)\s*[:=]\s*True\b)", {".py"},
                 "Disable debug mode in deployments and configure it through an environment-specific setting."),
    };
    return rules;
}
