#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>
#include <string>
#include <vector>

namespace fs = std::filesystem;

struct Finding {
    std::string rule_id;
    std::string severity;
    std::string title;
    std::string file_path;
    int line_number = 0;
    std::string snippet;
    std::string fix_prompt;
};

const std::set<std::string> skip_dirs = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "target",
    ".idea",
    ".pytest_cache",
    ".mypy_cache",
    "coverage",
    "vendor",
};

std::string json_escape(const std::string& value) {
    std::string output;
    output.reserve(value.size());
    for (char ch : value) {
        switch (ch) {
            case '\\': output += "\\\\"; break;
            case '"': output += "\\\""; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += ch; break;
        }
    }
    return output;
}

std::string json_string(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
}

bool should_skip(const fs::path& path) {
    for (const auto& part : path) {
        if (skip_dirs.count(part.string()) != 0) {
            return true;
        }
    }
    return false;
}

std::vector<Finding> analyze_file(const fs::path& file_path, const fs::path& root_path) {
    std::vector<Finding> findings;
    std::string rel_path;
    try {
        rel_path = fs::relative(file_path, root_path).string();
    } catch (...) {
        rel_path = file_path.filename().string();
    }

    std::ifstream input(file_path);
    if (!input.is_open()) {
        return findings;
    }

    std::string line;
    int line_number = 0;
    const std::regex secret_regex(R"(sk-(?:proj-)?[A-Za-z0-9_-]{32,})");
    const std::regex public_secret_prefix(R"((NEXT_PUBLIC_|VITE_).*(SECRET|SERVICE_ROLE|PRIVATE_KEY))", std::regex::icase);
    const std::regex open_firebase_regex(R"(allow\s+read,\s*write:\s*if\s+true)", std::regex::icase);

    while (std::getline(input, line)) {
        ++line_number;

        if (std::regex_search(line, secret_regex)) {
            findings.push_back({
                "SEC-001",
                "CRITICAL",
                "Hardcoded API Key Detected",
                rel_path,
                line_number,
                line.substr(0, 80),
                "Remove the hardcoded secret from " + rel_path + " at line " + std::to_string(line_number) + ", load it via environment variables, and rotate the key immediately."
            });
        }

        if (std::regex_search(line, public_secret_prefix)) {
            findings.push_back({
                "ENV-001",
                "CRITICAL",
                "Secret Exposed via Client Prefix",
                rel_path,
                line_number,
                line.substr(0, 80),
                "Move sensitive logic out of public client bundle in " + rel_path + " around line " + std::to_string(line_number) + "."
            });
        }

        if (file_path.extension() == ".rules" && std::regex_search(line, open_firebase_regex)) {
            findings.push_back({
                "DB-002",
                "CRITICAL",
                "Open Firebase Security Rules",
                rel_path,
                line_number,
                line.substr(0, 80),
                "Replace 'allow read, write: if true' in " + rel_path + " with strict authentication checks."
            });
        }
    }

    return findings;
}

std::string build_json_report(const std::vector<Finding>& findings) {
    int penalty = 0;
    for (const auto& finding : findings) {
        if (finding.severity == "CRITICAL") {
            penalty += 30;
        } else if (finding.severity == "HIGH") {
            penalty += 15;
        } else {
            penalty += 5;
        }
    }

    std::string json = "{\n";
    json += "  \"total_issues\": " + std::to_string(findings.size()) + ",\n";
    json += "  \"findings\": [\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& finding = findings[i];
        json += "    {\n";
        json += "      \"rule_id\": " + json_string(finding.rule_id) + ",\n";
        json += "      \"severity\": " + json_string(finding.severity) + ",\n";
        json += "      \"title\": " + json_string(finding.title) + ",\n";
        json += "      \"file_path\": " + json_string(finding.file_path) + ",\n";
        json += "      \"line_number\": " + std::to_string(finding.line_number) + ",\n";
        json += "      \"snippet\": " + json_string(finding.snippet) + ",\n";
        json += "      \"fix_prompt\": " + json_string(finding.fix_prompt) + "\n";
        json += "    }" + std::string(i + 1 == findings.size() ? "" : ",") + "\n";
    }
    json += "  ],\n";
    json += "  \"security_score\": " + std::to_string(std::max(0, 100 - penalty)) + "\n";
    json += "}\n";
    return json;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: scanner <repository_path>\n";
        return 1;
    }

    const fs::path root_path = argv[1];
    std::vector<Finding> findings;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(root_path, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            const auto path = entry.path();
            if (path.filename() == "main.cpp" || path.filename() == "main.py" || path.filename() == "scanner_core") {
                continue;
            }
            if (should_skip(path)) {
                continue;
            }
            const auto suffix = path.extension().string();
            if (suffix == ".ts" || suffix == ".tsx" || suffix == ".js" || suffix == ".py" || suffix == ".sql" || suffix == ".rules" || path.filename() == ".env") {
                auto file_findings = analyze_file(path, root_path);
                findings.insert(findings.end(), file_findings.begin(), file_findings.end());
            }
        }
    } catch (const fs::filesystem_error&) {
        std::cerr << "Could not read repository path: " << root_path << "\n";
        return 1;
    }

    std::cout << build_json_report(findings) << std::endl;
    return 0;
}
