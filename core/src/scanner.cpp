#include "../include/scanner.hpp"

#include "../include/mmap_file.hpp"
#include "../include/rules.hpp"
#include "../include/tree_sitter_comments.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <exception>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <unordered_set>
#include <utility>

namespace fs = std::filesystem;

namespace {

const std::unordered_set<std::string> kSkippedDirectories = {
    ".git", ".idea", ".mypy_cache", ".next", ".pytest_cache", ".venv",
    ".vscode", "__pycache__", "__tests__", "build", "coverage", "dist",
    "node_modules", "spec", "specs", "target", "test", "tests", "vendor", "venv",
};

const std::unordered_set<std::string> kAllowedExtensions = {
    ".c", ".cjs", ".cpp", ".cs", ".css", ".cts", ".go", ".h", ".hpp", ".html",
    ".java", ".js", ".jsx", ".json", ".kt", ".mjs", ".mts", ".php", ".py", ".rb",
    ".rules", ".rs", ".sh", ".sql", ".swift", ".toml", ".ts", ".tsx", ".vue",
    ".yaml", ".yml",
};

const std::unordered_set<std::string> kEnvTemplates = {
    ".env.example", ".env.example.local", ".env.sample", ".env.template",
};

const std::regex kEntropyAssignment(
    R"(\b(?:api[_-]?key|secret|token|password|passwd|auth[_-]?key|private[_-]?key)\s*[:=]\s*(['"])([A-Za-z0-9_+/=-]{24,})\1)",
    std::regex::icase
);
const std::regex kCreateTable(
    R"(\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z0-9_."]+))",
    std::regex::icase
);
const std::regex kAlterTableRls(
    R"(\bALTER\s+TABLE\b[^;]*(?:;|$))",
    std::regex::icase
);
const std::regex kNextMutation(
    R"(\bexport\s+async\s+function\s+(POST|PUT|PATCH|DELETE)\b)"
);
const std::regex kNextAuth(
    R"(\b(?:getUser|getSession|currentUser|verifyIdToken|requireAuth|auth\s*\()|headers\s*\(\s*\)\s*\.get\s*\(\s*['"]authorization)",
    std::regex::icase
);
const std::regex kFastApiMutation(
    R"(@\s*(?:app|router)\.(?:post|put|patch|delete)\s*\()",
    std::regex::icase
);
const std::regex kFastApiAuth(
    R"(\b(?:Depends\s*\(|current_user|require_user|verify_token|auth_required)\b)",
    std::regex::icase
);
const std::regex kSetCookie(R"(\b(?:set_cookie|Set-Cookie)\b)", std::regex::icase);
const std::regex kHttpOnly(R"(\bhttponly\s*=\s*true\b)", std::regex::icase);

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool hasExtension(const fs::path& path, const std::unordered_set<std::string>& extensions) {
    return extensions.contains(lower(path.extension().string()));
}

bool hasRuleExtension(const std::string& extension, const Rule& rule) {
    return rule.extensions.empty() ||
        std::find(rule.extensions.begin(), rule.extensions.end(), extension) != rule.extensions.end();
}

std::string toGenericRelativePath(const fs::path& path, const fs::path& root) {
    std::error_code error;
    auto relative = fs::relative(path, root, error);
    return (error ? path.filename() : relative).generic_string();
}

std::string formatFix(const std::string& fix, const std::string& path, std::size_t line) {
    return fix + " File: " + path + ", line " + std::to_string(line) + ".";
}

std::string makeSnippet(
    std::string_view line,
    std::size_t match_start = std::string_view::npos,
    std::size_t match_length = 0
) {
    constexpr std::size_t kMaxSnippetLength = 110;
    const auto visible_length = std::min(line.size(), kMaxSnippetLength);
    std::string snippet(line.substr(0, visible_length));

    if (match_start < visible_length && match_length > 10) {
        const auto visible_match_length = std::min(match_length, visible_length - match_start);
        const auto masked = visible_match_length > 7
            ? std::string(line.substr(match_start, 4)) + "..." +
                std::string(line.substr(match_start + visible_match_length - 3, 3))
            : "***";
        snippet.replace(match_start, visible_match_length, masked);
    }

    if (line.size() > kMaxSnippetLength) {
        snippet += "...";
    }
    return snippet;
}

std::size_t lineAt(std::string_view text, std::size_t offset) {
    return static_cast<std::size_t>(std::count(text.begin(), text.begin() + offset, '\n')) + 1;
}

void addFinding(
    std::vector<Finding>& findings,
    const std::string& id,
    const std::string& category,
    const std::string& severity,
    const std::string& title,
    const std::string& path,
    std::size_t line,
    std::string snippet,
    const std::string& fix
) {
    findings.push_back({
        id,
        category,
        severity,
        title,
        path,
        line,
        std::move(snippet),
        formatFix(fix, path, line),
    });
}

std::string serializeString(const std::string& value) {
    std::ostringstream result;
    result << '"';
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"': result << "\\\""; break;
            case '\\': result << "\\\\"; break;
            case '\b': result << "\\b"; break;
            case '\f': result << "\\f"; break;
            case '\n': result << "\\n"; break;
            case '\r': result << "\\r"; break;
            case '\t': result << "\\t"; break;
            default:
                if (ch < 0x20) {
                    result << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<int>(ch) << std::dec;
                } else {
                    result << static_cast<char>(ch);
                }
        }
    }
    result << '"';
    return result.str();
}

std::string serializeFinding(const Finding& finding) {
    std::ostringstream output;
    output << "{"
           << "\"rule_id\":" << serializeString(finding.rule_id) << ','
           << "\"category\":" << serializeString(finding.category) << ','
           << "\"severity\":" << serializeString(finding.severity) << ','
           << "\"title\":" << serializeString(finding.title) << ','
           << "\"file_path\":" << serializeString(finding.file_path) << ','
           << "\"line_number\":" << finding.line_number << ','
           << "\"snippet\":" << serializeString(finding.snippet) << ','
           << "\"fix_prompt\":" << serializeString(finding.fix_prompt)
           << '}';
    return output.str();
}

struct FileResult {
    std::vector<Finding> findings;
    std::size_t line_count = 0;
};

bool isRuleSelected(
    const std::unordered_set<std::string>* rule_ids,
    const std::string& rule_id
) {
    return rule_ids == nullptr || rule_ids->contains(rule_id);
}

FileResult analyzeFile(
    const fs::path& file_path,
    const fs::path& root_path,
    const std::unordered_set<std::string>* selected_rule_ids
) {
    MappedFile mapped(file_path);
    if (!mapped.isValid()) {
        throw std::runtime_error("Could not map source file: " + file_path.string());
    }

    const std::string_view content = mapped.view();
    const auto probe_length = std::min<std::size_t>(512, content.size());
    if (content.substr(0, probe_length).find('\0') != std::string_view::npos) {
        return {};
    }

    FileResult result;
    const auto relative_path = toGenericRelativePath(file_path, root_path);
    const auto extension = lower(file_path.extension().string());
    const auto filename = lower(file_path.filename().string());
    std::string masked_content;
    std::string_view analysis_content = content;
    std::vector<TaintFlow> taint_flows;
    if (const auto language = sourceLanguageForPath(file_path)) {
        auto syntax = analyzeSource(
            content,
            *language,
            isRuleSelected(selected_rule_ids, "DATA-001")
        );
        masked_content = maskComments(content, syntax.comments);
        taint_flows = std::move(syntax.taint_flows);
        analysis_content = masked_content;
    }

    for (const auto& flow : taint_flows) {
        addFinding(
            result.findings,
            "DATA-001",
            "Data Flow",
            "HIGH",
            flow.dynamic_code
                ? "Untrusted input reaches dynamic code execution"
                : "Untrusted input reaches a SQL execution sink",
            relative_path,
            lineAt(content, flow.sink_start_byte),
            flow.sink + "(...)",
            flow.dynamic_code
                ? "Avoid eval/exec with untrusted input; replace it with fixed, validated operations."
                : "Use parameterized SQL queries instead of concatenating untrusted input."
        );
    }

    if (isRuleSelected(selected_rule_ids, "ENV-002") &&
        filename.starts_with(".env") && !kEnvTemplates.contains(filename)) {
        addFinding(
            result.findings, "ENV-002", "Exposure", "HIGH",
            "Environment file present in project tree", relative_path, 1, filename,
            "Confirm this environment file is excluded from version control, remove any committed copy, and rotate exposed values."
        );
    }

    const auto& rules = securityRules();
    std::size_t offset = 0;
    while (offset < analysis_content.size()) {
        const auto line_end = analysis_content.find('\n', offset);
        const auto end = line_end == std::string_view::npos ? analysis_content.size() : line_end;
        auto line = analysis_content.substr(offset, end - offset);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        ++result.line_count;

        bool recognized_secret = false;
        for (const auto& rule : rules) {
            if (!hasRuleExtension(extension, rule)) {
                continue;
            }
            if (selected_rule_ids != nullptr &&
                !selected_rule_ids->contains(rule.id) &&
                !rule.id.starts_with("SEC-")) {
                continue;
            }
            std::match_results<std::string_view::const_iterator> match;
            if (!std::regex_search(line.begin(), line.end(), match, rule.pattern)) {
                continue;
            }
            recognized_secret = recognized_secret || rule.id.starts_with("SEC-");
            if (!isRuleSelected(selected_rule_ids, rule.id)) {
                continue;
            }
            const auto match_start = static_cast<std::size_t>(match.position());
            const auto match_length = static_cast<std::size_t>(match.length());
            addFinding(
                result.findings,
                rule.id,
                rule.category,
                rule.severity,
                rule.title,
                relative_path,
                result.line_count,
                makeSnippet(line, match_start, match_length),
                rule.fix
            );
        }

        if (isRuleSelected(selected_rule_ids, "SEC-007") && !recognized_secret) {
            std::match_results<std::string_view::const_iterator> entropy_match;
            if (std::regex_search(line.begin(), line.end(), entropy_match, kEntropyAssignment)) {
                const auto candidate = line.substr(
                    static_cast<std::size_t>(entropy_match.position(2)),
                    static_cast<std::size_t>(entropy_match.length(2))
                );
                const auto candidate_lower = lower(std::string(candidate));
                const bool placeholder =
                    candidate_lower.find("example") != std::string::npos ||
                    candidate_lower.find("your_") != std::string::npos ||
                    candidate_lower.find("changeme") != std::string::npos ||
                    candidate_lower.find("placeholder") != std::string::npos ||
                    candidate_lower.find("dummy") != std::string::npos ||
                    candidate_lower.find("sample") != std::string::npos;
                if (calculateShannonEntropy(candidate) >= 4.2 && !placeholder) {
                    addFinding(
                        result.findings, "SEC-007", "Secrets", "HIGH",
                        "High-entropy hardcoded credential", relative_path,
                        result.line_count,
                        makeSnippet(
                            line,
                            static_cast<std::size_t>(entropy_match.position(2)),
                            static_cast<std::size_t>(entropy_match.length(2))
                        ),
                        "Move this credential to a server-side secret store and rotate it."
                    );
                }
            }
        }

        if (line_end == std::string_view::npos) {
            break;
        }
        offset = line_end + 1;
    }

    if (isRuleSelected(selected_rule_ids, "DB-004") && extension == ".sql") {
        std::match_results<std::string_view::const_iterator> table_match;
        auto search_start = analysis_content.begin();
        while (std::regex_search(search_start, analysis_content.end(), table_match, kCreateTable)) {
            const auto table_offset = static_cast<std::size_t>(
                std::distance(analysis_content.begin(), table_match[0].first)
            );
            std::string table(table_match[1].first, table_match[1].second);
            table.erase(std::remove(table.begin(), table.end(), '"'), table.end());
            const auto separator = table.rfind('.');
            const auto table_name = separator == std::string::npos ? table : table.substr(separator + 1);
            bool rls_enabled = false;
            auto alter_start = analysis_content.begin();
            std::match_results<std::string_view::const_iterator> alter_match;
            while (std::regex_search(alter_start, analysis_content.end(), alter_match, kAlterTableRls)) {
                const std::string statement(alter_match[0].first, alter_match[0].second);
                const auto normalized_statement = lower(statement);
                if (normalized_statement.find(lower(table_name)) != std::string::npos &&
                    normalized_statement.find("enable row level security") != std::string::npos) {
                    rls_enabled = true;
                    break;
                }
                alter_start = alter_match[0].second;
            }
            if (!rls_enabled) {
                addFinding(
                    result.findings, "DB-004", "Database", "HIGH",
                    "Table " + table_name + " has no visible RLS enablement",
                    relative_path, lineAt(content, table_offset), "CREATE TABLE " + table,
                    "Enable row-level security and define explicit policies for this table."
                );
            }
            search_start = table_match[0].second;
        }
    }

    if (isRuleSelected(selected_rule_ids, "API-001") &&
        (extension == ".ts" || extension == ".tsx" || extension == ".mts" ||
        extension == ".cts" || extension == ".js" || extension == ".jsx" ||
        extension == ".mjs" || extension == ".cjs")) {
        const auto generic_path = "/" + relative_path;
        std::match_results<std::string_view::const_iterator> mutation_match;
        if (generic_path.find("/app/api/") != std::string::npos &&
            std::regex_search(analysis_content.begin(), analysis_content.end(), mutation_match, kNextMutation) &&
            !std::regex_search(analysis_content.begin(), analysis_content.end(), kNextAuth)) {
            const auto start = static_cast<std::size_t>(mutation_match.position());
            addFinding(
                result.findings, "API-001", "API Security", "HIGH",
                "Next.js mutation route has no visible authentication check",
                relative_path, lineAt(content, start),
                std::string(mutation_match[0].first, mutation_match[0].second),
                "Add server-side authentication and authorization checks before performing this mutation."
            );
        }
    }

    if (isRuleSelected(selected_rule_ids, "API-003") && extension == ".py") {
        std::match_results<std::string_view::const_iterator> mutation_match;
        if (std::regex_search(analysis_content.begin(), analysis_content.end(), mutation_match, kFastApiMutation) &&
            !std::regex_search(analysis_content.begin(), analysis_content.end(), kFastApiAuth)) {
            const auto start = static_cast<std::size_t>(mutation_match.position());
            addFinding(
                result.findings, "API-003", "API Security", "MEDIUM",
                "FastAPI mutation route has no visible auth dependency",
                relative_path, lineAt(content, start),
                std::string(mutation_match[0].first, mutation_match[0].second),
                "Require an authentication dependency and authorize the requested resource in this route."
            );
        }
    }

    std::match_results<std::string_view::const_iterator> cookie_match;
    if (isRuleSelected(selected_rule_ids, "AUTH-001") &&
        std::regex_search(analysis_content.begin(), analysis_content.end(), cookie_match, kSetCookie) &&
        !std::regex_search(analysis_content.begin(), analysis_content.end(), kHttpOnly)) {
        const auto start = static_cast<std::size_t>(cookie_match.position());
        const auto line = lineAt(analysis_content, start);
        const auto line_start = analysis_content.rfind('\n', start) == std::string_view::npos
        ? 0
        : analysis_content.rfind('\n', start) + 1;
        const auto line_end = analysis_content.find('\n', line_start);
        addFinding(
            result.findings, "AUTH-001", "Session Security", "MEDIUM",
            "Cookie may be missing HttpOnly", relative_path, line,
        makeSnippet(analysis_content.substr(
            line_start,
            line_end == std::string_view::npos ? analysis_content.size() - line_start : line_end - line_start
        )),
            "Set HttpOnly, Secure, and an appropriate SameSite policy on session cookies."
        );
    }

    return result;
}

}  // namespace

Scanner::Scanner(fs::path root, fs::path scanner_source_root)
    : root_(std::move(root)), scanner_source_root_(std::move(scanner_source_root)) {}

ScanReport Scanner::run(const ProgressCallback& progress) const {
    return runImpl(nullptr, nullptr, progress);
}

ScanReport Scanner::runFiles(
    const std::vector<fs::path>& relative_files,
    const ProgressCallback& progress
) const {
    return runImpl(&relative_files, nullptr, progress);
}

ScanReport Scanner::runFiles(
    const std::vector<fs::path>& relative_files,
    const std::vector<std::string>& rule_ids,
    const ProgressCallback& progress
) const {
    return runImpl(&relative_files, &rule_ids, progress);
}

ScanReport Scanner::runImpl(
    const std::vector<fs::path>* relative_files,
    const std::vector<std::string>* rule_ids,
    const ProgressCallback& progress
) const {
    if (!fs::exists(root_) || !fs::is_directory(root_)) {
        throw std::invalid_argument("The target path does not exist or is not a directory: " + root_.string());
    }

    const auto start_time = std::chrono::steady_clock::now();
    std::unordered_set<std::string> selected_rule_ids;
    const std::unordered_set<std::string> structural_rule_ids = {
        "ENV-002", "SEC-007", "DB-004", "API-001", "API-003", "AUTH-001",
        "DATA-001",
    };
    if (rule_ids != nullptr) {
        std::unordered_set<std::string> known_rule_ids = structural_rule_ids;
        for (const auto& rule : securityRules()) {
            known_rule_ids.insert(rule.id);
        }
        for (const auto& rule_id : *rule_ids) {
            if (!known_rule_ids.contains(rule_id)) {
                throw std::invalid_argument("Unknown scanner rule ID: " + rule_id);
            }
            selected_rule_ids.insert(rule_id);
        }
    }
    const auto* selected_rule_set = rule_ids == nullptr ? nullptr : &selected_rule_ids;
    std::vector<fs::path> files;
    const auto scanner_root = fs::weakly_canonical(scanner_source_root_);
    std::unordered_set<fs::path> scanner_sources;
    for (const auto& path : {
             scanner_root / "src" / "main.py",
             scanner_root / "main.cpp",
             scanner_root / "src" / "scanner_rules.py",
             scanner_root / "core" / "include" / "mmap_file.hpp",
             scanner_root / "core" / "include" / "rules.hpp",
             scanner_root / "core" / "include" / "scanner.hpp",
             scanner_root / "core" / "include" / "tree_sitter_comments.hpp",
             scanner_root / "core" / "src" / "main.cpp",
             scanner_root / "core" / "src" / "scanner.cpp",
             scanner_root / "core" / "src" / "tree_sitter_comments.cpp",
         }) {
        scanner_sources.insert(fs::weakly_canonical(path));
    }

    if (relative_files != nullptr) {
        const auto canonical_root = fs::weakly_canonical(root_);
        std::unordered_set<fs::path> selected_files;
        for (const auto& relative_path : *relative_files) {
            if (relative_path.empty() || relative_path.is_absolute() ||
                std::find(relative_path.begin(), relative_path.end(), fs::path("..")) != relative_path.end()) {
                throw std::invalid_argument("Incremental scan paths must be relative to the project root.");
            }
            const auto path = root_ / relative_path;
            if (fs::is_symlink(path)) {
                continue;
            }
            if (!fs::is_regular_file(path)) {
                throw std::runtime_error("Incremental scan file is missing or not regular: " + path.string());
            }
            const auto canonical_path = fs::weakly_canonical(path);
            const auto within_root = canonical_path.lexically_relative(canonical_root);
            if (within_root.empty() || within_root.is_absolute() ||
                *within_root.begin() == fs::path("..")) {
                throw std::invalid_argument("Incremental scan path resolves outside the project root.");
            }
            const auto filename = lower(path.filename().string());
            const auto extension = lower(path.extension().string());
            if (!hasExtension(path, kAllowedExtensions) && !filename.starts_with(".env")) {
                continue;
            }
            if (scanner_sources.contains(canonical_path)) {
                continue;
            }
            bool skipped_directory = false;
            for (auto part = within_root.begin(); part != within_root.end(); ++part) {
                if (std::next(part) != within_root.end() &&
                    kSkippedDirectories.contains(lower(part->string()))) {
                    skipped_directory = true;
                    break;
                }
            }
            if (!skipped_directory) {
                selected_files.insert(path);
            }
        }
        files.assign(selected_files.begin(), selected_files.end());
    } else {
        for (fs::recursive_directory_iterator iterator(root_);
             iterator != fs::recursive_directory_iterator();
             ++iterator) {
            const auto path = iterator->path();
            if (iterator->is_symlink()) {
                if (iterator->is_directory()) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }
            if (iterator->is_directory()) {
                if (kSkippedDirectories.contains(lower(path.filename().string()))) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }
            if (!iterator->is_regular_file()) {
                continue;
            }

            const auto filename = lower(path.filename().string());
            const auto extension = lower(path.extension().string());
            if (!hasExtension(path, kAllowedExtensions) && !filename.starts_with(".env")) {
                continue;
            }

            const auto canonical_path = fs::weakly_canonical(path);
            if (scanner_sources.contains(canonical_path) ||
                kSkippedDirectories.contains(lower(path.parent_path().filename().string()))) {
                continue;
            }
            files.push_back(path);
        }
    }

    std::sort(files.begin(), files.end());
    std::vector<FileResult> results(files.size());
    std::vector<std::string> errors(files.size());
    std::atomic<std::size_t> next_file{0};
    std::atomic<std::size_t> completed{0};
    std::atomic<std::size_t> lines_scanned{0};
    const auto hardware_threads = std::thread::hardware_concurrency();
    const auto worker_count = std::min<std::size_t>(
        files.size(),
        std::clamp<std::size_t>(hardware_threads == 0 ? 4 : hardware_threads, 1, 32)
    );
    std::mutex progress_mutex;
    std::vector<std::jthread> workers;
    workers.reserve(worker_count);

    for (std::size_t worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&]() {
            while (true) {
                const auto index = next_file.fetch_add(1, std::memory_order_relaxed);
                if (index >= files.size()) {
                    break;
                }
                try {
                    results[index] = analyzeFile(files[index], root_, selected_rule_set);
                    lines_scanned.fetch_add(results[index].line_count, std::memory_order_relaxed);
                } catch (const std::exception& error) {
                    errors[index] = error.what();
                }

                if (progress) {
                    std::lock_guard<std::mutex> lock(progress_mutex);
                    const auto finished = completed.fetch_add(1, std::memory_order_relaxed) + 1;
                    progress(finished, files.size(), toGenericRelativePath(files[index], root_));
                } else {
                    completed.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    workers.clear();

    for (const auto& error : errors) {
        if (!error.empty()) {
            throw std::runtime_error(error);
        }
    }

    ScanReport report;
    report.files_scanned = files.size();
    report.lines_scanned = lines_scanned.load(std::memory_order_relaxed);
    for (auto& result : results) {
        report.findings.insert(
            report.findings.end(),
            std::make_move_iterator(result.findings.begin()),
            std::make_move_iterator(result.findings.end())
        );
    }
    std::sort(report.findings.begin(), report.findings.end(), [](const Finding& left, const Finding& right) {
        if (left.file_path != right.file_path) {
            return left.file_path < right.file_path;
        }
        if (left.line_number != right.line_number) {
            return left.line_number < right.line_number;
        }
        return left.rule_id < right.rule_id;
    });

    int penalty = 0;
    for (const auto& finding : report.findings) {
        ++report.summary.total;
        if (finding.severity == "CRITICAL") {
            ++report.summary.critical;
            penalty += 25;
        } else if (finding.severity == "HIGH") {
            ++report.summary.high;
            penalty += 12;
        } else if (finding.severity == "MEDIUM") {
            ++report.summary.medium;
            penalty += 5;
        } else {
            ++report.summary.low;
            penalty += 2;
        }
    }
    report.security_score = std::max(0, 100 - penalty);
    report.elapsed_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start_time
    ).count();
    return report;
}

std::string serializeReport(const ScanReport& report) {
    std::ostringstream output;
    output << std::fixed << std::setprecision(2);
    output << "{"
           << "\"security_score\":" << report.security_score << ','
           << "\"total_issues\":" << report.summary.total << ','
           << "\"files_scanned\":" << report.files_scanned << ','
           << "\"lines_scanned\":" << report.lines_scanned << ','
           << "\"elapsed_ms\":" << report.elapsed_ms << ','
           << "\"summary\":{"
           << "\"critical\":" << report.summary.critical << ','
           << "\"high\":" << report.summary.high << ','
           << "\"medium\":" << report.summary.medium << ','
           << "\"low\":" << report.summary.low << ','
           << "\"total\":" << report.summary.total << "},"
           << "\"findings\":[";
    for (std::size_t index = 0; index < report.findings.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << serializeFinding(report.findings[index]);
    }
    output << "]}";
    return output.str();
}

std::string serializeRuleMetadata() {
    std::ostringstream output;
    output << "{\"engine_version\":" << kRuleEngineVersion << ",\"rules\":[";
    const auto& rules = securityRules();
    for (std::size_t index = 0; index < rules.size(); ++index) {
        const auto& rule = rules[index];
        if (index != 0) {
            output << ',';
        }
        output << "{"
               << "\"id\":" << serializeString(rule.id) << ','
               << "\"category\":" << serializeString(rule.category) << ','
               << "\"severity\":" << serializeString(rule.severity) << ','
               << "\"title\":" << serializeString(rule.title) << ','
               << "\"pattern\":" << serializeString(rule.pattern_source) << ','
               << "\"pattern_flags\":" << static_cast<unsigned int>(rule.pattern_flags) << ','
               << "\"extensions\":[";
        for (std::size_t extension_index = 0; extension_index < rule.extensions.size(); ++extension_index) {
            if (extension_index != 0) {
                output << ',';
            }
            output << serializeString(rule.extensions[extension_index]);
        }
        output << "],"
               << "\"fix\":" << serializeString(rule.fix)
               << '}';
    }
    output << "]}";
    return output.str();
}
