#include "../../core/include/scanner.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void writeFile(const fs::path& path, const std::string& contents) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output || !(output << contents)) {
        throw std::runtime_error("Could not write scanner test input");
    }
}

std::size_t countRule(const ScanReport& report, const std::string& rule_id) {
    std::size_t count = 0;
    for (const auto& finding : report.findings) {
        if (finding.rule_id == rule_id) {
            ++count;
        }
    }
    return count;
}

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        throw std::runtime_error("Expected a writable test workspace path");
    }

    const fs::path workspace = argv[1];
    fs::remove_all(workspace);
    writeFile(
        workspace / "source.ts",
        "// sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "const apiKey = \"sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\";\n"
        "const value = eval(input);\n"
    );
    writeFile(
        workspace / "comment.js",
        "// sk-cccccccccccccccccccccccccccccccccccccccc\n"
    );
    writeFile(
        workspace / "comment.tsx",
        "const view = <div />; // sk-ffffffffffffffffffffffffffffffffffffffff\n"
    );
    writeFile(
        workspace / "comment.py",
        "# sk-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n"
    );
    writeFile(
        workspace / "schema.sql",
        "-- CREATE TABLE public.ignored (id integer);\n"
        "CREATE TABLE public.accounts (id integer);\n"
    );
    writeFile(
        workspace / "__tests__" / "ignored.ts",
        "const apiKey = \"sk-cccccccccccccccccccccccccccccccccccccccc\";\n"
    );
    const auto outside_file = workspace.parent_path() / "outside-secret.py";
    writeFile(
        outside_file,
        "token = \"sk-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\";\n"
    );
    std::error_code symlink_error;
    fs::create_symlink(outside_file, workspace / "linked.py", symlink_error);

    const Scanner scanner(workspace, workspace);
    const auto report = scanner.run();
    fs::remove(outside_file);
    require(report.files_scanned == 5, "Common test directories should be excluded");
    require(countRule(report, "SEC-001") == 1, "A code string secret should be detected once");
    require(countRule(report, "DB-004") == 1, "Only the parsed SQL table should be checked");
    for (const auto& finding : report.findings) {
        if (finding.rule_id == "DB-004") {
            require(finding.line_number == 2, "SQL finding should retain its source line");
        }
    }
    const auto selected_report = scanner.runFiles({fs::path("source.ts")});
    require(selected_report.files_scanned == 1, "Selected-file scans should omit unchanged files");
    require(countRule(selected_report, "SEC-001") == 1, "Selected-file scans should retain findings");
    const auto single_rule_report = scanner.runFiles(
        {fs::path("source.ts")},
        std::vector<std::string>{"SEC-001"}
    );
    require(countRule(single_rule_report, "SEC-001") == 1, "Selected-rule scans should run the requested rule");
    require(countRule(single_rule_report, "INJ-002") == 0, "Selected-rule scans should omit other rules");
    bool rejected_traversal = false;
    try {
        static_cast<void>(scanner.runFiles({fs::path("../outside-secret.py")}));
    } catch (const std::invalid_argument&) {
        rejected_traversal = true;
    }
    require(rejected_traversal, "Selected-file scans must reject paths outside the project");
    return 0;
}
