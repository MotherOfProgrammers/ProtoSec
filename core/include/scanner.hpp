#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

struct Finding {
    std::string rule_id;
    std::string category;
    std::string severity;
    std::string title;
    std::string file_path;
    std::size_t line_number = 0;
    std::string snippet;
    std::string fix_prompt;
};

struct ScanSummary {
    std::size_t critical = 0;
    std::size_t high = 0;
    std::size_t medium = 0;
    std::size_t low = 0;
    std::size_t total = 0;
};

struct ScanReport {
    int security_score = 100;
    std::size_t files_scanned = 0;
    std::size_t lines_scanned = 0;
    double elapsed_ms = 0.0;
    ScanSummary summary;
    std::vector<Finding> findings;
};

class Scanner {
public:
    using ProgressCallback = std::function<void(std::size_t, std::size_t, const std::string&)>;

    Scanner(std::filesystem::path root, std::filesystem::path scanner_source_root);
    [[nodiscard]] ScanReport run(const ProgressCallback& progress = {}) const;

private:
    std::filesystem::path root_;
    std::filesystem::path scanner_source_root_;
};

[[nodiscard]] std::string serializeReport(const ScanReport& report);
