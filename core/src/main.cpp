#include "../include/scanner.hpp"
#include "../include/rules.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#ifndef PROTOSEC_SOURCE_DIR
#define PROTOSEC_SOURCE_DIR "."
#endif

namespace {

std::vector<std::filesystem::path> readFileList(const std::filesystem::path& list_path) {
    std::ifstream input(list_path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Could not open incremental scan file list.");
    }
    const std::string contents{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };
    constexpr std::size_t kMaxFileListBytes = 16 * 1024 * 1024;
    if (contents.size() > kMaxFileListBytes) {
        throw std::runtime_error("Incremental scan file list exceeds the 16 MiB limit.");
    }
    if (!contents.empty() && contents.back() != '\0') {
        throw std::runtime_error("Incremental scan file list is malformed.");
    }

    std::vector<std::filesystem::path> paths;
    std::size_t start = 0;
    while (start < contents.size()) {
        const auto end = contents.find('\0', start);
        if (end == std::string::npos || end == start) {
            throw std::runtime_error("Incremental scan file list contains an invalid path.");
        }
        std::u8string utf8_path;
        utf8_path.reserve(end - start);
        for (auto position = start; position < end; ++position) {
            utf8_path.push_back(static_cast<char8_t>(contents[position]));
        }
        paths.emplace_back(std::move(utf8_path));
        start = end + 1;
    }
    return paths;
}

std::vector<std::string> parseRuleIds(const std::string& value) {
    std::vector<std::string> rule_ids;
    std::size_t start = 0;
    while (start < value.size()) {
        const auto end = value.find(',', start);
        const auto length = end == std::string::npos ? value.size() - start : end - start;
        if (length == 0) {
            throw std::runtime_error("Rule ID list contains an empty value.");
        }
        rule_ids.push_back(value.substr(start, length));
        if (end == std::string::npos) {
            return rule_ids;
        }
        start = end + 1;
    }
    throw std::runtime_error("Rule ID list must not be empty.");
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string(argv[1]) == "--rule-engine-version") {
        std::cout << kRuleEngineVersion << '\n';
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--rule-metadata") {
        std::cout << serializeRuleMetadata() << '\n';
        return 0;
    }
    const bool staged_only = argc == 3 && std::string(argv[1]) == "--staged-only";
    const bool files_from = (argc == 4 || argc == 6) &&
        std::string(argv[1]) == "--files-from";
    const bool select_rules = argc == 6 &&
        std::string(argv[4]) == "--only-rules";
    const bool project_directory = argc == 2 &&
        std::string(argv[1]) != "--staged-only" &&
        std::string(argv[1]) != "--files-from" &&
        std::string(argv[1]) != "--rule-engine-version" &&
        std::string(argv[1]) != "--rule-metadata";
    if ((!project_directory && !staged_only && !files_from) ||
        (argc == 6 && !select_rules)) {
        std::cerr << "Usage: scanner_core <project_directory>\n"
                     "       scanner_core --staged-only <snapshot_directory>\n"
                     "       scanner_core --files-from <project_directory> <nul_list_file> "
                     "[--only-rules <comma-separated-ids>]\n"
                     "       scanner_core --rule-engine-version\n"
                     "       scanner_core --rule-metadata\n";
        return 2;
    }

    try {
        const std::filesystem::path target = staged_only || files_from ? argv[2] : argv[1];
        const std::filesystem::path source_root = PROTOSEC_SOURCE_DIR;
        Scanner scanner(target, source_root);
        const auto progress = [](
            std::size_t completed,
            std::size_t total,
            const std::string& path
        ) {
            const auto interval = std::max<std::size_t>(1, total / 100);
            if (completed == 1 || completed == total || completed % interval == 0) {
                std::cerr << "PROGRESS\t" << completed << '\t' << total << '\t' << path << '\n';
            }
        };
        const auto report = files_from
            ? select_rules
                ? scanner.runFiles(readFileList(argv[3]), parseRuleIds(argv[5]), progress)
                : scanner.runFiles(readFileList(argv[3]), progress)
            : scanner.run(progress);
        std::cout << serializeReport(report) << '\n';
        return staged_only && !report.findings.empty() ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
