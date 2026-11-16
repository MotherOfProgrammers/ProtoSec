#include "../include/scanner.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>

#ifndef PROTOSEC_SOURCE_DIR
#define PROTOSEC_SOURCE_DIR "."
#endif

int main(int argc, char* argv[]) {
    const bool staged_only = argc == 3 && std::string(argv[1]) == "--staged-only";
    const bool project_directory = argc == 2 && std::string(argv[1]) != "--staged-only";
    if (!project_directory && !staged_only) {
        std::cerr << "Usage: scanner_core <project_directory>\n"
                     "       scanner_core --staged-only <snapshot_directory>\n";
        return 2;
    }

    try {
        const std::filesystem::path target = staged_only ? argv[2] : argv[1];
        const std::filesystem::path source_root = PROTOSEC_SOURCE_DIR;
        Scanner scanner(target, source_root);
        const auto report = scanner.run([](
            std::size_t completed,
            std::size_t total,
            const std::string& path
        ) {
            const auto interval = std::max<std::size_t>(1, total / 100);
            if (completed == 1 || completed == total || completed % interval == 0) {
                std::cerr << "PROGRESS\t" << completed << '\t' << total << '\t' << path << '\n';
            }
        });
        std::cout << serializeReport(report) << '\n';
        return staged_only && !report.findings.empty() ? 1 : 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
