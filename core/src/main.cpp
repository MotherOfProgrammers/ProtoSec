#include "../include/scanner.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>

#ifndef PROTOSEC_SOURCE_DIR
#define PROTOSEC_SOURCE_DIR "."
#endif

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: scanner_core <project_directory>\n";
        return 2;
    }

    try {
        const std::filesystem::path target = argv[1];
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
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
