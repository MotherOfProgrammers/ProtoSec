#include "../include/tree_sitter_comments.hpp"
#include "../include/taint_analysis.hpp"

#include <tree_sitter/api.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

extern "C" {
const TSLanguage* tree_sitter_typescript(void);
const TSLanguage* tree_sitter_tsx(void);
const TSLanguage* tree_sitter_python(void);
const TSLanguage* tree_sitter_sql(void);
}

namespace {

const TSLanguage* languageFor(SourceLanguage language) {
    switch (language) {
        case SourceLanguage::JavaScript:
        case SourceLanguage::Tsx: return tree_sitter_tsx();
        case SourceLanguage::TypeScript: return tree_sitter_typescript();
        case SourceLanguage::Python: return tree_sitter_python();
        case SourceLanguage::Sql: return tree_sitter_sql();
    }
    throw std::invalid_argument("Unsupported Tree-sitter language");
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        if (ch >= 'A' && ch <= 'Z') {
            return static_cast<char>(ch - 'A' + 'a');
        }
        return static_cast<char>(ch);
    });
    return value;
}

}  // namespace

std::optional<SourceLanguage> sourceLanguageForPath(const std::filesystem::path& path) {
    const auto extension = lowercase(path.extension().string());
    if (extension == ".js" || extension == ".jsx" || extension == ".mjs" ||
        extension == ".cjs") {
        return SourceLanguage::JavaScript;
    }
    if (extension == ".tsx") {
        return SourceLanguage::Tsx;
    }
    if (extension == ".ts" || extension == ".mts" || extension == ".cts") {
        return SourceLanguage::TypeScript;
    }
    if (extension == ".py") {
        return SourceLanguage::Python;
    }
    if (extension == ".sql") {
        return SourceLanguage::Sql;
    }
    return std::nullopt;
}

TreeSitterAnalysis analyzeSource(
    std::string_view source,
    SourceLanguage language,
    bool analyze_taint
) {
    if (source.size() > UINT32_MAX) {
        throw std::length_error("Source file is too large for Tree-sitter parsing");
    }

    std::unique_ptr<TSParser, decltype(&ts_parser_delete)> parser(
        ts_parser_new(),
        &ts_parser_delete
    );
    if (!parser) {
        throw std::bad_alloc();
    }
    if (!ts_parser_set_language(parser.get(), languageFor(language))) {
        throw std::runtime_error("Tree-sitter rejected the configured grammar");
    }

    std::unique_ptr<TSTree, decltype(&ts_tree_delete)> tree(
        ts_parser_parse_string(
            parser.get(),
            nullptr,
            source.empty() ? "" : source.data(),
            static_cast<std::uint32_t>(source.size())
        ),
        &ts_tree_delete
    );
    if (!tree) {
        throw std::runtime_error("Tree-sitter could not parse the source file");
    }

    TreeSitterAnalysis analysis;
    std::vector<TSNode> pending{ts_tree_root_node(tree.get())};
    while (!pending.empty()) {
        const auto node = pending.back();
        pending.pop_back();
        if (std::string_view(ts_node_type(node)) == "comment") {
            analysis.comments.push_back({
                ts_node_start_byte(node),
                ts_node_end_byte(node),
            });
        }
        const auto child_count = ts_node_child_count(node);
        for (std::uint32_t index = 0; index < child_count; ++index) {
            pending.push_back(ts_node_child(node, index));
        }
    }

    std::sort(analysis.comments.begin(), analysis.comments.end(), [](const auto& left, const auto& right) {
        return left.start_byte < right.start_byte;
    });
    if (analyze_taint &&
        language != SourceLanguage::Sql) {
        analysis.taint_flows = analyzeTaintFlows(source, ts_tree_root_node(tree.get()));
    }
    return analysis;
}

std::vector<CommentByteRange> findCommentByteRanges(
    std::string_view source,
    SourceLanguage language
) {
    return analyzeSource(source, language, false).comments;
}

std::string maskComments(
    std::string_view source,
    const std::vector<CommentByteRange>& comments
) {
    std::string masked(source);
    for (const auto& comment : comments) {
        const auto start = std::min(comment.start_byte, masked.size());
        const auto end = std::min(comment.end_byte, masked.size());
        for (auto index = start; index < end; ++index) {
            if (masked[index] != '\n' && masked[index] != '\r') {
                masked[index] = ' ';
            }
        }
    }
    return masked;
}
