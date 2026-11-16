#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class SourceLanguage {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
    Sql,
};

struct CommentByteRange {
    std::size_t start_byte;
    std::size_t end_byte;
};

struct TaintFlow {
    std::size_t sink_start_byte;
    std::string sink;
    bool dynamic_code;
};

struct TreeSitterAnalysis {
    std::vector<CommentByteRange> comments;
    std::vector<TaintFlow> taint_flows;
};

[[nodiscard]] std::optional<SourceLanguage> sourceLanguageForPath(
    const std::filesystem::path& path
);
[[nodiscard]] TreeSitterAnalysis analyzeSource(
    std::string_view source,
    SourceLanguage language,
    bool analyze_taint
);
[[nodiscard]] std::vector<CommentByteRange> findCommentByteRanges(
    std::string_view source,
    SourceLanguage language
);
[[nodiscard]] std::string maskComments(
    std::string_view source,
    const std::vector<CommentByteRange>& comments
);
