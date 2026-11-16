#include "../include/tree_sitter_comments.hpp"

#include <tree_sitter/api.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
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

std::string nodeType(TSNode node) {
    return ts_node_is_null(node) ? std::string{} : ts_node_type(node);
}

std::string nodeText(std::string_view source, TSNode node) {
    const auto start = ts_node_start_byte(node);
    const auto end = ts_node_end_byte(node);
    if (start > end || end > source.size()) {
        return {};
    }
    return std::string(source.substr(start, end - start));
}

TSNode field(TSNode node, const char* name) {
    return ts_node_child_by_field_name(
        node,
        name,
        static_cast<std::uint32_t>(std::char_traits<char>::length(name))
    );
}

std::string memberPath(std::string_view source, TSNode node, unsigned depth = 0) {
    if (ts_node_is_null(node) || depth >= 64) {
        return {};
    }
    const auto type = nodeType(node);
    if (type == "identifier" || type == "property_identifier") {
        return nodeText(source, node);
    }
    if (type == "attribute" || type == "member_expression") {
        const auto object = field(node, "object");
        const auto property = field(node, type == "attribute" ? "attribute" : "property");
        const auto parent = memberPath(source, object, depth + 1);
        const auto member = nodeText(source, property);
        return parent.empty() || member.empty() ? std::string{} : parent + "." + member;
    }
    if (type == "call" || type == "call_expression") {
        return memberPath(source, field(node, "function"), depth + 1);
    }
    if (type == "subscript" || type == "subscript_expression") {
        const auto value = field(node, type == "subscript" ? "value" : "object");
        return memberPath(source, value, depth + 1);
    }
    if (type == "parenthesized_expression") {
        return memberPath(source, ts_node_named_child(node, 0), depth + 1);
    }
    if (type == "primary_expression" || type == "expression" || type == "await") {
        return ts_node_named_child_count(node) == 1
            ? memberPath(source, ts_node_named_child(node, 0), depth + 1)
            : std::string{};
    }
    return {};
}

bool isTaintSource(std::string_view source, TSNode node) {
    const auto path = memberPath(source, node);
    static const std::vector<std::string> sources = {
        "request.args", "request.form", "request.values", "request.json",
        "request.data", "request.query_params", "request.body", "request.query",
        "request.params", "req.body", "req.query", "req.params",
    };
    return std::any_of(sources.begin(), sources.end(), [&path](const auto& source_path) {
        return path == source_path ||
            (path.size() > source_path.size() &&
                path.compare(0, source_path.size(), source_path) == 0 &&
                path[source_path.size()] == '.');
    });
}

bool containsTaintedValue(
    std::string_view source,
    TSNode expression,
    const std::unordered_set<std::string>& tainted,
    unsigned depth = 0
) {
    if (ts_node_is_null(expression) || depth >= 128 ||
        nodeType(expression) == "comment") {
        return false;
    }
    if (isTaintSource(source, expression)) {
        return true;
    }
    if (nodeType(expression) == "identifier" &&
        tainted.contains(nodeText(source, expression))) {
        return true;
    }
    const auto count = ts_node_named_child_count(expression);
    for (std::uint32_t index = 0; index < count; ++index) {
        if (containsTaintedValue(
                source,
                ts_node_named_child(expression, index),
                tainted,
                depth + 1
            )) {
            return true;
        }
    }
    return false;
}

void collectAssignedNames(
    std::string_view source,
    TSNode target,
    std::vector<std::string>& names
) {
    static const std::unordered_set<std::string> destructuring_nodes = {
        "array_pattern", "assignment_pattern", "list_pattern", "object_pattern",
        "pattern_list", "tuple_pattern",
    };
    std::vector<TSNode> pending{target};
    while (!pending.empty()) {
        const auto node = pending.back();
        pending.pop_back();
        const auto type = nodeType(node);
        if (type == "identifier") {
            names.push_back(nodeText(source, node));
        } else if (destructuring_nodes.contains(type)) {
            const auto count = ts_node_named_child_count(node);
            for (std::uint32_t index = 0; index < count; ++index) {
                pending.push_back(ts_node_named_child(node, index));
            }
        }
    }
}

bool isAssignmentNode(const std::string& type) {
    return type == "assignment" || type == "augmented_assignment" ||
        type == "assignment_expression" || type == "augmented_assignment_expression" ||
        type == "variable_declarator";
}

bool isCallNode(const std::string& type) {
    return type == "call" || type == "call_expression";
}

bool isScopeNode(const std::string& type) {
    return type == "function_definition" || type == "lambda" ||
        type == "class_definition" || type == "function_declaration" ||
        type == "function_expression" || type == "arrow_function" ||
        type == "method_definition" || type == "generator_function_declaration";
}

bool isTaintedSink(
    std::string_view source,
    TSNode call,
    const std::unordered_set<std::string>& tainted,
    TaintFlow& flow
) {
    const auto function = field(call, "function");
    const auto path = memberPath(source, function);
    if (path.empty()) {
        return false;
    }
    const auto separator = path.rfind('.');
    const auto name = path.substr(separator == std::string::npos ? 0 : separator + 1);
    const bool dynamic_code = name == "eval" || name == "exec" || name == "Function";
    const bool sql_execution = name == "query" || name == "execute" ||
        name == "executemany" || name == "executescript";
    if (!dynamic_code && !sql_execution) {
        return false;
    }
    const auto arguments = field(call, "arguments");
    if (ts_node_is_null(arguments) || ts_node_named_child_count(arguments) == 0) {
        return false;
    }
    const auto first_argument = ts_node_named_child(arguments, 0);
    if (!containsTaintedValue(source, first_argument, tainted)) {
        return false;
    }
    flow = {ts_node_start_byte(call), name, dynamic_code};
    return true;
}

struct ScopeEvents {
    std::vector<TSNode> assignments;
    std::vector<TSNode> calls;
};

struct AnalysisEvent {
    TSNode node;
    bool assignment;
};

std::vector<TaintFlow> findTaintFlows(std::string_view source, TSNode root) {
    std::vector<ScopeEvents> scopes(1);
    struct PendingNode {
        TSNode node;
        std::size_t scope;
    };
    std::vector<PendingNode> pending{{root, 0}};
    while (!pending.empty()) {
        const auto current = pending.back();
        pending.pop_back();
        const auto type = nodeType(current.node);
        std::size_t scope = current.scope;
        if (current.node.id != root.id && isScopeNode(type)) {
            scopes.emplace_back();
            scope = scopes.size() - 1;
        }
        if (isAssignmentNode(type)) {
            scopes[scope].assignments.push_back(current.node);
        } else if (isCallNode(type)) {
            scopes[scope].calls.push_back(current.node);
        }
        const auto child_count = ts_node_child_count(current.node);
        for (std::uint32_t index = 0; index < child_count; ++index) {
            pending.push_back({ts_node_child(current.node, index), scope});
        }
    }

    std::vector<TaintFlow> flows;
    std::unordered_set<std::string> unique_flows;
    for (const auto& scope : scopes) {
        std::vector<AnalysisEvent> events;
        events.reserve(scope.assignments.size() + scope.calls.size());
        for (const auto node : scope.assignments) {
            events.push_back({node, true});
        }
        for (const auto node : scope.calls) {
            events.push_back({node, false});
        }
        std::stable_sort(events.begin(), events.end(), [](const auto& left, const auto& right) {
            return ts_node_start_byte(left.node) < ts_node_start_byte(right.node);
        });

        std::unordered_set<std::string> tainted;
        for (const auto& event : events) {
            if (event.assignment) {
                TSNode left = field(event.node, "left");
                TSNode right = field(event.node, "right");
                if (nodeType(event.node) == "variable_declarator") {
                    left = field(event.node, "name");
                    right = field(event.node, "value");
                }
                if (ts_node_is_null(left)) {
                    continue;
                }
                const bool tainted_value = containsTaintedValue(source, right, tainted);
                std::vector<std::string> names;
                collectAssignedNames(source, left, names);
                for (const auto& name : names) {
                    if (tainted_value) {
                        tainted.insert(name);
                    } else {
                        tainted.erase(name);
                    }
                }
                continue;
            }

            TaintFlow flow{};
            if (!isTaintedSink(source, event.node, tainted, flow)) {
                continue;
            }
            const auto key = std::to_string(flow.sink_start_byte) + ":" + flow.sink;
            if (unique_flows.insert(key).second) {
                flows.push_back(std::move(flow));
            }
        }
    }
    return flows;
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
        analysis.taint_flows = findTaintFlows(source, ts_tree_root_node(tree.get()));
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
