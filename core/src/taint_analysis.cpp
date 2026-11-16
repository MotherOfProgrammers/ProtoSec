#include "../include/taint_analysis.hpp"

#include <tree_sitter/api.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <queue>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using FlowNodeId = std::size_t;
using Environment = std::unordered_map<std::string, FlowNodeId>;

std::string nodeType(TSNode node) {
    return ts_node_is_null(node) ? std::string{} : ts_node_type(node);
}

std::string nodeText(std::string_view source, TSNode node) {
    const auto start = ts_node_start_byte(node);
    const auto end = ts_node_end_byte(node);
    if (ts_node_is_null(node) || start > end || end > source.size()) {
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

bool isCallNode(const std::string& type) {
    return type == "call" || type == "call_expression";
}

bool isFunctionNode(const std::string& type) {
    return type == "function_definition" || type == "lambda" ||
        type == "function_declaration" || type == "function_expression" ||
        type == "arrow_function" || type == "method_definition" ||
        type == "generator_function_declaration";
}

bool isScopeNode(const std::string& type) {
    return isFunctionNode(type) || type == "class_definition" || type == "class";
}

bool isAssignmentNode(const std::string& type) {
    return type == "assignment" || type == "augmented_assignment" ||
        type == "assignment_expression" || type == "augmented_assignment_expression" ||
        type == "variable_declarator";
}

bool isSanitizerCall(std::string_view name) {
    std::string normalized(name);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return ch >= 'A' && ch <= 'Z'
            ? static_cast<char>(ch - 'A' + 'a')
            : static_cast<char>(ch);
    });
    return normalized == "int" || normalized == "float" || normalized == "decimal" ||
        normalized == "number" || normalized == "parseint" || normalized == "parsefloat";
}

std::string lastPathComponent(std::string path) {
    const auto separator = path.rfind('.');
    if (separator != std::string::npos) {
        path.erase(0, separator + 1);
    }
    return path;
}

bool isTaintedSinkName(std::string_view name, bool& dynamic_code) {
    std::string normalized(name);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return ch >= 'A' && ch <= 'Z'
            ? static_cast<char>(ch - 'A' + 'a')
            : static_cast<char>(ch);
    });
    dynamic_code = normalized == "eval" || normalized == "exec" ||
        normalized == "function";
    return dynamic_code || normalized == "query" || normalized == "execute" ||
        normalized == "executemany" || normalized == "executescript";
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

TSNode parameterTarget(TSNode parameter) {
    TSNode target = field(parameter, "name");
    if (ts_node_is_null(target)) {
        target = field(parameter, "pattern");
    }
    if (!ts_node_is_null(target)) {
        return target;
    }
    if (nodeType(parameter) == "identifier") {
        return parameter;
    }
    const auto type = nodeType(parameter);
    const auto count = ts_node_named_child_count(parameter);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto child = ts_node_named_child(parameter, index);
        const auto child_type = nodeType(child);
        if (child_type == "identifier" || child_type == "array_pattern" ||
            child_type == "object_pattern" || child_type == "tuple_pattern") {
            return child;
        }
        if (type == "parameter" || type == "typed_parameter") {
            const auto nested = parameterTarget(child);
            if (!ts_node_is_null(nested)) {
                return nested;
            }
        }
    }
    return TSNode{};
}

std::vector<std::string> functionParameters(std::string_view source, TSNode function) {
    TSNode parameters = field(function, "parameters");
    if (ts_node_is_null(parameters)) {
        parameters = field(function, "parameter");
    }
    if (ts_node_is_null(parameters)) {
        return {};
    }

    std::vector<std::string> names;
    if (nodeType(parameters) == "identifier") {
        names.push_back(nodeText(source, parameters));
        return names;
    }
    const auto count = ts_node_named_child_count(parameters);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto target = parameterTarget(ts_node_named_child(parameters, index));
        collectAssignedNames(source, target, names);
    }
    return names;
}

std::string functionName(std::string_view source, TSNode function) {
    auto name = field(function, "name");
    if (ts_node_is_null(name)) {
        const auto parent = ts_node_parent(function);
        const auto parent_type = nodeType(parent);
        if (parent_type == "variable_declarator") {
            name = field(parent, "name");
        } else if (parent_type == "assignment_expression") {
            name = field(parent, "left");
        }
    }
    return nodeText(source, name);
}

class DataFlowGraph {
public:
    FlowNodeId addNode(std::size_t byte_offset, bool is_source = false) {
        const auto id = offsets_.size();
        offsets_.push_back(byte_offset);
        sources_.push_back(is_source);
        outgoing_.emplace_back();
        return id;
    }

    void addEdge(FlowNodeId from, FlowNodeId to) {
        if (from >= outgoing_.size() || to >= outgoing_.size()) {
            return;
        }
        auto& edges = outgoing_[from];
        if (std::find(edges.begin(), edges.end(), to) == edges.end()) {
            edges.push_back(to);
        }
    }

    void resolve() {
        provenance_.assign(offsets_.size(), kNoNode);
        predecessor_.assign(offsets_.size(), kNoNode);
        std::queue<FlowNodeId> pending;
        for (FlowNodeId index = 0; index < sources_.size(); ++index) {
            if (sources_[index]) {
                provenance_[index] = index;
                pending.push(index);
            }
        }
        while (!pending.empty()) {
            const auto current = pending.front();
            pending.pop();
            for (const auto next : outgoing_[current]) {
                if (provenance_[next] != kNoNode) {
                    continue;
                }
                provenance_[next] = provenance_[current];
                predecessor_[next] = current;
                pending.push(next);
            }
        }
    }

    [[nodiscard]] std::size_t sourceOffset(FlowNodeId node) const {
        return offsets_[provenance_[node]];
    }

    [[nodiscard]] std::vector<std::size_t> pathTo(FlowNodeId node) const {
        std::vector<std::size_t> path;
        if (node >= provenance_.size() || provenance_[node] == kNoNode) {
            return path;
        }
        auto current = node;
        while (current != kNoNode) {
            path.push_back(offsets_[current]);
            if (current == provenance_[node]) {
                break;
            }
            current = predecessor_[current];
        }
        std::reverse(path.begin(), path.end());
        return path;
    }

    static constexpr FlowNodeId kNoNode = std::numeric_limits<FlowNodeId>::max();

private:
    std::vector<std::size_t> offsets_;
    std::vector<bool> sources_;
    std::vector<std::vector<FlowNodeId>> outgoing_;
    std::vector<FlowNodeId> provenance_;
    std::vector<FlowNodeId> predecessor_;
};

struct FunctionScope {
    TSNode node;
    bool callable = false;
    std::string name;
    std::vector<std::string> parameter_names;
    std::vector<FlowNodeId> parameter_nodes;
    FlowNodeId return_node = DataFlowGraph::kNoNode;
};

struct CallArgument {
    std::string name;
    std::vector<FlowNodeId> dependencies;
};

struct SinkUse {
    std::size_t start_byte;
    std::string name;
    bool dynamic_code;
    std::vector<FlowNodeId> dependencies;
};

class TaintAnalyzer {
public:
    TaintAnalyzer(std::string_view source, TSNode root)
        : source_(source), root_(root) {
        collectScopes();
        indexFunctions();
    }

    std::vector<TaintFlow> run() {
        for (std::size_t index = 0; index < scopes_.size(); ++index) {
            analyzeScope(index);
        }
        graph_.resolve();
        return collectFlows();
    }

private:
    struct PendingNode {
        TSNode node;
        std::size_t scope_index;
    };

    void collectScopes() {
        FunctionScope root_scope;
        root_scope.node = root_;
        scopes_.push_back(std::move(root_scope));
        std::vector<PendingNode> pending{{root_, 0}};
        while (!pending.empty()) {
            const auto current = pending.back();
            pending.pop_back();
            const auto type = nodeType(current.node);
            std::size_t scope_index = current.scope_index;
            if (current.node.id != root_.id && isScopeNode(type)) {
                FunctionScope scope;
                scope.node = current.node;
                scopes_.push_back(std::move(scope));
                scope_index = scopes_.size() - 1;
            }
            const auto child_count = ts_node_child_count(current.node);
            for (std::uint32_t index = 0; index < child_count; ++index) {
                pending.push_back({ts_node_child(current.node, index), scope_index});
            }
        }
    }

    void indexFunctions() {
        for (auto& scope : scopes_) {
            if (!isFunctionNode(nodeType(scope.node))) {
                continue;
            }
            scope.callable = true;
            scope.name = functionName(source_, scope.node);
            scope.parameter_names = functionParameters(source_, scope.node);
            for (const auto& name : scope.parameter_names) {
                scope.parameter_nodes.push_back(
                    graph_.addNode(ts_node_start_byte(scope.node))
                );
                static_cast<void>(name);
            }
            scope.return_node = graph_.addNode(ts_node_start_byte(scope.node));
            if (!scope.name.empty()) {
                functions_by_name_[lastPathComponent(scope.name)].push_back(&scope);
            }
        }
    }

    void analyzeScope(std::size_t index) {
        auto& scope = scopes_[index];
        Environment environment;
        for (std::size_t parameter = 0;
             parameter < scope.parameter_names.size();
             ++parameter) {
            environment[scope.parameter_names[parameter]] = scope.parameter_nodes[parameter];
        }

        TSNode body = scope.callable ? field(scope.node, "body") : scope.node;
        if (ts_node_is_null(body)) {
            return;
        }
        if (scope.callable && nodeType(body) != "block" &&
            nodeType(body) != "statement_block") {
            const auto dependencies = expressionDependencies(body, index, environment);
            for (const auto dependency : dependencies) {
                graph_.addEdge(dependency, scope.return_node);
            }
            return;
        }
        processStatement(body, index, environment);
    }

    FlowNodeId sourceNode(TSNode node) {
        const auto offset = ts_node_start_byte(node);
        const auto found = source_nodes_.find(offset);
        if (found != source_nodes_.end()) {
            return found->second;
        }
        const auto created = graph_.addNode(offset, true);
        source_nodes_.emplace(offset, created);
        return created;
    }

    std::vector<CallArgument> callArguments(
        TSNode call,
        std::size_t scope_index,
        Environment& environment
    ) {
        std::vector<CallArgument> arguments;
        const auto container = field(call, "arguments");
        if (ts_node_is_null(container)) {
            return arguments;
        }
        const auto count = ts_node_named_child_count(container);
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto argument = ts_node_named_child(container, index);
            const auto type = nodeType(argument);
            const auto value = type == "keyword_argument" ? field(argument, "value") : argument;
            const auto name = type == "keyword_argument"
                ? nodeText(source_, field(argument, "name"))
                : std::string{};
            arguments.push_back({
                name,
                expressionDependencies(value, scope_index, environment),
            });
        }
        return arguments;
    }

    void connectCall(
        std::string_view callee,
        const std::vector<CallArgument>& arguments,
        FlowNodeId result_node
    ) {
        const auto targets = functions_by_name_.find(std::string(callee));
        if (targets == functions_by_name_.end()) {
            for (const auto& argument : arguments) {
                for (const auto dependency : argument.dependencies) {
                    graph_.addEdge(dependency, result_node);
                }
            }
            return;
        }

        for (const auto* target : targets->second) {
            std::size_t positional_index = 0;
            for (const auto& argument : arguments) {
                std::size_t parameter_index = positional_index;
                if (argument.name.empty()) {
                    ++positional_index;
                } else {
                    const auto parameter = std::find(
                        target->parameter_names.begin(),
                        target->parameter_names.end(),
                        argument.name
                    );
                    if (parameter == target->parameter_names.end()) {
                        continue;
                    }
                    parameter_index = static_cast<std::size_t>(
                        std::distance(target->parameter_names.begin(), parameter)
                    );
                }
                if (parameter_index >= target->parameter_nodes.size()) {
                    continue;
                }
                for (const auto dependency : argument.dependencies) {
                    graph_.addEdge(dependency, target->parameter_nodes[parameter_index]);
                }
            }
            graph_.addEdge(target->return_node, result_node);
        }
    }

    std::vector<FlowNodeId> expressionDependencies(
        TSNode expression,
        std::size_t scope_index,
        Environment& environment
    ) {
        if (ts_node_is_null(expression) || nodeType(expression) == "comment") {
            return {};
        }
        if (isTaintSource(source_, expression)) {
            return {sourceNode(expression)};
        }

        const auto type = nodeType(expression);
        if (type == "identifier") {
            const auto found = environment.find(nodeText(source_, expression));
            return found == environment.end()
                ? std::vector<FlowNodeId>{}
                : std::vector<FlowNodeId>{found->second};
        }
        if (isScopeNode(type)) {
            return {};
        }
        if (isCallNode(type)) {
            const auto start = ts_node_start_byte(expression);
            auto arguments = callArguments(expression, scope_index, environment);
            std::vector<FlowNodeId> first_argument;
            if (!arguments.empty()) {
                first_argument = arguments.front().dependencies;
            }

            const auto function_path = memberPath(
                source_,
                field(expression, "function")
            );
            const auto name = lastPathComponent(function_path);
            bool dynamic_code = false;
            const bool local_function_call =
                function_path.find('.') == std::string::npos &&
                functions_by_name_.contains(name);
            if (!local_function_call && isTaintedSinkName(name, dynamic_code)) {
                sinks_.push_back({
                    start,
                    name,
                    dynamic_code,
                    std::move(first_argument),
                });
            }

            auto [result, inserted] = call_nodes_.try_emplace(
                start,
                DataFlowGraph::kNoNode
            );
            if (inserted) {
                result->second = graph_.addNode(start);
            }
            if (!isSanitizerCall(name)) {
                connectCall(name, arguments, result->second);
            }
            return isSanitizerCall(name)
                ? std::vector<FlowNodeId>{}
                : std::vector<FlowNodeId>{result->second};
        }

        std::vector<FlowNodeId> dependencies;
        const auto count = ts_node_named_child_count(expression);
        for (std::uint32_t index = 0; index < count; ++index) {
            const auto nested = expressionDependencies(
                ts_node_named_child(expression, index),
                scope_index,
                environment
            );
            dependencies.insert(dependencies.end(), nested.begin(), nested.end());
        }
        return dependencies;
    }

    void processAssignment(
        TSNode assignment,
        std::size_t scope_index,
        Environment& environment
    ) {
        TSNode left = field(assignment, "left");
        TSNode right = field(assignment, "right");
        const auto type = nodeType(assignment);
        if (type == "variable_declarator") {
            left = field(assignment, "name");
            right = field(assignment, "value");
        }

        auto dependencies = expressionDependencies(right, scope_index, environment);
        if (type == "augmented_assignment" ||
            type == "augmented_assignment_expression") {
            std::vector<std::string> left_names;
            collectAssignedNames(source_, left, left_names);
            for (const auto& name : left_names) {
                const auto existing = environment.find(name);
                if (existing != environment.end()) {
                    dependencies.push_back(existing->second);
                }
            }
        }

        std::vector<std::string> names;
        collectAssignedNames(source_, left, names);
        for (const auto& name : names) {
            const auto value = graph_.addNode(ts_node_start_byte(assignment));
            for (const auto dependency : dependencies) {
                graph_.addEdge(dependency, value);
            }
            environment[name] = value;
        }
    }

    void mergeEnvironments(
        const Environment& left,
        const Environment& right,
        std::size_t merge_offset,
        Environment& output
    ) {
        std::unordered_set<std::string> names;
        for (const auto& [name, _] : left) {
            names.insert(name);
        }
        for (const auto& [name, _] : right) {
            names.insert(name);
        }
        output.clear();
        for (const auto& name : names) {
            const auto left_value = left.find(name);
            const auto right_value = right.find(name);
            if (left_value != left.end() && right_value != right.end() &&
                left_value->second == right_value->second) {
                output[name] = left_value->second;
                continue;
            }
            const auto merged = graph_.addNode(merge_offset);
            if (left_value != left.end()) {
                graph_.addEdge(left_value->second, merged);
            }
            if (right_value != right.end()) {
                graph_.addEdge(right_value->second, merged);
            }
            output[name] = merged;
        }
    }

    void processBranch(
        TSNode branch,
        std::size_t scope_index,
        Environment& environment
    ) {
        const auto condition = field(branch, "condition");
        static_cast<void>(expressionDependencies(condition, scope_index, environment));

        const auto before = environment;
        Environment consequence = before;
        Environment alternative = before;
        const auto consequence_node = field(branch, "consequence");
        const auto alternative_node = field(branch, "alternative");
        processStatement(consequence_node, scope_index, consequence);
        if (!ts_node_is_null(alternative_node)) {
            processStatement(alternative_node, scope_index, alternative);
        }
        mergeEnvironments(
            consequence,
            alternative,
            ts_node_start_byte(branch),
            environment
        );
    }

    void processLoop(
        TSNode loop,
        std::size_t scope_index,
        Environment& environment
    ) {
        const auto before = environment;
        const auto body = field(loop, "body");
        const auto consequence = field(loop, "consequence");
        const auto body_node = ts_node_is_null(body) ? consequence : body;
        const auto child_count = ts_node_named_child_count(loop);
        for (std::uint32_t index = 0; index < child_count; ++index) {
            const auto child = ts_node_named_child(loop, index);
            if (child.id != body_node.id) {
                static_cast<void>(expressionDependencies(child, scope_index, environment));
            }
        }
        Environment loop_environment = before;
        processStatement(body_node, scope_index, loop_environment);
        mergeEnvironments(
            before,
            loop_environment,
            ts_node_start_byte(loop),
            environment
        );
    }

    void processStatement(
        TSNode statement,
        std::size_t scope_index,
        Environment& environment
    ) {
        if (ts_node_is_null(statement)) {
            return;
        }
        const auto type = nodeType(statement);
        if (isScopeNode(type) && statement.id != scopes_[scope_index].node.id) {
            return;
        }
        if (isAssignmentNode(type)) {
            processAssignment(statement, scope_index, environment);
            return;
        }
        if (type == "return_statement") {
            const auto count = ts_node_named_child_count(statement);
            if (count != 0 && scopes_[scope_index].callable) {
                const auto dependencies = expressionDependencies(
                    ts_node_named_child(statement, 0),
                    scope_index,
                    environment
                );
                for (const auto dependency : dependencies) {
                    graph_.addEdge(dependency, scopes_[scope_index].return_node);
                }
            }
            return;
        }
        if (type == "if_statement" || type == "elif_clause") {
            processBranch(statement, scope_index, environment);
            return;
        }
        if (type == "for_statement" || type == "for_in_statement" ||
            type == "while_statement") {
            processLoop(statement, scope_index, environment);
            return;
        }
        if (type == "block" || type == "statement_block" ||
            type == "program" || type == "module" || type == "class_body") {
            const auto count = ts_node_named_child_count(statement);
            for (std::uint32_t index = 0; index < count; ++index) {
                processStatement(ts_node_named_child(statement, index), scope_index, environment);
            }
            return;
        }
        if (type == "expression_statement") {
            const auto count = ts_node_named_child_count(statement);
            for (std::uint32_t index = 0; index < count; ++index) {
                const auto expression = ts_node_named_child(statement, index);
                if (isAssignmentNode(nodeType(expression))) {
                    processStatement(expression, scope_index, environment);
                } else {
                    static_cast<void>(expressionDependencies(
                        expression,
                        scope_index,
                        environment
                    ));
                }
            }
            return;
        }
        const auto count = ts_node_named_child_count(statement);
        for (std::uint32_t index = 0; index < count; ++index) {
            processStatement(ts_node_named_child(statement, index), scope_index, environment);
        }
    }

    std::vector<TaintFlow> collectFlows() const {
        std::vector<TaintFlow> flows;
        std::unordered_set<std::string> unique;
        for (const auto& sink : sinks_) {
            for (const auto dependency : sink.dependencies) {
                const auto path = graph_.pathTo(dependency);
                if (path.empty()) {
                    continue;
                }
                const auto key = std::to_string(sink.start_byte) + ":" + sink.name;
                if (!unique.insert(key).second) {
                    break;
                }
                auto flow_path = path;
                if (flow_path.back() != sink.start_byte) {
                    flow_path.push_back(sink.start_byte);
                }
                flows.push_back({
                    graph_.sourceOffset(dependency),
                    sink.start_byte,
                    sink.name,
                    sink.dynamic_code,
                    std::move(flow_path),
                });
                break;
            }
        }
        return flows;
    }

    std::string_view source_;
    TSNode root_;
    DataFlowGraph graph_;
    std::vector<FunctionScope> scopes_;
    std::unordered_map<std::string, std::vector<FunctionScope*>> functions_by_name_;
    std::unordered_map<std::size_t, FlowNodeId> source_nodes_;
    std::unordered_map<std::size_t, FlowNodeId> call_nodes_;
    std::vector<SinkUse> sinks_;
};

}  // namespace

std::vector<TaintFlow> analyzeTaintFlows(std::string_view source, TSNode root) {
    return TaintAnalyzer(source, root).run();
}
