#pragma once

#include "tree_sitter_comments.hpp"

#include <tree_sitter/api.h>

#include <string_view>
#include <vector>

[[nodiscard]] std::vector<TaintFlow> analyzeTaintFlows(
    std::string_view source,
    TSNode root
);
