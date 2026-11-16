cmake_minimum_required(VERSION 3.20)
project(ProtoSecCore VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

FetchContent_Declare(tree_sitter_runtime
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
    GIT_TAG da6fe9beb4f7f67beb75914ca8e0d48ae48d6406
    GIT_SHALLOW TRUE
)
FetchContent_Declare(tree_sitter_typescript
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-typescript.git
    GIT_TAG f975a621f4e7f532fe322e13c4f79495e0a7b2e7
    GIT_SHALLOW TRUE
)
FetchContent_Declare(tree_sitter_python
    GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-python.git
    GIT_TAG bffb65a8cfe4e46290331dfef0dbf0ef3679de11
    GIT_SHALLOW TRUE
)
FetchContent_Declare(tree_sitter_sql
    GIT_REPOSITORY https://github.com/m-novikov/tree-sitter-sql.git
    GIT_TAG 587f30d184b058450be2a2330878210c5f33b3f9
    GIT_SHALLOW TRUE
)

foreach(dependency IN ITEMS
        tree_sitter_runtime
        tree_sitter_typescript
        tree_sitter_python
        tree_sitter_sql)
    FetchContent_GetProperties(${dependency})
    if(NOT ${dependency}_POPULATED)
        FetchContent_Populate(${dependency})
    endif()
endforeach()

set(TREE_SITTER_RUNTIME_DIR "${tree_sitter_runtime_SOURCE_DIR}")
set(TREE_SITTER_TYPESCRIPT_DIR "${tree_sitter_typescript_SOURCE_DIR}")
set(TREE_SITTER_PYTHON_DIR "${tree_sitter_python_SOURCE_DIR}")
set(TREE_SITTER_SQL_DIR "${tree_sitter_sql_SOURCE_DIR}")

add_library(tree_sitter_runtime STATIC
    "${TREE_SITTER_RUNTIME_DIR}/lib/src/lib.c"
)
target_include_directories(tree_sitter_runtime
    PUBLIC "${TREE_SITTER_RUNTIME_DIR}/lib/include"
    PRIVATE "${TREE_SITTER_RUNTIME_DIR}/lib/src"
)

add_library(tree_sitter_typescript STATIC
    "${TREE_SITTER_TYPESCRIPT_DIR}/typescript/src/parser.c"
    "${TREE_SITTER_TYPESCRIPT_DIR}/typescript/src/scanner.c"
    "${TREE_SITTER_TYPESCRIPT_DIR}/tsx/src/parser.c"
    "${TREE_SITTER_TYPESCRIPT_DIR}/tsx/src/scanner.c"
)
target_include_directories(tree_sitter_typescript PRIVATE
    "${TREE_SITTER_TYPESCRIPT_DIR}/typescript/src"
    "${TREE_SITTER_TYPESCRIPT_DIR}/tsx/src"
    "${TREE_SITTER_TYPESCRIPT_DIR}/common"
    "${TREE_SITTER_RUNTIME_DIR}/lib/include"
)
target_link_libraries(tree_sitter_typescript PUBLIC tree_sitter_runtime)

add_library(tree_sitter_python STATIC
    "${TREE_SITTER_PYTHON_DIR}/src/parser.c"
    "${TREE_SITTER_PYTHON_DIR}/src/scanner.c"
)
target_include_directories(tree_sitter_python PRIVATE
    "${TREE_SITTER_PYTHON_DIR}/src"
    "${TREE_SITTER_RUNTIME_DIR}/lib/include"
)
target_link_libraries(tree_sitter_python PUBLIC tree_sitter_runtime)

add_library(tree_sitter_sql STATIC
    "${TREE_SITTER_SQL_DIR}/src/parser.c"
    "${TREE_SITTER_SQL_DIR}/src/scanner.cc"
)
target_include_directories(tree_sitter_sql PRIVATE
    "${TREE_SITTER_SQL_DIR}/src"
    "${TREE_SITTER_RUNTIME_DIR}/lib/include"
)
target_link_libraries(tree_sitter_sql PUBLIC tree_sitter_runtime)

add_library(protosec_scanner
    core/src/scanner.cpp
    core/src/tree_sitter_comments.cpp
)
target_include_directories(protosec_scanner PUBLIC core/include)
target_link_libraries(protosec_scanner
    PUBLIC
        tree_sitter_runtime
        tree_sitter_typescript
        tree_sitter_python
        tree_sitter_sql
)

add_executable(scanner_core core/src/main.cpp)
target_link_libraries(scanner_core PRIVATE protosec_scanner)
target_compile_definitions(scanner_core PRIVATE "PROTOSEC_SOURCE_DIR=\"${PROJECT_SOURCE_DIR}\"")

set_target_properties(scanner_core PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
)

foreach(configuration DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set_target_properties(scanner_core PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY_${configuration} "${CMAKE_BINARY_DIR}/bin"
    )
endforeach()

if(MSVC)
    target_compile_options(protosec_scanner PRIVATE $<$<CONFIG:Release>:/O2> $<$<CONFIG:Release>:/GL>)
    target_compile_options(scanner_core PRIVATE $<$<CONFIG:Release>:/O2> $<$<CONFIG:Release>:/GL>)
    target_link_options(scanner_core PRIVATE $<$<CONFIG:Release>:/LTCG>)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(protosec_scanner PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-Wall>
        $<$<CONFIG:Release>:-Wextra>
        $<$<CONFIG:Release>:-Wpedantic>
        $<$<CONFIG:Release>:-flto>
    )
    target_compile_options(scanner_core PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-Wall>
        $<$<CONFIG:Release>:-Wextra>
        $<$<CONFIG:Release>:-Wpedantic>
        $<$<CONFIG:Release>:-flto>
    )
    target_link_options(scanner_core PRIVATE $<$<CONFIG:Release>:-flto>)
    if(UNIX AND NOT APPLE)
        target_link_libraries(protosec_scanner PUBLIC pthread)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(scanner_tree_sitter_test tests/cpp/test_tree_sitter.cpp)
    target_link_libraries(scanner_tree_sitter_test PRIVATE protosec_scanner)
    add_test(
        NAME scanner_tree_sitter_comments_and_structure
        COMMAND scanner_tree_sitter_test "${CMAKE_BINARY_DIR}/test-workspace"
    )
    add_test(
        NAME scanner_cli_staged_only
        COMMAND
            "${CMAKE_COMMAND}"
            "-DSCANNER=$<TARGET_FILE:scanner_core>"
            "-DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/test_staged_cli.cmake"
    )
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(
            NAME scanner_python_regressions
            COMMAND "${Python3_EXECUTABLE}" -m unittest discover -s tests
        )
        set_tests_properties(
            scanner_python_regressions
            PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        )
    endif()
endif()
