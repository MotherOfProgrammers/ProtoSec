cmake_minimum_required(VERSION 3.20)
project(ProtoSecCore VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(scanner_core
    core/src/main.cpp
    core/src/scanner.cpp
)

target_include_directories(scanner_core PRIVATE core/include)
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
    target_compile_options(scanner_core PRIVATE $<$<CONFIG:Release>:/O2> $<$<CONFIG:Release>:/GL>)
    target_link_options(scanner_core PRIVATE $<$<CONFIG:Release>:/LTCG>)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(scanner_core PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-Wall>
        $<$<CONFIG:Release>:-Wextra>
        $<$<CONFIG:Release>:-Wpedantic>
        $<$<CONFIG:Release>:-flto>
    )
    target_link_options(scanner_core PRIVATE $<$<CONFIG:Release>:-flto>)
    if(UNIX AND NOT APPLE)
        target_link_libraries(scanner_core PRIVATE pthread)
    endif()
endif()
