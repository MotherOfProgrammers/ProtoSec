set(snapshot "${SOURCE_DIR}/tests/fixtures/staged_snapshot")
set(clean_snapshot "${SOURCE_DIR}/tests/fixtures/staged_snapshot_clean")

execute_process(
    COMMAND "${SCANNER}" --staged-only "${snapshot}"
    RESULT_VARIABLE staged_result
    OUTPUT_VARIABLE staged_output
    ERROR_VARIABLE staged_error
)
if(NOT staged_result EQUAL 1)
    message(FATAL_ERROR "Staged findings must fail the commit (exit=${staged_result}): ${staged_error}")
endif()
if(NOT staged_output MATCHES "SEC-001")
    message(FATAL_ERROR "Staged scan did not return its JSON findings: ${staged_output}")
endif()

execute_process(
    COMMAND "${SCANNER}" --staged-only "${clean_snapshot}"
    RESULT_VARIABLE clean_staged_result
    OUTPUT_VARIABLE clean_staged_output
    ERROR_VARIABLE clean_staged_error
)
if(NOT clean_staged_result EQUAL 0)
    message(FATAL_ERROR "A clean staged snapshot must pass (exit=${clean_staged_result}): ${clean_staged_error}")
endif()

execute_process(
    COMMAND "${SCANNER}" "${snapshot}"
    RESULT_VARIABLE regular_result
    OUTPUT_VARIABLE regular_output
    ERROR_VARIABLE regular_error
)
if(NOT regular_result EQUAL 0)
    message(FATAL_ERROR "Regular scans must retain their existing exit behavior (exit=${regular_result}): ${regular_error}")
endif()
