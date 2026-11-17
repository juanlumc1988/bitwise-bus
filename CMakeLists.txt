# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.

cmake_minimum_required(VERSION 3.16)
project(bitwise-bus VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BW_BUILD_TESTS "Build the unit tests" ON)
option(BW_WERROR      "Treat warnings as errors" OFF)
option(BW_STATIC_CLI  "Link the bitwise CLI's C++ runtime statically (GCC, MinGW)" OFF)

# C++17 throughout.
#
# Unlike rewind-mcu -- where core/ and target/ are pinned to strict C++98
# because they cross-compile to a microcontroller -- nothing here ever leaves
# a workstation. This is an analysis tool: it reads capture files, searches a
# parameter space and prints an answer. Constraining the standard would buy
# nothing and cost the standard library.

set(BW_WARNINGS "")
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(BW_WARNINGS -Wall -Wextra)
    if(BW_WERROR)
        list(APPEND BW_WARNINGS -Werror)
    endif()
elseif(MSVC)
    set(BW_WARNINGS /W4)
    if(BW_WERROR)
        list(APPEND BW_WARNINGS /WX)
    endif()
endif()

function(bw_configure tgt)
    set_target_properties(${tgt} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)
    target_compile_options(${tgt} PRIVATE ${BW_WARNINGS})
endfunction()

# Static only. The public API passes std::vector across the boundary, so a
# shared library's ABI would depend on the consumer's compiler and C++ runtime.
add_library(bw_core STATIC
    src/crc.cpp
    src/catalog.cpp
    src/crc_search.cpp
    src/capture.cpp
    src/model.cpp
    src/evaluate.cpp
    src/dataset.cpp
    src/protocol.cpp
    src/protocols/modbus_rtu.cpp
    src/segmentation.cpp
    src/checksum.cpp
    src/fields.cpp
    src/analyze.cpp)
add_library(bw::core ALIAS bw_core)
set_target_properties(bw_core PROPERTIES EXPORT_NAME core)
target_include_directories(bw_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
bw_configure(bw_core)

if(MSVC)
    # Debug and Release static libraries cannot be linked into one another
    # under MSVC (_ITERATOR_DEBUG_LEVEL, runtime library), and std::vector is
    # in the API. The postfix lets both live in one package; the exported
    # target picks the right file for the consumer's configuration.
    set_target_properties(bw_core PROPERTIES DEBUG_POSTFIX d)
endif()

add_executable(bitwise tools/main.cpp)
target_link_libraries(bitwise PRIVATE bw_core)
bw_configure(bitwise)

# A binary that runs without the toolchain's own runtime libraries next to it.
# Not for MSVC: the CRT has to match the static library's, which consumers pick.
if(BW_STATIC_CLI)
    if(MINGW)
        target_link_options(bitwise PRIVATE -static)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_link_options(bitwise PRIVATE -static-libstdc++ -static-libgcc)
    endif()
endif()

# ---- Install ---------------------------------------------------------------
# Two components so a second configuration (Debug next to Release on MSVC) can
# add its library without replacing the CLI: cmake --install --component dev.
set(BW_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/bitwise-bus)

install(TARGETS bw_core
    EXPORT bw_targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    COMPONENT dev)
install(DIRECTORY include/bw
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT dev
    FILES_MATCHING PATTERN "*.h")
install(EXPORT bw_targets
    FILE bitwise-bus-targets.cmake
    NAMESPACE bw::
    DESTINATION ${BW_CMAKE_DIR}
    COMPONENT dev)

configure_package_config_file(cmake/bitwise-bus-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/bitwise-bus-config.cmake
    INSTALL_DESTINATION ${BW_CMAKE_DIR})
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/bitwise-bus-config-version.cmake
    COMPATIBILITY SameMinorVersion)   # 0.x: a minor bump may break the API
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/bitwise-bus-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/bitwise-bus-config-version.cmake
    DESTINATION ${BW_CMAKE_DIR}
    COMPONENT dev)

install(TARGETS bitwise RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT cli)
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR} COMPONENT dev)

if(BW_BUILD_TESTS)
    enable_testing()

    add_executable(bw_tests
        tests/main.cpp
        tests/test_crc.cpp
        tests/test_crc_search.cpp
        tests/test_capture.cpp
        tests/test_model.cpp
        tests/test_evaluate.cpp
        tests/test_dataset.cpp
        tests/test_protocol.cpp
        tests/test_segmentation.cpp
        tests/test_checksum.cpp
        tests/test_fields.cpp
        tests/test_analyze.cpp)
    target_include_directories(bw_tests PRIVATE tests/third_party)
    target_compile_definitions(bw_tests PRIVATE
        "BW_CORPUS_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus\"")
    target_link_libraries(bw_tests PRIVATE bw_core)
    bw_configure(bw_tests)

    add_test(NAME unit COMMAND bw_tests --force-colors=off)

    # The command line, on a file that is checked in: argument handling and
    # file reading are covered by no unit test.
    # The pattern spans lines with `.*` rather than `\n`: on Windows the lines end in CRLF.
    add_test(NAME cli_capture_info
        COMMAND bitwise capture-info ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/modbus_rtu_two_requests.csv)
    set_tests_properties(cli_capture_info PROPERTIES PASS_REGULAR_EXPRESSION
        "events +16 \\(16 bytes\\).*channels +1: rs485 \\(16\\).*intervals +15 between timed events: min 1145833 ns, median 1145833 ns, max 11145833 ns")

    # Each of these reads the output of the real program. A pattern only has to say
    # that the right thing came out; the exact bytes are checked by the unit tests.
    add_test(NAME cli_protocols COMMAND bitwise protocols)
    set_tests_properties(cli_protocols PROPERTIES PASS_REGULAR_EXPRESSION
        "modbus-rtu +Modbus RTU requests")
    add_test(NAME cli_protocols_model COMMAND bitwise protocols modbus-rtu)
    set_tests_properties(cli_protocols_model PROPERTIES PASS_REGULAR_EXPRESSION
        "framing: idle gap, at least 4010415 ns.*4 \"crc\" +checksum +16 bits @48 little-endian covers 0..3 CRC-16/MODBUS")
    add_test(NAME cli_synth COMMAND bitwise synth modbus-rtu --seed 1 --frames 3)
    set_tests_properties(cli_synth PROPERTIES PASS_REGULAR_EXPRESSION
        "# bitwise-capture 1.*time_ns,channel,direction,id,data.*0,rs485,,,03.*1145833,rs485,,,04")
    add_test(NAME cli_synth_unknown COMMAND bitwise synth nope)
    set_tests_properties(cli_synth_unknown PROPERTIES PASS_REGULAR_EXPRESSION
        "unknown protocol 'nope'; known: modbus-rtu")
    add_test(NAME cli_synth_bad_number COMMAND bitwise synth modbus-rtu --frames 100001)
    set_tests_properties(cli_synth_bad_number PROPERTIES PASS_REGULAR_EXPRESSION
        "--frames: '100001' is not a whole number from 0 to 100000")
    add_test(NAME cli_synth_missing_value COMMAND bitwise synth modbus-rtu --frames)
    set_tests_properties(cli_synth_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--frames needs a value")

    # The pipeline, on a synthetic Modbus RTU capture of 50 frames made by a second
    # implementation: the framing, the checksum and the fields it recovers.
    add_test(NAME cli_analyze
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv)
    set_tests_properties(cli_analyze PROPERTIES PASS_REGULAR_EXPRESSION
        "idle gap: a gap of at least 6918373 ns ends a frame.*type0 +8 bytes, 50 frames; checksum CRC-16/MODBUS, 16 bits little-endian, evidence 800 bits.*5 \"checksum\" +checksum +16 bits @48 little-endian covers 0..4")
    add_test(NAME cli_analyze_option
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv
                --min-frames 51)
    set_tests_properties(cli_analyze_option PROPERTIES PASS_REGULAR_EXPRESSION
        "frames +50 \\(50 of a size too rare to say anything about\\)")
    add_test(NAME cli_analyze_no_file COMMAND bitwise analyze)
    set_tests_properties(cli_analyze_no_file PROPERTIES PASS_REGULAR_EXPRESSION
        "analyze takes exactly one file")
    add_test(NAME cli_analyze_missing_file COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/no-such-file.csv)
    set_tests_properties(cli_analyze_missing_file PROPERTIES PASS_REGULAR_EXPRESSION
        "cannot read .*no-such-file.csv")
    add_test(NAME cli_analyze_not_a_capture COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE)
    set_tests_properties(cli_analyze_not_a_capture PROPERTIES PASS_REGULAR_EXPRESSION
        "LICENSE: line [0-9]+: ")
    add_test(NAME cli_analyze_bad_number
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/modbus_rtu_two_requests.csv --min-frames 0)
    set_tests_properties(cli_analyze_bad_number PROPERTIES PASS_REGULAR_EXPRESSION
        "--min-frames: '0' is not a whole number from 1 to 1000000")
    add_test(NAME cli_analyze_missing_value
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/modbus_rtu_two_requests.csv --min-gap-ratio)
    set_tests_properties(cli_analyze_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--min-gap-ratio needs a value")
endif()
