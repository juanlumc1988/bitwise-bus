# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.

cmake_minimum_required(VERSION 3.16)
project(bitwise-bus VERSION 1.0.0 LANGUAGES CXX)

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
    src/sums.cpp
    src/messages.cpp
    src/text.cpp
    src/crc_search.cpp
    src/capture.cpp
    src/model.cpp
    src/evaluate.cpp
    src/dataset.cpp
    src/protocol.cpp
    src/synthetic.cpp
    src/protocols/modbus_rtu.cpp
    src/protocols/ubx.cpp
    src/protocols/mavlink1.cpp
    src/protocols/mavlink2.cpp
    src/protocols/nmea0183.cpp
    src/protocols/slip.cpp
    src/protocols/hdlc_ppp.cpp
    src/segmentation.cpp
    src/checksum.cpp
    src/fields.cpp
    src/analyze.cpp
    src/kaitai.cpp)
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
target_compile_definitions(bitwise PRIVATE BW_VERSION="${PROJECT_VERSION}")
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
    COMPATIBILITY SameMajorVersion)   # 1.x: no break in the API (docs/api.md)
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
        tests/test_analyze.cpp
        tests/test_kaitai.cpp
        tests/test_ubx_mavlink.cpp
        tests/test_nmea.cpp
        tests/test_mavlink2.cpp
        tests/test_stuffing.cpp
        tests/test_flags.cpp
        tests/test_sync.cpp
        tests/test_lines.cpp
        tests/test_unstuff.cpp
        tests/test_sums.cpp
        tests/test_messages.cpp
        tests/test_synthetic.cpp
        tests/test_text.cpp
        tests/test_synthetic_text.cpp
        tests/test_api.cpp)
    target_include_directories(bw_tests PRIVATE tests/third_party)
    # The headers that are installed, to check that docs/api.md says what each one is.
    file(GLOB BW_HEADER_FILES CONFIGURE_DEPENDS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/include/bw
         ${CMAKE_CURRENT_SOURCE_DIR}/include/bw/*.h)
    list(SORT BW_HEADER_FILES)
    list(JOIN BW_HEADER_FILES " " BW_HEADER_LIST)
    target_compile_definitions(bw_tests PRIVATE
        "BW_CORPUS_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus\""
        "BW_ROUNDTRIP_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/tests/roundtrip\""
        "BW_DOCS_DIR=\"${CMAKE_CURRENT_SOURCE_DIR}/docs\""
        "BW_PUBLIC_HEADERS=\"${BW_HEADER_LIST}\""
        "BW_PROJECT_VERSION=\"${PROJECT_VERSION}\"")
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

    # The version is the project's, which the package script and the release tag are checked against.
    add_test(NAME cli_version COMMAND bitwise --version)
    set_tests_properties(cli_version PROPERTIES PASS_REGULAR_EXPRESSION "^bitwise ${PROJECT_VERSION}")

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
    add_test(NAME cli_synth_ubx COMMAND bitwise synth ubx --seed 1 --frames 2)
    set_tests_properties(cli_synth_ubx PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,b5.*86805,uart,,,62.*173610,uart,,,0[0-9a-f]")
    add_test(NAME cli_synth_mavlink1 COMMAND bitwise synth mavlink1 --seed 1 --frames 2)
    set_tests_properties(cli_synth_mavlink1 PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,fe.*173611,uart,,,[0-9a-f][0-9a-f]")
    add_test(NAME cli_synth_mavlink2 COMMAND bitwise synth mavlink2 --seed 1 --frames 2)
    set_tests_properties(cli_synth_mavlink2 PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,fd.*173611,uart,,,[0-9a-f][0-9a-f]")
    add_test(NAME cli_protocols_mavlink2 COMMAND bitwise protocols mavlink2)
    set_tests_properties(cli_protocols_mavlink2 PROPERTIES PASS_REGULAR_EXPRESSION
        "message type 3 \"protocol_version\".*\"message_id\" +constant +24 bits @56 little-endian = 0x12C.*\"payload\" +payload +sized by field 1.*seeded with 217")
    add_test(NAME cli_synth_nmea0183 COMMAND bitwise synth nmea0183 --seed 1 --frames 1)
    set_tests_properties(cli_synth_nmea0183 PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,24.*2083333,uart,,,47.*4166666,uart,,,50")
    add_test(NAME cli_protocols_nmea0183 COMMAND bitwise protocols nmea0183)
    set_tests_properties(cli_protocols_nmea0183 PROPERTIES PASS_REGULAR_EXPRESSION
        "framing: ends with 0xA.*\"address\" +constant +48 bits @8 big-endian = 0x47504747412C.*\"checksum\" +checksum +16 bits @[?] big-endian as hex text covers 1..15 XOR-8")
    add_test(NAME cli_protocols_ubx COMMAND bitwise protocols ubx)
    set_tests_properties(cli_protocols_ubx PROPERTIES PASS_REGULAR_EXPRESSION
        "framing: contiguous, nothing between frames.*message type 0 \"ack_ack\".*message type 2 \"nav_status\".*\"checksum\" +checksum +16 bits @[0-9]+ little-endian covers 2..11 FLETCHER-8")
    add_test(NAME cli_protocols_mavlink1 COMMAND bitwise protocols mavlink1)
    set_tests_properties(cli_protocols_mavlink1 PROPERTIES PASS_REGULAR_EXPRESSION
        "message type 1 \"sys_status\".*\"crc\" +checksum.*CRC-16/MCRF4XX seeded with 124")
    add_test(NAME cli_synth_slip COMMAND bitwise synth slip --seed 1 --frames 2)
    set_tests_properties(cli_synth_slip PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,c0.*86805,uart,,,20.*173610,uart,,,00")
    add_test(NAME cli_synth_hdlc_ppp COMMAND bitwise synth hdlc-ppp --seed 1 --frames 2)
    set_tests_properties(cli_synth_hdlc_ppp PROPERTIES PASS_REGULAR_EXPRESSION
        "time_ns,channel.*0,uart,,,7e.*86805,uart,,,7e.*173610,uart,,,7e.*260415,uart,,,ff.*347220,uart,,,03.*434025,uart,,,80")
    add_test(NAME cli_protocols_slip COMMAND bitwise protocols slip)
    set_tests_properties(cli_protocols_slip PROPERTIES PASS_REGULAR_EXPRESSION
        "framing: between 0xC0, escape 0xDB: 0xC0 as 0xDB 0xDC, 0xDB as 0xDB 0xDD.*message type 0 \"sample\".*\"sequence\" +counter +16 bits @8 big-endian step 1.*message type 1 \"status\".*\"battery\" +payload +16 bits @64")
    add_test(NAME cli_protocols_hdlc_ppp COMMAND bitwise protocols hdlc-ppp)
    set_tests_properties(cli_protocols_hdlc_ppp PROPERTIES PASS_REGULAR_EXPRESSION
        "framing: between 0x7E, escape 0x7D: 0x7E as 0x7D 0x5E, 0x7D as 0x7D 0x5D.*message type 0 \"lcp_echo\".*\"magic_number\" +constant +32 bits @64 big-endian = 0xB7E9A31.*message type 2 \"ip_datagram\".*\"fcs\" +checksum +16 bits @224 little-endian covers 0..3 CRC-16/IBM-SDLC")
    add_test(NAME cli_synth_unknown COMMAND bitwise synth nope)
    set_tests_properties(cli_synth_unknown PROPERTIES PASS_REGULAR_EXPRESSION
        "unknown protocol 'nope'[;] known: hdlc-ppp, mavlink1, mavlink2, modbus-rtu, nmea0183, slip, ubx")
    add_test(NAME cli_synth_bad_number COMMAND bitwise synth modbus-rtu --frames 100001)
    set_tests_properties(cli_synth_bad_number PROPERTIES PASS_REGULAR_EXPRESSION
        "--frames: '100001' is not a whole number from 0 to 100000")
    add_test(NAME cli_synth_random COMMAND bitwise synth random --seed 1 --frames 3)
    set_tests_properties(cli_synth_random PROPERTIES PASS_REGULAR_EXPRESSION
        "# bitwise-capture 1.*time_ns,channel,direction,id,data.*0,line,,,[0-9a-f][0-9a-f]")
    add_test(NAME cli_synth_random_text COMMAND bitwise synth random-text --seed 1 --frames 3)
    set_tests_properties(cli_synth_random_text PROPERTIES PASS_REGULAR_EXPRESSION
        "# bitwise-capture 1.*time_ns,channel,direction,id,data.*0,line,,,[0-9a-f][0-9a-f]")
    add_test(NAME cli_synth_noise_rate COMMAND bitwise synth random --frames 3 --lose-permille 1001)
    set_tests_properties(cli_synth_noise_rate PROPERTIES PASS_REGULAR_EXPRESSION
        "--lose-permille: '1001' is not a whole number from 0 to 1000")
    add_test(NAME cli_synth_noise_missing_value COMMAND bitwise synth random --corrupt-permille)
    set_tests_properties(cli_synth_noise_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--corrupt-permille needs a value")
    add_test(NAME cli_synth_missing_value COMMAND bitwise synth modbus-rtu --frames)
    set_tests_properties(cli_synth_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--frames needs a value")

    # The pipeline, on a synthetic Modbus RTU capture of 50 frames made by a second
    # implementation: the framing, the checksum and the fields it recovers.
    add_test(NAME cli_analyze
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv)
    set_tests_properties(cli_analyze PROPERTIES PASS_REGULAR_EXPRESSION
        "idle gap: a gap of at least 6918373 ns ends a frame.*type0 +8 bytes, 50 frames[;] checksum CRC-16/MODBUS, 16 bits little-endian, evidence 800 bits.*5 \"checksum\" +checksum +16 bits @48 little-endian covers 0..4")
    # And on the two captures of byte-stuffed protocols, which have no gaps to cut at: the flags, and the frames
    # read without them and unstuffed, so that the FCS of PPP is found.
    add_test(NAME cli_analyze_slip
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_slip_seed3_30frames.csv)
    set_tests_properties(cli_analyze_slip PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +flags: the byte 0xC0 bounds each frame \\(60 of them in the capture\\), stuffed.*frames +30\n+type0 +19 bytes, 16 frames[;] no checksum found.*type1 +10 bytes, 14 frames.*framing: between 0xC0")
    add_test(NAME cli_analyze_hdlc_ppp
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_hdlc_ppp_seed2_30frames.csv)
    set_tests_properties(cli_analyze_hdlc_ppp PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +flags: the byte 0x7E bounds each frame \\(90 of them in the capture\\), stuffed.*frames +30\n+type0 +14 bytes, 14 frames[;] checksum CRC-16/IBM-SDLC, 16 bits little-endian, evidence 224 bits.*framing: between 0x7E")
    # And on the three of frames that start with a sync byte and say how long they are.
    add_test(NAME cli_analyze_ubx
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_ubx_seed1_30frames.csv)
    set_tests_properties(cli_analyze_ubx PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +sync byte 0xB5, frame size = the 1-byte length at offset 4 plus 8 \\(0 breaks in the chain\\).*frames +30.*type0 +14 bytes, 12 frames[;] checksum FLETCHER-8, 16 bits little-endian, evidence 144 bits.*type1 +24 bytes, 12 frames[;] checksum FLETCHER-8, 16 bits little-endian, evidence 192 bits.*type2 +10 bytes, 6 frames[;] no checksum found: 2 candidates that cannot be told apart.*framing: contiguous, nothing between frames")
    add_test(NAME cli_analyze_mavlink1
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_mavlink1_seed1_30frames.csv)
    set_tests_properties(cli_analyze_mavlink1 PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +sync byte 0xFE, frame size = the 1-byte length at offset 1 plus 8 \\(0 breaks in the chain\\).*frames +30.*type0 +39 bytes, 11 frames[;] checksum CRC-16/MCRF4XX seeded with 124, 16 bits little-endian, evidence 168 bits.*type1 +36 bytes, 10 frames[;] checksum CRC-16/MCRF4XX seeded with 39, 16 bits little-endian, evidence 152 bits.*type2 +17 bytes, 9 frames[;] checksum CRC-16/MCRF4XX seeded with 50")
    add_test(NAME cli_analyze_mavlink2
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_mavlink2_seed1_30frames.csv)
    set_tests_properties(cli_analyze_mavlink2 PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +sync byte 0xFD, frame size = the 1-byte length at offset 1 plus 12 \\(0 breaks in the chain\\).*frames +30\n+type0 +31 to 43 bytes, 10 frames[;] checksum CRC-16/MCRF4XX seeded with 124, 16 bits little-endian, evidence 152 bits.*type1 +36 to 40 bytes, 8 frames[;] checksum CRC-16/MCRF4XX seeded with 39.*type2 +21 bytes, 6 frames[;] checksum CRC-16/MCRF4XX seeded with 50.*type3 +26 bytes, 6 frames[;] checksum CRC-16/MCRF4XX seeded with 217")
    # And on the one of text, whose sentences end with a line feed, with a second of silence after three.
    add_test(NAME cli_analyze_nmea0183
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_nmea0183_seed3_9frames_jitter300.csv)
    set_tests_properties(cli_analyze_nmea0183 PROPERTIES PASS_REGULAR_EXPRESSION
        "framing +lines: each frame ends with the byte 0x0A \\(9 of them in the capture\\).*frames +9.*framing: ends with 0xA")
    # And on a longer one, where each kind of sentence has enough lines to be a type: the fields that the commas make.
    add_test(NAME cli_analyze_nmea0183_fields
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_nmea0183_seed3_60frames_jitter300.csv)
    set_tests_properties(cli_analyze_nmea0183_fields PROPERTIES PASS_REGULAR_EXPRESSION
        "frames +60\n+type0 +72 to 74 bytes, 20 frames[;] checksum XOR-8, written as two hexadecimal characters, evidence 160 bits.*type2 +36 to 40 bytes, 20 frames.*0 \"field_0\" +constant +8 bits @0 = 0x24.*1 \"field_1\" +constant +48 bits @8 big-endian = 0x47504747412C.*2 \"field_2\" +text +up to 0x2C @56.*\"checksum\" +checksum +16 bits @[?] big-endian as hex text covers 1..15")
    add_test(NAME cli_export_nmea0183
        COMMAND bitwise export ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_nmea0183_seed3_60frames_jitter300.csv --type 2)
    set_tests_properties(cli_export_nmea0183 PROPERTIES PASS_REGULAR_EXPRESSION
        "id: field_2.*type: str.*terminator: 0x2c.*include: true.*encoding: ASCII.*id: checksum.*type: str.*size: 2.*encoding: ASCII")
    add_test(NAME cli_analyze_option
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv
                --min-frames 51)
    set_tests_properties(cli_analyze_option PROPERTIES PASS_REGULAR_EXPRESSION
        "frames +50 \\(50 of a size or kind too rare to say anything about\\)")
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
    set(BW_CORPUS_50 ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv)
    add_test(NAME cli_export COMMAND bitwise export ${BW_CORPUS_50})
    set_tests_properties(cli_export PROPERTIES PASS_REGULAR_EXPRESSION
        "meta:.*id: type0.*seq:.*id: field_0.*type: u1.*id: field_4.*contents: \\[0x00\\].*id: checksum.*type: u2le")
    add_test(NAME cli_export_id COMMAND bitwise export ${BW_CORPUS_50} --format kaitai --type 0 --id modbus_request)
    set_tests_properties(cli_export_id PROPERTIES PASS_REGULAR_EXPRESSION "id: modbus_request")
    # A type of several sizes: the payload is sized by the length, and the CRC after it is read as a number.
    add_test(NAME cli_export_sized_payload
        COMMAND bitwise export ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/synth_mavlink2_seed3_40frames_jitter300.csv --type 0)
    set_tests_properties(cli_export_sized_payload PROPERTIES PASS_REGULAR_EXPRESSION
        "id: length\n    type: u1.*id: payload\n    size: length\n.*id: checksum\n    type: u2le")
    add_test(NAME cli_export_bad_id COMMAND bitwise export ${BW_CORPUS_50} --id Bad)
    set_tests_properties(cli_export_bad_id PROPERTIES PASS_REGULAR_EXPRESSION
        "'Bad' is not a Kaitai identifier")
    add_test(NAME cli_export_bad_format COMMAND bitwise export ${BW_CORPUS_50} --format wireshark)
    set_tests_properties(cli_export_bad_format PROPERTIES PASS_REGULAR_EXPRESSION
        "unknown format 'wireshark'[;] known: kaitai")
    add_test(NAME cli_export_bad_type COMMAND bitwise export ${BW_CORPUS_50} --type 3)
    set_tests_properties(cli_export_bad_type PROPERTIES PASS_REGULAR_EXPRESSION
        "--type 3: the analysis found 1 message type")
    add_test(NAME cli_export_nothing
        COMMAND bitwise export ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/modbus_rtu_two_requests.csv)
    set_tests_properties(cli_export_nothing PROPERTIES PASS_REGULAR_EXPRESSION
        "nothing to export: the analysis of .* found no message type")
    add_test(NAME cli_export_no_file COMMAND bitwise export)
    set_tests_properties(cli_export_no_file PROPERTIES PASS_REGULAR_EXPRESSION
        "export takes exactly one file")
    add_test(NAME cli_export_missing_value COMMAND bitwise export ${BW_CORPUS_50} --id)
    set_tests_properties(cli_export_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--id needs a value")
    add_test(NAME cli_analyze_missing_value
        COMMAND bitwise analyze ${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus/modbus_rtu_two_requests.csv --min-gap-ratio)
    set_tests_properties(cli_analyze_missing_value PROPERTIES PASS_REGULAR_EXPRESSION
        "--min-gap-ratio needs a value")
endif()
