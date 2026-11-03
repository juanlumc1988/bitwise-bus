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
    src/crc_search.cpp)
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
        tests/test_crc_search.cpp)
    target_include_directories(bw_tests PRIVATE tests/third_party)
    target_link_libraries(bw_tests PRIVATE bw_core)
    bw_configure(bw_tests)

    add_test(NAME unit COMMAND bw_tests --force-colors=off)
endif()
