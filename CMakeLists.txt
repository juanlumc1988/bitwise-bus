# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.

cmake_minimum_required(VERSION 3.16)
project(bitwise-bus LANGUAGES CXX)

option(BW_BUILD_TESTS "Build the unit tests" ON)
option(BW_WERROR      "Treat warnings as errors" OFF)

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

add_library(bw_core STATIC
    src/crc.cpp
    src/catalog.cpp
    src/crc_search.cpp)
target_include_directories(bw_core PUBLIC include)
bw_configure(bw_core)

add_executable(bitwise tools/main.cpp)
target_link_libraries(bitwise PRIVATE bw_core)
bw_configure(bitwise)

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
