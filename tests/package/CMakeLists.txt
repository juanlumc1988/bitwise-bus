# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
#
# Consumes an *installed* bitwise-bus the way a user would, so what is tested
# is the package and not the build tree. scripts/package.sh drives it:
#
#   cmake -S tests/package -B build-consumer -DCMAKE_PREFIX_PATH=<install dir>

cmake_minimum_required(VERSION 3.16)
project(bw_consumer LANGUAGES CXX)

# The headers are plain C++11; only the library itself is built as C++17.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(BW_EXPECT_VERSION "" CACHE STRING "Exact package version to require")
if(BW_EXPECT_VERSION)
    find_package(bitwise-bus ${BW_EXPECT_VERSION} EXACT CONFIG REQUIRED)
else()
    find_package(bitwise-bus CONFIG REQUIRED)
endif()

# Every installed header stands on its own, as plain C++11: one translation unit for each.
get_target_property(bw_include bw::core INTERFACE_INCLUDE_DIRECTORIES)
file(GLOB bw_headers RELATIVE "${bw_include}" "${bw_include}/bw/*.h")
if(NOT bw_headers)
    message(FATAL_ERROR "no header found under ${bw_include}/bw")
endif()
set(bw_header_sources "")
foreach(header ${bw_headers})
    string(REPLACE "/" "_" stem "${header}")
    set(source "${CMAKE_CURRENT_BINARY_DIR}/header_${stem}.cpp")
    file(WRITE "${source}" "#include \"${header}\"\n")
    list(APPEND bw_header_sources "${source}")
endforeach()
add_library(headers OBJECT ${bw_header_sources})
target_link_libraries(headers PRIVATE bw::core)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE bw::core)
add_dependencies(consumer headers)

enable_testing()
add_test(NAME consumer COMMAND consumer)
