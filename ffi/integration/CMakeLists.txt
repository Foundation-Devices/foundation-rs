# SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
# SPDX-License-Identifier: GPL-3.0-or-later

cmake_minimum_required(VERSION 3.22)
project(foundation-ffi C CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 14)

FetchContent_Declare(
        Corrosion
        GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
        GIT_TAG v0.3.5
)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.13.0
)

FetchContent_MakeAvailable(Corrosion)
FetchContent_MakeAvailable(googletest)

corrosion_import_crate(MANIFEST_PATH ../Cargo.toml)

find_package(nlohmann_json 3.2.0 REQUIRED)

enable_testing()
add_executable(integration-codecs codecs.cpp)
target_include_directories(integration-codecs PUBLIC ../include)
target_link_libraries(
        integration-codecs
        PUBLIC foundation-ffi
        PRIVATE GTest::gtest_main nlohmann_json::nlohmann_json
)
include(GoogleTest)
gtest_discover_tests(integration-codecs)
