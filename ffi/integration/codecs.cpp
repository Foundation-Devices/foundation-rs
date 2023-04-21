/*
 * SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "foundation.h"

namespace nip19 {
struct TestVector {
    std::string          name;
    std::string          kind;
    std::vector<uint8_t> bytes;
    std::string          encoded;
};

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}

// used by nlohmann::json, C++ magic it seems.
__attribute__((unused)) void from_json(const nlohmann::json& j, TestVector& v) {
    std::string bytes;
    j.at("name").get_to(v.name);
    j.at("kind").get_to(v.kind);
    j.at("bytes").get_to(bytes);
    j.at("encoded").get_to(v.encoded);

    v.bytes = from_hex(bytes);
}

std::vector<TestVector> get_tests(const std::string& path) {
    std::ifstream  file(path);
    nlohmann::json j;
    file >> j;
    return j;
}
}  // namespace nip19

class NIP19Test : public testing::TestWithParam<nip19::TestVector> {};

INSTANTIATE_TEST_SUITE_P(Json,
                         NIP19Test,
                         testing::ValuesIn(nip19::get_tests("../../../test-vectors/data/nip-19.json")));

// Demonstrate some basic assertions.
TEST_P(NIP19Test, Encode) {
    if (GetParam().kind == "npub") {
        EXPECT_EQ(GetParam().bytes.size(), 32) << GetParam().name;

        char npub[FOUNDATION_NPUB_LEN + 1];
        auto bytes  = reinterpret_cast<const uint8_t(*)[32]>(GetParam().bytes.data());
        auto result = reinterpret_cast<uint8_t(*)[FOUNDATION_NPUB_LEN]>(npub);
        foundation_encode_npub(bytes, result);
        npub[FOUNDATION_NPUB_LEN] = '\0';

        EXPECT_EQ(std::strlen(npub), FOUNDATION_NPUB_LEN) << GetParam().name;
        EXPECT_STREQ(npub, GetParam().encoded.data()) << GetParam().name;
    }

    if (GetParam().kind == "nsec") {
        EXPECT_EQ(GetParam().bytes.size(), 32) << GetParam().name;

        char nsec[FOUNDATION_NSEC_LEN + 1];
        auto bytes  = reinterpret_cast<const uint8_t(*)[32]>(GetParam().bytes.data());
        auto result = reinterpret_cast<uint8_t(*)[FOUNDATION_NSEC_LEN]>(nsec);
        foundation_encode_nsec(bytes, result);
        nsec[FOUNDATION_NSEC_LEN] = '\0';

        EXPECT_EQ(std::strlen(nsec), FOUNDATION_NSEC_LEN) << GetParam().name;
        EXPECT_STREQ(nsec, GetParam().encoded.data()) << GetParam().name;
    }
}
