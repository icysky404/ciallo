#include "ciallo/crypto/sha2.hpp"

#include "sha2_reference.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace ciallo;
using namespace std::string_view_literals;

namespace {

const auto hash = [](const void *data, std::size_t size) noexcept { return sha384(data, size); };

const auto reference = [](const std::uint8_t *data, std::size_t size) {
    return sha2_test::reference_sha384(data, size);
};

constexpr std::array<std::size_t, 15> padding_boundaries = {
    111, 112, 127, 128, 129, 239, 240, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

} // namespace

TEST(sha384, known_vectors) {
    // Check values from the FIPS 180-4 examples and common tooling.
    constexpr std::pair<std::string_view, std::string_view> vectors[] = {
        {""sv, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
               "274edebfe76f65fbd51ad2f14898b95b"sv},
        {"abc"sv, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                  "8086072ba1e7cc2358baeca134c825a7"sv},
        {"message digest"sv, "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61"
                             "dbd0d8b4de1390c256dcbb5d5fd99cd5"sv},
        {"The quick brown fox jumps over the lazy dog"sv,
         "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a50"
         "9cb1e5dc1e85a941bbee3d7f2afbc9b1"sv},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"sv,
         "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
         "b0455a8520bc4e6f5fe95b1fe3c8452b"sv},
    };

    for (const auto &[input, expected] : vectors) {
        EXPECT_EQ(hash(input.data(), input.size()), sha2_test::from_hex<48>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha384, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(
        hash(input.data(), input.size()),
        sha2_test::from_hex<48>("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
                                "07b8b3dc38ecc4ebae97ddd87f3d8985"sv));
}

TEST(sha384, api_contract) {
    static_assert(std::is_same_v<decltype(sha384(nullptr, 0)), std::array<std::uint8_t, 48>>);
    static_assert(noexcept(sha384(nullptr, 0)));
    static_assert(noexcept(sha384(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 48> digest = {};
    sha384(nullptr, 0, digest.data());
    EXPECT_EQ(digest, sha2_test::from_hex<48>(
                          "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                          "274edebfe76f65fbd51ad2f14898b95b"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha384(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha384(input.data(), input.size()));
}

TEST(sha384, matches_reference_for_all_small_sizes) {
    sha2_test::check_all_small(hash, reference, 600, 21);
}

TEST(sha384, matches_reference_at_padding_boundaries) {
    sha2_test::check_boundaries(hash, reference, padding_boundaries, 22);
}

TEST(sha384, matches_reference_for_random_sizes) {
    sha2_test::check_random(hash, reference, 16384, 23);
}

TEST(sha384, result_is_independent_of_alignment) {
    sha2_test::check_alignment(hash, reference, 4096, 24);
}

TEST(sha384, large_input_matches_reference) {
    sha2_test::check_large(hash, reference, std::size_t{1} << 20, 25);
}

TEST(sha384, exact_size_allocation_for_all_small_sizes) {
    sha2_test::check_exact_size(hash, reference, 300, 26);
}
