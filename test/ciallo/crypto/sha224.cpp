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

const auto hash = [](const void *data, std::size_t size) noexcept { return sha224(data, size); };

const auto reference = [](const std::uint8_t *data, std::size_t size) {
    return sha2_test::reference_sha224(data, size);
};

constexpr std::array<std::size_t, 18> padding_boundaries = {
    55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

} // namespace

TEST(sha224, known_vectors) {
    // Check values from the FIPS 180-4 examples and common tooling.
    constexpr std::pair<std::string_view, std::string_view> vectors[] = {
        {""sv, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"sv},
        {"a"sv, "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5"sv},
        {"abc"sv, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"sv},
        {"message digest"sv, "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb"sv},
        {"The quick brown fox jumps over the lazy dog"sv,
         "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525"sv},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"sv,
         "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"sv},
    };

    for (const auto &[input, expected] : vectors) {
        EXPECT_EQ(hash(input.data(), input.size()), sha2_test::from_hex<28>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha224, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(
        hash(input.data(), input.size()),
        sha2_test::from_hex<28>("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"sv));
}

TEST(sha224, api_contract) {
    static_assert(std::is_same_v<decltype(sha224(nullptr, 0)), std::array<std::uint8_t, 28>>);
    static_assert(noexcept(sha224(nullptr, 0)));
    static_assert(noexcept(sha224(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 28> digest = {};
    sha224(nullptr, 0, digest.data());
    EXPECT_EQ(digest, sha2_test::from_hex<28>(
                          "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha224(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha224(input.data(), input.size()));
}

TEST(sha224, matches_reference_for_all_small_sizes) {
    sha2_test::check_all_small(hash, reference, 600, 11);
}

TEST(sha224, matches_reference_at_padding_boundaries) {
    sha2_test::check_boundaries(hash, reference, padding_boundaries, 12);
}

TEST(sha224, matches_reference_for_random_sizes) {
    sha2_test::check_random(hash, reference, 16384, 13);
}

TEST(sha224, result_is_independent_of_alignment) {
    sha2_test::check_alignment(hash, reference, 4096, 14);
}

TEST(sha224, large_input_matches_reference) {
    sha2_test::check_large(hash, reference, std::size_t{1} << 20, 15);
}

TEST(sha224, exact_size_allocation_for_all_small_sizes) {
    sha2_test::check_exact_size(hash, reference, 300, 16);
}
