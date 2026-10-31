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

const auto hash = [](const void *data, std::size_t size) noexcept { return sha512(data, size); };

const auto reference = [](const std::uint8_t *data, std::size_t size) {
    return sha2_test::reference_sha512(data, size);
};

constexpr std::array<std::size_t, 15> padding_boundaries = {
    111, 112, 127, 128, 129, 239, 240, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

} // namespace

TEST(sha512, known_vectors) {
    // Check values from the FIPS 180-4 examples and common tooling.
    constexpr std::pair<std::string_view, std::string_view> vectors[] = {
        {""sv, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"sv},
        {"abc"sv, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"sv},
        {"message digest"sv, "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
                             "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"sv},
        {"The quick brown fox jumps over the lazy dog"sv,
         "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64"
         "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"sv},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"sv,
         "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
         "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"sv},
    };

    for (const auto &[input, expected] : vectors) {
        EXPECT_EQ(hash(input.data(), input.size()), sha2_test::from_hex<64>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha512, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(hash(input.data(), input.size()),
              sha2_test::from_hex<64>(
                  "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                  "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"sv));
}

TEST(sha512, api_contract) {
    static_assert(std::is_same_v<decltype(sha512(nullptr, 0)), std::array<std::uint8_t, 64>>);
    static_assert(noexcept(sha512(nullptr, 0)));
    static_assert(noexcept(sha512(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 64> digest = {};
    sha512(nullptr, 0, digest.data());
    EXPECT_EQ(digest, sha2_test::from_hex<64>(
                          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                          "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha512(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha512(input.data(), input.size()));
}

TEST(sha512, matches_reference_for_all_small_sizes) {
    sha2_test::check_all_small(hash, reference, 600, 31);
}

TEST(sha512, matches_reference_at_padding_boundaries) {
    sha2_test::check_boundaries(hash, reference, padding_boundaries, 32);
}

TEST(sha512, matches_reference_for_random_sizes) {
    sha2_test::check_random(hash, reference, 16384, 33);
}

TEST(sha512, result_is_independent_of_alignment) {
    sha2_test::check_alignment(hash, reference, 4096, 34);
}

TEST(sha512, large_input_matches_reference) {
    sha2_test::check_large(hash, reference, std::size_t{1} << 20, 35);
}

TEST(sha512, exact_size_allocation_for_all_small_sizes) {
    sha2_test::check_exact_size(hash, reference, 300, 36);
}
