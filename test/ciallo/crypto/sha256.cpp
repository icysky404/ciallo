#include "ciallo/crypto/sha2.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <random>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace ciallo;
using namespace std::string_view_literals;

/// @brief
///   SHA256 round constants (FIPS 180-4, section 4.2.2).
static constexpr std::uint32_t sha256_round_constants[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

/// @brief
///   Initial SHA256 hash value (FIPS 180-4, section 5.3.3).
static constexpr std::uint32_t sha256_initial_state[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// @brief
///   Rotate a 32-bit value to the right.
[[nodiscard]] static std::uint32_t rotr(std::uint32_t value, int amount) noexcept {
    return (value >> amount) | (value << (32 - amount));
}

/// @brief
///   SHA256 @c Ch function.
[[nodiscard]] static std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

/// @brief
///   SHA256 @c Maj function.
[[nodiscard]] static std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

/// @brief
///   SHA256 upper-case sigma 0 function.
[[nodiscard]] static std::uint32_t big_sigma0(std::uint32_t value) noexcept {
    return rotr(value, 2) ^ rotr(value, 13) ^ rotr(value, 22);
}

/// @brief
///   SHA256 upper-case sigma 1 function.
[[nodiscard]] static std::uint32_t big_sigma1(std::uint32_t value) noexcept {
    return rotr(value, 6) ^ rotr(value, 11) ^ rotr(value, 25);
}

/// @brief
///   SHA256 lower-case sigma 0 function.
[[nodiscard]] static std::uint32_t small_sigma0(std::uint32_t value) noexcept {
    return rotr(value, 7) ^ rotr(value, 18) ^ (value >> 3);
}

/// @brief
///   SHA256 lower-case sigma 1 function.
[[nodiscard]] static std::uint32_t small_sigma1(std::uint32_t value) noexcept {
    return rotr(value, 17) ^ rotr(value, 19) ^ (value >> 10);
}

/// @brief
///   Straightforward SHA256 used as the test oracle.
/// @param data
///   Pointer to start of data to calculate SHA256 for.
/// @param size
///   Size in byte of data to calculate SHA256 for.
/// @return
///   SHA256 hash value.
[[nodiscard]] static std::array<std::uint8_t, 32> reference_sha256(const std::uint8_t *data,
                                                                   std::size_t size) {
    std::array<std::uint32_t, 8> state = {};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = sha256_initial_state[index];
    }

    // Pad the message with 0x80, zeros, and the 64-bit big-endian bit length.
    const std::uint64_t bit_length = static_cast<std::uint64_t>(size) * 8;
    const std::size_t padded_size  = ((size + 8) / 64 + 1) * 64;

    std::vector<std::uint8_t> message(padded_size, 0);
    if (size != 0) {
        std::memcpy(message.data(), data, size);
    }
    message[size] = 0x80;
    for (std::size_t index = 0; index < 8; ++index) {
        message[padded_size - 1 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8));
    }

    for (std::size_t block = 0; block < padded_size; block += 64) {
        std::uint32_t words[64];
        for (std::size_t index = 0; index < 16; ++index) {
            const std::uint8_t *word = message.data() + block + index * 4;
            words[index]             = (static_cast<std::uint32_t>(word[0]) << 24) |
                                       (static_cast<std::uint32_t>(word[1]) << 16) |
                                       (static_cast<std::uint32_t>(word[2]) << 8) |
                                       static_cast<std::uint32_t>(word[3]);
        }
        for (std::size_t index = 16; index < 64; ++index) {
            words[index] = words[index - 16] + small_sigma0(words[index - 15]) + words[index - 7] +
                           small_sigma1(words[index - 2]);
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        std::uint32_t e = state[4];
        std::uint32_t f = state[5];
        std::uint32_t g = state[6];
        std::uint32_t h = state[7];

        for (std::size_t index = 0; index < 64; ++index) {
            const std::uint32_t t1 =
                h + big_sigma1(e) + ch(e, f, g) + sha256_round_constants[index] + words[index];
            const std::uint32_t t2 = big_sigma0(a) + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    std::array<std::uint8_t, 32> digest = {};
    for (std::size_t index = 0; index < state.size(); ++index) {
        digest[index * 4]     = static_cast<std::uint8_t>(state[index] >> 24);
        digest[index * 4 + 1] = static_cast<std::uint8_t>(state[index] >> 16);
        digest[index * 4 + 2] = static_cast<std::uint8_t>(state[index] >> 8);
        digest[index * 4 + 3] = static_cast<std::uint8_t>(state[index]);
    }
    return digest;
}

/// @brief
///   Parse a 64-character hexadecimal string into a SHA256 digest.
/// @param hex
///   Hexadecimal representation of the digest.
/// @return
///   Parsed digest.
[[nodiscard]] static std::array<std::uint8_t, 32> from_hex(std::string_view hex) {
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(character - 'A' + 10);
    };

    std::array<std::uint8_t, 32> digest = {};
    for (std::size_t index = 0; index < digest.size(); ++index) {
        digest[index] =
            static_cast<std::uint8_t>((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    }
    return digest;
}

/// @brief
///   Generate deterministic pseudo-random bytes for test inputs.
/// @param size
///   Number of bytes to generate.
/// @param seed
///   Seed of the random engine.
/// @return
///   Vector containing @p size pseudo-random bytes.
[[nodiscard]] static std::vector<std::uint8_t> make_test_data(std::size_t size,
                                                              std::uint64_t seed) {
    std::mt19937_64 engine(seed);

    std::vector<std::uint8_t> data(size);
    for (std::uint8_t &byte : data) {
        byte = static_cast<std::uint8_t>(engine());
    }
    return data;
}

/// @brief
///   Copy @p size bytes from @p source into a buffer holding exactly @p offset + @p size bytes.
///   With AddressSanitizer enabled, any access outside that range is reported immediately.
/// @param source
///   Buffer containing the bytes to copy.
/// @param size
///   Number of bytes to copy.
/// @param offset
///   Offset of the copied bytes inside the returned buffer.
/// @return
///   Exact-size buffer containing the copied input.
[[nodiscard]] static std::vector<std::uint8_t>
make_exact_size_buffer(const std::vector<std::uint8_t> &source,
                       std::size_t size,
                       std::size_t offset) {
    std::vector<std::uint8_t> storage(offset + size);
    if (size != 0) {
        std::memcpy(storage.data() + offset, source.data(), size);
    }
    return storage;
}

/// @brief
///   Input sizes that are close to the padding and message schedule boundaries of SHA256.
static constexpr std::size_t sha256_boundary_sizes[] = {
    55,   56,   63,   64,    65,    119,   120,   127,   128,   129,   191,   192,   193,  255,
    256,  257,  511,  512,   513,   1023,  1024,  1025,  2047,  2048,  2049,  4095,  4096, 4097,
    8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537,
};

/// @brief
///   Number of start offsets to test for unaligned inputs. 64 covers every alignment relative to
///   a 64-byte cache line.
static constexpr std::size_t sha256_alignment_count = 64;

TEST(sha256, known_vectors) {
    // Check values from the FIPS 180-4 examples and common tooling.
    constexpr std::pair<std::string_view, std::string_view> vectors[] = {
        {""sv, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"sv},
        {"a"sv, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"sv},
        {"abc"sv, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"sv},
        {"message digest"sv, "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"sv},
        {"abcdefghijklmnopqrstuvwxyz"sv,
         "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"sv},
        {"The quick brown fox jumps over the lazy dog"sv,
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"sv},
    };

    for (const auto &[input, expected] : vectors) {
        EXPECT_EQ(sha256(input.data(), input.size()), from_hex(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha256, nist_padding_boundary_vector) {
    // Two-block message from FIPS 180-4 / NIST examples.
    constexpr std::string_view input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"sv;
    EXPECT_EQ(sha256(input.data(), input.size()),
              from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"sv));
}

TEST(sha256, nist_million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(sha256(input.data(), input.size()),
              from_hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"sv));
}

TEST(sha256, api_contract) {
    static_assert(std::is_same_v<decltype(sha256(nullptr, 0)), std::array<std::uint8_t, 32>>);
    static_assert(noexcept(sha256(nullptr, 0)));
    static_assert(noexcept(sha256(nullptr, 0, nullptr)));

    // The digest of empty input is the well-known SHA256 value, and a null pointer is valid when
    // size is zero.
    std::array<std::uint8_t, 32> digest = {};
    sha256(nullptr, 0, digest.data());
    EXPECT_EQ(digest,
              from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha256(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha256(input.data(), input.size()));
}

TEST(sha256, matches_reference_for_all_small_sizes) {
    constexpr std::size_t max_size = 600;
    const auto data                = make_test_data(max_size + 16, 1);

    for (std::size_t size = 0; size <= max_size; ++size) {
        for (std::size_t offset = 0; offset < 8; ++offset) {
            const std::uint8_t *input = data.data() + offset;
            ASSERT_EQ(sha256(input, size), reference_sha256(input, size))
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(sha256, matches_reference_at_padding_boundaries) {
    // Boundaries of the padding rules and of the message schedule.
    const auto data = make_test_data(65537 + 16, 2);

    for (const std::size_t size : sha256_boundary_sizes) {
        for (const std::size_t offset : {std::size_t{0}, std::size_t{7}}) {
            const std::uint8_t *input = data.data() + offset;
            EXPECT_EQ(sha256(input, size), reference_sha256(input, size))
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(sha256, matches_reference_for_random_sizes) {
    constexpr std::size_t max_size = 16384;
    const auto data                = make_test_data(max_size + 16, 3);

    std::random_device random_dev;
    std::mt19937_64 engine(random_dev());
    std::uniform_int_distribution<std::size_t> size_distribution(0, max_size);
    std::uniform_int_distribution<std::size_t> offset_distribution(0, 15);

    for (int iteration = 0; iteration < 200; ++iteration) {
        const std::size_t size    = size_distribution(engine);
        const std::size_t offset  = offset_distribution(engine);
        const std::uint8_t *input = data.data() + offset;

        EXPECT_EQ(sha256(input, size), reference_sha256(input, size))
            << "size=" << size << ", offset=" << offset;
    }
}

TEST(sha256, matches_reference_for_constant_patterns) {
    constexpr std::size_t sizes[] = {1, 7, 16, 17, 32, 33, 55, 56, 63, 64, 65, 4096, 4097};

    for (const std::uint8_t value :
         {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x55}, std::uint8_t{0xAA}}) {
        for (const std::size_t size : sizes) {
            const std::vector<std::uint8_t> data(size, value);
            EXPECT_EQ(sha256(data.data(), size), reference_sha256(data.data(), size))
                << "value=" << static_cast<int>(value) << ", size=" << size;
        }
    }
}

TEST(sha256, result_is_independent_of_alignment) {
    constexpr std::size_t size = 4096;
    const auto data            = make_test_data(size, 5);
    const auto expected        = sha256(data.data(), size);

    std::vector<std::uint8_t> storage(size + 16);
    for (std::size_t offset = 0; offset < 16; ++offset) {
        std::memcpy(storage.data() + offset, data.data(), size);
        EXPECT_EQ(sha256(storage.data() + offset, size), expected) << "offset=" << offset;
    }
}

TEST(sha256, large_input_matches_reference) {
    constexpr std::size_t size = std::size_t{1} << 20;
    const auto data            = make_test_data(size, 6);

    EXPECT_EQ(sha256(data.data(), size), reference_sha256(data.data(), size));
}

TEST(sha256, exact_size_allocation_for_all_small_sizes) {
    // Every input owns exactly its own bytes, so AddressSanitizer reports any read outside the
    // input. Varying the offset also exercises unaligned starts for every small size.
    constexpr std::size_t max_size = 600;

    for (std::size_t size = 0; size <= max_size; ++size) {
        const auto source   = make_test_data(size, 9);
        const auto expected = reference_sha256(source.data(), size);

        for (std::size_t offset = 0; offset < sha256_alignment_count; ++offset) {
            const auto storage = make_exact_size_buffer(source, size, offset);

            EXPECT_EQ(sha256(storage.data() + offset, size), expected)
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(sha256, exact_size_allocation_at_padding_boundaries) {
    // Check each padding boundary and its immediate neighbours at every start alignment. Reads
    // past the end or before the start of the exact-size allocation are caught by
    // AddressSanitizer.
    for (const std::size_t boundary : sha256_boundary_sizes) {
        for (const std::size_t size : {boundary - 1, boundary, boundary + 1}) {
            const auto source   = make_test_data(size, 10);
            const auto expected = reference_sha256(source.data(), size);

            for (std::size_t offset = 0; offset < sha256_alignment_count; ++offset) {
                const auto storage = make_exact_size_buffer(source, size, offset);

                EXPECT_EQ(sha256(storage.data() + offset, size), expected)
                    << "size=" << size << ", offset=" << offset;
            }
        }
    }
}
