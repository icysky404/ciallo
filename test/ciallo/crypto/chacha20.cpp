#include "ciallo/crypto/chacha20.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <random>
#include <span>
#include <string>
#include <vector>

using namespace ciallo;
using namespace std::string_view_literals;

/// @brief
///   Key used by the RFC 8439 examples, 00 01 02 ... 1f.
static constexpr std::array<std::uint8_t, 32> rfc8439_key = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

/// @brief
///   Nonce used by the RFC 8439 encryption example.
static constexpr std::array<std::uint8_t, 12> rfc8439_nonce = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00,
};

/// @brief
///   Load a 32-bit value in little-endian byte order.
[[nodiscard]] static std::uint32_t load_le32(const std::uint8_t *data) noexcept {
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

/// @brief
///   Store a 32-bit value in little-endian byte order.
static void store_le32(std::uint8_t *data, std::uint32_t value) noexcept {
    data[0] = static_cast<std::uint8_t>(value);
    data[1] = static_cast<std::uint8_t>(value >> 8);
    data[2] = static_cast<std::uint8_t>(value >> 16);
    data[3] = static_cast<std::uint8_t>(value >> 24);
}

/// @brief
///   ChaCha20 quarter round used by the test oracle.
static void
quarter_round(std::uint32_t &a, std::uint32_t &b, std::uint32_t &c, std::uint32_t &d) noexcept {
    a += b;
    d = std::rotl(d ^ a, 16);
    c += d;
    b = std::rotl(b ^ c, 12);
    a += b;
    d = std::rotl(d ^ a, 8);
    c += d;
    b = std::rotl(b ^ c, 7);
}

/// @brief
///   Straightforward ChaCha20 block function used as the test oracle.
[[nodiscard]] static std::array<std::uint8_t, 64>
reference_keystream(const std::array<std::uint8_t, 32> &key,
                    const std::array<std::uint8_t, 12> &nonce,
                    std::uint32_t counter) {
    std::array<std::uint32_t, 16> state = {
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
    };
    for (std::size_t index = 0; index < 8; ++index) {
        state[4 + index] = load_le32(key.data() + index * 4);
    }
    state[12] = counter;
    for (std::size_t index = 0; index < 3; ++index) {
        state[13 + index] = load_le32(nonce.data() + index * 4);
    }

    std::array<std::uint32_t, 16> working = state;
    for (std::size_t round = 0; round < 10; ++round) {
        quarter_round(working[0], working[4], working[8], working[12]);
        quarter_round(working[1], working[5], working[9], working[13]);
        quarter_round(working[2], working[6], working[10], working[14]);
        quarter_round(working[3], working[7], working[11], working[15]);
        quarter_round(working[0], working[5], working[10], working[15]);
        quarter_round(working[1], working[6], working[11], working[12]);
        quarter_round(working[2], working[7], working[8], working[13]);
        quarter_round(working[3], working[4], working[9], working[14]);
    }

    std::array<std::uint8_t, 64> keystream = {};
    for (std::size_t index = 0; index < 16; ++index) {
        store_le32(keystream.data() + index * 4, working[index] + state[index]);
    }
    return keystream;
}

/// @brief
///   Straightforward ChaCha20 implementation used as the test oracle.
[[nodiscard]] static std::vector<std::uint8_t>
reference_chacha20(const std::uint8_t *data,
                   std::size_t size,
                   const std::array<std::uint8_t, 32> &key,
                   const std::array<std::uint8_t, 12> &nonce,
                   std::uint32_t counter) {
    std::vector<std::uint8_t> result(size);
    std::size_t offset = 0;
    while (offset < size) {
        const auto keystream    = reference_keystream(key, nonce, counter);
        const std::size_t count = std::min<std::size_t>(64, size - offset);
        for (std::size_t index = 0; index < count; ++index) {
            result[offset + index] =
                static_cast<std::uint8_t>(data[offset + index] ^ keystream[index]);
        }
        offset += count;
        ++counter;
    }
    return result;
}

/// @brief
///   Encrypt/decrypt data with the public raw-pointer API.
[[nodiscard]] static std::vector<std::uint8_t>
encrypt_chacha20(const std::uint8_t *data,
                 std::size_t size,
                 const std::array<std::uint8_t, 32> &key,
                 const std::array<std::uint8_t, 12> &nonce,
                 std::uint32_t counter) {
    std::vector<std::uint8_t> result(size);
    chacha20(data, size, key.data(), nonce.data(), counter, result.data());
    return result;
}

/// @brief
///   Generate a deterministic key or nonce for test inputs.
template <std::size_t Size>
[[nodiscard]] static std::array<std::uint8_t, Size> make_secret(std::uint64_t seed) {
    std::mt19937_64 engine(seed);

    std::array<std::uint8_t, Size> secret = {};
    for (std::uint8_t &byte : secret) {
        byte = static_cast<std::uint8_t>(engine());
    }
    return secret;
}

/// @brief
///   Generate deterministic pseudo-random bytes for test inputs.
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
///   Parse a hexadecimal string into bytes.
[[nodiscard]] static std::vector<std::uint8_t> from_hex(std::string_view hex) {
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(character - 'A' + 10);
    };

    std::vector<std::uint8_t> bytes(hex.size() / 2);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] =
            static_cast<std::uint8_t>((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    }
    return bytes;
}

/// @brief
///   Compare a ChaCha20 implementation and its reference for all small sizes and alignments.
static void check_all_small(const std::array<std::uint8_t, 32> &key,
                            const std::array<std::uint8_t, 12> &nonce,
                            std::uint32_t counter,
                            std::size_t max_size,
                            std::uint64_t seed) {
    const auto data = make_test_data(max_size + 16, seed);
    for (std::size_t size = 0; size <= max_size; ++size) {
        for (std::size_t offset = 0; offset < 8; ++offset) {
            const std::uint8_t *input = data.data() + offset;
            SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
            EXPECT_EQ(encrypt_chacha20(input, size, key, nonce, counter),
                      reference_chacha20(input, size, key, nonce, counter));
        }
    }
}

/// @brief
///   Compare a ChaCha20 implementation and its reference around every block boundary.
static void check_boundaries(const std::array<std::uint8_t, 32> &key,
                             const std::array<std::uint8_t, 12> &nonce,
                             std::uint32_t counter,
                             std::span<const std::size_t> boundaries,
                             std::uint64_t seed) {
    const std::size_t max_boundary = *std::ranges::max_element(boundaries);
    const auto data                = make_test_data(max_boundary + 1 + 16, seed);

    for (const std::size_t boundary : boundaries) {
        for (const std::size_t size : {boundary - 1, boundary, boundary + 1}) {
            for (const std::size_t offset : {std::size_t{0}, std::size_t{7}}) {
                const std::uint8_t *input = data.data() + offset;
                SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
                EXPECT_EQ(encrypt_chacha20(input, size, key, nonce, counter),
                          reference_chacha20(input, size, key, nonce, counter));
            }
        }
    }
}

/// @brief
///   Compare a ChaCha20 implementation and its reference for random sizes and alignments.
static void check_random(const std::array<std::uint8_t, 32> &key,
                         const std::array<std::uint8_t, 12> &nonce,
                         std::uint32_t counter,
                         std::size_t max_size,
                         std::uint64_t seed) {
    const auto data = make_test_data(max_size + 16, seed);

    std::random_device random_dev;
    std::mt19937_64 engine(random_dev());
    std::uniform_int_distribution<std::size_t> size_distribution(0, max_size);
    std::uniform_int_distribution<std::size_t> offset_distribution(0, 15);

    for (int iteration = 0; iteration < 200; ++iteration) {
        const std::size_t size    = size_distribution(engine);
        const std::size_t offset  = offset_distribution(engine);
        const std::uint8_t *input = data.data() + offset;

        SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
        EXPECT_EQ(encrypt_chacha20(input, size, key, nonce, counter),
                  reference_chacha20(input, size, key, nonce, counter));
    }
}

/// @brief
///   Check that a ChaCha20 implementation does not depend on input alignment.
static void check_alignment(const std::array<std::uint8_t, 32> &key,
                            const std::array<std::uint8_t, 12> &nonce,
                            std::uint32_t counter,
                            std::size_t size,
                            std::uint64_t seed) {
    const auto data     = make_test_data(size, seed);
    const auto expected = encrypt_chacha20(data.data(), size, key, nonce, counter);

    std::vector<std::uint8_t> storage(size + 16);
    for (std::size_t offset = 0; offset < 16; ++offset) {
        std::memcpy(storage.data() + offset, data.data(), size);
        SCOPED_TRACE(testing::Message() << "offset=" << offset);
        EXPECT_EQ(encrypt_chacha20(storage.data() + offset, size, key, nonce, counter), expected);
    }
}

/// @brief
///   Compare a ChaCha20 implementation and its reference for a large input.
static void check_large(const std::array<std::uint8_t, 32> &key,
                        const std::array<std::uint8_t, 12> &nonce,
                        std::uint32_t counter,
                        std::size_t size,
                        std::uint64_t seed) {
    const auto data = make_test_data(size, seed);
    EXPECT_EQ(encrypt_chacha20(data.data(), size, key, nonce, counter),
              reference_chacha20(data.data(), size, key, nonce, counter));
}

/// @brief
///   Exercise exact-size allocations so AddressSanitizer catches out-of-bounds reads.
static void check_exact_size(const std::array<std::uint8_t, 32> &key,
                             const std::array<std::uint8_t, 12> &nonce,
                             std::uint32_t counter,
                             std::size_t max_size,
                             std::uint64_t seed) {
    constexpr std::size_t alignment_count = 64;

    for (std::size_t size = 0; size <= max_size; ++size) {
        const auto source   = make_test_data(size, seed);
        const auto expected = reference_chacha20(source.data(), size, key, nonce, counter);

        for (std::size_t offset = 0; offset < alignment_count; ++offset) {
            const auto storage = make_exact_size_buffer(source, size, offset);
            SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
            EXPECT_EQ(encrypt_chacha20(storage.data() + offset, size, key, nonce, counter),
                      expected);
        }
    }
}

/// @brief
///   Input sizes close to the 64-byte and 256-byte processing boundaries.
static constexpr std::size_t chacha20_boundary_sizes[] = {
    63,   64,   65,   127,  128,  129,  191,   192,   193,   255,   256,   257,
    319,  320,  321,  511,  512,  513,  1023,  1024,  1025,  2047,  2048,  2049,
    4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 65535, 65536, 65537,
};

TEST(chacha20, rfc8439_encryption_vector) {
    constexpr std::string_view plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the "
        "future, sunscreen would be it."sv;

    // RFC 8439, section 2.4.2.
    const auto expected =
        from_hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                 "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                 "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                 "5af90bbf74a35be6b40b8eedf2785e42874d");

    const auto *bytes = reinterpret_cast<const std::uint8_t *>(plaintext.data());
    const auto ciphertext =
        encrypt_chacha20(bytes, plaintext.size(), rfc8439_key, rfc8439_nonce, 1);
    EXPECT_EQ(ciphertext, expected);

    // Make sure the test oracle also agrees with the RFC vector.
    EXPECT_EQ(reference_chacha20(bytes, plaintext.size(), rfc8439_key, rfc8439_nonce, 1), expected);

    // ChaCha20 decryption is the same operation as encryption.
    EXPECT_EQ(encrypt_chacha20(ciphertext.data(), ciphertext.size(), rfc8439_key, rfc8439_nonce, 1),
              std::vector<std::uint8_t>(plaintext.begin(), plaintext.end()));
}

TEST(chacha20, rfc8439_block_vector) {
    // RFC 8439, section 2.3.2.
    constexpr std::array<std::uint8_t, 12> nonce = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x00,
    };
    const auto expected =
        from_hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                 "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");

    const std::vector<std::uint8_t> zeros(64, 0);
    EXPECT_EQ(encrypt_chacha20(zeros.data(), zeros.size(), rfc8439_key, nonce, 1), expected);
    EXPECT_EQ(reference_chacha20(zeros.data(), zeros.size(), rfc8439_key, nonce, 1), expected);
}

TEST(chacha20, zero_key_and_nonce_vector) {
    // Well-known all-zero key/nonce/counter keystream, also produced by OpenSSL 4.1.
    constexpr std::array<std::uint8_t, 32> key   = {};
    constexpr std::array<std::uint8_t, 12> nonce = {};
    const auto expected =
        from_hex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                 "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");

    const std::vector<std::uint8_t> zeros(64, 0);
    EXPECT_EQ(encrypt_chacha20(zeros.data(), zeros.size(), key, nonce, 0), expected);
    EXPECT_EQ(reference_chacha20(zeros.data(), zeros.size(), key, nonce, 0), expected);
}

TEST(chacha20, api_contract) {
    static_assert(
        std::is_same_v<decltype(chacha20(nullptr, 0, nullptr, nullptr, 0, nullptr)), std::size_t>);
    static_assert(noexcept(chacha20(nullptr, 0, nullptr, nullptr, 0, nullptr)));
    static_assert(noexcept(chacha20(nullptr, 0, nullptr, nullptr, nullptr)));

    const auto key   = make_secret<32>(1);
    const auto nonce = make_secret<12>(2);

    // A null data/output pointer is valid when size is zero.
    EXPECT_EQ(chacha20(nullptr, 0, key.data(), nonce.data(), 0, nullptr), std::size_t{0});

    // The default counter overload must behave like an explicit zero counter.
    const auto data = make_test_data(257, 3);
    std::vector<std::uint8_t> with_default_counter(data.size());
    std::vector<std::uint8_t> with_zero_counter(data.size());
    EXPECT_EQ(
        chacha20(data.data(), data.size(), key.data(), nonce.data(), with_default_counter.data()),
        data.size());
    chacha20(data.data(), data.size(), key.data(), nonce.data(), 0, with_zero_counter.data());
    EXPECT_EQ(with_default_counter, with_zero_counter);
}

TEST(chacha20, in_place_encryption_matches_out_of_place) {
    const auto key   = make_secret<32>(4);
    const auto nonce = make_secret<12>(5);
    const auto data  = make_test_data(4096 + 16, 6);

    for (const std::size_t size : {std::size_t{0}, std::size_t{1}, std::size_t{63}, std::size_t{64},
                                   std::size_t{65}, std::size_t{255}, std::size_t{256},
                                   std::size_t{257}, std::size_t{1024}, std::size_t{4096}}) {
        for (const std::size_t offset : {std::size_t{0}, std::size_t{7}}) {
            const std::uint8_t *input = data.data() + offset;
            const auto expected       = encrypt_chacha20(input, size, key, nonce, 9);

            std::vector<std::uint8_t> storage(size + 16);
            if (size != 0) {
                std::memcpy(storage.data() + offset, input, size);
            }
            ciallo::chacha20(storage.data() + offset, size, key.data(), nonce.data(), 9,
                             storage.data() + offset);

            const std::vector<std::uint8_t> actual(
                storage.begin() + static_cast<std::ptrdiff_t>(offset),
                storage.begin() + static_cast<std::ptrdiff_t>(offset + size));
            EXPECT_EQ(actual, expected) << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(chacha20, round_trip_restores_plaintext) {
    const auto key   = make_secret<32>(7);
    const auto nonce = make_secret<12>(8);
    const auto data  = make_test_data(4096, 9);

    for (const std::uint32_t counter :
         {std::uint32_t{0}, std::uint32_t{1}, std::uint32_t{0xFFFFFFFFU}}) {
        const auto ciphertext = encrypt_chacha20(data.data(), data.size(), key, nonce, counter);
        const auto plaintext =
            encrypt_chacha20(ciphertext.data(), ciphertext.size(), key, nonce, counter);
        EXPECT_EQ(plaintext, data) << "counter=" << counter;
    }
}

TEST(chacha20, matches_reference_for_all_small_sizes) {
    const auto key   = make_secret<32>(10);
    const auto nonce = make_secret<12>(11);
    check_all_small(key, nonce, 0, 600, 12);
}

TEST(chacha20, matches_reference_at_block_boundaries) {
    const auto key   = make_secret<32>(13);
    const auto nonce = make_secret<12>(14);
    check_boundaries(key, nonce, 3, chacha20_boundary_sizes, 15);
}

TEST(chacha20, matches_reference_for_random_sizes) {
    const auto key   = make_secret<32>(16);
    const auto nonce = make_secret<12>(17);
    check_random(key, nonce, 7, 16384, 18);
}

TEST(chacha20, matches_reference_for_constant_patterns) {
    const auto key                = make_secret<32>(19);
    const auto nonce              = make_secret<12>(20);
    constexpr std::size_t sizes[] = {1, 7, 16, 63, 64, 65, 255, 256, 257, 1024, 4096};

    for (const std::uint8_t value :
         {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x55}, std::uint8_t{0xAA}}) {
        for (const std::size_t size : sizes) {
            const std::vector<std::uint8_t> data(size, value);
            EXPECT_EQ(encrypt_chacha20(data.data(), size, key, nonce, 5),
                      reference_chacha20(data.data(), size, key, nonce, 5))
                << "value=" << static_cast<int>(value) << ", size=" << size;
        }
    }
}

TEST(chacha20, result_is_independent_of_alignment) {
    const auto key   = make_secret<32>(21);
    const auto nonce = make_secret<12>(22);
    check_alignment(key, nonce, 11, 4096, 23);
}

TEST(chacha20, large_input_matches_reference) {
    const auto key   = make_secret<32>(24);
    const auto nonce = make_secret<12>(25);
    check_large(key, nonce, 13, std::size_t{1} << 20, 26);
}

TEST(chacha20, counter_wraps_around) {
    const auto key   = make_secret<32>(27);
    const auto nonce = make_secret<12>(28);
    const auto data  = make_test_data(4096, 29);

    EXPECT_EQ(encrypt_chacha20(data.data(), data.size(), key, nonce, 0xFFFFFFFFU),
              reference_chacha20(data.data(), data.size(), key, nonce, 0xFFFFFFFFU));
}

TEST(chacha20, exact_size_allocation_for_all_small_sizes) {
    const auto key   = make_secret<32>(30);
    const auto nonce = make_secret<12>(31);
    check_exact_size(key, nonce, 15, 300, 32);
}

TEST(chacha20, exact_size_allocation_at_block_boundaries) {
    const auto key                        = make_secret<32>(33);
    const auto nonce                      = make_secret<12>(34);
    constexpr std::size_t alignment_count = 64;

    for (const std::size_t boundary : chacha20_boundary_sizes) {
        for (const std::size_t size : {boundary - 1, boundary, boundary + 1}) {
            const auto source   = make_test_data(size, 35);
            const auto expected = reference_chacha20(source.data(), size, key, nonce, 17);

            for (std::size_t offset = 0; offset < alignment_count; ++offset) {
                const auto storage = make_exact_size_buffer(source, size, offset);
                SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
                EXPECT_EQ(encrypt_chacha20(storage.data() + offset, size, key, nonce, 17),
                          expected);
            }
        }
    }
}

TEST(chacha20, exact_size_allocation_in_place) {
    const auto key                        = make_secret<32>(41);
    const auto nonce                      = make_secret<12>(42);
    constexpr std::size_t alignment_count = 64;
    constexpr std::size_t sizes[]         = {1,   63,  64,  65,   127,  128,  129,  255,  256, 257,
                                             511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097};

    for (const std::size_t size : sizes) {
        const auto source   = make_test_data(size, 43);
        const auto expected = reference_chacha20(source.data(), size, key, nonce, 21);

        for (std::size_t offset = 0; offset < alignment_count; ++offset) {
            auto storage         = make_exact_size_buffer(source, size, offset);
            std::uint8_t *buffer = storage.data() + offset;

            // The allocation is exactly offset + size bytes.  Passing the same pointer as input
            // and output makes AddressSanitizer catch any read or write outside that range.
            SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
            ciallo::chacha20(buffer, size, key.data(), nonce.data(), 21, buffer);
            EXPECT_TRUE(std::ranges::equal(std::span<const std::uint8_t>(buffer, size), expected));
        }
    }
}

TEST(chacha20, template_overload) {
    const auto key      = make_secret<32>(36);
    const auto nonce    = make_secret<12>(37);
    const auto data     = make_test_data(257, 38);
    const auto expected = reference_chacha20(data.data(), data.size(), key, nonce, 19);

    auto bytes = chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), key, nonce, 19);
    static_assert(std::is_same_v<decltype(bytes), std::vector<std::uint8_t>>);
    EXPECT_EQ(bytes, expected);

    const auto text = chacha20<std::string>(data.data(), data.size(), key, nonce, 19);
    EXPECT_EQ(std::vector<std::uint8_t>(text.begin(), text.end()), expected);

    // Any contiguous container can hold the key and nonce.
    const std::vector<std::uint8_t> key_vector(key.begin(), key.end());
    const std::vector<std::uint8_t> nonce_vector(nonce.begin(), nonce.end());
    EXPECT_EQ(
        chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), key_vector, nonce_vector, 19),
        expected);

    const std::string key_string(reinterpret_cast<const char *>(key.data()), key.size());
    const std::string nonce_string(reinterpret_cast<const char *>(nonce.data()), nonce.size());
    EXPECT_EQ(
        chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), key_string, nonce_string, 19),
        expected);

    std::uint8_t key_array[32]   = {};
    std::uint8_t nonce_array[12] = {};
    std::ranges::copy(key, key_array);
    std::ranges::copy(nonce, nonce_array);
    EXPECT_EQ(
        chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), key_array, nonce_array, 19),
        expected);

    // The key size is measured in bytes, not elements.
    std::array<std::uint32_t, 8> word_key = {};
    std::memcpy(word_key.data(), key.data(), key.size());
    EXPECT_EQ(chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), word_key, nonce, 19),
              expected);

    // The counter defaults to zero.
    EXPECT_EQ(chacha20<std::vector<std::uint8_t>>(data.data(), data.size(), key, nonce),
              reference_chacha20(data.data(), data.size(), key, nonce, 0));

    // A zero-size request is valid with a null data pointer.
    EXPECT_TRUE(chacha20<std::vector<std::uint8_t>>(nullptr, 0, key, nonce).empty());
}

TEST(chacha20, template_overload_rejects_bad_key_or_nonce_size) {
    const auto key                                 = make_secret<32>(39);
    const auto nonce                               = make_secret<12>(40);
    const std::array<std::uint8_t, 31> short_key   = {};
    const std::array<std::uint8_t, 11> short_nonce = {};

    EXPECT_THROW((chacha20<std::vector<std::uint8_t>>(nullptr, 0, short_key, nonce)),
                 std::invalid_argument);
    EXPECT_THROW((chacha20<std::vector<std::uint8_t>>(nullptr, 0, key, short_nonce)),
                 std::invalid_argument);
}
