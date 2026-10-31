#include "ciallo/crypto/sha2.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <random>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace ciallo;
using namespace std::string_view_literals;

/// @brief
///   SHA256/SHA224 round constants (FIPS 180-4, section 4.2.2).
static constexpr std::uint32_t k256[64] = {
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
///   Initial SHA256 hash value.
static constexpr std::uint32_t iv256[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// @brief
///   Initial SHA224 hash value.
static constexpr std::uint32_t iv224[8] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
};

/// @brief
///   SHA512/SHA384 round constants (FIPS 180-4, section 4.2.3).
static constexpr std::uint64_t k512[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL,
};

/// @brief
///   Initial SHA512 hash value.
static constexpr std::uint64_t iv512[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
};

/// @brief
///   Initial SHA384 hash value.
static constexpr std::uint64_t iv384[8] = {
    0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL, 0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
};

/// @brief
///   Rotate a word to the right.
template <typename Word>
[[nodiscard]] static Word rotr(Word value, int amount) noexcept {
    constexpr int word_bits = static_cast<int>(sizeof(Word) * 8);
    return static_cast<Word>((value >> amount) | (value << (word_bits - amount)));
}

/// @brief
///   SHA-2 @c Ch function.
template <typename Word>
[[nodiscard]] static Word ch(Word x, Word y, Word z) noexcept {
    return (x & y) ^ (~x & z);
}

/// @brief
///   SHA-2 @c Maj function.
template <typename Word>
[[nodiscard]] static Word maj(Word x, Word y, Word z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

/// @brief
///   SHA-2 upper-case sigma 0 function.
template <typename Word>
[[nodiscard]] static Word big_sigma0(Word value) noexcept {
    if constexpr (sizeof(Word) == 4) {
        return rotr(value, 2) ^ rotr(value, 13) ^ rotr(value, 22);
    } else {
        return rotr(value, 28) ^ rotr(value, 34) ^ rotr(value, 39);
    }
}

/// @brief
///   SHA-2 upper-case sigma 1 function.
template <typename Word>
[[nodiscard]] static Word big_sigma1(Word value) noexcept {
    if constexpr (sizeof(Word) == 4) {
        return rotr(value, 6) ^ rotr(value, 11) ^ rotr(value, 25);
    } else {
        return rotr(value, 14) ^ rotr(value, 18) ^ rotr(value, 41);
    }
}

/// @brief
///   SHA-2 lower-case sigma 0 function.
template <typename Word>
[[nodiscard]] static Word small_sigma0(Word value) noexcept {
    if constexpr (sizeof(Word) == 4) {
        return rotr(value, 7) ^ rotr(value, 18) ^ (value >> 3);
    } else {
        return rotr(value, 1) ^ rotr(value, 8) ^ (value >> 7);
    }
}

/// @brief
///   SHA-2 lower-case sigma 1 function.
template <typename Word>
[[nodiscard]] static Word small_sigma1(Word value) noexcept {
    if constexpr (sizeof(Word) == 4) {
        return rotr(value, 17) ^ rotr(value, 19) ^ (value >> 10);
    } else {
        return rotr(value, 19) ^ rotr(value, 61) ^ (value >> 6);
    }
}

/// @brief
///   Load a word in big-endian byte order.
template <typename Word>
[[nodiscard]] static Word load_be(const std::uint8_t *data) noexcept {
    Word value = 0;
    for (std::size_t index = 0; index < sizeof(Word); ++index) {
        value = static_cast<Word>((value << 8) | data[index]);
    }
    return value;
}

/// @brief
///   Straightforward SHA-2 implementation used as the test oracle.
/// @tparam Word
///   Word type of the SHA-2 variant.
/// @tparam BlockSize
///   Message block size in byte.
/// @tparam Rounds
///   Number of compression rounds.
/// @tparam LengthSize
///   Size in byte of the message length field.
/// @tparam DigestSize
///   Size in byte of the digest.
template <typename Word,
          std::size_t BlockSize,
          std::size_t Rounds,
          std::size_t LengthSize,
          std::size_t DigestSize>
[[nodiscard]] static std::array<std::uint8_t, DigestSize>
reference_hash(const std::uint8_t *data,
               std::size_t size,
               const Word (&round_constants)[Rounds],
               const Word (&initial_state)[8]) {
    static_assert(BlockSize == 16 * sizeof(Word));
    static_assert(DigestSize % sizeof(Word) == 0);

    std::array<Word, 8> state = {};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = initial_state[index];
    }

    // Pad with 0x80, zeros, and the big-endian message length.
    const std::size_t padded_size =
        ((size + 1 + LengthSize + BlockSize - 1) / BlockSize) * BlockSize;
    std::vector<std::uint8_t> message(padded_size, 0);
    if (size != 0) {
        std::memcpy(message.data(), data, size);
    }
    message[size] = 0x80;

    const std::uint64_t bit_length = static_cast<std::uint64_t>(size) * 8;
    for (std::size_t index = 0; index < 8; ++index) {
        message[padded_size - 1 - index] = static_cast<std::uint8_t>(bit_length >> (index * 8));
    }

    for (std::size_t block = 0; block < padded_size; block += BlockSize) {
        std::array<Word, Rounds> words = {};
        for (std::size_t index = 0; index < 16; ++index) {
            words[index] = load_be<Word>(message.data() + block + index * sizeof(Word));
        }
        for (std::size_t index = 16; index < Rounds; ++index) {
            words[index] = words[index - 16] + small_sigma0(words[index - 15]) + words[index - 7] +
                           small_sigma1(words[index - 2]);
        }

        Word a = state[0];
        Word b = state[1];
        Word c = state[2];
        Word d = state[3];
        Word e = state[4];
        Word f = state[5];
        Word g = state[6];
        Word h = state[7];

        for (std::size_t index = 0; index < Rounds; ++index) {
            const Word t1 = h + big_sigma1(e) + ch(e, f, g) + round_constants[index] + words[index];
            const Word t2 = big_sigma0(a) + maj(a, b, c);

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

    std::array<std::uint8_t, DigestSize> digest = {};
    for (std::size_t word_index = 0; word_index < DigestSize / sizeof(Word); ++word_index) {
        for (std::size_t byte_index = 0; byte_index < sizeof(Word); ++byte_index) {
            digest[word_index * sizeof(Word) + byte_index] = static_cast<std::uint8_t>(
                state[word_index] >> (8 * (sizeof(Word) - 1 - byte_index)));
        }
    }
    return digest;
}

[[nodiscard]] static std::array<std::uint8_t, 28> reference_sha224(const std::uint8_t *data,
                                                                   std::size_t size) {
    return reference_hash<std::uint32_t, 64, 64, 8, 28>(data, size, k256, iv224);
}

[[nodiscard]] static std::array<std::uint8_t, 32> reference_sha256(const std::uint8_t *data,
                                                                   std::size_t size) {
    return reference_hash<std::uint32_t, 64, 64, 8, 32>(data, size, k256, iv256);
}

[[nodiscard]] static std::array<std::uint8_t, 48> reference_sha384(const std::uint8_t *data,
                                                                   std::size_t size) {
    return reference_hash<std::uint64_t, 128, 80, 16, 48>(data, size, k512, iv384);
}

[[nodiscard]] static std::array<std::uint8_t, 64> reference_sha512(const std::uint8_t *data,
                                                                   std::size_t size) {
    return reference_hash<std::uint64_t, 128, 80, 16, 64>(data, size, k512, iv512);
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
///   Parse a hexadecimal string into a digest.
template <std::size_t DigestSize>
[[nodiscard]] static std::array<std::uint8_t, DigestSize> from_hex(std::string_view hex) {
    const auto nibble = [](char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        return static_cast<std::uint8_t>(character - 'A' + 10);
    };

    std::array<std::uint8_t, DigestSize> digest = {};
    for (std::size_t index = 0; index < DigestSize; ++index) {
        digest[index] =
            static_cast<std::uint8_t>((nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]));
    }
    return digest;
}

/// @brief
///   Compare a hash implementation and its reference for all small sizes and alignments.
template <typename Hash, typename Reference>
static void
check_all_small(Hash hash, Reference reference, std::size_t max_size, std::uint64_t seed) {
    const auto data = make_test_data(max_size + 16, seed);
    for (std::size_t size = 0; size <= max_size; ++size) {
        for (std::size_t offset = 0; offset < 8; ++offset) {
            const std::uint8_t *input = data.data() + offset;
            SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
            EXPECT_EQ(hash(input, size), reference(input, size));
        }
    }
}

/// @brief
///   Compare a hash implementation and its reference around every padding boundary.
template <typename Hash, typename Reference>
static void check_boundaries(Hash hash,
                             Reference reference,
                             std::span<const std::size_t> boundaries,
                             std::uint64_t seed) {
    const std::size_t max_boundary = *std::max_element(boundaries.begin(), boundaries.end());
    const auto data                = make_test_data(max_boundary + 1 + 16, seed);

    for (const std::size_t boundary : boundaries) {
        for (const std::size_t size : {boundary - 1, boundary, boundary + 1}) {
            for (const std::size_t offset : {std::size_t{0}, std::size_t{7}}) {
                const std::uint8_t *input = data.data() + offset;
                SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
                EXPECT_EQ(hash(input, size), reference(input, size));
            }
        }
    }
}

/// @brief
///   Compare a hash implementation and its reference for random sizes and alignments.
template <typename Hash, typename Reference>
static void check_random(Hash hash, Reference reference, std::size_t max_size, std::uint64_t seed) {
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
        EXPECT_EQ(hash(input, size), reference(input, size));
    }
}

/// @brief
///   Check that a hash implementation does not depend on input alignment.
template <typename Hash, typename Reference>
static void check_alignment(Hash hash, Reference reference, std::size_t size, std::uint64_t seed) {
    const auto data     = make_test_data(size, seed);
    const auto expected = reference(data.data(), size);

    std::vector<std::uint8_t> storage(size + 16);
    for (std::size_t offset = 0; offset < 16; ++offset) {
        std::memcpy(storage.data() + offset, data.data(), size);
        SCOPED_TRACE(testing::Message() << "offset=" << offset);
        EXPECT_EQ(hash(storage.data() + offset, size), expected);
    }
}

/// @brief
///   Compare a hash implementation and its reference for a large input.
template <typename Hash, typename Reference>
static void check_large(Hash hash, Reference reference, std::size_t size, std::uint64_t seed) {
    const auto data = make_test_data(size, seed);
    EXPECT_EQ(hash(data.data(), size), reference(data.data(), size));
}

/// @brief
///   Exercise exact-size allocations so AddressSanitizer catches out-of-bounds reads.
template <typename Hash, typename Reference>
static void
check_exact_size(Hash hash, Reference reference, std::size_t max_size, std::uint64_t seed) {
    constexpr std::size_t alignment_count = 64;

    for (std::size_t size = 0; size <= max_size; ++size) {
        const auto source   = make_test_data(size, seed);
        const auto expected = reference(source.data(), size);

        for (std::size_t offset = 0; offset < alignment_count; ++offset) {
            const auto storage = make_exact_size_buffer(source, size, offset);
            SCOPED_TRACE(testing::Message() << "size=" << size << ", offset=" << offset);
            EXPECT_EQ(hash(storage.data() + offset, size), expected);
        }
    }
}

/// @brief
///   Input sizes close to the padding boundaries of the 32-bit SHA-2 variants.
static constexpr std::array<std::size_t, 18> sha224_boundaries = {
    55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

/// @brief
///   Input sizes close to the padding and message schedule boundaries of SHA256.
static constexpr std::size_t sha256_boundary_sizes[] = {
    55,   56,   63,   64,    65,    119,   120,   127,   128,   129,   191,   192,   193,  255,
    256,  257,  511,  512,   513,   1023,  1024,  1025,  2047,  2048,  2049,  4095,  4096, 4097,
    8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537,
};

/// @brief
///   Number of start offsets to test for unaligned SHA256 inputs.
static constexpr std::size_t sha256_alignment_count = 64;

/// @brief
///   Input sizes close to the padding boundaries of the 64-bit SHA-2 variants.
static constexpr std::array<std::size_t, 15> sha384_boundaries = {
    111, 112, 127, 128, 129, 239, 240, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

/// @brief
///   Input sizes close to the padding boundaries of the 64-bit SHA-2 variants.
static constexpr std::array<std::size_t, 15> sha512_boundaries = {
    111, 112, 127, 128, 129, 239, 240, 255, 256, 257, 1023, 1024, 1025, 4096, 4097,
};

[[nodiscard]] static std::array<std::uint8_t, 28> hash_sha224(const void *data,
                                                              std::size_t size) noexcept {
    return sha224(data, size);
}

[[nodiscard]] static std::array<std::uint8_t, 48> hash_sha384(const void *data,
                                                              std::size_t size) noexcept {
    return sha384(data, size);
}

[[nodiscard]] static std::array<std::uint8_t, 64> hash_sha512(const void *data,
                                                              std::size_t size) noexcept {
    return sha512(data, size);
}

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
        EXPECT_EQ(sha256(input.data(), input.size()), from_hex<32>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha256, nist_padding_boundary_vector) {
    // Two-block message from FIPS 180-4 / NIST examples.
    constexpr std::string_view input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"sv;
    EXPECT_EQ(sha256(input.data(), input.size()),
              from_hex<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"sv));
}

TEST(sha256, nist_million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(sha256(input.data(), input.size()),
              from_hex<32>("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"sv));
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
              from_hex<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"sv));

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
        EXPECT_EQ(sha224(input.data(), input.size()), from_hex<28>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha224, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(sha224(input.data(), input.size()),
              from_hex<28>("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"sv));
}

TEST(sha224, api_contract) {
    static_assert(std::is_same_v<decltype(sha224(nullptr, 0)), std::array<std::uint8_t, 28>>);
    static_assert(noexcept(sha224(nullptr, 0)));
    static_assert(noexcept(sha224(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 28> digest = {};
    sha224(nullptr, 0, digest.data());
    EXPECT_EQ(digest, from_hex<28>("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha224(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha224(input.data(), input.size()));
}

TEST(sha224, matches_reference_for_all_small_sizes) {
    check_all_small(hash_sha224, reference_sha224, 600, 11);
}

TEST(sha224, matches_reference_at_padding_boundaries) {
    check_boundaries(hash_sha224, reference_sha224, sha224_boundaries, 12);
}

TEST(sha224, matches_reference_for_random_sizes) {
    check_random(hash_sha224, reference_sha224, 16384, 13);
}

TEST(sha224, result_is_independent_of_alignment) {
    check_alignment(hash_sha224, reference_sha224, 4096, 14);
}

TEST(sha224, large_input_matches_reference) {
    check_large(hash_sha224, reference_sha224, std::size_t{1} << 20, 15);
}

TEST(sha224, exact_size_allocation_for_all_small_sizes) {
    check_exact_size(hash_sha224, reference_sha224, 300, 16);
}

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
        EXPECT_EQ(sha384(input.data(), input.size()), from_hex<48>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha384, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(sha384(input.data(), input.size()),
              from_hex<48>("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
                           "07b8b3dc38ecc4ebae97ddd87f3d8985"sv));
}

TEST(sha384, api_contract) {
    static_assert(std::is_same_v<decltype(sha384(nullptr, 0)), std::array<std::uint8_t, 48>>);
    static_assert(noexcept(sha384(nullptr, 0)));
    static_assert(noexcept(sha384(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 48> digest = {};
    sha384(nullptr, 0, digest.data());
    EXPECT_EQ(digest,
              from_hex<48>("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                           "274edebfe76f65fbd51ad2f14898b95b"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha384(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha384(input.data(), input.size()));
}

TEST(sha384, matches_reference_for_all_small_sizes) {
    check_all_small(hash_sha384, reference_sha384, 600, 21);
}

TEST(sha384, matches_reference_at_padding_boundaries) {
    check_boundaries(hash_sha384, reference_sha384, sha384_boundaries, 22);
}

TEST(sha384, matches_reference_for_random_sizes) {
    check_random(hash_sha384, reference_sha384, 16384, 23);
}

TEST(sha384, result_is_independent_of_alignment) {
    check_alignment(hash_sha384, reference_sha384, 4096, 24);
}

TEST(sha384, large_input_matches_reference) {
    check_large(hash_sha384, reference_sha384, std::size_t{1} << 20, 25);
}

TEST(sha384, exact_size_allocation_for_all_small_sizes) {
    check_exact_size(hash_sha384, reference_sha384, 300, 26);
}

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
        EXPECT_EQ(sha512(input.data(), input.size()), from_hex<64>(expected))
            << "input: \"" << input << '"';
    }
}

TEST(sha512, million_a_vector) {
    const std::vector<std::uint8_t> input(1000000, static_cast<std::uint8_t>('a'));
    EXPECT_EQ(sha512(input.data(), input.size()),
              from_hex<64>("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                           "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"sv));
}

TEST(sha512, api_contract) {
    static_assert(std::is_same_v<decltype(sha512(nullptr, 0)), std::array<std::uint8_t, 64>>);
    static_assert(noexcept(sha512(nullptr, 0)));
    static_assert(noexcept(sha512(nullptr, 0, nullptr)));

    // A null pointer is valid when size is zero.
    std::array<std::uint8_t, 64> digest = {};
    sha512(nullptr, 0, digest.data());
    EXPECT_EQ(digest,
              from_hex<64>("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"sv));

    // Both overloads must produce the same result.
    constexpr std::string_view input = "abc"sv;
    digest.fill(0);
    sha512(input.data(), input.size(), digest.data());
    EXPECT_EQ(digest, sha512(input.data(), input.size()));
}

TEST(sha512, matches_reference_for_all_small_sizes) {
    check_all_small(hash_sha512, reference_sha512, 600, 31);
}

TEST(sha512, matches_reference_at_padding_boundaries) {
    check_boundaries(hash_sha512, reference_sha512, sha512_boundaries, 32);
}

TEST(sha512, matches_reference_for_random_sizes) {
    check_random(hash_sha512, reference_sha512, 16384, 33);
}

TEST(sha512, result_is_independent_of_alignment) {
    check_alignment(hash_sha512, reference_sha512, 4096, 34);
}

TEST(sha512, large_input_matches_reference) {
    check_large(hash_sha512, reference_sha512, std::size_t{1} << 20, 35);
}

TEST(sha512, exact_size_allocation_for_all_small_sizes) {
    check_exact_size(hash_sha512, reference_sha512, 300, 36);
}
