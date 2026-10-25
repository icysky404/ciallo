#include "ciallo/crypto/crc32.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <random>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace ciallo;
using namespace std::string_view_literals;

// Reflected form of the CRC-32/ISO-HDLC polynomial (0x04C11DB7).
static constexpr std::uint32_t crc32_polynomial = 0xEDB88320U;

/// @brief
///   Straightforward bit-by-bit CRC-32/ISO-HDLC used as the test oracle.
/// @param data
///   Pointer to start of data to calculate CRC32 for.
/// @param size
///   Size in byte of data to calculate CRC32 for.
/// @return
///   CRC32/ISO-HDLC value.
[[nodiscard]] static std::uint32_t reference_crc32(const std::uint8_t *data,
                                                   std::size_t size) noexcept {
    std::uint32_t crc = 0xFFFFFFFFU;
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (crc32_polynomial & (0U - (crc & 1U)));
        }
    }
    return ~crc;
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
///   Input sizes that are close to every transition of the vectorized CRC32 implementations:
///   the portable tail, each vector width, and each fold stride.
static constexpr std::size_t crc32_boundary_sizes[] = {
    7,    8,    9,    15,   16,   17,    31,    32,    33,    63,    64,    65,    127,   128,
    129,  255,  256,  257,  511,  512,   513,   1023,  1024,  1025,  2047,  2048,  2049,  4095,
    4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537,
};

/// @brief
///   Number of start offsets to test for unaligned inputs. 64 covers every alignment relative to
///   a 64-byte cache line.
static constexpr std::size_t crc32_alignment_count = 64;

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

TEST(crc32, known_vectors) {
    // Check values from the CRC-32/ISO-HDLC specification and common tooling.
    constexpr std::pair<std::string_view, std::uint32_t> vectors[] = {
        {""sv, 0x00000000U},
        {"a"sv, 0xE8B7BE43U},
        {"abc"sv, 0x352441C2U},
        {"123456789"sv, 0xCBF43926U},
        {"The quick brown fox jumps over the lazy dog"sv, 0x414FA339U},
    };

    for (const auto &[input, expected] : vectors) {
        EXPECT_EQ(crc32(input.data(), input.size()), expected) << "input: \"" << input << '"';
    }
}

TEST(crc32, api_contract) {
    static_assert(std::is_same_v<decltype(crc32(nullptr, 0)), std::uint32_t>);
    static_assert(noexcept(crc32(nullptr, 0)));

    // The CRC of empty input is zero, and a null pointer is valid when size is zero.
    EXPECT_EQ(crc32(nullptr, 0), 0U);
}

TEST(crc32, matches_reference_for_all_small_sizes) {
    constexpr std::size_t max_size = 600;
    const auto data                = make_test_data(max_size + 16, 1);

    for (std::size_t size = 0; size <= max_size; ++size) {
        for (std::size_t offset = 0; offset < 8; ++offset) {
            const std::uint8_t *input = data.data() + offset;
            ASSERT_EQ(crc32(input, size), reference_crc32(input, size))
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(crc32, matches_reference_at_fold_boundaries) {
    // Boundaries of every vector width and fold stride used by the vectorized implementations.
    constexpr std::size_t sizes[] = {
        15,   16,   17,   31,   32,    33,    63,    64,    65,    127,   128,   129,   255,
        256,  257,  511,  512,  513,   1023,  1024,  1025,  2047,  2048,  2049,  4095,  4096,
        4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537,
    };
    constexpr std::size_t max_size = 65537;
    const auto data                = make_test_data(max_size + 16, 2);

    for (const std::size_t size : sizes) {
        for (const std::size_t offset : {std::size_t{0}, std::size_t{7}}) {
            const std::uint8_t *input = data.data() + offset;
            EXPECT_EQ(crc32(input, size), reference_crc32(input, size))
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(crc32, matches_reference_for_random_sizes) {
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

        EXPECT_EQ(crc32(input, size), reference_crc32(input, size))
            << "size=" << size << ", offset=" << offset;
    }
}

TEST(crc32, matches_reference_for_constant_patterns) {
    constexpr std::size_t sizes[] = {1, 7, 16, 17, 32, 33, 64, 65, 4096, 4097};

    for (const std::uint8_t value :
         {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x55}, std::uint8_t{0xAA}}) {
        for (const std::size_t size : sizes) {
            const std::vector<std::uint8_t> data(size, value);
            EXPECT_EQ(crc32(data.data(), size), reference_crc32(data.data(), size))
                << "value=" << static_cast<int>(value) << ", size=" << size;
        }
    }
}

TEST(crc32, result_is_independent_of_alignment) {
    constexpr std::size_t size   = 4096;
    const auto data              = make_test_data(size, 5);
    const std::uint32_t expected = crc32(data.data(), size);

    std::vector<std::uint8_t> storage(size + 16);
    for (std::size_t offset = 0; offset < 16; ++offset) {
        std::memcpy(storage.data() + offset, data.data(), size);
        EXPECT_EQ(crc32(storage.data() + offset, size), expected) << "offset=" << offset;
    }
}

TEST(crc32, large_input_matches_reference) {
    constexpr std::size_t size = std::size_t{1} << 20;
    const auto data            = make_test_data(size, 6);

    EXPECT_EQ(crc32(data.data(), size), reference_crc32(data.data(), size));
}

TEST(crc32, exact_size_allocation_for_all_small_sizes) {
    // Every input owns exactly its own bytes, so AddressSanitizer reports any read outside the
    // input. Varying the offset also exercises unaligned starts for every small size.
    constexpr std::size_t max_size = 600;

    for (std::size_t size = 0; size <= max_size; ++size) {
        const auto source            = make_test_data(size, 9);
        const std::uint32_t expected = reference_crc32(source.data(), size);

        for (std::size_t offset = 0; offset < crc32_alignment_count; ++offset) {
            const auto storage = make_exact_size_buffer(source, size, offset);

            EXPECT_EQ(crc32(storage.data() + offset, size), expected)
                << "size=" << size << ", offset=" << offset;
        }
    }
}

TEST(crc32, exact_size_allocation_at_fold_boundaries) {
    // Check each fold boundary and its immediate neighbours at every start alignment. Reads past
    // the end or before the start of the exact-size allocation are caught by AddressSanitizer.
    for (const std::size_t boundary : crc32_boundary_sizes) {
        for (const std::size_t size : {boundary - 1, boundary, boundary + 1}) {
            const auto source            = make_test_data(size, 10);
            const std::uint32_t expected = reference_crc32(source.data(), size);

            for (std::size_t offset = 0; offset < crc32_alignment_count; ++offset) {
                const auto storage = make_exact_size_buffer(source, size, offset);

                EXPECT_EQ(crc32(storage.data() + offset, size), expected)
                    << "size=" << size << ", offset=" << offset;
            }
        }
    }
}
