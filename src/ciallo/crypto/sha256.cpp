#include "ciallo/crypto/sha256.hpp"

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#    include <immintrin.h>
#    if defined(_MSC_VER)
#        include <intrin.h>
#    else
#        include <cpuid.h>
#    endif
#endif

#include <bit>
#include <cstring>

/// @brief
///   Size in byte of one SHA256 message block.
static constexpr std::size_t sha256_block_size = 64;

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
///   Load a 32-bit value in big-endian byte order.
/// @param data
///   Pointer to the first byte of the value.
/// @return
///   Value read from @p data.
[[nodiscard]] static std::uint32_t sha256_load_be32(const std::uint8_t *data) noexcept {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) | static_cast<std::uint32_t>(data[3]);
}

/// @brief
///   Store a 32-bit value in big-endian byte order.
/// @param data
///   Pointer to the destination.
/// @param value
///   Value to store.
static void sha256_store_be32(std::uint8_t *data, std::uint32_t value) noexcept {
    data[0] = static_cast<std::uint8_t>(value >> 24);
    data[1] = static_cast<std::uint8_t>(value >> 16);
    data[2] = static_cast<std::uint8_t>(value >> 8);
    data[3] = static_cast<std::uint8_t>(value);
}

/// @brief
///   Store a 64-bit value in big-endian byte order.
/// @param data
///   Pointer to the destination.
/// @param value
///   Value to store.
static void sha256_store_be64(std::uint8_t *data, std::uint64_t value) noexcept {
    sha256_store_be32(data, static_cast<std::uint32_t>(value >> 32));
    sha256_store_be32(data + 4, static_cast<std::uint32_t>(value));
}

/// @brief
///   SHA256 @c Ch function.
[[nodiscard]] static std::uint32_t
sha256_ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (~x & z);
}

/// @brief
///   SHA256 @c Maj function.
[[nodiscard]] static std::uint32_t
sha256_maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

/// @brief
///   SHA256 upper-case sigma 0 function.
[[nodiscard]] static std::uint32_t sha256_big_sigma0(std::uint32_t value) noexcept {
    return std::rotr(value, 2) ^ std::rotr(value, 13) ^ std::rotr(value, 22);
}

/// @brief
///   SHA256 upper-case sigma 1 function.
[[nodiscard]] static std::uint32_t sha256_big_sigma1(std::uint32_t value) noexcept {
    return std::rotr(value, 6) ^ std::rotr(value, 11) ^ std::rotr(value, 25);
}

/// @brief
///   SHA256 lower-case sigma 0 function.
[[nodiscard]] static std::uint32_t sha256_small_sigma0(std::uint32_t value) noexcept {
    return std::rotr(value, 7) ^ std::rotr(value, 18) ^ (value >> 3);
}

/// @brief
///   SHA256 lower-case sigma 1 function.
[[nodiscard]] static std::uint32_t sha256_small_sigma1(std::uint32_t value) noexcept {
    return std::rotr(value, 17) ^ std::rotr(value, 19) ^ (value >> 10);
}

/// @brief
///   Portable SHA256 compression function for all architectures.
/// @param state
///   Current SHA256 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 64-byte message blocks to compress.
static void sha256_compress_portable(std::uint32_t state[8],
                                     const std::uint8_t *data,
                                     std::size_t blocks) noexcept {
    for (; blocks != 0; --blocks, data += sha256_block_size) {
        std::uint32_t words[64];
        for (std::size_t index = 0; index < 16; ++index) {
            words[index] = sha256_load_be32(data + index * 4);
        }
        for (std::size_t index = 16; index < 64; ++index) {
            words[index] = words[index - 16] + sha256_small_sigma0(words[index - 15]) +
                           words[index - 7] + sha256_small_sigma1(words[index - 2]);
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
            const std::uint32_t t1 = h + sha256_big_sigma1(e) + sha256_ch(e, f, g) +
                                     sha256_round_constants[index] + words[index];
            const std::uint32_t t2 = sha256_big_sigma0(a) + sha256_maj(a, b, c);

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
}

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#    if defined(_MSC_VER)
#        define CIALLO_SHA256_TARGET_SHA
#        define CIALLO_SHA256_INLINE __forceinline
#    else
#        define CIALLO_SHA256_TARGET_SHA __attribute__((target("sha,sse4.1")))
#        define CIALLO_SHA256_INLINE     __attribute__((always_inline)) inline
#    endif

/// @brief
///   CPUID for x86 CPU.
static void cpuid(std::uint32_t leaf,
                  std::uint32_t subleaf,
                  std::uint32_t &eax,
                  std::uint32_t &ebx,
                  std::uint32_t &ecx,
                  std::uint32_t &edx) noexcept {
#    if defined(_MSC_VER)
    int registers[4] = {};
    __cpuidex(registers, static_cast<int>(leaf), static_cast<int>(subleaf));
    eax = static_cast<std::uint32_t>(registers[0]);
    ebx = static_cast<std::uint32_t>(registers[1]);
    ecx = static_cast<std::uint32_t>(registers[2]);
    edx = static_cast<std::uint32_t>(registers[3]);
#    else
    __cpuid_count(leaf, subleaf, eax, ebx, ecx, edx);
#    endif
}

/// @brief
///   Perform four SHA256 rounds and update the message schedule for a later group.
/// @param group
///   Index of the four-round group, in the range [0, 15].
/// @param state0
///   State vector holding {A, B, E, F}.
/// @param state1
///   State vector holding {C, D, G, H}.
/// @param words
///   Message vectors carrying the current message schedule.
CIALLO_SHA256_TARGET_SHA static CIALLO_SHA256_INLINE void
sha256_round_group(std::size_t group,
                   __m128i &state0,
                   __m128i &state1,
                   __m128i (&words)[4]) noexcept {
    const __m128i message = _mm_add_epi32(
        words[group & 3],
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(&sha256_round_constants[group * 4])));
    state1 = _mm_sha256rnds2_epu32(state1, state0, message);
    state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(message, 0x0E));

    // Build the message schedule for the group three iterations ahead.  The @c sha256msg1
    // instruction accumulates the lower-case sigma 0 terms, and the @c sha256msg2 instruction
    // adds the lower-case sigma 1 terms.
    if (group >= 3 && group <= 14) {
        __m128i &next = words[(group + 1) & 3];
        next = _mm_add_epi32(next, _mm_alignr_epi8(words[group & 3], words[(group - 1) & 3], 4));
        next = _mm_sha256msg2_epu32(next, words[group & 3]);
    }

    // Accumulate the lower-case sigma 0 terms for the group four iterations ahead.  The last
    // three groups do not need another message schedule.
    if (group >= 1 && group <= 12) {
        __m128i &previous = words[(group - 1) & 3];
        previous          = _mm_sha256msg1_epu32(previous, words[group & 3]);
    }
}

/// @brief
///   SHA256 compression function with Intel @c sha extensions.
/// @param state
///   Current SHA256 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 64-byte message blocks to compress.
CIALLO_SHA256_TARGET_SHA static void sha256_compress_shani(std::uint32_t state[8],
                                                           const std::uint8_t *data,
                                                           std::size_t blocks) noexcept {
    // Byte-swap the four message words of a vector from big-endian to little-endian order.
    const __m128i byte_swap = _mm_set_epi64x(0x0C0D0E0F08090A0BLL, 0x0405060700010203LL);

    for (; blocks != 0; --blocks, data += sha256_block_size) {
        // Rearrange the state into the two vectors expected by the sha instructions:
        // {A, B, E, F} and {C, D, G, H}.
        __m128i tmp    = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&state[0]));
        __m128i state1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(&state[4]));

        tmp            = _mm_shuffle_epi32(tmp, 0xB1);       // CDAB
        state1         = _mm_shuffle_epi32(state1, 0x1B);    // EFGH
        __m128i state0 = _mm_alignr_epi8(tmp, state1, 8);    // ABEF
        state1         = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        const __m128i state0_save = state0;
        const __m128i state1_save = state1;

        // The four message vectors also carry the partially computed message schedule.
        __m128i words[4];
        words[0] = _mm_shuffle_epi8(
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + 0 * 16)), byte_swap);
        words[1] = _mm_shuffle_epi8(
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + 1 * 16)), byte_swap);
        words[2] = _mm_shuffle_epi8(
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + 2 * 16)), byte_swap);
        words[3] = _mm_shuffle_epi8(
            _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + 3 * 16)), byte_swap);

        // Unroll all sixteen groups so that the compiler keeps the schedule vectors in registers
        // and folds the group-index conditions of sha256_round_group.
        sha256_round_group(0, state0, state1, words);
        sha256_round_group(1, state0, state1, words);
        sha256_round_group(2, state0, state1, words);
        sha256_round_group(3, state0, state1, words);
        sha256_round_group(4, state0, state1, words);
        sha256_round_group(5, state0, state1, words);
        sha256_round_group(6, state0, state1, words);
        sha256_round_group(7, state0, state1, words);
        sha256_round_group(8, state0, state1, words);
        sha256_round_group(9, state0, state1, words);
        sha256_round_group(10, state0, state1, words);
        sha256_round_group(11, state0, state1, words);
        sha256_round_group(12, state0, state1, words);
        sha256_round_group(13, state0, state1, words);
        sha256_round_group(14, state0, state1, words);
        sha256_round_group(15, state0, state1, words);

        state0 = _mm_add_epi32(state0, state0_save);
        state1 = _mm_add_epi32(state1, state1_save);

        tmp    = _mm_shuffle_epi32(state0, 0x1B);    // FEBA
        state1 = _mm_shuffle_epi32(state1, 0xB1);    // DCHG
        state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        state1 = _mm_alignr_epi8(state1, tmp, 8);    // HGFE

        _mm_storeu_si128(reinterpret_cast<__m128i *>(&state[0]), state0);
        _mm_storeu_si128(reinterpret_cast<__m128i *>(&state[4]), state1);
    }
}
#endif

/// @brief
///   SHA256 compression function pointer.
using sha256_compress_fn = void (*)(std::uint32_t *, const std::uint8_t *, std::size_t);

/// @brief
///   Select SHA256 compression implementation according to current CPU features.
/// @return
///   SHA256 compression implementation that best suits current CPU.
[[nodiscard]] static sha256_compress_fn select_sha256_compress() noexcept {
#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;

    cpuid(0, 0, eax, ebx, ecx, edx);
    const std::uint32_t max_leaf = eax;
    if (max_leaf < 1) {
        return &sha256_compress_portable;
    }

    cpuid(1, 0, eax, ebx, ecx, edx);
    const bool support_ssse3 = (ecx & (1U << 9)) != 0;
    const bool support_sse41 = (ecx & (1U << 19)) != 0;

    if (max_leaf < 7) {
        return &sha256_compress_portable;
    }

    cpuid(7, 0, eax, ebx, ecx, edx);
    const bool support_sha = (ebx & (1U << 29)) != 0;

    if (support_ssse3 && support_sse41 && support_sha) {
        return &sha256_compress_shani;
    }

    return &sha256_compress_portable;
#else
    return &sha256_compress_portable;
#endif
}

void ciallo::sha256(const void *data, std::size_t size, void *hash) noexcept {
    static const sha256_compress_fn compress = select_sha256_compress();

    std::uint32_t state[8];
    for (std::size_t index = 0; index < 8; ++index) {
        state[index] = sha256_initial_state[index];
    }

    const auto *bytes             = static_cast<const std::uint8_t *>(data);
    const std::size_t block_count = size / sha256_block_size;
    if (block_count != 0) {
        compress(state, bytes, block_count);
    }

    // Append the mandatory 0x80 byte and the zero padding.  One or two blocks are required
    // depending on whether the message length still fits in the current block.
    const std::size_t remaining              = size % sha256_block_size;
    std::uint8_t tail[2 * sha256_block_size] = {};
    if (remaining != 0) {
        std::memcpy(tail, bytes + block_count * sha256_block_size, remaining);
    }
    tail[remaining] = 0x80U;

    const std::size_t tail_size = remaining < 56 ? sha256_block_size : 2 * sha256_block_size;
    sha256_store_be64(tail + tail_size - 8, static_cast<std::uint64_t>(size) * 8);
    compress(state, tail, tail_size / sha256_block_size);

    auto *digest = static_cast<std::uint8_t *>(hash);
    for (std::size_t index = 0; index < 8; ++index) {
        sha256_store_be32(digest + index * 4, state[index]);
    }
}
