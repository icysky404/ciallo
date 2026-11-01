#include "ciallo/crypto/sha2.hpp"

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#    include <immintrin.h>
#    if defined(_MSC_VER)
#        include <intrin.h>
#    else
#        include <cpuid.h>
#    endif
#elif (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
#    if defined(_MSC_VER) && !defined(__clang__)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
#    if defined(__linux__)
#        include <sys/auxv.h>
#        if __has_include(<asm/hwcap.h>)
#            include <asm/hwcap.h>
#        endif
#        ifndef HWCAP_SHA2
#            define HWCAP_SHA2 (1UL << 6)
#        endif
#        ifndef HWCAP_SHA512
#            define HWCAP_SHA512 (1UL << 21)
#        endif
#    elif defined(__APPLE__)
#        include <sys/sysctl.h>
#    elif defined(_WIN32)
#        ifndef WIN32_LEAN_AND_MEAN
#            define WIN32_LEAN_AND_MEAN
#        endif
#        include <Windows.h>
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
///   Initial SHA224 hash value (FIPS 180-4, section 5.3.2).
static constexpr std::uint32_t sha224_initial_state[8] = {
    0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
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
#elif (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
#    if defined(_MSC_VER) && !defined(__clang__)
#        define CIALLO_SHA256_TARGET_SHA2
#        define CIALLO_SHA256_INLINE_SHA2 __forceinline
#    else
#        define CIALLO_SHA256_TARGET_SHA2 __attribute__((target("arch=armv8-a+crypto")))
#        define CIALLO_SHA256_INLINE_SHA2 __attribute__((always_inline)) inline
#    endif

/// @brief
///   Perform four SHA256 rounds and update the message schedule for a later group.
/// @param group
///   Index of the four-round group, in the range [0, 15].
/// @param state0
///   State vector holding {A, B, C, D}.
/// @param state1
///   State vector holding {E, F, G, H}.
/// @param words
///   Message vectors carrying the current message schedule.
CIALLO_SHA256_TARGET_SHA2 static CIALLO_SHA256_INLINE_SHA2 void
sha256_round_group_sha2(std::size_t group,
                        uint32x4_t &state0,
                        uint32x4_t &state1,
                        uint32x4_t (&words)[4]) noexcept {
    const uint32x4_t message =
        vaddq_u32(words[group & 3], vld1q_u32(&sha256_round_constants[group * 4]));
    const uint32x4_t previous = state0;
    state0                    = vsha256hq_u32(previous, state1, message);
    state1                    = vsha256h2q_u32(state1, previous, message);

    // Build the message schedule for the group four iterations ahead.  The @c sha256su0
    // instruction accumulates the lower-case sigma 0 terms, and the @c sha256su1 instruction
    // adds the lower-case sigma 1 terms.  The last four groups do not need another schedule.
    if (group <= 11) {
        uint32x4_t &next = words[group & 3];
        next             = vsha256su1q_u32(vsha256su0q_u32(next, words[(group + 1) & 3]),
                                           words[(group + 2) & 3], words[(group + 3) & 3]);
    }
}

/// @brief
///   SHA256 compression function with ARMv8 @c sha2 extensions.
/// @param state
///   Current SHA256 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 64-byte message blocks to compress.
CIALLO_SHA256_TARGET_SHA2 static void sha256_compress_sha2(std::uint32_t state[8],
                                                           const std::uint8_t *data,
                                                           std::size_t blocks) noexcept {
    uint32x4_t state0 = vld1q_u32(&state[0]);
    uint32x4_t state1 = vld1q_u32(&state[4]);

    for (; blocks != 0; --blocks, data += sha256_block_size) {
        const uint32x4_t state0_save = state0;
        const uint32x4_t state1_save = state1;

        // The four message vectors also carry the partially computed message schedule.
        uint32x4_t words[4];
        words[0] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 0 * 16)));
        words[1] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 1 * 16)));
        words[2] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 2 * 16)));
        words[3] = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 3 * 16)));

        // Unroll all sixteen groups so that the compiler keeps the schedule vectors in registers
        // and folds the group-index conditions of sha256_round_group_sha2.
        sha256_round_group_sha2(0, state0, state1, words);
        sha256_round_group_sha2(1, state0, state1, words);
        sha256_round_group_sha2(2, state0, state1, words);
        sha256_round_group_sha2(3, state0, state1, words);
        sha256_round_group_sha2(4, state0, state1, words);
        sha256_round_group_sha2(5, state0, state1, words);
        sha256_round_group_sha2(6, state0, state1, words);
        sha256_round_group_sha2(7, state0, state1, words);
        sha256_round_group_sha2(8, state0, state1, words);
        sha256_round_group_sha2(9, state0, state1, words);
        sha256_round_group_sha2(10, state0, state1, words);
        sha256_round_group_sha2(11, state0, state1, words);
        sha256_round_group_sha2(12, state0, state1, words);
        sha256_round_group_sha2(13, state0, state1, words);
        sha256_round_group_sha2(14, state0, state1, words);
        sha256_round_group_sha2(15, state0, state1, words);

        state0 = vaddq_u32(state0, state0_save);
        state1 = vaddq_u32(state1, state1_save);
    }

    vst1q_u32(&state[0], state0);
    vst1q_u32(&state[4], state1);
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
#elif (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
    if constexpr (std::endian::native != std::endian::little) {
        return &sha256_compress_portable;
    } else {
#    if defined(__linux__)
        const unsigned long hwcap = getauxval(AT_HWCAP);
        if ((hwcap & HWCAP_SHA2) != 0) {
            return &sha256_compress_sha2;
        }
#    elif defined(__APPLE__)
        // All Apple-designed ARM64 processors implement the crypto extensions.
        return &sha256_compress_sha2;
#    elif defined(_WIN32)
#        if defined(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)
        if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0) {
            return &sha256_compress_sha2;
        }
#        endif
#    endif
        return &sha256_compress_portable;
    }
#else
    return &sha256_compress_portable;
#endif
}

/// @brief
///   Calculate SHA224 or SHA256 hash value.
/// @param data
///   Pointer to start of data to be hashed.
/// @param size
///   Size in byte of data to be hashed.
/// @param hash
///   Pointer to memory to store the hash result.
/// @param initial_state
///   Initial hash value of the algorithm.
/// @param digest_size
///   Size in byte of the hash result.
static void sha256_hash_impl(const void *data,
                             std::size_t size,
                             void *hash,
                             const std::uint32_t (&initial_state)[8],
                             std::size_t digest_size) noexcept {
    static const sha256_compress_fn compress = select_sha256_compress();

    std::uint32_t state[8];
    for (std::size_t index = 0; index < 8; ++index) {
        state[index] = initial_state[index];
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
    for (std::size_t index = 0; index < digest_size / 4; ++index) {
        sha256_store_be32(digest + index * 4, state[index]);
    }
}

void ciallo::sha256(const void *data, std::size_t size, void *hash) noexcept {
    sha256_hash_impl(data, size, hash, sha256_initial_state, 32);
}

void ciallo::sha224(const void *data, std::size_t size, void *hash) noexcept {
    sha256_hash_impl(data, size, hash, sha224_initial_state, 28);
}

/// @brief
///   Size in byte of one SHA512 message block.
static constexpr std::size_t sha512_block_size = 128;

/// @brief
///   SHA512 round constants (FIPS 180-4, section 4.2.3).
static constexpr std::uint64_t sha512_round_constants[80] = {
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
///   Initial SHA512 hash value (FIPS 180-4, section 5.3.5).
static constexpr std::uint64_t sha512_initial_state[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
};

/// @brief
///   Initial SHA384 hash value (FIPS 180-4, section 5.3.4).
static constexpr std::uint64_t sha384_initial_state[8] = {
    0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL, 0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
};

/// @brief
///   Load a 64-bit value in big-endian byte order.
/// @param data
///   Pointer to the first byte of the value.
/// @return
///   Value read from @p data.
[[nodiscard]] static std::uint64_t sha512_load_be64(const std::uint8_t *data) noexcept {
    return (static_cast<std::uint64_t>(data[0]) << 56) |
           (static_cast<std::uint64_t>(data[1]) << 48) |
           (static_cast<std::uint64_t>(data[2]) << 40) |
           (static_cast<std::uint64_t>(data[3]) << 32) |
           (static_cast<std::uint64_t>(data[4]) << 24) |
           (static_cast<std::uint64_t>(data[5]) << 16) |
           (static_cast<std::uint64_t>(data[6]) << 8) | static_cast<std::uint64_t>(data[7]);
}

/// @brief
///   Store a 64-bit value in big-endian byte order.
/// @param data
///   Pointer to the destination.
/// @param value
///   Value to store.
static void sha512_store_be64(std::uint8_t *data, std::uint64_t value) noexcept {
    data[0] = static_cast<std::uint8_t>(value >> 56);
    data[1] = static_cast<std::uint8_t>(value >> 48);
    data[2] = static_cast<std::uint8_t>(value >> 40);
    data[3] = static_cast<std::uint8_t>(value >> 32);
    data[4] = static_cast<std::uint8_t>(value >> 24);
    data[5] = static_cast<std::uint8_t>(value >> 16);
    data[6] = static_cast<std::uint8_t>(value >> 8);
    data[7] = static_cast<std::uint8_t>(value);
}

/// @brief
///   SHA512 @c Ch function.
[[nodiscard]] static std::uint64_t
sha512_ch(std::uint64_t x, std::uint64_t y, std::uint64_t z) noexcept {
    return (x & y) ^ (~x & z);
}

/// @brief
///   SHA512 @c Maj function.
[[nodiscard]] static std::uint64_t
sha512_maj(std::uint64_t x, std::uint64_t y, std::uint64_t z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

/// @brief
///   SHA512 upper-case sigma 0 function.
[[nodiscard]] static std::uint64_t sha512_big_sigma0(std::uint64_t value) noexcept {
    return std::rotr(value, 28) ^ std::rotr(value, 34) ^ std::rotr(value, 39);
}

/// @brief
///   SHA512 upper-case sigma 1 function.
[[nodiscard]] static std::uint64_t sha512_big_sigma1(std::uint64_t value) noexcept {
    return std::rotr(value, 14) ^ std::rotr(value, 18) ^ std::rotr(value, 41);
}

/// @brief
///   SHA512 lower-case sigma 0 function.
[[nodiscard]] static std::uint64_t sha512_small_sigma0(std::uint64_t value) noexcept {
    return std::rotr(value, 1) ^ std::rotr(value, 8) ^ (value >> 7);
}

/// @brief
///   SHA512 lower-case sigma 1 function.
[[nodiscard]] static std::uint64_t sha512_small_sigma1(std::uint64_t value) noexcept {
    return std::rotr(value, 19) ^ std::rotr(value, 61) ^ (value >> 6);
}

/// @brief
///   Portable SHA512 compression function for all architectures.
/// @param state
///   Current SHA512 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 128-byte message blocks to compress.
static void sha512_compress_portable(std::uint64_t state[8],
                                     const std::uint8_t *data,
                                     std::size_t blocks) noexcept {
    for (; blocks != 0; --blocks, data += sha512_block_size) {
        std::uint64_t words[80];
        for (std::size_t index = 0; index < 16; ++index) {
            words[index] = sha512_load_be64(data + index * 8);
        }
        for (std::size_t index = 16; index < 80; ++index) {
            words[index] = words[index - 16] + sha512_small_sigma0(words[index - 15]) +
                           words[index - 7] + sha512_small_sigma1(words[index - 2]);
        }

        std::uint64_t a = state[0];
        std::uint64_t b = state[1];
        std::uint64_t c = state[2];
        std::uint64_t d = state[3];
        std::uint64_t e = state[4];
        std::uint64_t f = state[5];
        std::uint64_t g = state[6];
        std::uint64_t h = state[7];

        for (std::size_t index = 0; index < 80; ++index) {
            const std::uint64_t t1 = h + sha512_big_sigma1(e) + sha512_ch(e, f, g) +
                                     sha512_round_constants[index] + words[index];
            const std::uint64_t t2 = sha512_big_sigma0(a) + sha512_maj(a, b, c);

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
#        define CIALLO_SHA512_TARGET_AVX2
#        define CIALLO_SHA512_INLINE_AVX2 __forceinline
#    else
#        define CIALLO_SHA512_TARGET_AVX2 __attribute__((target("avx2,bmi,bmi2")))
#        define CIALLO_SHA512_INLINE_AVX2                                                          \
            __attribute__((target("avx2,bmi,bmi2"), always_inline)) inline
#    endif

/// @brief
///   Read extended control register 0 (XCR0), which reports the processor state components that
///   the operating system has enabled.  AVX2 code must not run unless the XMM and YMM state are
///   enabled.
/// @return
///   Current value of XCR0.
[[nodiscard]] static std::uint64_t sha512_xgetbv0() noexcept {
#    if defined(_MSC_VER)
    return static_cast<std::uint64_t>(_xgetbv(0));
#    else
    std::uint32_t low  = 0;
    std::uint32_t high = 0;
    __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0U));
    return (static_cast<std::uint64_t>(high) << 32) | low;
#    endif
}

/// @brief
///   Rotate two 64-bit lanes to the right by a compile-time amount.
/// @tparam Amount
///   Number of bits to rotate by, in the range [1, 63].
/// @param value
///   Vector to rotate.
/// @return
///   Rotated vector.
template <int Amount>
[[nodiscard]] static CIALLO_SHA512_INLINE_AVX2 __m256i
sha512_rotate_right_epi64(__m256i value) noexcept {
    static_assert(Amount > 0 && Amount < 64, "Invalid SHA512 rotation amount.");
    return _mm256_or_si256(_mm256_srli_epi64(value, Amount), _mm256_slli_epi64(value, 64 - Amount));
}

/// @brief
///   SHA512 lower-case sigma 0 on the message words of two blocks at once.
/// @param value
///   Vector holding one message word of both blocks.
/// @return
///   Vector holding the sigma 0 result of both blocks.
[[nodiscard]] static CIALLO_SHA512_INLINE_AVX2 __m256i
sha512_small_sigma0_epi64(__m256i value) noexcept {
    return _mm256_xor_si256(
        _mm256_xor_si256(sha512_rotate_right_epi64<1>(value), sha512_rotate_right_epi64<8>(value)),
        _mm256_srli_epi64(value, 7));
}

/// @brief
///   SHA512 lower-case sigma 1 on the message words of two blocks at once.
/// @param value
///   Vector holding one message word of both blocks.
/// @return
///   Vector holding the sigma 1 result of both blocks.
[[nodiscard]] static CIALLO_SHA512_INLINE_AVX2 __m256i
sha512_small_sigma1_epi64(__m256i value) noexcept {
    return _mm256_xor_si256(_mm256_xor_si256(sha512_rotate_right_epi64<19>(value),
                                             sha512_rotate_right_epi64<61>(value)),
                            _mm256_srli_epi64(value, 6));
}

/// @brief
///   Load the message words @p index and @p index + 1 of two message blocks into one vector.
/// @param low
///   Message schedule of the first block.
/// @param high
///   Message schedule of the second block.
/// @param index
///   Index of the first word to load.
/// @return
///   Vector whose low lane holds the words of @p low and high lane those of @p high .
[[nodiscard]] static CIALLO_SHA512_INLINE_AVX2 __m256i
sha512_load_schedule_pair(const std::uint64_t *low,
                          const std::uint64_t *high,
                          std::size_t index) noexcept {
    const __m128i first  = _mm_loadu_si128(reinterpret_cast<const __m128i *>(low + index));
    const __m128i second = _mm_loadu_si128(reinterpret_cast<const __m128i *>(high + index));
    return _mm256_set_m128i(second, first);
}

/// @brief
///   Store one pair of message schedule words to the schedules of two message blocks.
/// @param low
///   Message schedule of the first block.
/// @param high
///   Message schedule of the second block.
/// @param index
///   Index of the first word to store.
/// @param value
///   Vector whose low lane goes to @p low and high lane to @p high .
static CIALLO_SHA512_INLINE_AVX2 void sha512_store_schedule_pair(std::uint64_t *low,
                                                                 std::uint64_t *high,
                                                                 std::size_t index,
                                                                 __m256i value) noexcept {
    _mm_storeu_si128(reinterpret_cast<__m128i *>(low + index), _mm256_castsi256_si128(value));
    _mm_storeu_si128(reinterpret_cast<__m128i *>(high + index), _mm256_extracti128_si256(value, 1));
}

/// @brief
///   Extend the message schedule of two SHA512 blocks by one pair of words.
/// @param words
///   Message schedule of both blocks.
/// @param index
///   Index of the first word of the pair, in the range [16, 78].
static CIALLO_SHA512_INLINE_AVX2 void sha512_schedule_step(std::uint64_t (&words)[2][80],
                                                           std::size_t index) noexcept {
    const __m256i w16   = sha512_load_schedule_pair(words[0], words[1], index - 16);
    const __m256i w15   = sha512_load_schedule_pair(words[0], words[1], index - 15);
    const __m256i w7    = sha512_load_schedule_pair(words[0], words[1], index - 7);
    const __m256i w2    = sha512_load_schedule_pair(words[0], words[1], index - 2);
    const __m256i value = _mm256_add_epi64(
        _mm256_add_epi64(w16, w7),
        _mm256_add_epi64(sha512_small_sigma0_epi64(w15), sha512_small_sigma1_epi64(w2)));
    sha512_store_schedule_pair(words[0], words[1], index, value);
}

/// @brief
///   Compute the message schedule of two SHA512 blocks at once.
///
///   Consecutive message blocks of one stream are chained through the hash state, so their round
///   functions cannot run in parallel.  Their message schedules are independent, however: both are
///   derived from the message alone.  Computing two schedules side by side fills all four 64-bit
///   lanes of an AVX2 vector.
/// @param words
///   Message schedule of both blocks, @c words[0] for the first block and @c words[1] for the
///   second one.  The first sixteen words of each row must already be loaded.
static CIALLO_SHA512_INLINE_AVX2 void
sha512_schedule_pair_blocks(std::uint64_t (&words)[2][80]) noexcept {
    for (std::size_t index = 16; index < 80; index += 2) {
        sha512_schedule_step(words, index);
    }
}

/// @brief
///   Load the first sixteen words of two SHA512 blocks in big-endian byte order.
/// @param data
///   Pointer to the start of the first block; the second block follows it immediately.
/// @param words
///   Message schedule of both blocks to fill.
static CIALLO_SHA512_INLINE_AVX2 void
sha512_load_pair_blocks(const std::uint8_t *data, std::uint64_t (&words)[2][80]) noexcept {
    const __m256i byte_swap =
        _mm256_setr_epi8(7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
                         0, 15, 14, 13, 12, 11, 10, 9, 8);

    for (std::size_t group = 0; group < 4; ++group) {
        const __m256i first = _mm256_shuffle_epi8(
            _mm256_loadu_si256(reinterpret_cast<const __m256i *>(data + group * 32)), byte_swap);
        const __m256i second =
            _mm256_shuffle_epi8(_mm256_loadu_si256(reinterpret_cast<const __m256i *>(
                                    data + sha512_block_size + group * 32)),
                                byte_swap);
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(&words[0][group * 4]), first);
        _mm256_storeu_si256(reinterpret_cast<__m256i *>(&words[1][group * 4]), second);
    }
}

/// @brief
///   Perform one SHA512 round on a scalar state.
/// @param a
///   State word A of the round.
/// @param b
///   State word B of the round.
/// @param c
///   State word C of the round.
/// @param d
///   State word D of the round.
/// @param e
///   State word E of the round.
/// @param f
///   State word F of the round.
/// @param g
///   State word G of the round.
/// @param h
///   State word H of the round.
/// @param word
///   Message schedule word of the round.
/// @param constant
///   Round constant of the round.
static CIALLO_SHA512_INLINE_AVX2 void sha512_round(std::uint64_t &a,
                                                   std::uint64_t &b,
                                                   std::uint64_t &c,
                                                   std::uint64_t &d,
                                                   std::uint64_t &e,
                                                   std::uint64_t &f,
                                                   std::uint64_t &g,
                                                   std::uint64_t &h,
                                                   std::uint64_t word,
                                                   std::uint64_t constant) noexcept {
    const std::uint64_t t1 = h + sha512_big_sigma1(e) + sha512_ch(e, f, g) + constant + word;
    const std::uint64_t t2 = sha512_big_sigma0(a) + sha512_maj(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
}

/// @brief
///   Run the eighty SHA512 rounds of one block.
///
///   The rounds are unrolled eight at a time.  When @p next is not null, two pairs of message
///   schedule words of the next block pair are computed after every group of eight rounds: the
///   message schedule is latency bound while the round chain is throughput bound, so the two
///   interleave well and the schedule cost almost disappears.
/// @param state
///   Hash state to update in place.
/// @param words
///   Message schedule of the block.
/// @param next
///   Message schedule of the next block pair to extend, or null when there is no next pair.
/// @param next_index
///   Index of the next message schedule pair to compute.  Advanced by this function.
static CIALLO_SHA512_INLINE_AVX2 void sha512_compress_rounds(std::uint64_t state[8],
                                                             const std::uint64_t *words,
                                                             std::uint64_t (*next)[2][80],
                                                             std::size_t &next_index) noexcept {
    std::uint64_t a = state[0];
    std::uint64_t b = state[1];
    std::uint64_t c = state[2];
    std::uint64_t d = state[3];
    std::uint64_t e = state[4];
    std::uint64_t f = state[5];
    std::uint64_t g = state[6];
    std::uint64_t h = state[7];

    for (std::size_t index = 0; index < 80; index += 8) {
        sha512_round(a, b, c, d, e, f, g, h, words[index + 0], sha512_round_constants[index + 0]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 1], sha512_round_constants[index + 1]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 2], sha512_round_constants[index + 2]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 3], sha512_round_constants[index + 3]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 4], sha512_round_constants[index + 4]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 5], sha512_round_constants[index + 5]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 6], sha512_round_constants[index + 6]);
        sha512_round(a, b, c, d, e, f, g, h, words[index + 7], sha512_round_constants[index + 7]);

        if (next != nullptr && next_index < 80) {
            sha512_schedule_step(*next, next_index);
            sha512_schedule_step(*next, next_index + 2);
            next_index += 4;
        }
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

/// @brief
///   SHA512 compression function with AVX2 instructions.
///
///   The round function of one block is a single dependency chain and stays scalar.  The message
///   schedule is vectorized for two blocks at once and the schedule of the next block pair is
///   computed while the rounds of the current pair run.  The last block of an odd count is
///   handled by the portable implementation.
/// @param state
///   Current SHA512 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 128-byte message blocks to compress.
CIALLO_SHA512_TARGET_AVX2 static void sha512_compress_avx2(std::uint64_t state[8],
                                                           const std::uint8_t *data,
                                                           std::size_t blocks) noexcept {
    if (blocks < 2) {
        sha512_compress_portable(state, data, blocks);
        return;
    }

    // Two schedule buffers alternate: while the rounds of one pair of blocks run, the schedule of
    // the next pair is computed into the other buffer.
    std::uint64_t first[2][80];
    std::uint64_t second[2][80];
    std::uint64_t (*current)[2][80] = &first;
    std::uint64_t (*next)[2][80]    = &second;

    sha512_load_pair_blocks(data, *current);
    sha512_schedule_pair_blocks(*current);
    data += 2 * sha512_block_size;
    blocks -= 2;

    while (blocks >= 2) {
        sha512_load_pair_blocks(data, *next);

        std::size_t next_index = 16;
        sha512_compress_rounds(state, (*current)[0], next, next_index);
        sha512_compress_rounds(state, (*current)[1], next, next_index);

        std::uint64_t (*swap)[2][80] = current;
        current                      = next;
        next                         = swap;

        data += 2 * sha512_block_size;
        blocks -= 2;
    }

    std::size_t unused_index = 80;
    sha512_compress_rounds(state, (*current)[0], nullptr, unused_index);
    sha512_compress_rounds(state, (*current)[1], nullptr, unused_index);

    if (blocks != 0) {
        sha512_compress_portable(state, data, blocks);
    }
}
#endif

#if (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
#    if defined(_MSC_VER) && !defined(__clang__)
#        define CIALLO_SHA512_TARGET_SHA512
#        define CIALLO_SHA512_INLINE_SHA512 __forceinline
#    else
#        define CIALLO_SHA512_TARGET_SHA512 __attribute__((target("arch=armv8.2-a+sha3")))
#        define CIALLO_SHA512_INLINE_SHA512 __attribute__((always_inline)) inline
#    endif

/// @brief
///   Update one pair of SHA512 message schedule words.
/// @param w16
///   Message vector holding the words sixteen and fifteen positions back.
/// @param w14
///   Message vector holding the words fourteen and thirteen positions back.
/// @param w8
///   Message vector holding the words eight and seven positions back.
/// @param w6
///   Message vector holding the words six and five positions back.
/// @param w2
///   Message vector holding the words two and one positions back.
/// @return
///   Message vector holding the next two words of the schedule.
[[nodiscard]] CIALLO_SHA512_TARGET_SHA512 static CIALLO_SHA512_INLINE_SHA512 uint64x2_t
sha512_schedule_update(uint64x2_t w16,
                       uint64x2_t w14,
                       uint64x2_t w8,
                       uint64x2_t w6,
                       uint64x2_t w2) noexcept {
    // The @c sha512su0 instruction accumulates the lower-case sigma 0 terms, and the @c sha512su1
    // instruction adds the lower-case sigma 1 terms.  The words seven and six positions back
    // straddle two vectors, so @c vextq_u64 assembles them into one vector.
    return vsha512su1q_u64(vsha512su0q_u64(w16, w14), w2, vextq_u64(w8, w6, 1));
}

/// @brief
///   Perform two SHA512 rounds and update the state vectors.
/// @param round_index
///   Index of the first round, in the range [0, 78].
/// @param schedule
///   Message vector holding the two message schedule words of the rounds.
/// @param ab
///   First state vector of the round pair.
/// @param cd
///   Second state vector of the round pair.
/// @param ef
///   Third state vector of the round pair.
/// @param gh
///   Fourth state vector of the round pair.
CIALLO_SHA512_TARGET_SHA512 static CIALLO_SHA512_INLINE_SHA512 void
sha512_round_pair(std::size_t round_index,
                  uint64x2_t schedule,
                  uint64x2_t &ab,
                  uint64x2_t &cd,
                  uint64x2_t &ef,
                  uint64x2_t &gh) noexcept {
    const uint64x2_t constants   = vld1q_u64(&sha512_round_constants[round_index]);
    const uint64x2_t initial_sum = vaddq_u64(schedule, constants);

    // The sha512h instruction expects the words of the first round in the high half of the
    // vector, so swap the two halves of the round-constant and message sum before adding @p gh.
    const uint64x2_t sum = vaddq_u64(vextq_u64(initial_sum, initial_sum, 1), gh);
    const uint64x2_t de  = vextq_u64(cd, ef, 1);
    const uint64x2_t fg  = vextq_u64(ef, gh, 1);

    // The @c sha512h instruction computes the upper-case sigma 1 and @c Ch terms, while @c
    // sha512h2 adds the upper-case sigma 0 and @c Maj terms.  The intermediate result is also
    // added to the state vector holding {C, D}.
    const uint64x2_t intermediate = vsha512hq_u64(sum, fg, de);
    gh                            = vsha512h2q_u64(intermediate, cd, ab);
    cd                            = vaddq_u64(cd, intermediate);
}

/// @brief
///   Perform sixteen SHA512 rounds and update the message schedule for the next group.
/// @param group
///   Index of the sixteen-round group, in the range [0, 4].
/// @param ab
///   State vector holding {A, B}.
/// @param cd
///   State vector holding {C, D}.
/// @param ef
///   State vector holding {E, F}.
/// @param gh
///   State vector holding {G, H}.
/// @param words
///   Message vectors carrying the current message schedule.
CIALLO_SHA512_TARGET_SHA512 static CIALLO_SHA512_INLINE_SHA512 void
sha512_round_group(std::size_t group,
                   uint64x2_t &ab,
                   uint64x2_t &cd,
                   uint64x2_t &ef,
                   uint64x2_t &gh,
                   uint64x2_t (&words)[8]) noexcept {
    // Extend the message schedule to the next sixteen rounds.  The first group uses the words
    // loaded directly from the message block, so it does not need an update.
    if (group != 0) {
        words[0] = sha512_schedule_update(words[0], words[1], words[4], words[5], words[7]);
        words[1] = sha512_schedule_update(words[1], words[2], words[5], words[6], words[0]);
        words[2] = sha512_schedule_update(words[2], words[3], words[6], words[7], words[1]);
        words[3] = sha512_schedule_update(words[3], words[4], words[7], words[0], words[2]);
        words[4] = sha512_schedule_update(words[4], words[5], words[0], words[1], words[3]);
        words[5] = sha512_schedule_update(words[5], words[6], words[1], words[2], words[4]);
        words[6] = sha512_schedule_update(words[6], words[7], words[2], words[3], words[5]);
        words[7] = sha512_schedule_update(words[7], words[0], words[3], words[4], words[6]);
    }

    // Rotate the four state vectors through the round pairs, which keeps the {G, H} vector in
    // the fourth parameter expected by sha512_round_pair.
    const std::size_t round = group * 16;
    sha512_round_pair(round + 0, words[0], ab, cd, ef, gh);
    sha512_round_pair(round + 2, words[1], gh, ab, cd, ef);
    sha512_round_pair(round + 4, words[2], ef, gh, ab, cd);
    sha512_round_pair(round + 6, words[3], cd, ef, gh, ab);
    sha512_round_pair(round + 8, words[4], ab, cd, ef, gh);
    sha512_round_pair(round + 10, words[5], gh, ab, cd, ef);
    sha512_round_pair(round + 12, words[6], ef, gh, ab, cd);
    sha512_round_pair(round + 14, words[7], cd, ef, gh, ab);
}

/// @brief
///   SHA512 compression function with ARMv8.2 @c sha512 extensions.
/// @param state
///   Current SHA512 state to update.
/// @param data
///   Pointer to start of the message blocks to be compressed.
/// @param blocks
///   Number of 128-byte message blocks to compress.
CIALLO_SHA512_TARGET_SHA512 static void sha512_compress_sha512(std::uint64_t state[8],
                                                               const std::uint8_t *data,
                                                               std::size_t blocks) noexcept {
    uint64x2_t ab = vld1q_u64(&state[0]);
    uint64x2_t cd = vld1q_u64(&state[2]);
    uint64x2_t ef = vld1q_u64(&state[4]);
    uint64x2_t gh = vld1q_u64(&state[6]);

    for (; blocks != 0; --blocks, data += sha512_block_size) {
        const uint64x2_t ab_save = ab;
        const uint64x2_t cd_save = cd;
        const uint64x2_t ef_save = ef;
        const uint64x2_t gh_save = gh;

        // The eight message vectors also carry the partially computed message schedule.
        uint64x2_t words[8];
        words[0] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 0 * 16)));
        words[1] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 1 * 16)));
        words[2] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 2 * 16)));
        words[3] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 3 * 16)));
        words[4] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 4 * 16)));
        words[5] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 5 * 16)));
        words[6] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 6 * 16)));
        words[7] = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data + 7 * 16)));

        // Unroll all five groups so that the compiler keeps the schedule vectors in registers
        // and folds the group-index condition of sha512_round_group.
        sha512_round_group(0, ab, cd, ef, gh, words);
        sha512_round_group(1, ab, cd, ef, gh, words);
        sha512_round_group(2, ab, cd, ef, gh, words);
        sha512_round_group(3, ab, cd, ef, gh, words);
        sha512_round_group(4, ab, cd, ef, gh, words);

        ab = vaddq_u64(ab, ab_save);
        cd = vaddq_u64(cd, cd_save);
        ef = vaddq_u64(ef, ef_save);
        gh = vaddq_u64(gh, gh_save);
    }

    vst1q_u64(&state[0], ab);
    vst1q_u64(&state[2], cd);
    vst1q_u64(&state[4], ef);
    vst1q_u64(&state[6], gh);
}
#endif

/// @brief
///   SHA512 compression function pointer.
using sha512_compress_fn = void (*)(std::uint64_t *, const std::uint8_t *, std::size_t);

/// @brief
///   Select SHA512 compression implementation according to current CPU features.
/// @return
///   SHA512 compression implementation that best suits current CPU.
[[nodiscard]] static sha512_compress_fn select_sha512_compress() noexcept {
#if (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
    if constexpr (std::endian::native != std::endian::little) {
        return &sha512_compress_portable;
    } else {
#    if defined(__linux__)
        const unsigned long hwcap = getauxval(AT_HWCAP);
        if ((hwcap & HWCAP_SHA512) != 0) {
            return &sha512_compress_sha512;
        }
#    elif defined(__APPLE__)
        int value        = 0;
        std::size_t size = sizeof(value);
        if (sysctlbyname("hw.optional.armv8_2_sha512", &value, &size, nullptr, 0) == 0 &&
            value != 0) {
            return &sha512_compress_sha512;
        }
#    elif defined(_WIN32)
#        if defined(PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE)
        if (IsProcessorFeaturePresent(PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE) != 0) {
            return &sha512_compress_sha512;
        }
#        endif
#    endif
        return &sha512_compress_portable;
    }
#elif defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||             \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;

    // AVX2 is only usable when the processor implements it and the operating system has enabled
    // the XMM and YMM state, which XCR0 reports.
    cpuid(0, 0, eax, ebx, ecx, edx);
    if (eax < 7) {
        return &sha512_compress_portable;
    }

    cpuid(1, 0, eax, ebx, ecx, edx);
    bool avx = (ecx & (1U << 28)) != 0;
    if ((ecx & (1U << 27)) != 0) {
        constexpr std::uint64_t avx_state_mask = (1U << 1) | (1U << 2);
        avx = avx && (sha512_xgetbv0() & avx_state_mask) == avx_state_mask;
    } else {
        avx = false;
    }
    if (!avx) {
        return &sha512_compress_portable;
    }

    cpuid(7, 0, eax, ebx, ecx, edx);
    // Every x86 processor that implements AVX2 also implements BMI2, which the scalar round
    // function uses to rotate without an extra move.  Check both bits anyway.
    constexpr std::uint32_t avx2_and_bmi2 = (1U << 5) | (1U << 8);
    if ((ebx & avx2_and_bmi2) == avx2_and_bmi2) {
        return &sha512_compress_avx2;
    }
    return &sha512_compress_portable;
#else
    return &sha512_compress_portable;
#endif
}

/// @brief
///   Calculate SHA384 or SHA512 hash value.
/// @param data
///   Pointer to start of data to be hashed.
/// @param size
///   Size in byte of data to be hashed.
/// @param hash
///   Pointer to memory to store the hash result.
/// @param initial_state
///   Initial hash value of the algorithm.
/// @param digest_size
///   Size in byte of the hash result.
static void sha512_hash_impl(const void *data,
                             std::size_t size,
                             void *hash,
                             const std::uint64_t (&initial_state)[8],
                             std::size_t digest_size) noexcept {
    static const sha512_compress_fn compress = select_sha512_compress();

    std::uint64_t state[8];
    for (std::size_t index = 0; index < 8; ++index) {
        state[index] = initial_state[index];
    }

    const auto *bytes             = static_cast<const std::uint8_t *>(data);
    const std::size_t block_count = size / sha512_block_size;
    if (block_count != 0) {
        compress(state, bytes, block_count);
    }

    // Append the mandatory 0x80 byte and the zero padding.  One or two blocks are required
    // depending on whether the 128-bit message length still fits in the current block.
    const std::size_t remaining              = size % sha512_block_size;
    std::uint8_t tail[2 * sha512_block_size] = {};
    if (remaining != 0) {
        std::memcpy(tail, bytes + block_count * sha512_block_size, remaining);
    }
    tail[remaining] = 0x80U;

    const std::size_t tail_size = remaining < 112 ? sha512_block_size : 2 * sha512_block_size;
    // The length field is 128-bit.  For size_t inputs below 2^61 bytes the high word is zero,
    // but compute it anyway so that the full message-length range is handled correctly.
    sha512_store_be64(tail + tail_size - 16, static_cast<std::uint64_t>(size) >> 61);
    sha512_store_be64(tail + tail_size - 8, static_cast<std::uint64_t>(size) * 8);
    compress(state, tail, tail_size / sha512_block_size);

    auto *digest = static_cast<std::uint8_t *>(hash);
    for (std::size_t index = 0; index < digest_size / 8; ++index) {
        sha512_store_be64(digest + index * 8, state[index]);
    }
}

void ciallo::sha512(const void *data, std::size_t size, void *hash) noexcept {
    sha512_hash_impl(data, size, hash, sha512_initial_state, 64);
}

void ciallo::sha384(const void *data, std::size_t size, void *hash) noexcept {
    sha512_hash_impl(data, size, hash, sha384_initial_state, 48);
}
