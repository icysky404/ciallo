#include "ciallo/crypto/chacha20.hpp"

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||             \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#    include <immintrin.h>
#    if defined(_MSC_VER)
#        include <intrin.h>
#    else
#        include <cpuid.h>
#    endif
#    define CIALLO_CHACHA20_X86 1
#elif (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
#    if defined(_MSC_VER) && !defined(__clang__)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
#    define CIALLO_CHACHA20_ARM 1
#endif

#include <bit>

/// @brief
///   Size in byte of one ChaCha20 keystream block.
static constexpr std::size_t chacha20_block_size = 64;

/// @brief
///   ChaCha20 state constants, "expand 32-byte k" (RFC 8439, section 2.3).
static constexpr std::uint32_t chacha20_constants[4] = {
    0x61707865,
    0x3320646E,
    0x79622D32,
    0x6B206574,
};

/// @brief
///   Load a 32-bit value in little-endian byte order.
/// @param data
///   Pointer to the first byte of the value.
/// @return
///   Value read from @p data.
[[nodiscard]] static std::uint32_t chacha20_load_le32(const std::uint8_t *data) noexcept {
    return static_cast<std::uint32_t>(data[0]) | (static_cast<std::uint32_t>(data[1]) << 8) |
           (static_cast<std::uint32_t>(data[2]) << 16) |
           (static_cast<std::uint32_t>(data[3]) << 24);
}

/// @brief
///   Store a 32-bit value in little-endian byte order.
/// @param data
///   Pointer to the destination.
/// @param value
///   Value to store.
static void chacha20_store_le32(std::uint8_t *data, std::uint32_t value) noexcept {
    data[0] = static_cast<std::uint8_t>(value);
    data[1] = static_cast<std::uint8_t>(value >> 8);
    data[2] = static_cast<std::uint8_t>(value >> 16);
    data[3] = static_cast<std::uint8_t>(value >> 24);
}

/// @brief
///   ChaCha20 quarter round (RFC 8439, section 2.1).
/// @param a
///   First state word of the quarter round.
/// @param b
///   Second state word of the quarter round.
/// @param c
///   Third state word of the quarter round.
/// @param d
///   Fourth state word of the quarter round.
static void chacha20_quarter_round(std::uint32_t &a,
                                   std::uint32_t &b,
                                   std::uint32_t &c,
                                   std::uint32_t &d) noexcept {
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
///   Portable ChaCha20 block function for all architectures.
/// @param state
///   Initial ChaCha20 state, including the block counter.
/// @param[out] keystream
///   Pointer to 64 bytes of memory that receives the keystream block.
static void chacha20_block_portable(const std::uint32_t *state, std::uint8_t *keystream) noexcept {
    std::uint32_t working[16];
    for (std::size_t index = 0; index < 16; ++index) {
        working[index] = state[index];
    }

    for (std::size_t round = 0; round < 10; ++round) {
        chacha20_quarter_round(working[0], working[4], working[8], working[12]);
        chacha20_quarter_round(working[1], working[5], working[9], working[13]);
        chacha20_quarter_round(working[2], working[6], working[10], working[14]);
        chacha20_quarter_round(working[3], working[7], working[11], working[15]);
        chacha20_quarter_round(working[0], working[5], working[10], working[15]);
        chacha20_quarter_round(working[1], working[6], working[11], working[12]);
        chacha20_quarter_round(working[2], working[7], working[8], working[13]);
        chacha20_quarter_round(working[3], working[4], working[9], working[14]);
    }

    for (std::size_t index = 0; index < 16; ++index) {
        chacha20_store_le32(keystream + index * 4, working[index] + state[index]);
    }
}

/// @brief
///   Portable ChaCha20 encrypt/decrypt function for all architectures.
/// @param input
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param state
///   Initial ChaCha20 state.  The block counter is advanced in place.
/// @param[out] output
///   Pointer to start of the output buffer.
static void chacha20_xor_portable(const std::uint8_t *input,
                                  std::size_t size,
                                  std::uint32_t *state,
                                  std::uint8_t *output) noexcept {
    alignas(16) std::uint8_t keystream[chacha20_block_size];

    while (size >= chacha20_block_size) {
        chacha20_block_portable(state, keystream);
        for (std::size_t index = 0; index < chacha20_block_size; ++index) {
            output[index] = static_cast<std::uint8_t>(input[index] ^ keystream[index]);
        }

        ++state[12];
        input += chacha20_block_size;
        output += chacha20_block_size;
        size -= chacha20_block_size;
    }

    if (size != 0) {
        chacha20_block_portable(state, keystream);
        for (std::size_t index = 0; index < size; ++index) {
            output[index] = static_cast<std::uint8_t>(input[index] ^ keystream[index]);
        }
    }
}

#if defined(CIALLO_CHACHA20_X86)
#    if defined(_MSC_VER)
#        define CIALLO_CHACHA20_X86_TARGET_SSE2
#        define CIALLO_CHACHA20_X86_TARGET_AVX2
#        define CIALLO_CHACHA20_SSE2_INLINE __forceinline
#        define CIALLO_CHACHA20_AVX2_INLINE __forceinline
#    else
#        define CIALLO_CHACHA20_X86_TARGET_SSE2 __attribute__((target("sse2")))
#        define CIALLO_CHACHA20_X86_TARGET_AVX2 __attribute__((target("avx2")))
#        define CIALLO_CHACHA20_SSE2_INLINE __attribute__((target("sse2"), always_inline)) inline
#        define CIALLO_CHACHA20_AVX2_INLINE __attribute__((target("avx2"), always_inline)) inline
#    endif

/// @brief
///   Execute the CPUID instruction.
/// @param leaf
///   CPUID leaf to query.
/// @param subleaf
///   CPUID subleaf to query.
/// @param[out] eax
///   Value of the EAX register after the instruction.
/// @param[out] ebx
///   Value of the EBX register after the instruction.
/// @param[out] ecx
///   Value of the ECX register after the instruction.
/// @param[out] edx
///   Value of the EDX register after the instruction.
static void chacha20_cpuid(std::uint32_t leaf,
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
///   Read extended control register 0 (XCR0), which reports the processor state components that
///   the operating system has enabled.  Unless bits 1 and 2 are set, the operating system has not
///   enabled the XMM and YMM state that AVX2 code requires, even if the processor implements it.
/// @return
///   Current value of XCR0.
[[nodiscard]] static std::uint64_t chacha20_xgetbv0() noexcept {
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
///   Rotate four 32-bit lanes to the left by a compile-time amount.
/// @tparam Amount
///   Number of bits to rotate by, in the range [1, 31].
/// @param value
///   Vector to rotate.
/// @return
///   Rotated vector.
template <int Amount>
[[nodiscard]] static CIALLO_CHACHA20_SSE2_INLINE __m128i
chacha20_rotl_sse2(__m128i value) noexcept {
    static_assert(Amount > 0 && Amount < 32, "Invalid ChaCha20 rotation amount.");
    if constexpr (Amount == 16) {
        // Swapping the two 16-bit halves of every 32-bit lane is exactly a rotation by 16.  SSE2
        // has no byte shuffle, so both 64-bit halves are shuffled separately.
        return _mm_shufflehi_epi16(_mm_shufflelo_epi16(value, 0xB1), 0xB1);
    } else {
        return _mm_or_si128(_mm_slli_epi32(value, Amount), _mm_srli_epi32(value, 32 - Amount));
    }
}

/// @brief
///   ChaCha20 quarter round on four independent blocks at once with SSE2 instructions.
/// @param a
///   First state vector of the quarter round.
/// @param b
///   Second state vector of the quarter round.
/// @param c
///   Third state vector of the quarter round.
/// @param d
///   Fourth state vector of the quarter round.
static CIALLO_CHACHA20_SSE2_INLINE void
chacha20_quarter_round_sse2(__m128i &a, __m128i &b, __m128i &c, __m128i &d) noexcept {
    a = _mm_add_epi32(a, b);
    d = chacha20_rotl_sse2<16>(_mm_xor_si128(d, a));
    c = _mm_add_epi32(c, d);
    b = chacha20_rotl_sse2<12>(_mm_xor_si128(b, c));
    a = _mm_add_epi32(a, b);
    d = chacha20_rotl_sse2<8>(_mm_xor_si128(d, a));
    c = _mm_add_epi32(c, d);
    b = chacha20_rotl_sse2<7>(_mm_xor_si128(b, c));
}

/// @brief
///   Transpose a 4x4 matrix of 32-bit lanes with SSE2 instructions.
/// @param x0
///   First row of the matrix.
/// @param x1
///   Second row of the matrix.
/// @param x2
///   Third row of the matrix.
/// @param x3
///   Fourth row of the matrix.
static CIALLO_CHACHA20_SSE2_INLINE void
chacha20_transpose_sse2(__m128i &x0, __m128i &x1, __m128i &x2, __m128i &x3) noexcept {
    // Interleave the two pairs of rows at 32-bit and then at 64-bit granularity.  The first
    // 64-bit transpose produces the even rows of the result, and the second one the odd rows.
    const __m128i t0 = _mm_unpacklo_epi32(x0, x1);
    const __m128i t1 = _mm_unpackhi_epi32(x0, x1);
    const __m128i t2 = _mm_unpacklo_epi32(x2, x3);
    const __m128i t3 = _mm_unpackhi_epi32(x2, x3);

    x0 = _mm_unpacklo_epi64(t0, t2);
    x1 = _mm_unpackhi_epi64(t0, t2);
    x2 = _mm_unpacklo_epi64(t1, t3);
    x3 = _mm_unpackhi_epi64(t1, t3);
}

/// @brief
///   XOR one 16-byte group of four keystream blocks with the input data.
/// @param input
///   Pointer to the first byte of the group in the four input blocks.
/// @param[out] output
///   Pointer to the first byte of the group in the four output blocks.
/// @param x0
///   State vector holding the first four words of each block.
/// @param x1
///   State vector holding the second four words of each block.
/// @param x2
///   State vector holding the third four words of each block.
/// @param x3
///   State vector holding the fourth four words of each block.
static CIALLO_CHACHA20_SSE2_INLINE void chacha20_xor_group_sse2(const std::uint8_t *input,
                                                                std::uint8_t *output,
                                                                __m128i x0,
                                                                __m128i x1,
                                                                __m128i x2,
                                                                __m128i x3) noexcept {
    chacha20_transpose_sse2(x0, x1, x2, x3);

    const __m128i data0 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + 0 * chacha20_block_size));
    const __m128i data1 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + 1 * chacha20_block_size));
    const __m128i data2 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + 2 * chacha20_block_size));
    const __m128i data3 =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(input + 3 * chacha20_block_size));

    _mm_storeu_si128(reinterpret_cast<__m128i *>(output + 0 * chacha20_block_size),
                     _mm_xor_si128(data0, x0));
    _mm_storeu_si128(reinterpret_cast<__m128i *>(output + 1 * chacha20_block_size),
                     _mm_xor_si128(data1, x1));
    _mm_storeu_si128(reinterpret_cast<__m128i *>(output + 2 * chacha20_block_size),
                     _mm_xor_si128(data2, x2));
    _mm_storeu_si128(reinterpret_cast<__m128i *>(output + 3 * chacha20_block_size),
                     _mm_xor_si128(data3, x3));
}

/// @brief
///   Perform the four column quarter rounds of a four-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_SSE2_INLINE void chacha20_column_round_sse2(__m128i (&x)[16]) noexcept {
    chacha20_quarter_round_sse2(x[0], x[4], x[8], x[12]);
    chacha20_quarter_round_sse2(x[1], x[5], x[9], x[13]);
    chacha20_quarter_round_sse2(x[2], x[6], x[10], x[14]);
    chacha20_quarter_round_sse2(x[3], x[7], x[11], x[15]);
}

/// @brief
///   Perform the four diagonal quarter rounds of a four-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_SSE2_INLINE void chacha20_diagonal_round_sse2(__m128i (&x)[16]) noexcept {
    chacha20_quarter_round_sse2(x[0], x[5], x[10], x[15]);
    chacha20_quarter_round_sse2(x[1], x[6], x[11], x[12]);
    chacha20_quarter_round_sse2(x[2], x[7], x[8], x[13]);
    chacha20_quarter_round_sse2(x[3], x[4], x[9], x[14]);
}

/// @brief
///   Encrypt/decrypt four consecutive ChaCha20 blocks with SSE2 instructions.
/// @param state
///   Initial ChaCha20 state, including the counter of the first block.
/// @param input
///   Pointer to the start of the 256-byte input.
/// @param[out] output
///   Pointer to the start of the 256-byte output.  May be the same as @p input .
CIALLO_CHACHA20_X86_TARGET_SSE2 static void
chacha20_xor_4blocks_sse2(const std::uint32_t *state,
                          const std::uint8_t *input,
                          std::uint8_t *output) noexcept {
    // Each vector holds one state word for the four blocks.  Lane @c i of every vector therefore
    // belongs to block @c i , so all four blocks progress through the rounds simultaneously.
    const __m128i initial_counter =
        _mm_add_epi32(_mm_set1_epi32(static_cast<int>(state[12])), _mm_setr_epi32(0, 1, 2, 3));

    __m128i x[16];
    for (std::size_t index = 0; index < 16; ++index) {
        x[index] = _mm_set1_epi32(static_cast<int>(state[index]));
    }
    x[12] = initial_counter;

    // Unroll all ten double rounds explicitly.  Relying on an unroll pragma would leave the loop
    // rolled on compilers that do not implement it, notably MSVC.
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);
    chacha20_column_round_sse2(x);
    chacha20_diagonal_round_sse2(x);

    for (std::size_t index = 0; index < 16; ++index) {
        if (index != 12) {
            x[index] = _mm_add_epi32(x[index], _mm_set1_epi32(static_cast<int>(state[index])));
        }
    }
    x[12] = _mm_add_epi32(x[12], initial_counter);

    // Words 0..3 of all four blocks, then words 4..7, and so on.  Transposing each group of four
    // state words turns them into one contiguous 16-byte chunk per block.
    chacha20_xor_group_sse2(input + 0 * 16, output + 0 * 16, x[0], x[1], x[2], x[3]);
    chacha20_xor_group_sse2(input + 1 * 16, output + 1 * 16, x[4], x[5], x[6], x[7]);
    chacha20_xor_group_sse2(input + 2 * 16, output + 2 * 16, x[8], x[9], x[10], x[11]);
    chacha20_xor_group_sse2(input + 3 * 16, output + 3 * 16, x[12], x[13], x[14], x[15]);
}

/// @brief
///   Rotate eight 32-bit lanes to the left by a compile-time amount.
/// @tparam Amount
///   Number of bits to rotate by, in the range [1, 31].
/// @param value
///   Vector to rotate.
/// @return
///   Rotated vector.
template <int Amount>
[[nodiscard]] static CIALLO_CHACHA20_AVX2_INLINE __m256i
chacha20_rotl_avx2(__m256i value) noexcept {
    static_assert(Amount > 0 && Amount < 32, "Invalid ChaCha20 rotation amount.");
    if constexpr (Amount == 16) {
        // Byte 2 of every 32-bit lane moves to byte 0, and so on.  The mask repeats in every
        // 128-bit lane, so the four indices of each lane are spelled out.
        return _mm256_shuffle_epi8(value, _mm256_setr_epi32(0x01000302, 0x05040706, 0x09080B0A,
                                                            0x0D0C0F0E, 0x01000302, 0x05040706,
                                                            0x09080B0A, 0x0D0C0F0E));
    } else if constexpr (Amount == 8) {
        return _mm256_shuffle_epi8(value, _mm256_setr_epi32(0x02010003, 0x06050407, 0x0A09080B,
                                                            0x0E0D0C0F, 0x02010003, 0x06050407,
                                                            0x0A09080B, 0x0E0D0C0F));
    } else {
        return _mm256_or_si256(_mm256_slli_epi32(value, Amount),
                               _mm256_srli_epi32(value, 32 - Amount));
    }
}

/// @brief
///   ChaCha20 quarter round on eight independent blocks at once with AVX2 instructions.
/// @param a
///   First state vector of the quarter round.
/// @param b
///   Second state vector of the quarter round.
/// @param c
///   Third state vector of the quarter round.
/// @param d
///   Fourth state vector of the quarter round.
static CIALLO_CHACHA20_AVX2_INLINE void
chacha20_quarter_round_avx2(__m256i &a, __m256i &b, __m256i &c, __m256i &d) noexcept {
    a = _mm256_add_epi32(a, b);
    d = chacha20_rotl_avx2<16>(_mm256_xor_si256(d, a));
    c = _mm256_add_epi32(c, d);
    b = chacha20_rotl_avx2<12>(_mm256_xor_si256(b, c));
    a = _mm256_add_epi32(a, b);
    d = chacha20_rotl_avx2<8>(_mm256_xor_si256(d, a));
    c = _mm256_add_epi32(c, d);
    b = chacha20_rotl_avx2<7>(_mm256_xor_si256(b, c));
}

/// @brief
///   Transpose the state words of one group of four words for eight blocks.
/// @param x0
///   State vector of the first word.
/// @param x1
///   State vector of the second word.
/// @param x2
///   State vector of the third word.
/// @param x3
///   State vector of the fourth word.
/// @param[out] columns
///   16-byte chunk of block @c i in the low lane of @c columns[i] and of block @c i + 4 in its
///   high lane.
static CIALLO_CHACHA20_AVX2_INLINE void chacha20_transpose_avx2(__m256i x0,
                                                                __m256i x1,
                                                                __m256i x2,
                                                                __m256i x3,
                                                                __m256i (&columns)[4]) noexcept {
    const __m256i t0 = _mm256_unpacklo_epi32(x0, x1);
    const __m256i t1 = _mm256_unpackhi_epi32(x0, x1);
    const __m256i t2 = _mm256_unpacklo_epi32(x2, x3);
    const __m256i t3 = _mm256_unpackhi_epi32(x2, x3);

    // The 128-bit lanes are transposed independently, so the low lane of every result holds
    // blocks 0..3 and the high lane blocks 4..7.
    columns[0] = _mm256_unpacklo_epi64(t0, t2);
    columns[1] = _mm256_unpackhi_epi64(t0, t2);
    columns[2] = _mm256_unpacklo_epi64(t1, t3);
    columns[3] = _mm256_unpackhi_epi64(t1, t3);
}

/// @brief
///   XOR two 32-byte half-blocks of keystream computed for blocks @p block and @p block + 4 .
/// @param input
///   Pointer to the start of the eight-block group in the input.
/// @param[out] output
///   Pointer to the start of the eight-block group in the output.
/// @param block
///   Index of the first block, in the range [0, 4).  The second block is @p block + 4 .
/// @param offset
///   Byte offset of the half-block inside its 64-byte block, either 0 or 32.
/// @param lower
///   Chunks of the first two groups of four state words of both blocks.
/// @param upper
///   Chunks of the last two groups of four state words of both blocks.
static CIALLO_CHACHA20_AVX2_INLINE void chacha20_xor_pair_avx2(const std::uint8_t *input,
                                                               std::uint8_t *output,
                                                               std::size_t block,
                                                               std::size_t offset,
                                                               __m256i lower,
                                                               __m256i upper) noexcept {
    // Concatenating the low lanes gives 32 contiguous bytes of block @c block , and the high
    // lanes the same bytes of block @c block + 4 .
    const __m256i first  = _mm256_permute2x128_si256(lower, upper, 0x20);
    const __m256i second = _mm256_permute2x128_si256(lower, upper, 0x31);

    const std::size_t first_offset  = block * chacha20_block_size + offset;
    const std::size_t second_offset = (block + 4) * chacha20_block_size + offset;

    const __m256i first_data =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(input + first_offset));
    const __m256i second_data =
        _mm256_loadu_si256(reinterpret_cast<const __m256i *>(input + second_offset));

    _mm256_storeu_si256(reinterpret_cast<__m256i *>(output + first_offset),
                        _mm256_xor_si256(first_data, first));
    _mm256_storeu_si256(reinterpret_cast<__m256i *>(output + second_offset),
                        _mm256_xor_si256(second_data, second));
}

/// @brief
///   Perform the four column quarter rounds of an eight-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_AVX2_INLINE void chacha20_column_round_avx2(__m256i (&x)[16]) noexcept {
    chacha20_quarter_round_avx2(x[0], x[4], x[8], x[12]);
    chacha20_quarter_round_avx2(x[1], x[5], x[9], x[13]);
    chacha20_quarter_round_avx2(x[2], x[6], x[10], x[14]);
    chacha20_quarter_round_avx2(x[3], x[7], x[11], x[15]);
}

/// @brief
///   Perform the four diagonal quarter rounds of an eight-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_AVX2_INLINE void chacha20_diagonal_round_avx2(__m256i (&x)[16]) noexcept {
    chacha20_quarter_round_avx2(x[0], x[5], x[10], x[15]);
    chacha20_quarter_round_avx2(x[1], x[6], x[11], x[12]);
    chacha20_quarter_round_avx2(x[2], x[7], x[8], x[13]);
    chacha20_quarter_round_avx2(x[3], x[4], x[9], x[14]);
}

/// @brief
///   Encrypt/decrypt eight consecutive ChaCha20 blocks with AVX2 instructions.
/// @param state
///   Initial ChaCha20 state, including the counter of the first block.
/// @param input
///   Pointer to the start of the 512-byte input.
/// @param[out] output
///   Pointer to the start of the 512-byte output.  May be the same as @p input .
CIALLO_CHACHA20_X86_TARGET_AVX2 static void
chacha20_xor_8blocks_avx2(const std::uint32_t *state,
                          const std::uint8_t *input,
                          std::uint8_t *output) noexcept {
    // Lane @c i of every vector holds state word @c w of block @c i , so eight blocks progress
    // through the rounds simultaneously.
    const __m256i initial_counter = _mm256_add_epi32(_mm256_set1_epi32(static_cast<int>(state[12])),
                                                     _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));

    __m256i x[16];
    for (std::size_t index = 0; index < 16; ++index) {
        x[index] = _mm256_set1_epi32(static_cast<int>(state[index]));
    }
    x[12] = initial_counter;

    // Unroll all ten double rounds explicitly, for the same reason as in the SSE2 kernel.
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);
    chacha20_column_round_avx2(x);
    chacha20_diagonal_round_avx2(x);

    for (std::size_t index = 0; index < 16; ++index) {
        if (index != 12) {
            x[index] =
                _mm256_add_epi32(x[index], _mm256_set1_epi32(static_cast<int>(state[index])));
        }
    }
    x[12] = _mm256_add_epi32(x[12], initial_counter);

    // Words 0..3 of every block are held in x[0..3], words 4..7 in x[4..7], and so on.
    // Transposing a group of four words yields one 16-byte chunk per block, and concatenating two
    // consecutive chunk groups yields 32 contiguous bytes of a single block.
    __m256i chunks0[4];
    __m256i chunks1[4];

    chacha20_transpose_avx2(x[0], x[1], x[2], x[3], chunks0);
    chacha20_transpose_avx2(x[4], x[5], x[6], x[7], chunks1);
    chacha20_xor_pair_avx2(input, output, 0, 0, chunks0[0], chunks1[0]);
    chacha20_xor_pair_avx2(input, output, 1, 0, chunks0[1], chunks1[1]);
    chacha20_xor_pair_avx2(input, output, 2, 0, chunks0[2], chunks1[2]);
    chacha20_xor_pair_avx2(input, output, 3, 0, chunks0[3], chunks1[3]);

    chacha20_transpose_avx2(x[8], x[9], x[10], x[11], chunks0);
    chacha20_transpose_avx2(x[12], x[13], x[14], x[15], chunks1);
    chacha20_xor_pair_avx2(input, output, 0, 32, chunks0[0], chunks1[0]);
    chacha20_xor_pair_avx2(input, output, 1, 32, chunks0[1], chunks1[1]);
    chacha20_xor_pair_avx2(input, output, 2, 32, chunks0[2], chunks1[2]);
    chacha20_xor_pair_avx2(input, output, 3, 32, chunks0[3], chunks1[3]);
}

/// @brief
///   ChaCha20 encrypt/decrypt function with AVX2 instructions.
/// @param input
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param state
///   Initial ChaCha20 state.  The block counter is advanced in place.
/// @param[out] output
///   Pointer to start of the output buffer.
static void chacha20_xor_avx2(const std::uint8_t *input,
                              std::size_t size,
                              std::uint32_t *state,
                              std::uint8_t *output) noexcept {
    while (size >= 8 * chacha20_block_size) {
        chacha20_xor_8blocks_avx2(state, input, output);
        state[12] += 8;

        input += 8 * chacha20_block_size;
        output += 8 * chacha20_block_size;
        size -= 8 * chacha20_block_size;
    }

    while (size >= 4 * chacha20_block_size) {
        chacha20_xor_4blocks_sse2(state, input, output);
        state[12] += 4;

        input += 4 * chacha20_block_size;
        output += 4 * chacha20_block_size;
        size -= 4 * chacha20_block_size;
    }

    // A tail longer than two blocks is cheaper with the four-way kernel even though some of the
    // generated keystream is discarded, because the scalar kernel would compute the blocks one by
    // one.  The scalar kernel is faster for one or two blocks.
    if (size > 2 * chacha20_block_size) {
        alignas(32) static constexpr std::uint8_t zero_block[4 * chacha20_block_size] = {};
        alignas(32) std::uint8_t tail_keystream[4 * chacha20_block_size];

        chacha20_xor_4blocks_sse2(state, zero_block, tail_keystream);
        for (std::size_t index = 0; index < size; ++index) {
            output[index] = static_cast<std::uint8_t>(input[index] ^ tail_keystream[index]);
        }
        return;
    }

    chacha20_xor_portable(input, size, state, output);
}

/// @brief
///   ChaCha20 encrypt/decrypt function with SSE2 instructions.
/// @param input
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param state
///   Initial ChaCha20 state.  The block counter is advanced in place.
/// @param[out] output
///   Pointer to start of the output buffer.
static void chacha20_xor_sse2(const std::uint8_t *input,
                              std::size_t size,
                              std::uint32_t *state,
                              std::uint8_t *output) noexcept {
    while (size >= 4 * chacha20_block_size) {
        chacha20_xor_4blocks_sse2(state, input, output);
        state[12] += 4;

        input += 4 * chacha20_block_size;
        output += 4 * chacha20_block_size;
        size -= 4 * chacha20_block_size;
    }

    if (size > 2 * chacha20_block_size) {
        alignas(16) static constexpr std::uint8_t zero_block[4 * chacha20_block_size] = {};
        alignas(16) std::uint8_t tail_keystream[4 * chacha20_block_size];

        chacha20_xor_4blocks_sse2(state, zero_block, tail_keystream);
        for (std::size_t index = 0; index < size; ++index) {
            output[index] = static_cast<std::uint8_t>(input[index] ^ tail_keystream[index]);
        }
        return;
    }

    chacha20_xor_portable(input, size, state, output);
}
#endif

#if defined(CIALLO_CHACHA20_ARM)
#    if defined(_MSC_VER) && !defined(__clang__)
#        define CIALLO_CHACHA20_NEON_INLINE __forceinline
#    else
#        define CIALLO_CHACHA20_NEON_INLINE __attribute__((always_inline)) inline
#    endif

/// @brief
///   Rotate four 32-bit lanes to the left by a compile-time amount.
/// @tparam Amount
///   Number of bits to rotate by, in the range [1, 31].
/// @param value
///   Vector to rotate.
/// @return
///   Rotated vector.
template <int Amount>
[[nodiscard]] static CIALLO_CHACHA20_NEON_INLINE uint32x4_t
chacha20_rotl_neon(uint32x4_t value) noexcept {
    static_assert(Amount > 0 && Amount < 32, "Invalid ChaCha20 rotation amount.");
    return vorrq_u32(vshlq_n_u32(value, Amount), vshrq_n_u32(value, 32 - Amount));
}

/// @brief
///   ChaCha20 quarter round on four independent blocks at once.
/// @param a
///   First state vector of the quarter round.
/// @param b
///   Second state vector of the quarter round.
/// @param c
///   Third state vector of the quarter round.
/// @param d
///   Fourth state vector of the quarter round.
static CIALLO_CHACHA20_NEON_INLINE void
chacha20_quarter_round_neon(uint32x4_t &a, uint32x4_t &b, uint32x4_t &c, uint32x4_t &d) noexcept {
    a = vaddq_u32(a, b);
    d = chacha20_rotl_neon<16>(veorq_u32(d, a));
    c = vaddq_u32(c, d);
    b = chacha20_rotl_neon<12>(veorq_u32(b, c));
    a = vaddq_u32(a, b);
    d = chacha20_rotl_neon<8>(veorq_u32(d, a));
    c = vaddq_u32(c, d);
    b = chacha20_rotl_neon<7>(veorq_u32(b, c));
}

/// @brief
///   Transpose a 4x4 matrix of 32-bit lanes.
/// @param x0
///   First row of the matrix.
/// @param x1
///   Second row of the matrix.
/// @param x2
///   Third row of the matrix.
/// @param x3
///   Fourth row of the matrix.
static CIALLO_CHACHA20_NEON_INLINE void
chacha20_transpose_neon(uint32x4_t &x0, uint32x4_t &x1, uint32x4_t &x2, uint32x4_t &x3) noexcept {
    // Interleave the two pairs of rows at 32-bit and then at 64-bit granularity.  The first
    // 64-bit transpose produces the even rows of the result, and the second one the odd rows.
    const uint32x4x2_t t01 = vtrnq_u32(x0, x1);
    const uint32x4x2_t t23 = vtrnq_u32(x2, x3);

    x0 = vreinterpretq_u32_u64(
        vzip1q_u64(vreinterpretq_u64_u32(t01.val[0]), vreinterpretq_u64_u32(t23.val[0])));
    x1 = vreinterpretq_u32_u64(
        vzip1q_u64(vreinterpretq_u64_u32(t01.val[1]), vreinterpretq_u64_u32(t23.val[1])));
    x2 = vreinterpretq_u32_u64(
        vzip2q_u64(vreinterpretq_u64_u32(t01.val[0]), vreinterpretq_u64_u32(t23.val[0])));
    x3 = vreinterpretq_u32_u64(
        vzip2q_u64(vreinterpretq_u64_u32(t01.val[1]), vreinterpretq_u64_u32(t23.val[1])));
}

/// @brief
///   XOR one 16-byte group of four keystream blocks with the input data.
/// @param input
///   Pointer to the first byte of the group in the four input blocks.
/// @param[out] output
///   Pointer to the first byte of the group in the four output blocks.
/// @param x0
///   State vector holding the first four words of each block.
/// @param x1
///   State vector holding the second four words of each block.
/// @param x2
///   State vector holding the third four words of each block.
/// @param x3
///   State vector holding the fourth four words of each block.
static CIALLO_CHACHA20_NEON_INLINE void chacha20_xor_group_neon(const std::uint8_t *input,
                                                                std::uint8_t *output,
                                                                uint32x4_t x0,
                                                                uint32x4_t x1,
                                                                uint32x4_t x2,
                                                                uint32x4_t x3) noexcept {
    chacha20_transpose_neon(x0, x1, x2, x3);

    const uint8x16_t data0 = vld1q_u8(input + 0 * chacha20_block_size);
    const uint8x16_t data1 = vld1q_u8(input + 1 * chacha20_block_size);
    const uint8x16_t data2 = vld1q_u8(input + 2 * chacha20_block_size);
    const uint8x16_t data3 = vld1q_u8(input + 3 * chacha20_block_size);

    vst1q_u8(output + 0 * chacha20_block_size, veorq_u8(data0, vreinterpretq_u8_u32(x0)));
    vst1q_u8(output + 1 * chacha20_block_size, veorq_u8(data1, vreinterpretq_u8_u32(x1)));
    vst1q_u8(output + 2 * chacha20_block_size, veorq_u8(data2, vreinterpretq_u8_u32(x2)));
    vst1q_u8(output + 3 * chacha20_block_size, veorq_u8(data3, vreinterpretq_u8_u32(x3)));
}

/// @brief
///   Counter offsets used to run four consecutive ChaCha20 blocks in parallel.
static constexpr std::uint32_t chacha20_counter_offsets4[4] = {0, 1, 2, 3};

/// @brief
///   Counter offsets used to run eight consecutive ChaCha20 blocks in parallel.
static constexpr std::uint32_t chacha20_counter_offsets8[8] = {0, 1, 2, 3, 4, 5, 6, 7};

/// @brief
///   Perform the four column quarter rounds of a four-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_NEON_INLINE void chacha20_column_round_neon4(uint32x4_t (&x)[16]) noexcept {
    chacha20_quarter_round_neon(x[0], x[4], x[8], x[12]);
    chacha20_quarter_round_neon(x[1], x[5], x[9], x[13]);
    chacha20_quarter_round_neon(x[2], x[6], x[10], x[14]);
    chacha20_quarter_round_neon(x[3], x[7], x[11], x[15]);
}

/// @brief
///   Perform the four diagonal quarter rounds of a four-block group.
/// @param x
///   State vectors of the group, one vector per state word.
static CIALLO_CHACHA20_NEON_INLINE void
chacha20_diagonal_round_neon4(uint32x4_t (&x)[16]) noexcept {
    chacha20_quarter_round_neon(x[0], x[5], x[10], x[15]);
    chacha20_quarter_round_neon(x[1], x[6], x[11], x[12]);
    chacha20_quarter_round_neon(x[2], x[7], x[8], x[13]);
    chacha20_quarter_round_neon(x[3], x[4], x[9], x[14]);
}

/// @brief
///   Encrypt/decrypt four consecutive ChaCha20 blocks with ARMv8 NEON instructions.
/// @param state
///   Initial ChaCha20 state, including the counter of the first block.
/// @param input
///   Pointer to the start of the 256-byte input.
/// @param[out] output
///   Pointer to the start of the 256-byte output.  May be the same as @p input .
static void chacha20_xor_4blocks_neon(const std::uint32_t *state,
                                      const std::uint8_t *input,
                                      std::uint8_t *output) noexcept {
    // Each vector holds one state word for the four blocks.  Lane @c i of every vector therefore
    // belongs to block @c i , so all four blocks progress through the rounds simultaneously.
    const uint32x4_t initial_counter =
        vaddq_u32(vdupq_n_u32(state[12]), vld1q_u32(chacha20_counter_offsets4));

    uint32x4_t x[16];
    for (std::size_t index = 0; index < 16; ++index) {
        x[index] = vdupq_n_u32(state[index]);
    }
    x[12] = initial_counter;

    // Unroll all ten double rounds explicitly.  Relying on an unroll pragma would leave the loop
    // rolled on compilers that do not implement it, notably MSVC.
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);
    chacha20_column_round_neon4(x);
    chacha20_diagonal_round_neon4(x);

    for (std::size_t index = 0; index < 16; ++index) {
        if (index != 12) {
            x[index] = vaddq_u32(x[index], vdupq_n_u32(state[index]));
        }
    }
    x[12] = vaddq_u32(x[12], initial_counter);

    // Words 0..3 of all four blocks, then words 4..7, and so on.  Transposing each group of four
    // state words turns them into one contiguous 16-byte chunk per block.
    chacha20_xor_group_neon(input + 0 * 16, output + 0 * 16, x[0], x[1], x[2], x[3]);
    chacha20_xor_group_neon(input + 1 * 16, output + 1 * 16, x[4], x[5], x[6], x[7]);
    chacha20_xor_group_neon(input + 2 * 16, output + 2 * 16, x[8], x[9], x[10], x[11]);
    chacha20_xor_group_neon(input + 3 * 16, output + 3 * 16, x[12], x[13], x[14], x[15]);
}

/// @brief
///   Perform the four column quarter rounds of two independent four-block groups.
/// @param x
///   State vectors of the two groups, sixteen vectors per group.
static CIALLO_CHACHA20_NEON_INLINE void chacha20_column_round_neon8(uint32x4_t (&x)[32]) noexcept {
    chacha20_quarter_round_neon(x[0], x[4], x[8], x[12]);
    chacha20_quarter_round_neon(x[16], x[20], x[24], x[28]);
    chacha20_quarter_round_neon(x[1], x[5], x[9], x[13]);
    chacha20_quarter_round_neon(x[17], x[21], x[25], x[29]);
    chacha20_quarter_round_neon(x[2], x[6], x[10], x[14]);
    chacha20_quarter_round_neon(x[18], x[22], x[26], x[30]);
    chacha20_quarter_round_neon(x[3], x[7], x[11], x[15]);
    chacha20_quarter_round_neon(x[19], x[23], x[27], x[31]);
}

/// @brief
///   Perform the four diagonal quarter rounds of two independent four-block groups.
/// @param x
///   State vectors of the two groups, sixteen vectors per group.
static CIALLO_CHACHA20_NEON_INLINE void
chacha20_diagonal_round_neon8(uint32x4_t (&x)[32]) noexcept {
    chacha20_quarter_round_neon(x[0], x[5], x[10], x[15]);
    chacha20_quarter_round_neon(x[16], x[21], x[26], x[31]);
    chacha20_quarter_round_neon(x[1], x[6], x[11], x[12]);
    chacha20_quarter_round_neon(x[17], x[22], x[27], x[28]);
    chacha20_quarter_round_neon(x[2], x[7], x[8], x[13]);
    chacha20_quarter_round_neon(x[18], x[23], x[24], x[29]);
    chacha20_quarter_round_neon(x[3], x[4], x[9], x[14]);
    chacha20_quarter_round_neon(x[19], x[20], x[25], x[30]);
}

/// @brief
///   Encrypt/decrypt eight consecutive ChaCha20 blocks with ARMv8 NEON instructions.
/// @param state
///   Initial ChaCha20 state, including the counter of the first block.
/// @param input
///   Pointer to the start of the 512-byte input.
/// @param[out] output
///   Pointer to the start of the 512-byte output.  May be the same as @p input .
static void chacha20_xor_8blocks_neon(const std::uint32_t *state,
                                      const std::uint8_t *input,
                                      std::uint8_t *output) noexcept {
    // Two groups of four blocks.  x[g * 16 + word] holds state word @c word for the four blocks of
    // group @c g .  Keeping both groups live gives the scheduler eight independent quarter-round
    // chains to interleave.
    uint32x4_t x[32];

    const uint32x4_t counter0 =
        vaddq_u32(vdupq_n_u32(state[12]), vld1q_u32(&chacha20_counter_offsets8[0]));
    const uint32x4_t counter1 =
        vaddq_u32(vdupq_n_u32(state[12]), vld1q_u32(&chacha20_counter_offsets8[4]));

    for (std::size_t index = 0; index < 16; ++index) {
        x[index]      = vdupq_n_u32(state[index]);
        x[index + 16] = vdupq_n_u32(state[index]);
    }
    x[12] = counter0;
    x[28] = counter1;

    for (std::size_t round = 0; round < 10; ++round) {
        chacha20_column_round_neon8(x);
        chacha20_diagonal_round_neon8(x);
    }

    for (std::size_t index = 0; index < 16; ++index) {
        if (index != 12) {
            const uint32x4_t original = vdupq_n_u32(state[index]);
            x[index]                  = vaddq_u32(x[index], original);
            x[index + 16]             = vaddq_u32(x[index + 16], original);
        }
    }
    x[12] = vaddq_u32(x[12], counter0);
    x[28] = vaddq_u32(x[28], counter1);

    for (std::size_t group = 0; group < 2; ++group) {
        const std::size_t block_offset = group * 4 * chacha20_block_size;
        for (std::size_t word_group = 0; word_group < 4; ++word_group) {
            const std::size_t base = group * 16 + word_group * 4;
            chacha20_xor_group_neon(input + block_offset + word_group * 16,
                                    output + block_offset + word_group * 16, x[base], x[base + 1],
                                    x[base + 2], x[base + 3]);
        }
    }
}

/// @brief
///   ChaCha20 encrypt/decrypt function with ARMv8 NEON instructions.
/// @param input
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param state
///   Initial ChaCha20 state.  The block counter is advanced in place.
/// @param[out] output
///   Pointer to start of the output buffer.
static void chacha20_xor_neon(const std::uint8_t *input,
                              std::size_t size,
                              std::uint32_t *state,
                              std::uint8_t *output) noexcept {
    while (size >= 8 * chacha20_block_size) {
        chacha20_xor_8blocks_neon(state, input, output);
        state[12] += 8;

        input += 8 * chacha20_block_size;
        output += 8 * chacha20_block_size;
        size -= 8 * chacha20_block_size;
    }

    while (size >= 4 * chacha20_block_size) {
        chacha20_xor_4blocks_neon(state, input, output);
        state[12] += 4;

        input += 4 * chacha20_block_size;
        output += 4 * chacha20_block_size;
        size -= 4 * chacha20_block_size;
    }

    // A tail longer than two blocks benefits from the four-way kernel even though some of the
    // generated keystream is discarded.  The scalar kernel is faster for one or two blocks, because
    // it does not compute the unused blocks of the four-way group.
    if (size > 2 * chacha20_block_size) {
        static constexpr std::uint8_t zero_block[4 * chacha20_block_size] = {};
        alignas(16) std::uint8_t tail_keystream[4 * chacha20_block_size];

        chacha20_xor_4blocks_neon(state, zero_block, tail_keystream);
        for (std::size_t index = 0; index < size; ++index) {
            output[index] = static_cast<std::uint8_t>(input[index] ^ tail_keystream[index]);
        }
        return;
    }

    chacha20_xor_portable(input, size, state, output);
}
#endif

/// @brief
///   ChaCha20 encrypt/decrypt function pointer.
using chacha20_xor_fn = void (*)(const std::uint8_t *,
                                 std::size_t,
                                 std::uint32_t *,
                                 std::uint8_t *) noexcept;

/// @brief
///   Select ChaCha20 implementation according to the current architecture and CPU features.
///
///   The x86 implementations are selected at run time because a binary may be executed on a
///   processor that does not implement AVX2.  The SSE2 kernel is used when AVX2 is unavailable,
///   and the portable implementation when even SSE2 is missing.
///
///   AVX-512 is deliberately not used: its 512-bit instructions can lower the core frequency
///   enough to lose more throughput than the wider vectors gain, particularly when the cipher is
///   only one part of a larger workload.
/// @return
///   ChaCha20 implementation that best suits the current CPU.
[[nodiscard]] static chacha20_xor_fn select_chacha20_xor() noexcept {
#if defined(CIALLO_CHACHA20_X86)
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;

    chacha20_cpuid(0, 0, eax, ebx, ecx, edx);
    const std::uint32_t max_leaf = eax;
    if (max_leaf < 1) {
        return &chacha20_xor_portable;
    }

    // SSE2 is part of the x86-64 baseline, so it only needs to be checked on 32-bit x86.
    chacha20_cpuid(1, 0, eax, ebx, ecx, edx);
#    if defined(_M_X64) || defined(__x86_64) || defined(__x86_64__)
    const bool support_sse2 = true;
#    else
    const bool support_sse2 = (edx & (1U << 26)) != 0;
#    endif

    bool avx = (ecx & (1U << 28)) != 0;
    if ((ecx & (1U << 27)) != 0) {
        // The operating system must save and restore the full XMM and YMM state before AVX code
        // may run, whether or not the processor itself implements the extensions.
        constexpr std::uint64_t avx_state_mask = (1U << 1) | (1U << 2);
        avx = avx && (chacha20_xgetbv0() & avx_state_mask) == avx_state_mask;
    } else {
        avx = false;
    }

    bool support_avx2 = false;
    if (max_leaf >= 7) {
        chacha20_cpuid(7, 0, eax, ebx, ecx, edx);
        support_avx2 = avx && (ebx & (1U << 5)) != 0;
    }

    if (support_avx2) {
        return &chacha20_xor_avx2;
    }
    if (support_sse2) {
        return &chacha20_xor_sse2;
    }
    return &chacha20_xor_portable;
#elif defined(CIALLO_CHACHA20_ARM)
    if constexpr (std::endian::native == std::endian::little) {
        return &chacha20_xor_neon;
    }
    return &chacha20_xor_portable;
#else
    return &chacha20_xor_portable;
#endif
}

std::size_t ciallo::chacha20(const void *data,
                             std::size_t size,
                             const void *key,
                             const void *nonce,
                             std::uint32_t counter,
                             void *output) noexcept {
    if (size == 0) {
        return 0;
    }

    std::uint32_t state[16];
    for (std::size_t index = 0; index < 4; ++index) {
        state[index] = chacha20_constants[index];
    }

    const auto *key_bytes = static_cast<const std::uint8_t *>(key);
    for (std::size_t index = 0; index < 8; ++index) {
        state[4 + index] = chacha20_load_le32(key_bytes + index * 4);
    }

    state[12] = counter;

    const auto *nonce_bytes = static_cast<const std::uint8_t *>(nonce);
    for (std::size_t index = 0; index < 3; ++index) {
        state[13 + index] = chacha20_load_le32(nonce_bytes + index * 4);
    }

    static const chacha20_xor_fn process = select_chacha20_xor();
    process(static_cast<const std::uint8_t *>(data), size, state,
            static_cast<std::uint8_t *>(output));
    return size;
}
