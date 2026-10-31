#include "ciallo/crypto/chacha20.hpp"

#if (defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC)
#    if defined(_MSC_VER) && !defined(__clang__)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
#    define CIALLO_CHACHA20_ARM 1
#elif defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||             \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
// x86 intrinsic headers (for example <immintrin.h>) will be included here when the AVX2/AVX-512
// backends are added.
#    define CIALLO_CHACHA20_X86 1
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
///   The x86 branch is intentionally present but currently returns the portable implementation.
///   Adding AVX2 or AVX-512 support only requires implementing another function with the
///   @c chacha20_xor_fn signature and returning it from that branch after CPU feature detection.
/// @return
///   ChaCha20 implementation that best suits the current CPU.
[[nodiscard]] static chacha20_xor_fn select_chacha20_xor() noexcept {
#if defined(CIALLO_CHACHA20_ARM)
    if constexpr (std::endian::native == std::endian::little) {
        return &chacha20_xor_neon;
    }
    return &chacha20_xor_portable;
#elif defined(CIALLO_CHACHA20_X86)
    // x86 CPU feature detection and the AVX2/AVX-512 implementations go here.
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
