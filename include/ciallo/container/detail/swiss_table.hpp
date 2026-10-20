#pragma once

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) ||             \
    defined(_M_ARM64EC)
#    include <emmintrin.h>
#elif defined(__arm__) || defined(__aarch64__) || defined(_M_ARM) || defined(_M_ARM64)
#    include <arm_neon.h>
#else
#    error "unsupported architecture."
#endif

#include <bit>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace ciallo::detail {

/// @brief
///   Number of elements in each control group.
inline constexpr std::size_t swiss_table_group_size = 16;

/// @brief
///   Swiss table sentinel flag.
inline constexpr std::int8_t swiss_table_sentinel = -1;

/// @brief
///   Swiss table deleted flag.
inline constexpr std::int8_t swiss_table_deleted = -2;

/// @brief
///   Swiss table empty flag.
inline constexpr std::int8_t swiss_table_empty = -128;

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) || defined(_M_X64) ||             \
    defined(_M_ARM64EC)
/// @brief
///   Swiss table control group represented in SIMD register.
class swiss_table_control_group {
public:
    /// @brief
    ///   Load a control group from memory.
    /// @param group
    ///   Pointer to memory to load a control group.
    explicit swiss_table_control_group(const std::int8_t *group) noexcept
        : m_value(_mm_loadu_si128(reinterpret_cast<const __m128i *>(group))) {}

    /// @brief
    ///   Match this control group with @p hash.
    /// @param hash
    ///   The H2 hash value to be matched.
    /// @return
    ///   A 16-bit mask that represents which control flag matches @p hash.
    [[nodiscard]] std::uint16_t match(std::int8_t hash) const noexcept {
        __m128i cmp = _mm_cmpeq_epi8(_mm_set1_epi8(static_cast<char>(hash)), m_value);
        return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
    }

    /// @brief
    ///   Match all empty control flags.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty.
    [[nodiscard]] std::uint16_t match_empty() const noexcept {
        __m128i cmp = _mm_cmpeq_epi8(_mm_set1_epi8(static_cast<char>(swiss_table_empty)), m_value);
        return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
    }

    /// @brief
    ///   Match all control flags that is filled with H2 hash value.
    /// @return
    ///   A 16-bit mask that represents which control flag is filled with H2 hash value.
    [[nodiscard]] std::uint16_t match_full() const noexcept {
        int non_full = _mm_movemask_epi8(m_value);
        return static_cast<std::uint16_t>(non_full ^ 0xFFFF);
    }

    /// @brief
    ///   Match all control flags that is empty flag, deleted flag or sentinel flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty flag, deleted flag or sentinel
    ///   flag.
    [[nodiscard]] std::uint16_t match_non_full() const noexcept {
        return static_cast<std::uint16_t>(_mm_movemask_epi8(m_value));
    }

    /// @brief
    ///   Match all control flags that is empty or deleted flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty or deleted flag.
    [[nodiscard]] std::uint16_t match_empty_or_deleted() const noexcept {
        __m128i sentinel = _mm_set1_epi8(static_cast<char>(swiss_table_sentinel));
        if constexpr (std::is_unsigned_v<char>) {
            __m128i mask = _mm_set1_epi8(static_cast<char>(0x80));
            __m128i diff = _mm_subs_epi8(m_value, sentinel);
            __m128i cmp  = _mm_cmpeq_epi8(_mm_and_si128(diff, mask), mask);
            return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
        } else {
            __m128i cmp = _mm_cmpgt_epi8(sentinel, m_value);
            return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
        }
    }

    /// @brief
    ///   Match all control flags that is filled with H2 hash value or sentinel flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is filled with H2 hash value or sentinel
    ///   flag.
    [[nodiscard]] std::uint16_t match_full_or_sentinel() const noexcept {
        __m128i sentinel = _mm_set1_epi8(static_cast<char>(swiss_table_sentinel - 1));
        if constexpr (std::is_unsigned_v<char>) {
            __m128i mask = _mm_set1_epi8(static_cast<char>(0x80));
            __m128i diff = _mm_subs_epi8(sentinel, m_value);
            __m128i cmp  = _mm_cmpeq_epi8(_mm_and_si128(diff, mask), mask);
            return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
        } else {
            __m128i cmp = _mm_cmpgt_epi8(m_value, sentinel);
            return static_cast<std::uint16_t>(_mm_movemask_epi8(cmp));
        }
    }

private:
    /// @brief
    ///   A group of control flags.
    __m128i m_value;
};
#elif defined(__arm__) || defined(__aarch64__) || defined(_M_ARM) || defined(_M_ARM64)
/// @brief
///   Swiss table control group represented in SIMD register.
class swiss_table_control_group {
public:
    /// @brief
    ///   Load a control group from memory.
    /// @param group
    ///   Pointer to memory to load a control group.
    explicit swiss_table_control_group(const std::int8_t *group) noexcept
        : m_value(vld1q_u8(reinterpret_cast<const std::uint8_t *>(group))) {}

    /// @brief
    ///   Match this control group with @p hash.
    /// @param hash
    ///   The H2 hash value to be matched.
    /// @return
    ///   A 16-bit mask that represents which control flag matches @p hash.
    [[nodiscard]] std::uint16_t match(std::int8_t hash) const noexcept {
        alignas(16) constexpr std::uint8_t powers[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                                         1, 2, 4, 8, 16, 32, 64, 128};
        uint8x16_t cmp    = vceqq_u8(m_value, vdupq_n_u8(static_cast<std::uint8_t>(hash)));
        uint8x16_t masked = vandq_u8(cmp, vld1q_u8(powers));
        uint64x2_t sum    = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(masked)));
        std::uint64_t mask =
            ((vgetq_lane_u64(sum, 0) & 0xFF) | ((vgetq_lane_u64(sum, 1) & 0xFF) << 8));
        return static_cast<std::uint16_t>(mask);
    }

    /// @brief
    ///   Match all empty control flags.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty.
    [[nodiscard]] std::uint16_t match_empty() const noexcept {
        return match(swiss_table_empty);
    }

    /// @brief
    ///   Match all control flags that is filled with H2 hash value.
    /// @return
    ///   A 16-bit mask that represents which control flag is filled with H2 hash value.
    [[nodiscard]] std::uint16_t match_full() const noexcept {
        alignas(16) constexpr std::uint8_t powers[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                                         1, 2, 4, 8, 16, 32, 64, 128};
        uint8x16_t cmp    = vcgeq_s8(vreinterpretq_s8_u8(m_value), vdupq_n_s8(0));
        uint8x16_t masked = vandq_u8(cmp, vld1q_u8(powers));
        uint64x2_t sum    = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(masked)));
        std::uint64_t mask =
            ((vgetq_lane_u64(sum, 0) & 0xFF) | ((vgetq_lane_u64(sum, 1) & 0xFF) << 8));
        return static_cast<std::uint16_t>(mask);
    }

    /// @brief
    ///   Match all control flags that is empty flag, deleted flag or sentinel flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty flag, deleted flag or sentinel
    ///   flag.
    [[nodiscard]] std::uint16_t match_non_full() const noexcept {
        alignas(16) constexpr std::uint8_t powers[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                                         1, 2, 4, 8, 16, 32, 64, 128};
        uint8x16_t cmp    = vcltq_s8(vreinterpretq_s8_u8(m_value), vdupq_n_s8(0));
        uint8x16_t masked = vandq_u8(cmp, vld1q_u8(powers));
        uint64x2_t sum    = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(masked)));
        std::uint64_t mask =
            ((vgetq_lane_u64(sum, 0) & 0xFF) | ((vgetq_lane_u64(sum, 1) & 0xFF) << 8));
        return static_cast<std::uint16_t>(mask);
    }

    /// @brief
    ///   Match all control flags that is empty or deleted flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is empty or deleted flag.
    [[nodiscard]] std::uint16_t match_empty_or_deleted() const noexcept {
        alignas(16) constexpr std::uint8_t powers[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                                         1, 2, 4, 8, 16, 32, 64, 128};
        uint8x16_t cmp = vcgtq_s8(vdupq_n_s8(swiss_table_sentinel), vreinterpretq_s8_u8(m_value));
        uint8x16_t masked = vandq_u8(cmp, vld1q_u8(powers));
        uint64x2_t sum    = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(masked)));
        std::uint64_t mask =
            ((vgetq_lane_u64(sum, 0) & 0xFF) | ((vgetq_lane_u64(sum, 1) & 0xFF) << 8));
        return static_cast<std::uint16_t>(mask);
    }

    /// @brief
    ///   Match all control flags that is filled with H2 hash value or sentinel flag.
    /// @return
    ///   A 16-bit mask that represents which control flag is filled with H2 hash value or sentinel
    ///   flag.
    [[nodiscard]] std::uint16_t match_full_or_sentinel() const noexcept {
        alignas(16) constexpr std::uint8_t powers[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                                         1, 2, 4, 8, 16, 32, 64, 128};
        uint8x16_t cmp =
            vcgtq_s8(vreinterpretq_s8_u8(m_value), vdupq_n_s8(swiss_table_sentinel - 1));
        uint8x16_t masked = vandq_u8(cmp, vld1q_u8(powers));
        uint64x2_t sum    = vpaddlq_u32(vpaddlq_u16(vpaddlq_u8(masked)));
        std::uint64_t mask =
            ((vgetq_lane_u64(sum, 0) & 0xFF) | ((vgetq_lane_u64(sum, 1) & 0xFF) << 8));
        return static_cast<std::uint16_t>(mask);
    }

private:
    /// @brief
    ///   A group of control flags stored in NEON register.
    uint8x16_t m_value;
};
#endif

/// @brief
///   Helper class to generate probe sequence for swiss table.
class swiss_table_probe_sequence {
public:
    /// @brief
    ///   Create a new sequence prober for SwissTable.
    /// @param h1
    ///   H1 hash value to generate probe sequence for.
    /// @param mask
    ///   Mask to limit the generated index size.
    constexpr swiss_table_probe_sequence(std::size_t h1, std::size_t mask) noexcept
        : m_mask(mask),
          m_offset(h1 & mask),
          m_index(0) {}

    /// @brief
    ///   Get current offset based on the first hash table element.
    /// @return
    ///   Current offset based on the first hash table element.
    [[nodiscard]] constexpr std::size_t offset() const noexcept {
        return m_offset;
    }

    /// @brief
    ///   Get offset based on the first hash table element after applying the specified extra
    ///   offset.
    /// @param extra
    ///   Extra offset to be applied.
    /// @return
    ///   Offset based on the first hash table element after applying the specified extra offset.
    [[nodiscard]] constexpr std::size_t offset(std::size_t extra) const noexcept {
        return (m_offset + extra) & m_mask;
    }

    /// @brief
    ///   Get current probe index. It is guaranteed that probe index is always a multiple of @c
    ///   swiss_table_group_size .
    /// @return
    ///   Current probe index.
    [[nodiscard]] constexpr std::size_t index() const noexcept {
        return m_index;
    }

    /// @brief
    ///   Move to next probe sequence offset using triangulation detection.
    constexpr void next() noexcept {
        m_index += 16;
        m_offset = (m_offset + m_index) & m_mask;
    }

private:
    std::size_t m_mask;
    std::size_t m_offset;
    std::size_t m_index;
};

/// @brief
///   Helper function to find the first non-full slot in the hash table.
/// @param states
///   Control state array of the hash table.
/// @param h1
///   H1 hash value of the key to insert.
/// @param capacity
///   Capacity of the hash table.
/// @return
///   Index of the first non-full slot.
[[nodiscard]] inline std::size_t swiss_table_find_first_non_full(std::int8_t *states,
                                                                 std::size_t h1,
                                                                 std::size_t capacity) noexcept {
    swiss_table_probe_sequence probe(h1, capacity);
    std::size_t index = probe.offset();
    if (states[index] < swiss_table_sentinel) {
        return index;
    }

    for (;;) {
        swiss_table_control_group group(states + probe.offset());
        if (std::uint16_t mask = group.match_empty_or_deleted(); mask != 0) {
            return probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
        }
        probe.next();
    }
}

/// @brief
///   Helper struct to align up swiss table allocator.
template <typename T>
struct alignas(T) swiss_table_alignment_t {
    std::byte padding[alignof(T)];
};

/// @brief
///   Helper function to calculate swiss table value offset based on the backing array.
/// @tparam T
///   Type of element to be stored in swiss table.
/// @param capacity
///   Number of elements to be stored in swiss table.
/// @return
///   Alignment block offset of the first element that should be stored in swiss table based on
///   backing array.
template <typename T>
[[nodiscard]] constexpr std::size_t swiss_table_value_offset(std::size_t capacity) noexcept {
    return ((capacity + swiss_table_group_size + alignof(T) - 1) / alignof(T));
}

/// @brief
///   Helper function to calculate how much memory should be allocated to store at least @p capacity
///   elements in swiss table.
/// @tparam T
///   Type of element to be stored in swiss table.
/// @param capacity
///   Number of elements to be stored in swiss table.
/// @return
///   Least number of alignment block that should be allocated to store at least @p capacity
///   elements in swiss table.
template <typename T>
[[nodiscard]] constexpr std::size_t swiss_table_block_count(std::size_t capacity) noexcept {
    return swiss_table_value_offset<T>(capacity) + capacity * (sizeof(T) / alignof(T));
}

/// @brief
///   Get next capacity for the hash table based on current capacity.
/// @param capacity
///   Current capacity of the hash table. Must be 2^N - 1.
/// @return
///   Next capacity for hash table. It is guaranteed that the returned value is 2^N - 1.
[[nodiscard]] constexpr std::size_t swiss_table_next_capacity(std::size_t capacity) noexcept {
    return (capacity < 0xF) ? 0xF : ((capacity << 1) | 1);
}

/// @brief
///   Normalize the specified value to next 2^N -1 capacity.
/// @param count
///   The capacity to normalize.
/// @return
///   Next 2^N - 1 capacity value after @p count.
[[nodiscard]] constexpr std::size_t swiss_table_normalize_capacity(std::size_t count) noexcept {
    return (count < 0xF) ? 0xF : (~static_cast<std::size_t>(0) >> std::countl_zero(count));
}

/// @brief
///   Helper function to get expected capacity according to the specified size. This is the same as
///   @c swiss_table_normalize_capacity(size * 8 / 7) if @p size is not 0.
/// @param size
///   The size to get capacity from.
/// @return
///   Expected capacity to store at least @p size elements.
[[nodiscard]] constexpr std::size_t swiss_table_size_to_capacity(std::size_t size) noexcept {
    if (size == 0) {
        return 0xF;
    }

    constexpr std::size_t last_3_bits = static_cast<std::size_t>(7)
                                        << (std::numeric_limits<std::size_t>::digits - 3);

    // Avoid overflow.
    if (size > last_3_bits) [[unlikely]] {
        return (std::numeric_limits<std::size_t>::max)();
    }

    std::size_t leading_zeros = std::countl_zero(size);
    std::size_t max_size      = last_3_bits >> leading_zeros;
    leading_zeros -= (size > max_size);

    std::size_t result = ~static_cast<std::size_t>(0) >> leading_zeros;
    return (result < 0xF) ? 0xF : result;
}

/// @brief
///   Helper function to set state for a slot in the Swiss Table state array.
/// @param states
///   Pointer to the state array.
/// @param capacity
///   Capacity of the state array.
/// @param offset
///   Offset of the slot to set.
/// @param state
///   State value to set.
constexpr void swiss_table_set_state(std::int8_t *states,
                                     std::size_t capacity,
                                     std::size_t offset,
                                     std::int8_t state) noexcept {
    states[offset]                          = state;
    states[((offset - 15) & capacity) + 15] = state;
}

} // namespace ciallo::detail
