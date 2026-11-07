#pragma once

#include "ciallo/configuration.hpp"

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <ranges>
#include <stdexcept>
#include <type_traits>

namespace ciallo {

/// @brief
///   Encrypt/decrypt data with the ChaCha20 stream cipher (RFC 8439).
/// @param data
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param key
///   Pointer to the ChaCha20 key. The key must be exactly 32-byte in size.
/// @param nonce
///   Pointer to the ChaCha20 nonce. The nonce must be exactly 12-byte in size.
/// @param counter
///   Initial value of the 32-bit block counter. Normally zero, and incremented once for each
///   64-byte keystream block. The counter wraps modulo 2^32.
/// @param[out] output
///   Pointer to start of the output buffer. The output buffer must have at least @p size to hold
///   all encrypted/decrypted result data. If @c output is the same as @p data , this function
///   performs in-place encryption/decryption.
/// @return
///   Actual size in byte that is written to @p output . This value is guaranteed to be always equal
///   to @p size .
CIALLO_API std::size_t chacha20(const void *data,
                                std::size_t size,
                                const void *key,
                                const void *nonce,
                                std::uint32_t counter,
                                void *output) noexcept;

/// @brief
///   Encrypt/decrypt data with the ChaCha20 stream cipher, starting from block counter zero.
/// @param data
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param key
///   Pointer to the ChaCha20 key. The key must be exactly 32-byte in size.
/// @param nonce
///   Pointer to the ChaCha20 nonce. The nonce must be exactly 12-byte in size.
/// @param[out] output
///   Pointer to start of the output buffer. The output buffer must have at least @p size to hold
///   all encrypted/decrypted result data. If @c output is the same as @p data , this function
///   performs in-place encryption/decryption.
/// @return
///   Actual size in byte that is written to @p output . This value is guaranteed to be always equal
///   to @p size .
inline std::size_t chacha20(const void *data,
                            std::size_t size,
                            const void *key,
                            const void *nonce,
                            void *output) noexcept {
    return chacha20(data, size, key, nonce, 0, output);
}

/// @brief
///   Encrypt/decrypt data with the ChaCha20 stream cipher.
/// @tparam Range
///   Result type to store the encrypt/decrypt result. The range must be contiguous, hold one-byte
///   trivial values, be default constructible, and provide a @c resize() member function callable
///   with a @c std::size_t . You may want to use @c std::string or @c std::vector<std::uint8_t> as
///   the result range type.
/// @tparam KeyRange
///   Contiguous, sized range holding the key. The total size of the range in byte must be exactly
///   32. It may be any container, such as a built-in array, @c std::array , @c std::vector ,
///   @c std::string or @c std::span .
/// @tparam NonceRange
///   Contiguous, sized range holding the nonce. The total size of the range in byte must be exactly
///   12.
/// @param data
///   Pointer to start of data to be encrypted/decrypted.
/// @param size
///   Size in byte of data to be encrypted/decrypted.
/// @param key
///   ChaCha20 encrypt/decrypt key. The key must be exactly 32-byte in size.
/// @param nonce
///   ChaCha20 encrypt/decrypt nonce. The nonce must be exactly 12-byte in size.
/// @param counter
///   Initial value of the 32-bit block counter. The counter wraps modulo 2^32.
/// @return
///   A container that contains the encrypt/decrypt result.
/// @throw std::invalid_argument
///   Thrown if @p key is not exactly 32 bytes in size, or if @p nonce is not exactly 12 bytes in
///   size.
template <typename Range, typename KeyRange, typename NonceRange>
    requires(std::ranges::contiguous_range<Range> && std::default_initializable<Range> &&
             std::is_trivial_v<std::ranges::range_value_t<Range>> &&
             sizeof(std::ranges::range_value_t<Range>) == 1 &&
             std::ranges::contiguous_range<KeyRange> && std::ranges::sized_range<KeyRange> &&
             std::is_trivial_v<std::ranges::range_value_t<KeyRange>> &&
             std::ranges::contiguous_range<NonceRange> && std::ranges::sized_range<NonceRange> &&
             std::is_trivial_v<std::ranges::range_value_t<NonceRange>> &&
             requires(Range &range, std::size_t size) { range.resize(size); })
Range chacha20(const void *data,
               std::size_t size,
               const KeyRange &key,
               const NonceRange &nonce,
               std::uint32_t counter = 0) {
    const std::size_t key_bytes =
        std::ranges::size(key) * sizeof(std::ranges::range_value_t<KeyRange>);
    const std::size_t nonce_bytes =
        std::ranges::size(nonce) * sizeof(std::ranges::range_value_t<NonceRange>);
    if (key_bytes != 32) [[unlikely]] {
        throw std::invalid_argument("ciallo::chacha20(): bad key size");
    }
    if (nonce_bytes != 12) [[unlikely]] {
        throw std::invalid_argument("ciallo::chacha20(): bad nonce size");
    }

    Range result;
    result.resize(size);
    chacha20(data, size, std::ranges::data(key), std::ranges::data(nonce), counter,
             std::ranges::data(result));
    return result;
}

/// @brief
///   C++11-style ChaCha20 random generator. This random generator could be used as cryptographic
///   random generator.
class CIALLO_API chacha20_random {
public:
    using result_type = std::uint32_t;

    /// @brief
    ///   Create this ChaCha20 random stream generator.
    /// @note
    ///   This constructor may cause fast-fail on Windows if there is no available system
    ///   entropy-based random function.
    chacha20_random() noexcept;

    /// @brief
    ///   @c chacha20_random is not copyable.
    chacha20_random(const chacha20_random &other) noexcept = delete;

    /// @brief
    ///   Move constructor for @c chacha20_random .
    /// @param other
    ///   The @c chacha20_random generator to be moved from. The moved @c chacha20_random object
    ///   will be reinitialized.
    chacha20_random(chacha20_random &&other) noexcept;

    /// @brief
    ///   @c chacha20_random is trivially destructible.
    ~chacha20_random() = default;

    /// @brief
    ///   @c chacha20_random is not copyable.
    chacha20_random &operator=(const chacha20_random &other) = delete;

    /// @brief
    ///   Move assignment for @c chacha20_random .
    /// @param other
    ///   The @c chacha20_random generator to be moved from. The moved @c chacha20_random object
    ///   will be reinitialized.
    /// @return
    ///   Reference to this @c chacha20_random object.
    chacha20_random &operator=(chacha20_random &&other) noexcept;

    /// @brief
    ///   Get the minimum value that this random generator could generate.
    /// @return
    ///   Minimum value that this random generator could generate.
    static constexpr result_type min() noexcept {
        return (std::numeric_limits<result_type>::min)();
    }

    /// @brief
    ///   Get the maximum value that this random generator could generate.
    /// @return
    ///   Maximum value that this random generator could generate.
    static constexpr result_type max() noexcept {
        return (std::numeric_limits<result_type>::max)();
    }

    /// @brief
    ///   Generate a random value. This method is not concurrent safe.
    /// @return
    ///   New random value from this ChaCha20 random stream.
    /// @note
    ///   This function may cause fast-fail on Windows if there is no available system entropy-based
    ///   random function.
    [[nodiscard]] result_type operator()() noexcept;

    /// @brief
    ///   Fill the given buffer with ChaCha20 random stream.
    /// @param[out] buffer
    ///   Pointer to start of the buffer to be filled.
    /// @param size
    ///   Size in byte of @p buffer to be filled.
    /// @note
    ///   This function may cause fast-fail on Windows if there is no available system entropy-based
    ///   random function.
    void operator()(void *buffer, std::size_t size) noexcept;

private:
    std::array<std::byte, 32> m_key;
    std::array<std::byte, 12> m_nonce;
    std::array<result_type, 16> m_buffer;
    std::uint32_t m_position;
    std::uint32_t m_rounds;
};

} // namespace ciallo
