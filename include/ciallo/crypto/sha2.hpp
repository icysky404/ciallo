#pragma once

#include "ciallo/configuration.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ciallo {

/// @brief
///   Calculate SHA224 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA224 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @param[out] hash
///   Pointer to memory to store SHA224 result. SHA224 result is guaranteed to be 28-byte and
///   @p hash must remain at least 28-byte free space.
CIALLO_API void sha224(const void *data, std::size_t size, void *hash) noexcept;

/// @brief
///   Calculate SHA224 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA224 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @return
///   The SHA224 hash result.
[[nodiscard]] inline std::array<std::uint8_t, 28> sha224(const void *data,
                                                         std::size_t size) noexcept {
    std::array<std::uint8_t, 28> result;
    sha224(data, size, result.data());
    return result;
}

/// @brief
///   Calculate SHA256 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA256 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @param[out] hash
///   Pointer to memory to store SHA256 result. SHA256 result is guaranteed to be 32-byte and
///   @p hash must remain at least 32-byte free space.
CIALLO_API void sha256(const void *data, std::size_t size, void *hash) noexcept;

/// @brief
///   Calculate SHA256 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA256 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @return
///   The SHA256 hash result.
[[nodiscard]] inline std::array<std::uint8_t, 32> sha256(const void *data,
                                                         std::size_t size) noexcept {
    std::array<std::uint8_t, 32> result;
    sha256(data, size, result.data());
    return result;
}

/// @brief
///   Calculate SHA384 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA384 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @param[out] hash
///   Pointer to memory to store SHA384 result. SHA384 result is guaranteed to be 48-byte and
///   @p hash must remain at least 48-byte free space.
CIALLO_API void sha384(const void *data, std::size_t size, void *hash) noexcept;

/// @brief
///   Calculate SHA384 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA384 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @return
///   The SHA384 hash result.
[[nodiscard]] inline std::array<std::uint8_t, 48> sha384(const void *data,
                                                         std::size_t size) noexcept {
    std::array<std::uint8_t, 48> result;
    sha384(data, size, result.data());
    return result;
}

/// @brief
///   Calculate SHA512 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA512 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @param[out] hash
///   Pointer to memory to store SHA512 result. SHA512 result is guaranteed to be 64-byte and
///   @p hash must remain at least 64-byte free space.
CIALLO_API void sha512(const void *data, std::size_t size, void *hash) noexcept;

/// @brief
///   Calculate SHA512 hash value for the specified data.
/// @param data
///   Pointer to start of data to calculate SHA512 for.
/// @param size
///   Size in byte of data to be hashed. The hashed data could be any size.
/// @return
///   The SHA512 hash result.
[[nodiscard]] inline std::array<std::uint8_t, 64> sha512(const void *data,
                                                         std::size_t size) noexcept {
    std::array<std::uint8_t, 64> result;
    sha512(data, size, result.data());
    return result;
}

} // namespace ciallo
