#pragma once

#include "ciallo/configuration.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ciallo {

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

} // namespace ciallo
