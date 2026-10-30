#pragma once

#include "ciallo/configuration.hpp"

#include <cstddef>
#include <cstdint>

namespace ciallo {

/// @brief
///   Calculate hash value for the specified data using rapidhash.
/// @note
///   Rapidhash is not cryptographic hash method.
/// @param data
///   Pointer to start of data to be hashed.
/// @param size
///   Size in byte of data to be hashed.
/// @param seed
///   Initial seed for rapidhash. Default seed is 0.
/// @return
///   Hash value for the specified data.
[[nodiscard]] CIALLO_API std::uint64_t
rapidhash(const void *data, std::size_t size, std::uint64_t seed = 0) noexcept;

} // namespace ciallo
