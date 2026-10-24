#pragma once

#include "ciallo/configuration.hpp"

#include <cstddef>
#include <cstdint>

namespace ciallo {

/// @brief
///   Calculate CRC32/ISO-HDLC for the given data.
/// @param data
///   Pointer to start of data to calculate CRC32 for.
/// @param size
///   Size in byte of data to calculate CRC32 for.
[[nodiscard]] CIALLO_API std::uint32_t crc32(const void *data, std::size_t size) noexcept;

} // namespace ciallo
