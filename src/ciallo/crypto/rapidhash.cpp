/// Ported from rapidhash V3 by Nicolas De Carli.
///
/// Copyright 2025 Nicolas De Carli
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///
/// https://github.com/Nicoshev/rapidhash

#include "ciallo/crypto/rapidhash.hpp"

#if defined(_MSC_VER)
#    include <intrin.h>
#endif

#include <bit>
#include <concepts>
#include <cstring>

/// @brief
///   Default secret parameters for rapidhash.
static constexpr std::uint64_t rapid_secrets[8] = {
    0x2D358DCCAA6C78A5ULL, 0x8BB84B93962EACC9ULL, 0x4B33A62ED433d4A3ULL, 0x4D5A2DA51DE1AA47ULL,
    0xA0761D6478BD642FULL, 0xE7037ED1A0B428DBULL, 0x90ED1765281C388CULL, 0xAAAAAAAAAAAAAAAAULL,
};

/// @brief
///   Calculate multiplication of two 64-bit integers.
/// @param[inout] a
///   The first integer to multiply. This will also be used to store the low part of the result.
/// @param[inout] b
///   The second integer to multiply. This will also be used to store the high part of the result.
static void multiply(std::uint64_t &a, std::uint64_t &b) noexcept {
#if defined(__SIZEOF_INT128__)
    auto result = static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b);
    a           = static_cast<std::uint64_t>(result);
    b           = static_cast<std::uint64_t>(result >> 64);
#elif defined(_MSC_VER) && defined(_WIN64)
#    if defined(_M_X64)
    a = _umul128(a, b, &b);
#    else
    std::uint64_t c = __umulh(a, b);
    a *= b;
    b = c;
#    endif
#else
    std::uint64_t high_a = (a >> 32);
    std::uint64_t high_b = (b >> 32);
    std::uint64_t low_a  = (a & 0xFFFFFFFFU);
    std::uint64_t low_b  = (b & 0xFFFFFFFFU);

    std::uint64_t high_high = high_a * high_b;
    std::uint64_t high_low  = high_a * low_b;
    std::uint64_t low_high  = low_a * high_b;
    std::uint64_t low_low   = low_a * low_b;

    std::uint64_t temp  = low_low + (high_low << 32);
    std::uint64_t carry = (temp < low_low);
    std::uint64_t low   = temp + (low_high << 32);
    carry += (low < temp);
    std::uint64_t high = high_high + (high_low >> 32) + (low_high >> 32) + carry;

    a = low;
    b = high;
#endif
}

/// @brief
///   Multiply and XOR mix.
/// @param a
///   The first number to be mixed.
/// @param b
///   The second number to be mixed.
/// @return
///   The mixed result.
[[nodiscard]] static std::uint64_t mix(std::uint64_t a, std::uint64_t b) noexcept {
    multiply(a, b);
    return (a ^ b);
}

/// @brief
///   Read an unsigned integer from the specified address.
/// @tparam T
///   Type of the unsigned integer to be loaded.
/// @param data
///   Pointer to the data to be loaded.
/// @return
///   The loaded value.
template <std::unsigned_integral T>
[[nodiscard]] static T read(const std::byte *data) noexcept {
    T value;
#if defined(__has_builtin)
#    if __has_builtin(__builtin_memcpy)
    __builtin_memcpy(&value, data, sizeof(T));
#    else
    std::memcpy(&value, data, sizeof(T));
#    endif
#else
    std::memcpy(&value, data, sizeof(T));
#endif

    if constexpr (std::endian::native != std::endian::little) {
        value = std::byteswap(value);
    }
    return value;
}

std::uint64_t ciallo::rapidhash(const void *data, std::size_t size, std::uint64_t seed) noexcept {
    seed ^= mix(seed ^ rapid_secrets[2], rapid_secrets[1]);
    const auto *position = static_cast<const std::byte *>(data);

    std::uint64_t a = 0;
    std::uint64_t b = 0;

    std::size_t remaining = size;
    if (size <= 16) [[likely]] {
        if (size >= 4) {
            seed ^= size;
            if (size >= 8) {
                a = read<std::uint64_t>(position);
                b = read<std::uint64_t>(position + size - sizeof(std::uint64_t));
            } else {
                a = read<std::uint32_t>(position);
                b = read<std::uint32_t>(position + size - sizeof(std::uint32_t));
            }
        } else if (size > 0) {
            a = (static_cast<std::uint64_t>(position[0]) << 45) |
                static_cast<std::uint8_t>(position[size - 1]);
            b = static_cast<std::uint8_t>(position[size >> 1]);
        }
    } else {
        if (size > 112) {
            std::uint64_t seed1 = seed;
            std::uint64_t seed2 = seed;
            std::uint64_t seed3 = seed;
            std::uint64_t seed4 = seed;
            std::uint64_t seed5 = seed;
            std::uint64_t seed6 = seed;

            do {
                seed  = mix(read<std::uint64_t>(position) ^ rapid_secrets[0],
                            read<std::uint64_t>(position + 8) ^ seed);
                seed1 = mix(read<std::uint64_t>(position + 16) ^ rapid_secrets[1],
                            read<std::uint64_t>(position + 24) ^ seed1);
                seed2 = mix(read<std::uint64_t>(position + 32) ^ rapid_secrets[2],
                            read<std::uint64_t>(position + 40) ^ seed2);
                seed3 = mix(read<std::uint64_t>(position + 48) ^ rapid_secrets[3],
                            read<std::uint64_t>(position + 56) ^ seed3);
                seed4 = mix(read<std::uint64_t>(position + 64) ^ rapid_secrets[4],
                            read<std::uint64_t>(position + 72) ^ seed4);
                seed5 = mix(read<std::uint64_t>(position + 80) ^ rapid_secrets[5],
                            read<std::uint64_t>(position + 88) ^ seed5);
                seed6 = mix(read<std::uint64_t>(position + 96) ^ rapid_secrets[6],
                            read<std::uint64_t>(position + 104) ^ seed6);
                position += 112;
                remaining -= 112;
            } while (remaining > 112);

            seed ^= seed1;
            seed2 ^= seed3;
            seed4 ^= seed5;
            seed ^= seed6;
            seed2 ^= seed4;
            seed ^= seed2;
        }

        if (remaining > 16) {
            seed = mix(read<std::uint64_t>(position) ^ rapid_secrets[2],
                       read<std::uint64_t>(position + 8) ^ seed);
            if (remaining > 32) {
                seed = mix(read<std::uint64_t>(position + 16) ^ rapid_secrets[2],
                           read<std::uint64_t>(position + 24) ^ seed);
                if (remaining > 48) {
                    seed = mix(read<std::uint64_t>(position + 32) ^ rapid_secrets[1],
                               read<std::uint64_t>(position + 40) ^ seed);
                    if (remaining > 64) {
                        seed = mix(read<std::uint64_t>(position + 48) ^ rapid_secrets[1],
                                   read<std::uint64_t>(position + 56) ^ seed);
                        if (remaining > 80) {
                            seed = mix(read<std::uint64_t>(position + 64) ^ rapid_secrets[2],
                                       read<std::uint64_t>(position + 72) ^ seed);
                            if (remaining > 96) {
                                seed = mix(read<std::uint64_t>(position + 80) ^ rapid_secrets[1],
                                           read<std::uint64_t>(position + 88) ^ seed);
                            }
                        }
                    }
                }
            }
        }
        a = read<std::uint64_t>(position + remaining - 16) ^ remaining;
        b = read<std::uint64_t>(position + remaining - 8);
    }

    a ^= rapid_secrets[1];
    b ^= seed;

    multiply(a, b);
    return mix(a ^ rapid_secrets[7], b ^ rapid_secrets[1] ^ remaining);
}
