#pragma once

#include "ciallo/crypto/rapidhash.hpp"

#include <concepts>
#include <functional>
#include <string>

namespace ciallo {

/// @brief
///   General-purpose hasher for containers.
template <typename Key>
struct hash : std::hash<Key> {};

/// @brief
///   Hasher for boolean values.
template <>
struct hash<bool> : std::hash<bool> {};

/// @brief
///   Hasher for integer types.
template <std::integral T>
struct hash<T> {
    /// @brief
    ///   Calculate hash value for @p value .
    /// @param value
    ///   The value to calculate hash value for.
    [[nodiscard]] std::size_t operator()(T value) const noexcept {
        // FNV-1a
        constexpr std::size_t prime        = (sizeof(std::size_t) >= sizeof(std::uint64_t))
                                                 ? static_cast<std::size_t>(0x100000001B3ULL)
                                                 : static_cast<std::size_t>(0x01000193U);
        constexpr std::size_t offset_basis = (sizeof(std::size_t) >= sizeof(std::uint64_t))
                                                 ? static_cast<std::size_t>(0xCBF29CE484222325ULL)
                                                 : static_cast<std::size_t>(0x811C9DC5U);

        auto temp     = static_cast<std::make_unsigned_t<T>>(value);
        std::size_t h = offset_basis;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            h ^= static_cast<std::uint8_t>(temp >> (i * 8));
            h *= prime;
        }
        return h;
    }
};

/// @brief
///   Hasher for string types.
template <typename Char, typename Traits, typename Allocator>
struct hash<std::basic_string<Char, Traits, Allocator>> {
    using value_type     = std::basic_string<Char, Traits, Allocator>;
    using is_transparent = void;

    [[nodiscard]] std::size_t operator()(const value_type &str) const noexcept {
        return static_cast<std::size_t>(rapidhash(str.data(), str.size() * sizeof(Char)));
    }

    [[nodiscard]] std::size_t operator()(std::basic_string_view<Char, Traits> view) const noexcept {
        return static_cast<std::size_t>(rapidhash(view.data(), view.size() * sizeof(Char)));
    }

    [[nodiscard]] std::size_t operator()(const Char *str) const noexcept {
        return static_cast<std::size_t>(rapidhash(str, Traits::length(str) * sizeof(Char)));
    }
};

/// @brief
///   Hasher for string view types.
template <typename Char, typename Traits>
struct hash<std::basic_string_view<Char, Traits>> {
    using is_transparent = void;

    [[nodiscard]] std::size_t operator()(std::basic_string_view<Char, Traits> view) const noexcept {
        return static_cast<std::size_t>(rapidhash(view.data(), view.size() * sizeof(Char)));
    }
};

} // namespace ciallo
