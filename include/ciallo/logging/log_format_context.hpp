#pragma once

#include "ciallo/configuration.hpp"

#include <cstddef>
#include <iterator>
#include <string_view>

namespace ciallo {

/// @brief
///   Format context for logger and sinks.
class CIALLO_API log_format_context {
public:
    using value_type      = char;
    using reference       = char &;
    using const_reference = const char &;

    /// @brief
    ///   Construct this @c log_format_context for formatter support.
    log_format_context() noexcept
        : m_front(m_inline_buffer),
          m_back(m_inline_buffer),
          m_alloc_end(m_inline_buffer + sizeof(m_inline_buffer)) {}

    /// @brief
    ///   Copy constructor for @c log_format_context .
    /// @param other
    ///   The @c log_format_context to copy from.
    /// @throw std::bad_alloc
    ///   Thrown if failed to allocate heap memory.
    log_format_context(const log_format_context &other);

    /// @brief
    ///   Move constructor for @c log_format_context .
    /// @param other
    ///   The @c log_format_context to be moved from.
    log_format_context(log_format_context &&other) noexcept;

    /// @brief
    ///   Destroy this @c log_format_context .
    ~log_format_context();

    /// @brief
    ///   Copy assignment for @c log_format_context .
    /// @param other
    ///   The @c log_format_context to copy from.
    /// @return
    ///   Reference to this @c log_format_context .
    /// @throw std::bad_alloc
    ///   Thrown if failed to allocate heap memory.
    log_format_context &operator=(const log_format_context &other);

    /// @brief
    ///   Move assignment for @c log_format_context .
    /// @param other
    ///   The @c log_format_context to be moved from.
    /// @return
    ///   Reference to this @c log_format_context .
    log_format_context &operator=(log_format_context &&other) noexcept;

    /// @brief
    ///   Get pointer to start of this context.
    /// @return
    ///   Pointer to start of this context.
    [[nodiscard]] char *data() noexcept {
        return m_front;
    }

    /// @brief
    ///   Get pointer to start of this context.
    /// @return
    ///   Pointer to start of this context.
    [[nodiscard]] const char *data() const noexcept {
        return m_front;
    }

    /// @brief
    ///   Get current size of this @c context .
    /// @return
    ///   Current size of this @c context .
    [[nodiscard]] std::size_t size() const noexcept {
        return static_cast<std::size_t>(m_back - m_front);
    }

    /// @brief
    ///   Clear all data written to this context.
    void clear() noexcept {
        m_back = m_front;
    }

    /// @brief
    ///   Reserve memory for this @c log_format_context .
    /// @param new_capacity
    ///   New capacity for this @c log_format_context .
    /// @throw std::bad_alloc
    ///   Thrown if failed to allocate heap memory.
    void reserve(std::size_t new_capacity);

    /// @brief
    ///   Append a character to the end of this context.
    /// @param c
    ///   The character to be appended.
    /// @throw std::bad_alloc
    ///   Thrown if failed to allocate heap memory.
    void push_back(char c) {
        if (m_back == m_alloc_end) [[unlikely]] {
            reserve(size() * 2);
        }
        *m_back++ = c;
    }

    /// @brief
    ///   Get back insertor for this @c log_format_context .
    /// @return
    ///   Back insertor for this @c log_format_context .
    [[nodiscard]] std::back_insert_iterator<log_format_context> out() noexcept {
        return std::back_inserter(*this);
    }

    /// @brief
    ///   Allow implicit cast to @c std::string_view .
    [[nodiscard]] operator std::string_view() const noexcept {
        return std::string_view(m_front, m_back);
    }

private:
    char *m_front;
    char *m_back;
    char *m_alloc_end;
    char m_inline_buffer[512 - sizeof(m_front) - sizeof(m_back) - sizeof(m_alloc_end)];
};

} // namespace ciallo
