#include "ciallo/logging/log_format_context.hpp"

#include <cstring>
#include <new> // IWYU pragma: keep

using namespace ciallo;

ciallo::log_format_context::log_format_context(const log_format_context &other)
    : m_front(m_inline_buffer),
      m_back(m_inline_buffer),
      m_alloc_end(m_inline_buffer + sizeof(m_inline_buffer)) {
    std::size_t count = other.size();
    reserve(count);
    std::memcpy(m_front, other.data(), count);
    m_back += count;
}

ciallo::log_format_context::log_format_context(log_format_context &&other) noexcept
    : m_front(m_inline_buffer),
      m_back(m_inline_buffer),
      m_alloc_end(m_inline_buffer + sizeof(m_inline_buffer)) {
    if (other.m_front == other.m_inline_buffer) {
        std::size_t count = other.size();
        std::memcpy(m_inline_buffer, other.data(), count);
        m_back += count;
    } else {
        m_front     = other.m_front;
        m_back      = other.m_back;
        m_alloc_end = other.m_alloc_end;

        other.m_front     = other.m_inline_buffer;
        other.m_back      = other.m_front;
        other.m_alloc_end = other.m_inline_buffer + sizeof(m_inline_buffer);
    }
}

ciallo::log_format_context::~log_format_context() {
    if (m_front != m_inline_buffer) {
        ::operator delete(m_front, static_cast<std::size_t>(m_alloc_end - m_front));
    }
}

log_format_context &log_format_context::operator=(const log_format_context &other) {
    if (this == &other) [[unlikely]] {
        return *this;
    }

    std::size_t count = other.size();

    clear();
    reserve(count);

    std::memcpy(m_front, other.data(), count);
    m_back = m_front + count;

    return *this;
}

log_format_context &log_format_context::operator=(log_format_context &&other) noexcept {
    if (this == &other) [[unlikely]] {
        return *this;
    }

    if (m_front != m_inline_buffer) {
        ::operator delete(m_front, static_cast<std::size_t>(m_alloc_end - m_front));
        m_front     = m_inline_buffer;
        m_back      = m_front;
        m_alloc_end = m_front + sizeof(m_inline_buffer);
    }

    if (other.m_front == other.m_inline_buffer) {
        std::size_t count = other.size();
        std::memcpy(m_front, other.data(), count);
        m_back = m_front + count;
    } else {
        m_front     = other.m_front;
        m_back      = other.m_back;
        m_alloc_end = other.m_alloc_end;

        other.m_front     = other.m_inline_buffer;
        other.m_back      = other.m_front;
        other.m_alloc_end = other.m_inline_buffer + sizeof(m_inline_buffer);
    }

    return *this;
}

void log_format_context::reserve(std::size_t new_capacity) {
    if (m_front + new_capacity <= m_alloc_end) {
        return;
    }

    new_capacity = ((new_capacity + 0x1FF) & ~static_cast<std::size_t>(0x1FF));
    auto count   = static_cast<std::size_t>(m_back - m_front);
    auto *buffer = static_cast<char *>(::operator new(new_capacity));
    std::memcpy(buffer, m_front, count);

    if (m_front != m_inline_buffer) {
        ::operator delete(m_front, static_cast<std::size_t>(m_alloc_end - m_front));
    }

    m_front     = buffer;
    m_back      = m_front + count;
    m_alloc_end = m_front + new_capacity;
}
