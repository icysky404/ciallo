#include "ciallo/logging/logger.hpp"

#include <cstring>

using namespace ciallo;

ciallo::logger::logger(log_level level) noexcept
    : m_level(level),
      m_flush_level(log_level::error),
      m_sinks(nullptr) {}

ciallo::logger::~logger() {
    log_sink *sink = m_sinks.exchange(nullptr, std::memory_order_acq_rel);
    while (sink != nullptr) {
        log_sink *next = sink->m_next;
        delete sink;
        sink = next;
    }
}

void ciallo::logger::log(log_level level,
                         const std::source_location &location,
                         std::string_view format,
                         std::format_args args) const {
    if (level >= log_level::off || level < m_level.load(std::memory_order_relaxed)) {
        return;
    }

    log_message message{
        .level     = level,
        .location  = location,
        .timestamp = std::chrono::system_clock::now(),
        .format    = format,
        .arguments = args,
    };

    log_sink *sink = m_sinks.load(std::memory_order_acquire);
    if (message.level >= flush_level()) {
        while (sink != nullptr) {
            sink->write(message);
            sink->flush();
            sink = sink->m_next;
        }
    } else {
        while (sink != nullptr) {
            sink->write(message);
            sink = sink->m_next;
        }
    }
}

void ciallo::logger::flush() const {
    log_sink *sink = m_sinks.load(std::memory_order_acquire);
    while (sink != nullptr) {
        sink->flush();
        sink = sink->m_next;
    }
}

logger &ciallo::logger::singleton() noexcept {
    static logger instance;
    return instance;
}
