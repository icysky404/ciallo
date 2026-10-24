#pragma once

#include "ciallo/configuration.hpp"
#include "ciallo/logging/log_message.hpp"

namespace ciallo {

/// @brief
///   Base class for all log sinks.
class CIALLO_API log_sink {
public:
    /// @brief
    ///   Create this @c log_sink .
    log_sink() noexcept : m_next(nullptr) {}

    /// @brief
    ///   @c log_sink is not copyable.
    log_sink(const log_sink &other) = delete;

    /// @brief
    ///   @c log_sink is not movable.
    log_sink(log_sink &&other) = delete;

    /// @brief
    ///   Destroy this @c log_sink .
    virtual ~log_sink() = default;

    /// @brief
    ///   @c log_sink is not copyable.
    log_sink &operator=(const log_sink &other) = delete;

    /// @brief
    ///   @c log_sink is not movable.
    log_sink &operator=(log_sink &&other) = delete;

    /// @brief
    ///   Write a log message. The derived class must implement this method.
    /// @param message
    ///   The log message to be written.
    virtual void write(const log_message &message) = 0;

    /// @brief
    ///   Flush the logger immediately. The derived class must implement this method.
    virtual void flush() = 0;

    friend class logger;

private:
    /// @brief
    ///   @c log_sink may be managed as intrusive queue in @c logger .
    log_sink *m_next;
};

} // namespace ciallo
