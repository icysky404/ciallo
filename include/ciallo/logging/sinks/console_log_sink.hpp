#pragma once

#include "ciallo/configuration.hpp"
#include "ciallo/logging/log_sink.hpp"

#include <cstdio>
#include <mutex>

namespace ciallo {

/// @brief
///   Console log sink.
/// @note
///   @c console_log_sink uses @c std::mutex to protect concurrent writing operation, so it may be
///   slow when multiple threads writes concurrently.
class CIALLO_API console_log_sink : public log_sink {
public:
    /// @brief
    ///   Create this @c console_log_sink .
    console_log_sink() noexcept;

    /// @brief
    ///   Destroy this @c console_log_sink .
    ~console_log_sink() override;

    /// @brief
    ///   Write a log message. This method is concurrent safe.
    /// @param message
    ///   The log message to be written.
    void write(const log_message &message) override;

    /// @brief
    ///   Flush the standard output immediately. This method is concurrent safe.
    void flush() override;

private:
    mutable std::mutex m_mutex;
    std::FILE *m_stdout;
};

} // namespace ciallo
