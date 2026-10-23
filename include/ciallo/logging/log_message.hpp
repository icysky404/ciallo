#pragma once

#include <chrono>
#include <format>
#include <source_location>

namespace ciallo {

/// @brief
///   Log level for logger.
enum class log_level : std::uint8_t {
    trace    = 0,
    debug    = 1,
    info     = 2,
    warning  = 3,
    error    = 4,
    critical = 5,
    off      = 6,
};

/// @brief
///   General purpose message for log sinks.
struct log_message {
    /// @brief
    ///   Log level for this message.
    log_level level;

    /// @brief
    ///   The source location where the log command is required.
    std::source_location location;

    /// @brief
    ///   When this message should be written.
    std::chrono::system_clock::time_point timestamp;

    /// @brief
    ///   The log message pattern string.
    std::string_view format;

    /// @brief
    ///   Arguments to be formatted.
    std::format_args arguments;
};

} // namespace ciallo
