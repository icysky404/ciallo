#include "ciallo/logging/sinks/console_log_sink.hpp"
#include "ciallo/logging/log_format_context.hpp"

using namespace ciallo;

#if !defined(_WIN32) && !defined(_WIN64) && !defined(__CYGWIN__)
/// @brief
///   Foreground colors for log messages.
static constexpr std::string_view foreground_colors[] = {
    "\033[37m",        // White - trace
    "\033[36m",        // Cyan - debug
    "\033[32m",        // Green - info
    "\033[33m",        // Yellow - warning
    "\033[31m",        // Red - error
    "\033[31m\033[1m", // Red Bold - critical
};
#endif

/// @brief
///   Log level name.
static constexpr std::string_view level_names[] = {
    "trace", "debug", "info", "warning", "error", "critical",
};

/// @brief
///   Extract file name from a source location for logging.
/// @param file
///   The full file path to be extracted.
/// @return
///   Base file name for @p file .
static auto file_basename(std::string_view file) noexcept -> std::string_view {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    std::size_t position = file.find_last_of("/\\");
#else
    std::size_t position = file.find_last_of('/');
#endif
    return (position == std::string_view::npos) ? file : file.substr(position + 1);
}

ciallo::console_log_sink::console_log_sink() noexcept : log_sink(), m_mutex(), m_stdout(stdout) {}

ciallo::console_log_sink::~console_log_sink() = default;

void ciallo::console_log_sink::write(const log_message &message) {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    const std::string_view level_name = level_names[static_cast<int>(message.level)];

    const auto line = message.location.line();
    const auto file = message.location.file_name();

    log_format_context ctx;
    auto iter = ctx.out();

    if (line != 0 && file != nullptr) {
        std::string_view filename = file_basename(file);
        auto args = std::make_format_args(message.timestamp, level_name, filename, line);
        iter      = std::vformat_to(iter, "[{}] [{}] [{}:{}] ", args);
    } else {
        auto args = std::make_format_args(message.timestamp, level_name);
        iter      = std::vformat_to(iter, "[{}] [{}] ", args);
    }
#else
    const std::string_view color      = foreground_colors[static_cast<int>(message.level)];
    const std::string_view level_name = level_names[static_cast<int>(message.level)];

    const auto line = message.location.line();
    const auto file = message.location.file_name();

    log_format_context ctx;
    auto iter = ctx.out();

    if (line != 0 && file != nullptr) {
        std::string_view filename = file_basename(file);
        auto args = std::make_format_args(message.timestamp, color, level_name, filename, line);
        iter      = std::vformat_to(iter, "[{}] {}[{}]\033[0m [{}:{}] ", args);
    } else {
        auto args = std::make_format_args(message.timestamp, color, level_name);
        iter      = std::vformat_to(iter, "[{}] {}[{}]\033[0m ", args);
    }
#endif

    iter    = std::vformat_to(iter, message.format, message.arguments);
    *iter++ = '\n';

    // Write to console.
    const char *data      = ctx.data();
    std::size_t remaining = ctx.size();

    std::scoped_lock<std::mutex> lock(m_mutex);
    while (remaining != 0) {
        std::size_t written = std::fwrite(data, 1, remaining, m_stdout);
        if (written == 0) [[unlikely]] {
            std::clearerr(m_stdout);
            break;
        }
        data += written;
        remaining -= written;
    }
}

void ciallo::console_log_sink::flush() {
    std::scoped_lock<std::mutex> lock(m_mutex);
    std::fflush(m_stdout);
}
