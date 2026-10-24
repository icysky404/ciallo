#include "ciallo/logging/sinks/file_log_sink.hpp"
#include "ciallo/logging/log_format_context.hpp"

#include <cerrno>
#include <filesystem>

using namespace ciallo;
using namespace std::chrono_literals;

/// @brief
///   Maximum flush interval for @c file_log_sink .
static constexpr std::chrono::seconds max_flush_interval = 10s;

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

ciallo::file_log_sink::file_log_sink(std::string_view path)
    : m_mutex(),
      m_last_flush(std::chrono::steady_clock::now()),
      m_file() {
    std::filesystem::path full_path(path);
    if (full_path.has_parent_path()) {
        std::filesystem::create_directories(full_path.parent_path());
    }

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    errno = ::_wfopen_s(&m_file, full_path.c_str(), L"a");
#else
    m_file = std::fopen(full_path.c_str(), "a");
#endif

    if (m_file == nullptr) [[unlikely]] {
        throw std::system_error(errno, std::generic_category(),
                                std::format("std::fopen({})", path));
    }

    if (std::setvbuf(m_file, m_buffer, _IOFBF, sizeof(m_buffer)) != 0) [[unlikely]] {
        int error = errno;
        std::fclose(m_file);
        throw std::system_error(error, std::generic_category(),
                                std::format("std::setvbuf({})", path));
    }
}

ciallo::file_log_sink::~file_log_sink() {
    std::scoped_lock<std::mutex> lock(m_mutex);
    std::fclose(m_file);
    m_file = nullptr;
}

void ciallo::file_log_sink::write(const log_message &message) {
    std::string_view level_name = level_names[static_cast<int>(message.level)];

    const auto line = message.location.line();
    const auto file = message.location.file_name();

    log_format_context ctx;
    auto iter = ctx.out();

    if (line != 0 && file != nullptr) {
        auto basename = file_basename(file);
        auto args     = std::make_format_args(message.timestamp, level_name, basename, line);
        iter          = std::vformat_to(iter, "[{}] [{}] [{}:{}] ", args);
    } else {
        auto args = std::make_format_args(message.timestamp, level_name);
        iter      = std::vformat_to(iter, "[{}] [{}] ", args);
    }

    iter    = std::vformat_to(iter, message.format, message.arguments);
    *iter++ = '\n';

    // Write data to file.
    const char *data      = ctx.data();
    std::size_t remaining = ctx.size();

    std::scoped_lock<std::mutex> lock(m_mutex);
    do {
        std::size_t written = std::fwrite(data, 1, remaining, m_file);
        if (written == 0) [[unlikely]] {
            std::clearerr(m_file);
            break;
        }
        data += written;
        remaining -= written;
    } while (remaining != 0);

    auto now = std::chrono::steady_clock::now();
    if (m_last_flush + max_flush_interval <= now) {
        std::fflush(m_file);
        m_last_flush = now;
    }
}

void ciallo::file_log_sink::flush() {
    std::scoped_lock<std::mutex> lock(m_mutex);
    std::fflush(m_file);
    m_last_flush = std::chrono::steady_clock::now();
}
