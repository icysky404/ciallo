#pragma once

#include "ciallo/configuration.hpp"
#include "ciallo/logging/log_sink.hpp"

#include <cstdio>
#include <mutex>

namespace ciallo {

/// @brief
///   Single file log sink.
/// @note
///   @c file_log_sink uses @c std::mutex to protect concurrent writing operation, so it may be slow
///   when multiple threads writes concurrently.
class CIALLO_API file_log_sink : public log_sink {
public:
    /// @brief
    ///   Create @c file_log_sink and open the specified file.
    /// @param path
    ///   Path to the log file to be opened. The file will be automatically created if not exists.
    ///   New log messages will be appended to the file if it already exists.
    /// @throw std::filesystem::filesystem_error
    ///   Thrown if failed to create directory for @p path .
    /// @throw std::system_error
    ///   Thrown if failed to open the specified log file.
    explicit file_log_sink(std::string_view path);

    /// @brief
    ///   Destroy this @c file_log_sink and flush all data.
    ~file_log_sink() override;

    /// @brief
    ///   Write a new log message. This method is concurrent safe.
    /// @param message
    ///   The log message to be written.
    void write(const log_message &message) override;

    /// @brief
    ///   Flush this sink immediately.
    void flush() override;

private:
    std::mutex m_mutex;
    std::chrono::steady_clock::time_point m_last_flush;
    std::FILE *m_file;
    char m_buffer[16384];
};

} // namespace ciallo
