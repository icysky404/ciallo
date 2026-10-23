#pragma once

#include "ciallo/configuration.hpp"
#include "ciallo/logging/log_sink.hpp"
#include "ciallo/utility/spin_wait.hpp"

#include <atomic>

namespace ciallo {

/// @brief
///   A @c logger could manage a series of @c log_sinks.
class CIALLO_API logger {
public:
    /// @brief
    ///   Create a @c logger with log level set to @p level .
    /// @note
    ///   This constructor does not add any sink for this @c logger . User must add at least one
    ///   sink to make it available.
    /// @param level
    ///   Log message filter level for this @c logger .
    explicit logger(log_level level = log_level::info) noexcept;

    /// @brief
    ///   @c logger is not copyable.
    logger(const logger &other) = delete;

    /// @brief
    ///   @c logger is not movable.
    logger(logger &&other) = delete;

    /// @brief
    ///   Destroy this @c logger and all sinks.
    ~logger();

    /// @brief
    ///   @c logger is not copyable.
    logger &operator=(const logger &other) = delete;

    /// @brief
    ///   @c logger is not movable.
    logger &operator=(logger &&other) = delete;

    /// @brief
    ///   Set message filter level for this @c logger . This method is concurrent safe.
    /// @param value
    ///   The new log level to be set.
    void set_level(log_level value) noexcept {
        m_level.store(value, std::memory_order_relaxed);
    }

    /// @brief
    ///   Get message filter level for this @c logger . This method is concurrent safe.
    /// @return
    ///   Current message filter level for this @c logger .
    [[nodiscard]] log_level level() const noexcept {
        return m_level.load(std::memory_order_relaxed);
    }

    /// @brief
    ///   Set flush level for this @c logger . Logger will automatically flush sinks if log
    ///   message's level is greater than or equal to flush level. This method is concurrent safe.
    /// @param level
    ///   The new flush level to be set.
    void set_flush_level(log_level level) noexcept {
        m_flush_level.store(level, std::memory_order_relaxed);
    }

    /// @brief
    ///   Get current flush level for this @c logger . Logger will automatically flush sinks if log
    ///   message's level is greater than or equal to flush level. This method is concurrent safe.
    /// @return
    ///   Current flush level for this @c logger .
    [[nodiscard]] log_level flush_level() const noexcept {
        return m_flush_level.load(std::memory_order_relaxed);
    }

    /// @brief
    ///   Add a new sink to this @c logger . This method is concurrent safe.
    /// @tparam T
    ///   Type of the sink to be added. The new sink must be derived from @c log_sink .
    template <typename T, typename... Args>
        requires(std::derived_from<T, log_sink> && std::constructible_from<T, Args...>)
    T &add_sink(Args &&...args) {
        T *object      = new T(std::forward<Args>(args)...);
        log_sink *sink = object;
        log_sink *temp = m_sinks.load(std::memory_order_relaxed);
        sink->m_next   = temp;
        while (!m_sinks.compare_exchange_weak(temp, sink, std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
            spin_wait();
            temp         = m_sinks.load(std::memory_order_relaxed);
            sink->m_next = temp;
        }
        return *object;
    }

    /// @brief
    ///   Write a message to this @c logger . This method is concurrent safe for @c logger , but the
    ///   underlying sinks may not support concurrent visit.
    /// @param level
    ///   Level of the message to be written.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    void log(log_level level,
             const std::source_location &location,
             std::string_view format,
             std::format_args args) const;

    /// @brief
    ///   Flush all sinks immediately. This method is concurrent safe for @c logger , but the
    ///   underlying sinks may not support concurrent visit.
    void flush() const;

    /// @brief
    ///   Write a trace log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void trace(const std::source_location &location,
               std::format_string<Args...> format,
               Args &&...args) const {
        log(log_level::trace, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Write a debug log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void debug(const std::source_location &location,
               std::format_string<Args...> format,
               Args &&...args) const {
        log(log_level::debug, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Write a info log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void info(const std::source_location &location,
              std::format_string<Args...> format,
              Args &&...args) const {
        log(log_level::info, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Write a warning log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void warning(const std::source_location &location,
                 std::format_string<Args...> format,
                 Args &&...args) const {
        log(log_level::warning, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Write an error log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void error(const std::source_location &location,
               std::format_string<Args...> format,
               Args &&...args) const {
        log(log_level::error, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Write a critical log message.
    /// @tparam Args
    ///   Types of arguments to be formatted.
    /// @param location
    ///   Source location where the log message is written.
    /// @param format
    ///   The format pattern string.
    /// @param args
    ///   Arguments to be formatted.
    template <typename... Args>
    void critical(const std::source_location &location,
                  std::format_string<Args...> format,
                  Args &&...args) const {
        log(log_level::critical, location, format.get(), std::make_format_args(args...));
    }

    /// @brief
    ///   Get the global logger singleton instance. This method is concurrent safe.
    /// @note
    ///   The global singleton instance is created with no logger. User must manually add at least
    ///   one logger to enable it.
    /// @return
    ///   The global logger singleton instance.
    [[nodiscard]] static logger &singleton() noexcept;

private:
    /// @brief
    ///   Message level filter level for this @c logger .
    alignas(64) std::atomic<log_level> m_level;

    /// @brief
    ///   Log level that should flush all sinks immediately.
    alignas(64) std::atomic<log_level> m_flush_level;

    /// @brief
    ///   Sink list for this @c logger .
    alignas(64) std::atomic<log_sink *> m_sinks;
};

/// @brief
///   Helper type to write trace log to default log system.
template <typename... Args>
struct log_trace {
    log_trace(std::format_string<Args...> format,
              Args &&...args,
              std::source_location location = std::source_location::current()) {
        logger::singleton().trace<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write trace log with source location.
template <typename... Args>
log_trace(std::format_string<Args...>, Args &&...) -> log_trace<Args...>;

/// @brief
///   Helper type to write debug log to default log system.
template <typename... Args>
struct log_debug {
    log_debug(std::format_string<Args...> format,
              Args &&...args,
              std::source_location location = std::source_location::current()) {
        logger::singleton().debug<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write debug log with source location.
template <typename... Args>
log_debug(std::format_string<Args...>, Args &&...) -> log_debug<Args...>;

/// @brief
///   Helper type to write info log to default log system.
template <typename... Args>
struct log_info {
    log_info(std::format_string<Args...> format,
             Args &&...args,
             std::source_location location = std::source_location::current()) {
        logger::singleton().info<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write info log with source location.
template <typename... Args>
log_info(std::format_string<Args...>, Args &&...) -> log_info<Args...>;

/// @brief
///   Helper type to write warning log to default log system.
template <typename... Args>
struct log_warning {
    log_warning(std::format_string<Args...> format,
                Args &&...args,
                std::source_location location = std::source_location::current()) {
        logger::singleton().warning<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write warning log with source location.
template <typename... Args>
log_warning(std::format_string<Args...>, Args &&...) -> log_warning<Args...>;

/// @brief
///   Helper type to write error log to default log system.
template <typename... Args>
struct log_error {
    log_error(std::format_string<Args...> format,
              Args &&...args,
              std::source_location location = std::source_location::current()) {
        logger::singleton().error<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write error log with source location.
template <typename... Args>
log_error(std::format_string<Args...>, Args &&...) -> log_error<Args...>;

/// @brief
///   Helper type to write critical log to default log system.
template <typename... Args>
struct log_critical {
    log_critical(std::format_string<Args...> format,
                 Args &&...args,
                 std::source_location location = std::source_location::current()) {
        logger::singleton().critical<Args...>(location, format, std::forward<Args>(args)...);
    }
};

/// @brief
///   A trick to write critical log with source location.
template <typename... Args>
log_critical(std::format_string<Args...>, Args &&...) -> log_critical<Args...>;

} // namespace ciallo
