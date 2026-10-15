#pragma once

#include <concepts>
#include <utility>

namespace ciallo {

/// @brief
///   @c scope_guard is used to execute a guard function when leaving current scope.
/// @tparam Function
///   Type of the function to be executed when leaving current scope. The function must not throw
///   exception.
template <std::invocable Function>
class scope_guard {
public:
    /// @brief
    ///   Construct this @c scope_guard object.
    /// @tparam Args
    ///   Types of arguments to construct the function that should be called when leaving current
    ///   scope.
    /// @param args
    ///   Arguments to construct the function that should be called when leaving current scope.
    template <std::constructible_from<Function>... Args>
    scope_guard(Args &&...args) noexcept(std::is_nothrow_constructible_v<Function, Args...>)
        : m_function(std::forward<Args>(args)...),
          m_is_dismissed(false) {}

    /// @brief
    ///   @c scope_guard is not copyable.
    scope_guard(const scope_guard &other) = delete;

    /// @brief
    ///   @c scope_guard is not movable.
    scope_guard(scope_guard &&other) = delete;

    /// @brief
    ///   Invoke the underlying guard function.
    ~scope_guard() {
        if (!m_is_dismissed) {
            m_function();
        }
    }

    /// @brief
    ///   Dismiss this @c scope_guard so that the guard function will not be invoked.
    void dismiss() noexcept {
        m_is_dismissed = true;
    }

    /// @brief
    ///   Checks if this @c scope_guard is dismissed. Dismissed @c scope_guard will not invoke the
    ///   guard function when leaving current scope.
    /// @return
    ///   Return @c true if this @c scope_guard is dismissed. Otherwise, return @c false .
    [[nodiscard]] bool is_dismissed() const noexcept {
        return m_is_dismissed;
    }

private:
    Function m_function;
    bool m_is_dismissed;
};

/// @brief
///   Deducing guide for @c scope_guard to make it more convenient to use.
template <typename T>
scope_guard(T &&) -> scope_guard<std::unwrap_ref_decay_t<T>>;

} // namespace ciallo
