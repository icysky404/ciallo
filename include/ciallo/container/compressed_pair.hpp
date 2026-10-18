#pragma once

#include <concepts>
#include <tuple>
#include <type_traits>
#include <utility>

namespace ciallo {
namespace detail {

/// @brief
///   Element type for @c compressed_pair to enable empty-base class optimization for empty types.
/// @tparam T
///   Type of the element to be stored in this @c compressed_pair_element .
/// @tparam Index
///   Index of current element. It differentiates the two elements of @c compressed_pair when they
///   have the same type.
template <typename T,
          int Index,
          bool CouldOptimize = std::is_class_v<T> && std::is_empty_v<T> && !std::is_final_v<T>>
class compressed_pair_element {
public:
    using value_type      = T;
    using reference       = T &;
    using const_reference = const T &;

    /// @brief
    ///   Construct this @c compressed_pair_element with @c value_type 's default constructor.
    /// @note
    ///   It is ill-formed to call this @c constructor if @c value_type is not
    ///   default-constructible. For trivially-constructible @c value_type , the value will be
    ///   zero-initialized.
    constexpr compressed_pair_element() noexcept(std::is_nothrow_default_constructible_v<T>);

    /// @brief
    ///   Construct this @c comnpressed_pair_element and the underlying element with @p arg .
    /// @tparam Argument
    ///   Type of the argument to be used to construct the underlying element.
    /// @param arg
    ///   The argument to be used to construct the underlying element.
    template <typename Argument>
        requires(std::constructible_from<T, Argument> &&
                 !std::is_same_v<compressed_pair_element, std::remove_cvref_t<Argument>>)
    constexpr compressed_pair_element(Argument &&arg) noexcept(
        std::is_nothrow_constructible_v<T, Argument>)
        : m_value(std::forward<Argument>(arg)) {}

    /// @brief
    ///   Construct this @c comnpressed_pair_element and the underlying element with a tuple of
    ///   arguments.
    /// @tparam Args
    ///   Types of arguments to be used to construct the underlying element.
    /// @tparam Indices
    ///   Indices of each element to be used to construct the underlying element.
    /// @param args
    ///   Tuple of arguments to be used to construct the underlying element.
    template <typename... Args, std::size_t... Indices>
        requires(std::constructible_from<T, Args...>)
    constexpr compressed_pair_element(
        std::piecewise_construct_t,
        std::tuple<Args...> args,
        std::index_sequence<Indices...>) noexcept(std::is_nothrow_constructible_v<T, Args...>)
        : m_value(std::forward<Args>(std::get<Indices>(args))...) {}

    /// @brief
    ///   Get reference to the underlying element.
    /// @return
    ///   Reference to the underlying element.
    [[nodiscard]] constexpr reference get() noexcept {
        return m_value;
    }

    /// @brief
    ///   Get reference to the underlying element.
    /// @return
    ///   Reference to the underlying element.
    [[nodiscard]] constexpr const_reference get() const noexcept {
        return m_value;
    }

private:
    /// @brief
    ///   The value stored in this @c compressed_pair_element .
    value_type m_value;
};

template <typename T, int Index, bool CouldOptimize>
constexpr compressed_pair_element<T, Index, CouldOptimize>::compressed_pair_element() noexcept(
    std::is_nothrow_default_constructible_v<T>)
    : m_value() {}

/// @brief
///   Element type for @c compressed_pair to enable empty-base class optimization for empty types.
/// @tparam T
///   Type of the element to be stored in this @c compressed_pair_element .
/// @tparam Index
///   Index of current element. It differentiates the two elements of @c compressed_pair when they
///   have the same type.
template <typename T, int Index>
class compressed_pair_element<T, Index, true> : private T {
public:
    using value_type      = T;
    using reference       = T &;
    using const_reference = const T &;

    /// @brief
    ///   Construct this @c compressed_pair_element with @c value_type 's default constructor.
    /// @note
    ///   It is ill-formed to call this @c constructor if @c value_type is not
    ///   default-constructible. For trivially-constructible @c value_type , the value will be
    ///   zero-initialized.
    constexpr compressed_pair_element() noexcept(std::is_nothrow_default_constructible_v<T>);

    /// @brief
    ///   Construct this @c comnpressed_pair_element and the underlying element with @p arg .
    /// @tparam Argument
    ///   Type of the argument to be used to construct the underlying element.
    /// @param arg
    ///   The argument to be used to construct the underlying element.
    template <typename Argument>
        requires(std::constructible_from<T, Argument> &&
                 !std::is_same_v<compressed_pair_element, std::remove_cvref_t<Argument>>)
    constexpr compressed_pair_element(Argument &&arg) noexcept(
        std::is_nothrow_constructible_v<T, Argument>)
        : T(std::forward<Argument>(arg)) {}

    /// @brief
    ///   Construct this @c comnpressed_pair_element and the underlying element with a tuple of
    ///   arguments.
    /// @tparam Args
    ///   Types of arguments to be used to construct the underlying element.
    /// @tparam Indices
    ///   Indices of each element to be used to construct the underlying element.
    /// @param args
    ///   Tuple of arguments to be used to construct the underlying element.
    template <typename... Args, std::size_t... Indices>
        requires(std::constructible_from<T, Args...>)
    constexpr compressed_pair_element(
        std::piecewise_construct_t,
        std::tuple<Args...> args,
        std::index_sequence<Indices...>) noexcept(std::is_nothrow_constructible_v<T, Args...>)
        : T(std::forward<Args>(std::get<Indices>(args))...) {}

    /// @brief
    ///   Get reference to the underlying element.
    /// @return
    ///   Reference to the underlying element.
    [[nodiscard]] constexpr reference get() noexcept {
        return static_cast<reference>(*this);
    }

    /// @brief
    ///   Get reference to the underlying element.
    /// @return
    ///   Reference to the underlying element.
    [[nodiscard]] constexpr const_reference get() const noexcept {
        return static_cast<const_reference>(*this);
    }
};

template <typename T, int Index>
constexpr compressed_pair_element<T, Index, true>::compressed_pair_element() noexcept(
    std::is_nothrow_default_constructible_v<T>)
    : T() {}

} // namespace detail

/// @brief
///   Pair type that applies empty base optimization.
/// @note
///   An empty, non-final class element usually does not increase the size of the pair. The relative
///   addresses of the two elements are unspecified.
/// @tparam First
///   Type of the first element.
/// @tparam Second
///   Type of the second element.
template <typename First, typename Second>
class compressed_pair : detail::compressed_pair_element<First, 0>,
                        detail::compressed_pair_element<Second, 1> {
public:
    using first_type             = typename detail::compressed_pair_element<First, 0>::value_type;
    using second_type            = typename detail::compressed_pair_element<Second, 1>::value_type;
    using first_reference        = first_type &;
    using second_reference       = second_type &;
    using first_const_reference  = const first_type &;
    using second_const_reference = const second_type &;

    /// @brief
    ///   Construct the two underlying elements with their default-constructor.
    /// @note
    ///   It is ill-formed to call this @c constructor if neither @c First nor @c Second is
    ///   default-constructible. For trivially-constructible type, the value will be
    ///   zero-initialized.
    constexpr compressed_pair() noexcept(std::is_nothrow_default_constructible_v<First> &&
                                         std::is_nothrow_default_constructible_v<Second>);

    /// @brief
    ///   Construct this @c compressed_pair with the given element values.
    /// @tparam FirstArg
    ///   Type of the argument to construct the first element.
    /// @tparam SecondArg
    ///   Type of the argument to construct the second element.
    /// @param first
    ///   Argument to be used to construct the first element.
    /// @param second
    ///   Argument to be used to construct the second element.
    template <typename FirstArg, typename SecondArg>
        requires(std::constructible_from<First, FirstArg> &&
                 std::constructible_from<Second, SecondArg>)
    constexpr compressed_pair(FirstArg &&first, SecondArg &&second) noexcept(
        std::is_nothrow_constructible_v<First, FirstArg> &&
        std::is_nothrow_constructible_v<Second, SecondArg>)
        : detail::compressed_pair_element<First, 0>(std::forward<FirstArg>(first)),
          detail::compressed_pair_element<Second, 1>(std::forward<SecondArg>(second)) {}

    /// @brief
    ///   Construct the two underlying elements from tuples of arguments.
    /// @tparam Args1
    ///   Types of arguments to be used to construct the first element.
    /// @tparam Args2
    ///   Types of arguments to be used to construct the second element.
    /// @param args1
    ///   Tuple of arguments to be used to construct the first element.
    /// @param args2
    ///   Tuple of arguments to be used to construct the second element.
    template <typename... Args1, typename... Args2>
        requires(std::constructible_from<First, Args1...> &&
                 std::constructible_from<Second, Args2...>)
    constexpr compressed_pair(
        std::piecewise_construct_t,
        std::tuple<Args1...> args1,
        std::tuple<Args2...> args2) noexcept(std::is_nothrow_constructible_v<First, Args1...> &&
                                             std::is_nothrow_constructible_v<Second, Args2...>)
        : detail::compressed_pair_element<First, 0>(std::piecewise_construct,
                                                    std::move(args1),
                                                    std::make_index_sequence<sizeof...(Args1)>()),
          detail::compressed_pair_element<Second, 1>(std::piecewise_construct,
                                                     std::move(args2),
                                                     std::make_index_sequence<sizeof...(Args2)>()) {
    }

    /// @brief
    ///   Get the first element.
    /// @return
    ///   Reference to the first element.
    [[nodiscard]] first_reference first() noexcept {
        return this->detail::compressed_pair_element<First, 0>::get();
    }

    /// @brief
    ///   Get the first element.
    /// @return
    ///   Reference to the first element.
    [[nodiscard]] first_const_reference first() const noexcept {
        return this->detail::compressed_pair_element<First, 0>::get();
    }

    /// @brief
    ///   Get the second element.
    /// @return
    ///   Reference to the second element.
    [[nodiscard]] second_reference second() noexcept {
        return this->detail::compressed_pair_element<Second, 1>::get();
    }

    /// @brief
    ///   Get the second element.
    /// @return
    ///   Reference to the second element.
    [[nodiscard]] second_const_reference second() const noexcept {
        return this->detail::compressed_pair_element<Second, 1>::get();
    }
};

template <typename First, typename Second>
constexpr compressed_pair<First, Second>::compressed_pair() noexcept(
    std::is_nothrow_default_constructible_v<First> &&
    std::is_nothrow_default_constructible_v<Second>)
    : detail::compressed_pair_element<First, 0>(),
      detail::compressed_pair_element<Second, 1>() {}

/// @brief
///   Deducing guide for @c compressed_pair to make it constructible like @c std::make_pair .
template <typename First, typename Second>
compressed_pair(First &&, Second &&)
    -> compressed_pair<std::unwrap_ref_decay_t<First>, std::unwrap_ref_decay_t<Second>>;

/// @brief
///   Create a @c compressed_pair for the two elements, following @c std::make_pair .
/// @tparam First
///   Type of the first argument.
/// @tparam Second
///   Type of the second argument.
/// @param first
///   Argument used to construct the first element.
/// @param second
///   Argument used to construct the second element.
/// @return
///   A @c compressed_pair whose elements are initialized from @p first and @p second.
template <typename First, typename Second>
compressed_pair<std::unwrap_ref_decay_t<First>, std::unwrap_ref_decay_t<Second>>
make_compressed_pair(First &&first, Second &&second) noexcept(
    std::is_nothrow_constructible_v<std::unwrap_ref_decay_t<First>, First> &&
    std::is_nothrow_constructible_v<std::unwrap_ref_decay_t<Second>, Second>) {
    return compressed_pair<std::unwrap_ref_decay_t<First>, std::unwrap_ref_decay_t<Second>>(
        std::forward<First>(first), std::forward<Second>(second));
}

} // namespace ciallo
