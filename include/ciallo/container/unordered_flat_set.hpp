#pragma once

#include "ciallo/container/compressed_pair.hpp"
#include "ciallo/container/detail/swiss_table.hpp"
#include "ciallo/utility/scope_guard.hpp"

#include <cstring>
#include <functional>
#include <stdexcept>
#include <utility>

namespace ciallo {

/// @brief
///   Hash set that stores elements using sequence-probing hash table.
template <typename Key,
          typename Hash      = std::hash<Key>,
          typename KeyEqual  = std::equal_to<>,
          typename Allocator = std::allocator<Key>>
class unordered_flat_set {
public:
    using key_type        = Key;
    using value_type      = Key;
    using allocator_type  = Allocator;
    using size_type       = typename std::allocator_traits<allocator_type>::size_type;
    using difference_type = typename std::allocator_traits<allocator_type>::difference_type;
    using hasher          = Hash;
    using key_equal       = KeyEqual;
    using reference       = value_type &;
    using const_reference = const value_type &;
    using pointer         = typename std::allocator_traits<allocator_type>::pointer;
    using const_pointer   = typename std::allocator_traits<allocator_type>::const_pointer;

    /// @brief
    ///   Iterator for @c unordered_flat_set .
    class iterator {
    public:
        using value_type        = unordered_flat_set::value_type;
        using difference_type   = unordered_flat_set::difference_type;
        using pointer           = unordered_flat_set::const_pointer;
        using reference         = unordered_flat_set::const_reference;
        using iterator_category = std::forward_iterator_tag;
        using iterator_concept  = std::forward_iterator_tag;

        /// @brief
        ///   Create a null iterator.
        constexpr iterator() noexcept : m_state(nullptr), m_value(nullptr) {}

        /// @brief
        ///   Access the underlying value. It is undefined behavior if this @c iterator does not
        ///   point to a valid value.
        /// @return
        ///   Reference to the underlying value.
        [[nodiscard]] constexpr reference operator*() const noexcept {
            return *m_value;
        }

        /// @brief
        ///   Access the underlying value like a pointer.
        /// @return
        ///   Pointer to the underlying value.
        [[nodiscard]] constexpr pointer operator->() const noexcept {
            return m_value;
        }

        /// @brief
        ///   Move to next value in current @c unordered_flat_set .
        /// @return
        ///   Reference to this @c iterator after movement.
        constexpr iterator &operator++() noexcept {
            ++m_state;
            ++m_value;
            // We iterate over the state array one by one instead of using group because this should
            // be faster if the unordered_flat_set is dense.
            while (*m_state < detail::swiss_table_sentinel) {
                ++m_state;
                ++m_value;
            }
            return *this;
        }

        /// @brief
        ///   Move to next value in current @c unordered_flat_set .
        /// @return
        ///   Iterator to the value before movement.
        constexpr iterator operator++(int) noexcept {
            iterator temp(*this);
            ++(*this);
            return temp;
        }

        /// @brief
        ///   Checks if the two iterators are equal.
        /// @param a
        ///   The first iterator to be compared.
        /// @param b
        ///   The second iterator to be compared.
        /// @return
        ///   Return @c true if @p a is the same as @c b . Otherwise, return @c false .
        [[nodiscard]] friend constexpr bool operator==(iterator a, iterator b) noexcept {
            return a.m_state == b.m_state;
        }

        friend class unordered_flat_set;
        friend class const_iterator;

    private:
        /// @brief
        ///   For internal usage. Create an iterator with the specified state and value.
        /// @param state
        ///   Pointer to the state for current element.
        /// @param value
        ///   Pointer to the value for current element.
        constexpr iterator(std::int8_t *state, value_type *value) noexcept
            : m_state(state),
              m_value(value) {}

    private:
        std::int8_t *m_state;
        value_type *m_value;
    };

    /// @brief
    ///   Constant iterator for @c unordered_flat_set .
    class const_iterator {
    public:
        using value_type        = unordered_flat_set::value_type;
        using difference_type   = unordered_flat_set::difference_type;
        using pointer           = unordered_flat_set::const_pointer;
        using reference         = unordered_flat_set::const_reference;
        using iterator_category = std::forward_iterator_tag;
        using iterator_concept  = std::forward_iterator_tag;

        /// @brief
        ///   Create a null iterator.
        constexpr const_iterator() noexcept : m_state(nullptr), m_value(nullptr) {}

        /// @brief
        ///   Allow implicit cast from @c iterator .
        /// @param iter
        ///   The @c iterator to be copied from.
        constexpr const_iterator(iterator iter) noexcept
            : m_state(iter.m_state),
              m_value(iter.m_value) {}

        /// @brief
        ///   Access the underlying value. It is undefined behavior if this @c iterator does not
        ///   point to a valid value.
        /// @return
        ///   Reference to the underlying value.
        [[nodiscard]] constexpr reference operator*() const noexcept {
            return *m_value;
        }

        /// @brief
        ///   Access the underlying value like a pointer.
        /// @return
        ///   Pointer to the underlying value.
        [[nodiscard]] constexpr pointer operator->() const noexcept {
            return m_value;
        }

        /// @brief
        ///   Move to next value in current @c unordered_flat_set .
        /// @return
        ///   Reference to this @c iterator after movement.
        constexpr const_iterator &operator++() noexcept {
            ++m_state;
            ++m_value;
            while (*m_state < detail::swiss_table_sentinel) {
                ++m_state;
                ++m_value;
            }
            return *this;
        }

        /// @brief
        ///   Move to next value in current @c unordered_flat_set .
        /// @return
        ///   Iterator to the value before movement.
        constexpr const_iterator operator++(int) noexcept {
            const_iterator temp(*this);
            ++(*this);
            return temp;
        }

        /// @brief
        ///   Checks if the two iterators are equal.
        /// @param a
        ///   The first iterator to be compared.
        /// @param b
        ///   The second iterator to be compared.
        /// @return
        ///   Return @c true if @p a is the same as @c b . Otherwise, return @c false .
        [[nodiscard]] friend constexpr bool operator==(const_iterator a,
                                                       const_iterator b) noexcept {
            return a.m_state == b.m_state;
        }

        friend class unordered_flat_set;

    private:
        /// @brief
        ///   For internal usage. Create an iterator with the specified state and value.
        /// @param state
        ///   Pointer to the state for current element.
        /// @param value
        ///   Pointer to the value for current element.
        constexpr const_iterator(std::int8_t *state, value_type *value) noexcept
            : m_state(state),
              m_value(value) {}

    private:
        std::int8_t *m_state;
        value_type *m_value;
    };

private:
    using alloc_traits         = std::allocator_traits<allocator_type>;
    using value_storage_type   = detail::swiss_table_alignment_t<value_type>;
    using storage_alloc        = typename alloc_traits::template rebind_alloc<value_storage_type>;
    using storage_alloc_traits = std::allocator_traits<storage_alloc>;

    static_assert(alignof(value_storage_type) == alignof(value_type));
    static_assert(sizeof(value_type) % alignof(value_type) == 0);

    /// @brief
    ///   Destructor for @c unordered_flat_set . Destructor is implemented as a struct because this
    ///   is also used as exception guard.
    struct destructor {
        unordered_flat_set &self;
        size_type capacity;
        size_type size;
        void *backing_array;

        /// @brief
        ///   Create this @c destructor for the specified @c unordered_flat_set .
        /// @param set
        ///   The @c unordered_flat_set to be destroyed.
        destructor(unordered_flat_set &set) noexcept;

        /// @brief
        ///   Create this @c destructor for the specified backing array and array size.
        /// @param set
        ///   Current @c unordered_flat_set . This is used to acquire allocators.
        /// @param backing
        ///   Pointer to the backing array to be guarded.
        /// @param capacity
        ///   Current capacity for the backing array.
        /// @param size
        ///   Current number of elements stored in @p backing .
        destructor(unordered_flat_set &set,
                   void *backing,
                   size_type capacity,
                   size_type size) noexcept;

        /// @brief
        ///   Destroy the stored @c unordered_flat_set .
        void operator()();
    };

public:
    /// @brief
    ///   Create an empty @c unordered_flat_set .
    unordered_flat_set();

    /// @brief
    ///   Create this @c unordered_flat_set with the specified initial bucket count, hasher, key
    ///   equal comparer and allocator.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @param bucket_count
    ///   Expected initial number of buckets. The actual bucket count might be greater than this
    ///   value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param equal
    ///   Key equality comparer to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count exceeds @c max_size() .
    explicit unordered_flat_set(size_type bucket_count,
                                const hasher &hash          = hasher(),
                                const key_equal &equal      = key_equal(),
                                const allocator_type &alloc = allocator_type());

    /// @brief
    ///   Create this @c unordered_flat_set with the specified initial bucket count and allocator.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @param bucket_count
    ///   Expected initial number of buckets. The actual bucket count might be greater than this
    ///   value.
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count exceeds @c max_size() .
    unordered_flat_set(size_type bucket_count, const allocator_type &alloc);

    /// @brief
    ///   Create this @c unordered_flat_set with the specified initial bucket count, hasher and
    ///   allocator.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @param bucket_count
    ///   Expected initial number of buckets. The actual bucket count might be greater than this
    ///   value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count exceeds @c max_size() .
    unordered_flat_set(size_type bucket_count, const hasher &hash, const allocator_type &alloc);

    /// @brief
    ///   Create an empty @c unordered_flat_set with the specified allocator.
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    explicit unordered_flat_set(const allocator_type &alloc);

    /// @brief
    ///   Create this @c unordered_flat_set with the specified range of elements.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @tparam ForwardIt
    ///   Type of the iterators that represents all elements to be used to initialize this
    ///   @c unordered_flat_set .
    /// @param first
    ///   Iterator to the first element to be inserted into this @c unordered_flat_set .
    /// @param last
    ///   Iterator to the placeholder after the last element to be inserted.
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param equal
    ///   Key equality comparer to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    template <std::forward_iterator ForwardIt>
    unordered_flat_set(ForwardIt first,
                       ForwardIt last,
                       size_type bucket_count      = 0,
                       const hasher &hash          = hasher(),
                       const key_equal &equal      = key_equal(),
                       const allocator_type &alloc = allocator_type());

    /// @brief
    ///   Create this @c unordered_flat_set with the specified range of elements.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @tparam ForwardIt
    ///   Type of the iterators that represents all elements to be used to initialize this
    ///   @c unordered_flat_set .
    /// @param first
    ///   Iterator to the first element to be inserted into this @c unordered_flat_set .
    /// @param last
    ///   Iterator to the placeholder after the last element to be inserted.
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    template <std::forward_iterator ForwardIt>
    unordered_flat_set(ForwardIt first,
                       ForwardIt last,
                       size_type bucket_count,
                       const allocator_type &alloc);

    /// @brief
    ///   Create this @c unordered_flat_set with the specified range of elements.
    /// @note
    ///   This constructor provide strong exception guarantee.
    /// @tparam ForwardIt
    ///   Type of the iterators that represents all elements to be used to initialize this
    ///   @c unordered_flat_set .
    /// @param first
    ///   Iterator to the first element to be inserted into this @c unordered_flat_set .
    /// @param last
    ///   Iterator to the placeholder after the last element to be inserted.
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    template <std::forward_iterator ForwardIt>
    unordered_flat_set(ForwardIt first,
                       ForwardIt last,
                       size_type bucket_count,
                       const hasher &hash,
                       const allocator_type &alloc);

    /// @brief
    ///   Create this @c unordered_flat_set from an initializer list.
    /// @param list
    ///   The initializer list that contains elements to initialize this @c unordered_flat_set .
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param equal
    ///   Key equality comparer to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    unordered_flat_set(std::initializer_list<value_type> list,
                       size_type bucket_count      = 0,
                       const hasher &hash          = hasher(),
                       const key_equal &equal      = key_equal(),
                       const allocator_type &alloc = allocator_type());

    /// @brief
    ///   Create this @c unordered_flat_set from an initializer list.
    /// @param list
    ///   The initializer list that contains elements to initialize this @c unordered_flat_set .
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    unordered_flat_set(std::initializer_list<value_type> list,
                       size_type bucket_count,
                       const allocator_type &alloc);

    /// @brief
    ///   Create this @c unordered_flat_set from an initializer list.
    /// @param list
    ///   The initializer list that contains elements to initialize this @c unordered_flat_set .
    /// @param bucket_count
    ///   Initial number of buckets for this @c unordered_flat_set . The actual bucket size might be
    ///   greater than this value.
    /// @param hash
    ///   Hasher to be used for this @c unordered_flat_set .
    /// @param alloc
    ///   Allocator to be used to allocate memory for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p bucket_count or number of elements to be inserted exceeds @c max_size() .
    unordered_flat_set(std::initializer_list<value_type> list,
                       size_type bucket_count,
                       const hasher &hash,
                       const allocator_type &alloc);

    /// @brief
    ///   Copy constructor for @c unordered_flat_set .
    /// @param other
    ///   The @c unordered_flat_set to be copied from.
    unordered_flat_set(const unordered_flat_set &other);

    /// @brief
    ///   Move constructor for @c unordered_flat_set .
    /// @param other
    ///   The @c unordered_flat_set to be moved from. The moved @c unordered_flat_set will be in a
    ///   valid but unspecified state.
    unordered_flat_set(unordered_flat_set &&other) noexcept;

    /// @brief
    ///   Destroy this @c unordered_flat_set .
    ~unordered_flat_set();

    /// @brief
    ///   Copy assignment for @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception guarantee.
    /// @param other
    ///   The @c unordered_flat_set to be copied from.
    /// @return
    ///   Reference to this @c unordered_flat_set .
    unordered_flat_set &operator=(const unordered_flat_set &other);

    /// @brief
    ///   Move assignment for @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception guarantee.
    /// @param other
    ///   The @c unordered_flat_set to be moved from. The moved @c unordered_flat_set will be in a
    ///   valid but unspecified state.
    /// @return
    ///   Reference to this @c unordered_flat_set .
    unordered_flat_set &operator=(unordered_flat_set &&other) noexcept(
        alloc_traits::is_always_equal::value || std::is_nothrow_move_assignable_v<allocator_type>);

    /// @brief
    ///   Assign an initializer list of values to this @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception guarantee.
    /// @param list
    ///   The initializer list to be assigned.
    /// @return
    ///   Reference to this @c unordered_flat_set .
    unordered_flat_set &operator=(std::initializer_list<value_type> list);

    /// @brief
    ///   Get the allocator used by this @c unordered_flat_set .
    /// @return
    ///   A copy of allocator that is used by this @c unordered_flat_set .
    [[nodiscard]] allocator_type get_allocator() const noexcept {
        return m_states.second();
    }

    /// @brief
    ///   Get iterator to the first value in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the first value in this @c unordered_flat_set .
    [[nodiscard]] iterator begin() noexcept;

    /// @brief
    ///   Get iterator to the first value in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the first value in this @c unordered_flat_set .
    [[nodiscard]] const_iterator begin() const noexcept;

    /// @brief
    ///   Get iterator to the first value in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the first value in this @c unordered_flat_set .
    [[nodiscard]] const_iterator cbegin() const noexcept {
        return begin();
    }

    /// @brief
    ///   Get iterator to the placeholder after the last element in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the placeholder after the last element in this @c unordered_flat_set .
    [[nodiscard]] iterator end() noexcept {
        size_type offset = m_capacity.first();
        return iterator(m_states.first() + offset, m_values.first() + offset);
    }

    /// @brief
    ///   Get iterator to the placeholder after the last element in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the placeholder after the last element in this @c unordered_flat_set .
    [[nodiscard]] const_iterator end() const noexcept {
        size_type offset = m_capacity.first();
        return const_iterator(m_states.first() + offset, m_values.first() + offset);
    }

    /// @brief
    ///   Get iterator to the placeholder after the last element in this @c unordered_flat_set .
    /// @return
    ///   Iterator to the placeholder after the last element in this @c unordered_flat_set .
    [[nodiscard]] const_iterator cend() const noexcept {
        return end();
    }

    /// @brief
    ///   Checks if this @c unordered_flat_set is empty.
    /// @return
    ///   Return @c true if this @c unordered_flat_set is empty. Otherwise, return @c false .
    [[nodiscard]] bool empty() const noexcept {
        return m_size.first() == 0;
    }

    /// @brief
    ///   Get number of elements stored in this @c unordered_flat_set .
    /// @return
    ///   Number of elements stored in this @c unordered_flat_set .
    [[nodiscard]] size_type size() const noexcept {
        return m_size.first();
    }

    /// @brief
    ///   Get maximum number of elements that could be allocated by this @c unordered_flat_set .
    /// @return
    ///   Maximum number of elements that could be allocated by this @c unordered_flat_set .
    [[nodiscard]] size_type max_size() const noexcept {
        return (std::min<size_type>)(alloc_traits::max_size(m_states.second()),
                                     (std::numeric_limits<difference_type>::max)());
    }

    /// @brief
    ///   Erase all elements from this @c unordered_flat_set .
    void clear() noexcept;

    /// @brief
    ///   Try to insert a value into this @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param value
    ///   The value to be inserted.
    /// @return
    ///   A pair that contains an iterator to the inserted element, and a boolean value that
    ///   indicates whether the insertion is successful. The returned iterator points to the
    ///   existing value in this @c unordered_flat_set that matches @p value if insert failed.
    std::pair<iterator, bool> insert(const value_type &value);

    /// @brief
    ///   Try to insert a value into this @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param value
    ///   The value to be inserted.
    /// @return
    ///   A pair that contains an iterator to the inserted element, and a boolean value that
    ///   indicates whether the insertion is successful. The returned iterator points to the
    ///   existing value in this @c unordered_flat_set that matches @p value if insert failed.
    std::pair<iterator, bool> insert(value_type &&value);

    /// @brief
    ///   Try to insert a value into this @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param key
    ///   The value to be inserted.
    /// @return
    ///   A pair that contains an iterator to the inserted element, and a boolean value that
    ///   indicates whether the insertion is successful. The returned iterator points to the
    ///   existing value in this @c unordered_flat_set that matches @p value if insert failed.
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            requires std::constructible_from<Key, K>;
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    std::pair<iterator, bool> insert(K &&key);

    /// @brief
    ///   Try to insert a range of elements into this @c unordered_flat_set .
    /// @tparam InputIt
    ///   Type of iterator that represents the range of elements.
    /// @param first
    ///   Iterator to the first element to be inserted.
    /// @param last
    ///   Iterator to the placeholder after the last element to be inserted.
    template <std::input_iterator InputIt>
    void insert(InputIt first, InputIt last);

    /// @brief
    ///   Insert a list of values into this @c unordered_flat_set .
    /// @param list
    ///   An initializer list that represents values to be inserted.
    void insert(std::initializer_list<value_type> list);

    /// @brief
    ///   Try to emplace a value into this @c unordered_flat_set .
    /// @tparam Args
    ///   Types of arguments to be used to construct the new value.
    /// @param args
    ///   Arguments to be used to construct the new value.
    /// @return
    ///   A pair that contains an iterator to the inserted element, and a boolean value that
    ///   indicates whether the insertion is successful. The returned iterator points to the
    ///   existing value in this @c unordered_flat_set that matches @p value if insert failed.
    template <typename... Args>
        requires(std::constructible_from<value_type, Args...>)
    std::pair<iterator, bool> emplace(Args &&...args) {
        return insert(value_type(std::forward<Args>(args)...));
    }

    /// @brief
    ///   Erase the element at the specified position.
    ///
    ///   This method does not return iterator to next elemenet because it is relatively slow to
    ///   find next element.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param position
    ///   Iterator to the element to be erased.
    void erase(iterator position);

    /// @brief
    ///   Erase the element at the specified position.
    ///
    ///   This method does not return iterator to next elemenet because it is relatively slow to
    ///   find next element.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param position
    ///   Iterator to the element to be erased.
    void erase(const_iterator position);

    /// @brief
    ///   Erase all elements in the specified range.
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param first
    ///   Iterator to the first element to be erased.
    /// @param last
    ///   Iterator to the placeholder after the last element to be erased.
    /// @return
    ///   Iterator to the element after the last element that was erased.
    iterator erase(const_iterator first, const_iterator last);

    /// @brief
    ///   Erase the value that matches the specified key.
    /// @param key
    ///   The key to be erased in this @c unordered_flat_set .
    /// @return
    ///   Number of elements erased. The value is guaranteed to be always 0 or 1.
    size_type erase(const key_type &key);

    /// @brief
    ///   Erase the value that matches the specified key.
    /// @param key
    ///   The key to be erased in this @c unordered_flat_set .
    /// @return
    ///   Number of elements erased. The value is guaranteed to be always 0 or 1.
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    size_type erase(K &&key);

    /// @brief
    ///   Swap contents of this @c unordered_flat_set with another one.
    /// @param other
    ///   The @c unordered_flat_set object to swap with.
    void swap(unordered_flat_set &other) noexcept(alloc_traits::is_always_equal::value &&
                                                  std::is_nothrow_swappable_v<hasher> &&
                                                  std::is_nothrow_swappable_v<key_equal>);

    /// @brief
    ///   Count number of elements that matches the specified key in this @c unordered_flat_set .
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Number of elements that matches @p key in this @c unordered_flat_set . The value is always
    ///   0 or 1.
    [[nodiscard]] size_type count(const key_type &key) const;

    /// @brief
    ///   Count number of elements that matches the specified key in this @c unordered_flat_set .
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @tparam K
    ///   Type of the key to search for.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Number of elements that matches @p key in this @c unordered_flat_set . The value is always
    ///   0 or 1.
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    [[nodiscard]] size_type count(const K &key) const;

    /// @brief
    ///   Find the element that matches the specified key.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Iterator to the element that matches @p key if found. Return @c end() if no such element
    ///   found in this @c unordered_flat_set .
    [[nodiscard]] iterator find(const key_type &key);

    /// @brief
    ///   Find the element that matches the specified key.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Iterator to the element that matches @p key if found. Return @c end() if no such element
    ///   found in this @c unordered_flat_set .
    [[nodiscard]] const_iterator find(const key_type &key) const;

    /// @brief
    ///   Find the element that matches the specified key.
    /// @tparam K
    ///   Type of the key to search for.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Iterator to the element that matches @p key if found. Return @c end() if no such element
    ///   found in this @c unordered_flat_set .
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    [[nodiscard]] iterator find(const K &key);

    /// @brief
    ///   Find the element that matches the specified key.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @tparam K
    ///   Type of the key to search for.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Iterator to the element that matches @p key if found. Return @c end() if no such element
    ///   found in this @c unordered_flat_set .
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    [[nodiscard]] const_iterator find(const K &key) const;

    /// @brief
    ///   Checks if this @c unordered_flat_set contains any element that matches the specified key.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Return @c true if there is any element in this @c unordered_flat_set that matches @p key .
    ///   Otherwise, return @c false .
    [[nodiscard]] bool contains(const key_type &key) const {
        return count(key) != 0;
    }

    /// @brief
    ///   Checks if this @c unordered_flat_set contains any element that matches the specified key.
    /// @note
    ///   This method provide strong exception safety guarantee.
    /// @tparam K
    ///   Type of the key to search for.
    /// @param key
    ///   The key to search for.
    /// @return
    ///   Return @c true if there is any element in this @c unordered_flat_set that matches @p key .
    ///   Otherwise, return @c false .
    template <typename K>
        requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
            typename Hash::is_transparent;
            typename KeyEqual::is_transparent;
            { hash(key) } -> std::convertible_to<std::size_t>;
            { equal(value, key) } -> std::convertible_to<bool>;
        }
    [[nodiscard]] bool contains(const K &key) const {
        return count<K>(key) != 0;
    }

    /// @brief
    ///   Get current load factor of this @c unordered_flat_set .
    /// @return
    ///   Current load factor of this @c unordered_flat_set .
    [[nodiscard]] float load_factor() const noexcept {
        if (m_capacity.first() == 0) {
            return 0;
        }
        return static_cast<float>(static_cast<double>(m_size.first()) / (m_capacity.first() + 1));
    }

    /// @brief
    ///   Get maximum load factor of this @c unordered_flat_set .
    /// @note
    ///   @c unordered_flat_set does not support manually setting max load factor. The max load
    ///   factor is always 7/8.
    /// @return
    ///   Maximum load factor of this @c unordered_flat_set . The return value is always 7/8.
    [[nodiscard]] float max_load_factor() const noexcept {
        return 0.875f;
    }

    /// @brief
    ///   Set maximum load factor for this @c unordered_flat_set .
    /// @note
    ///   @c unordered_flat_set does not support setting max load factor and this method is no-op.
    [[deprecated("unordered_flat_set doesn\'t support setting max load factor")]]
    void max_load_factor(float) noexcept {}

    /// @brief
    ///   Change number of buckets for this @c unordered_flat_set . This method does nothing if
    ///   @p count is less than or equal to current bucket count.
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param count
    ///   Expected number of buckets to be used for this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p count is greater than `max_size()`.
    void rehash(size_type count);

    /// @brief
    ///   Reserve memory for at least @p count elements for this @c unordered_flat_set .
    /// @note
    ///   This method provide weak exception safety guarantee.
    /// @param count
    ///   Number of elements to be stored in this @c unordered_flat_set .
    /// @throw std::length_error
    ///   Thrown if @p count is greater than `max_size()`.
    void reserve(size_type count);

    /// @brief
    ///   Get hash function of this @c unordered_flat_set .
    /// @return
    ///   Hash function of this @c unordered_flat_set .
    [[nodiscard]] hasher hash_function() const {
        return m_capacity.second();
    }

    /// @brief
    ///   Get the key equal comparer of this @c unordered_flat_set .
    /// @return
    ///   Key equal comparer of this @c unordered_flat_set .
    [[nodiscard]] key_equal key_eq() const {
        return m_size.second();
    }

private:
    /// @brief
    ///   For internal usage. Actual do rehash.
    /// @param count
    ///   Number of new buckets. This value must be 2^N - 1.
    void rehash_impl(size_type count);

private:
    compressed_pair<size_type, hasher> m_capacity;
    compressed_pair<size_type, key_equal> m_size;
    compressed_pair<std::int8_t *, allocator_type> m_states;
    compressed_pair<value_type *, storage_alloc> m_values;
};

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set::destructor::destructor(
    unordered_flat_set &set) noexcept
    : self(set),
      capacity(set.m_capacity.first()),
      size(set.m_size.first()),
      backing_array(set.m_states.first()) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set::destructor::destructor(
    unordered_flat_set &set,
    void *backing,
    size_type capacity,
    size_type size) noexcept
    : self(set),
      capacity(capacity),
      size(size),
      backing_array(backing) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set::destructor::
operator()() {
    if (capacity == 0) {
        return;
    }

    // Destroy all elements.
    const size_type value_offset = detail::swiss_table_value_offset<value_type>(capacity);
    const size_type block_count  = detail::swiss_table_block_count<value_type>(capacity);

    auto *backing = static_cast<value_storage_type *>(backing_array);
    auto *states  = static_cast<std::int8_t *>(backing_array);
    auto *values  = reinterpret_cast<value_type *>(backing + value_offset);
    while (size != 0) {
        detail::swiss_table_control_group group(states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= (mask - 1)) {
            alloc_traits::destroy(self.m_states.second(), values + std::countr_zero(mask));
            --size;
        }
        states += detail::swiss_table_group_size;
        values += detail::swiss_table_group_size;
    }

    // Deallocate memory.
    storage_alloc_traits::deallocate(self.m_values.second(), backing, block_count);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set()
    : m_capacity(),
      m_size(),
      m_states(),
      m_values(nullptr, m_states.second()) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(size_type bucket_count,
                                                                       const hasher &hash,
                                                                       const key_equal &equal,
                                                                       const allocator_type &alloc)
    : m_capacity(0, hash),
      m_size(0, equal),
      m_states(nullptr, alloc),
      m_values(nullptr, alloc) {
    if (bucket_count == 0) [[unlikely]] {
        return;
    }

    bucket_count = detail::swiss_table_normalize_capacity(bucket_count);
    if (bucket_count > max_size()) [[unlikely]] {
        throw std::length_error("ciallo::unordered_flat_set");
    }

    const size_type value_offset = detail::swiss_table_value_offset<value_type>(bucket_count);
    const size_type block_count  = detail::swiss_table_block_count<value_type>(bucket_count);

    value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

    auto *states = reinterpret_cast<std::int8_t *>(memory);
    std::memset(states, detail::swiss_table_empty, bucket_count + detail::swiss_table_group_size);
    states[bucket_count] = detail::swiss_table_sentinel;

    m_capacity.first() = bucket_count;
    m_states.first()   = states;
    m_values.first()   = reinterpret_cast<value_type *>(memory + value_offset);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(size_type bucket_count,
                                                                       const allocator_type &alloc)
    : unordered_flat_set(bucket_count, hasher(), key_equal(), alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(size_type bucket_count,
                                                                       const hasher &hash,
                                                                       const allocator_type &alloc)
    : unordered_flat_set(bucket_count, hash, key_equal(), alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(const allocator_type &alloc)
    : m_capacity(),
      m_size(),
      m_states(nullptr, alloc),
      m_values(nullptr, alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <std::forward_iterator ForwardIt>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(ForwardIt first,
                                                                       ForwardIt last,
                                                                       size_type bucket_count,
                                                                       const hasher &hash,
                                                                       const key_equal &equal,
                                                                       const allocator_type &alloc)
    : m_capacity(0, hash),
      m_size(0, equal),
      m_states(nullptr, alloc),
      m_values(nullptr, alloc) {
    auto count   = static_cast<std::size_t>(std::distance(first, last));
    bucket_count = detail::swiss_table_size_to_capacity((std::max<size_type>)(bucket_count, count));
    if (bucket_count > max_size()) [[unlikely]] {
        throw std::length_error("ciallo::unordered_flat_set");
    }

    // Allocate memory.
    const size_type value_offset = detail::swiss_table_value_offset<value_type>(bucket_count);
    const size_type block_count  = detail::swiss_table_block_count<value_type>(bucket_count);

    value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

    auto *states = reinterpret_cast<std::int8_t *>(memory);
    std::memset(states, detail::swiss_table_empty, bucket_count + detail::swiss_table_group_size);
    states[bucket_count] = detail::swiss_table_sentinel;

    // Construct values.
    destructor dtor(*this, memory, bucket_count, 0);
    scope_guard<destructor &> exception_guard(dtor);

    auto *values = reinterpret_cast<value_type *>(memory + value_offset);
    for (; first != last; ++first) {
        std::size_t h  = m_capacity.second()(*first);
        std::size_t h1 = (h >> 7);
        auto h2        = static_cast<std::int8_t>(h & 0x7F);

        detail::swiss_table_probe_sequence probe(h1, bucket_count);
        const size_type max_probe_time = (bucket_count + 1) / detail::swiss_table_group_size;
        for (size_type i = 0; i < max_probe_time; ++i) {
            detail::swiss_table_control_group group(states + probe.offset());
            for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
                auto index  = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
                auto &value = values[index];
                if (m_size.second()(value, *first)) {
                    goto probe_done;
                }
            }

            if (group.match_empty() != 0 || i + 1 == max_probe_time) {
                auto offset = detail::swiss_table_find_first_non_full(states, h1, bucket_count);
                alloc_traits::construct(m_states.second(), values + offset, *first);
                detail::swiss_table_set_state(states, bucket_count, offset, h2);
                ++dtor.size;
                break;
            }

            probe.next();
        }
    probe_done:;
    }

    m_capacity.first() = bucket_count;
    m_size.first()     = dtor.size;
    m_states.first()   = states;
    m_values.first()   = values;

    exception_guard.dismiss();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <std::forward_iterator ForwardIt>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(ForwardIt first,
                                                                       ForwardIt last,
                                                                       size_type bucket_count,
                                                                       const allocator_type &alloc)
    : unordered_flat_set(static_cast<ForwardIt &&>(first),
                         static_cast<ForwardIt &&>(last),
                         bucket_count,
                         hasher(),
                         key_equal(),
                         alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <std::forward_iterator ForwardIt>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(ForwardIt first,
                                                                       ForwardIt last,
                                                                       size_type bucket_count,
                                                                       const hasher &hash,
                                                                       const allocator_type &alloc)
    : unordered_flat_set(static_cast<ForwardIt &&>(first),
                         static_cast<ForwardIt &&>(last),
                         bucket_count,
                         hash,
                         key_equal(),
                         alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(
    std::initializer_list<value_type> list,
    size_type bucket_count,
    const hasher &hash,
    const key_equal &equal,
    const allocator_type &alloc)
    : unordered_flat_set(list.begin(), list.end(), bucket_count, hash, equal, alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(
    std::initializer_list<value_type> list,
    size_type bucket_count,
    const allocator_type &alloc)
    : unordered_flat_set(list, bucket_count, hasher(), key_equal(), alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(
    std::initializer_list<value_type> list,
    size_type bucket_count,
    const hasher &hash,
    const allocator_type &alloc)
    : unordered_flat_set(list, bucket_count, hash, key_equal(), alloc) {}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(
    const unordered_flat_set &other)
    : m_capacity(0, other.m_capacity.second()),
      m_size(0, other.m_size.second()),
      m_states(nullptr,
               alloc_traits::select_on_container_copy_construction(other.m_states.second())),
      m_values(
          nullptr,
          storage_alloc_traits::select_on_container_copy_construction(other.m_values.second())) {
    const size_type bucket_count = detail::swiss_table_size_to_capacity(other.m_size.first());
    if (bucket_count > max_size()) [[unlikely]] {
        throw std::length_error("ciallo::unordered_flat_set");
    }

    // Allocate memory.
    const size_type value_offset = detail::swiss_table_value_offset<value_type>(bucket_count);
    const size_type block_count  = detail::swiss_table_block_count<value_type>(bucket_count);

    value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

    auto *states = reinterpret_cast<std::int8_t *>(memory);
    std::memset(states, detail::swiss_table_empty, bucket_count + detail::swiss_table_group_size);
    states[bucket_count] = detail::swiss_table_sentinel;

    // Copy values.
    destructor dtor(*this, memory, bucket_count, 0);
    scope_guard<destructor &> exception_guard(dtor);

    auto *values = reinterpret_cast<value_type *>(memory + value_offset);

    size_type remaining      = other.m_size.first();
    std::int8_t *from_states = other.m_states.first();
    value_type *from_values  = other.m_values.first();

    while (remaining != 0) {
        detail::swiss_table_control_group group(from_states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= mask - 1) {
            const value_type &value = from_values[std::countr_zero(mask)];

            std::size_t hash = m_capacity.second()(value);
            std::size_t h1   = (hash >> 7);
            auto h2          = static_cast<std::int8_t>(hash & 0x7F);

            std::size_t offset = detail::swiss_table_find_first_non_full(states, h1, bucket_count);
            alloc_traits::construct(m_states.second(), values + offset, value);
            detail::swiss_table_set_state(states, bucket_count, offset, h2);
            ++dtor.size;
            --remaining;
        }

        from_states += detail::swiss_table_group_size;
        from_values += detail::swiss_table_group_size;
    }

    m_capacity.first() = bucket_count;
    m_size.first()     = dtor.size;
    m_states.first()   = states;
    m_values.first()   = values;

    exception_guard.dismiss();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::unordered_flat_set(
    unordered_flat_set &&other) noexcept
    : m_capacity(other.m_capacity.first(), std::move(other.m_capacity.second())),
      m_size(other.m_size.first(), std::move(other.m_size.second())),
      m_states(other.m_states.first(), std::move(other.m_states.second())),
      m_values(other.m_values.first(), std::move(other.m_values.second())) {
    other.m_capacity.first() = 0;
    other.m_size.first()     = 0;
    other.m_states.first()   = nullptr;
    other.m_values.first()   = nullptr;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::~unordered_flat_set() {
    destructor (*this)();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator> &
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::operator=(const unordered_flat_set &other) {
    if (this == &other) [[unlikely]] {
        return *this;
    }

    if constexpr (std::is_copy_assignable_v<allocator_type> &&
                  alloc_traits::propagate_on_container_copy_assignment::value &&
                  !alloc_traits::is_always_equal::value) {
        if (m_values.second() != other.m_values.second()) {
            destructor (*this)();
            m_capacity.first() = 0;
            m_size.first()     = 0;
            m_states.first()   = nullptr;
            m_values.first()   = nullptr;

            m_states.second() = other.m_states.second();
            m_values.second() = other.m_values.second();
        }
    }

    // Destroy all elements.
    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();
    while (m_size.first() != 0) {
        detail::swiss_table_control_group group(states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= (mask - 1)) {
            alloc_traits::destroy(m_states.second(), values + std::countr_zero(mask));
            --m_size.first();
        }
        states += detail::swiss_table_group_size;
        values += detail::swiss_table_group_size;
    }

    // Allocate memory.
    size_type bucket_count = detail::swiss_table_size_to_capacity(other.m_size.first());
    if (m_capacity.first() < bucket_count) {
        if (m_states.first() != nullptr) {
            // Deallocate memory.
            auto *backing    = reinterpret_cast<value_storage_type *>(m_states.first());
            auto block_count = detail::swiss_table_block_count<value_type>(m_capacity.first());
            storage_alloc_traits::deallocate(m_values.second(), backing, block_count);

            m_capacity.first() = 0;
            m_states.first()   = nullptr;
            m_values.first()   = nullptr;
        }

        std::size_t value_offset   = detail::swiss_table_value_offset<value_type>(bucket_count);
        std::size_t block_count    = detail::swiss_table_block_count<value_type>(bucket_count);
        value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

        m_capacity.first() = bucket_count;
        m_states.first()   = reinterpret_cast<std::int8_t *>(memory);
        m_values.first()   = reinterpret_cast<value_type *>(memory + value_offset);
    } else {
        bucket_count = m_capacity.first();
    }

    states = m_states.first();
    values = m_values.first();
    std::memset(states, detail::swiss_table_empty, bucket_count + detail::swiss_table_group_size);
    states[bucket_count] = detail::swiss_table_sentinel;

    // Copy values.
    m_capacity.second() = other.m_capacity.second();
    m_size.second()     = other.m_size.second();

    size_type remaining      = other.m_size.first();
    std::int8_t *from_states = other.m_states.first();
    value_type *from_values  = other.m_values.first();
    while (remaining != 0) {
        detail::swiss_table_control_group group(from_states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= mask - 1) {
            const value_type &value = from_values[std::countr_zero(mask)];

            std::size_t hash = m_capacity.second()(value);
            std::size_t h1   = (hash >> 7);
            auto h2          = static_cast<std::int8_t>(hash & 0x7F);

            std::size_t offset = detail::swiss_table_find_first_non_full(states, h1, bucket_count);
            alloc_traits::construct(m_states.second(), values + offset, value);
            detail::swiss_table_set_state(states, bucket_count, offset, h2);
            ++m_size.first();
            --remaining;
        }

        from_states += detail::swiss_table_group_size;
        from_values += detail::swiss_table_group_size;
    }

    return *this;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator> &
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::operator=(unordered_flat_set &&other) noexcept(
    alloc_traits::is_always_equal::value || std::is_nothrow_move_assignable_v<allocator_type>) {
    if (this == &other) [[unlikely]] {
        return *this;
    }

    destructor (*this)();

    m_capacity.first() = 0;
    m_size.first()     = 0;
    m_states.first()   = nullptr;
    m_values.first()   = nullptr;

    if (m_values.second() != other.m_values.second()) {
        m_states.second() = std::move(other.m_states.second());
        m_values.second() = std::move(other.m_values.second());
    }

    m_capacity.first() = std::exchange(other.m_capacity.first(), 0);
    m_size.first()     = std::exchange(other.m_size.first(), 0);
    m_states.first()   = std::exchange(other.m_states.first(), nullptr);
    m_values.first()   = std::exchange(other.m_values.first(), nullptr);

    m_capacity.second() = std::move(other.m_capacity.second());
    m_size.second()     = std::move(other.m_size.second());

    return *this;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator> &
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::operator=(
    std::initializer_list<value_type> list) {

    // Destroy all elements.
    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();
    while (m_size.first() != 0) {
        detail::swiss_table_control_group group(states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= (mask - 1)) {
            alloc_traits::destroy(m_states.second(), values + std::countr_zero(mask));
            --m_size.first();
        }
        states += detail::swiss_table_group_size;
        values += detail::swiss_table_group_size;
    }

    // Allocate memory.
    size_type bucket_count = detail::swiss_table_size_to_capacity(list.size());
    if (m_capacity.first() < bucket_count) {
        if (m_states.first() != nullptr) {
            // Deallocate memory.
            auto *backing    = reinterpret_cast<value_storage_type *>(m_states.first());
            auto block_count = detail::swiss_table_block_count<value_type>(m_capacity.first());
            storage_alloc_traits::deallocate(m_values.second(), backing, block_count);

            m_capacity.first() = 0;
            m_states.first()   = nullptr;
            m_values.first()   = nullptr;
        }

        std::size_t value_offset   = detail::swiss_table_value_offset<value_type>(bucket_count);
        std::size_t block_count    = detail::swiss_table_block_count<value_type>(bucket_count);
        value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

        m_capacity.first() = bucket_count;
        m_states.first()   = reinterpret_cast<std::int8_t *>(memory);
        m_values.first()   = reinterpret_cast<value_type *>(memory + value_offset);
    } else {
        bucket_count = m_capacity.first();
    }

    states = m_states.first();
    values = m_values.first();
    std::memset(states, detail::swiss_table_empty, bucket_count + detail::swiss_table_group_size);
    states[bucket_count] = detail::swiss_table_sentinel;

    // Copy values.
    for (const value_type &element : list) {
        std::size_t h  = m_capacity.second()(element);
        std::size_t h1 = (h >> 7);
        auto h2        = static_cast<std::int8_t>(h & 0x7F);

        detail::swiss_table_probe_sequence probe(h1, bucket_count);
        const size_type max_probe_time = (bucket_count + 1) / detail::swiss_table_group_size;
        for (size_type i = 0; i < max_probe_time; ++i) {
            detail::swiss_table_control_group group(states + probe.offset());
            for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
                auto index  = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
                auto &value = values[index];
                if (m_size.second()(value, element)) {
                    goto probe_done;
                }
            }

            if (group.match_empty() != 0 || i + 1 == max_probe_time) {
                auto offset = detail::swiss_table_find_first_non_full(states, h1, bucket_count);
                alloc_traits::construct(m_states.second(), values + offset, element);
                detail::swiss_table_set_state(states, bucket_count, offset, h2);
                ++m_size.first();
                break;
            }

            probe.next();
        }
    probe_done:;
    }

    return *this;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::begin() noexcept {
    if (m_capacity.first() == 0) {
        return iterator();
    }
    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();
    while (*states < detail::swiss_table_sentinel) {
        ++states;
        ++values;
    }
    return iterator(states, values);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::const_iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::begin() const noexcept {
    if (m_capacity.first() == 0) {
        return const_iterator();
    }
    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();
    while (*states < detail::swiss_table_sentinel) {
        ++states;
        ++values;
    }
    return const_iterator(states, values);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::clear() noexcept {
    if (m_capacity.first() == 0) {
        return;
    }

    // Destroy all elements.
    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();
    while (m_size.first() != 0) {
        detail::swiss_table_control_group group(states);
        for (std::uint16_t mask = group.match_full(); mask != 0; mask &= (mask - 1)) {
            alloc_traits::destroy(m_states.second(), values + std::countr_zero(mask));
            --m_size.first();
        }
        states += detail::swiss_table_group_size;
        values += detail::swiss_table_group_size;
    }

    size_type bucket_count = m_capacity.first();
    std::memset(m_states.first(), detail::swiss_table_empty,
                bucket_count + detail::swiss_table_group_size);
    m_states.first()[bucket_count] = detail::swiss_table_sentinel;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
std::pair<typename unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator, bool>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::insert(const value_type &value) {
    if (m_capacity.first() == 0) {
        rehash_impl(0xF);
    }

    const std::size_t hash = m_capacity.second()(value);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, m_capacity.first());

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            std::size_t offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], value)) [[likely]] {
                return std::make_pair(iterator(states + offset, values + offset), false);
            }
        }

        if (auto empty_mask = group.match_empty(); empty_mask != 0 || i + 1 == max_probe_time) {
            if (m_capacity.first() - m_size.first() <= (m_capacity.first() >> 3)) {
                rehash_impl(detail::swiss_table_next_capacity(m_capacity.first()));
                states = m_states.first();
                values = m_values.first();
            } else if (empty_mask == 0 && i + 1 == max_probe_time) {
                rehash_impl(m_capacity.first());
                states = m_states.first();
                values = m_values.first();
            }

            auto offset = detail::swiss_table_find_first_non_full(states, h1, m_capacity.first());
            value_type *dest_value = values + offset;

            alloc_traits::construct(m_states.second(), dest_value, value);
            detail::swiss_table_set_state(states, m_capacity.first(), offset, h2);
            ++m_size.first();

            return std::make_pair(iterator(states + offset, dest_value), true);
        }

        probe.next();
    }

    std::unreachable();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
std::pair<typename unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator, bool>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::insert(value_type &&value) {
    if (m_capacity.first() == 0) {
        rehash_impl(0xF);
    }

    const std::size_t hash = m_capacity.second()(value);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, m_capacity.first());

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            std::size_t offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], value)) [[likely]] {
                return std::make_pair(iterator(states + offset, values + offset), false);
            }
        }

        if (auto empty_mask = group.match_empty(); empty_mask != 0 || i + 1 == max_probe_time) {
            if (m_capacity.first() - m_size.first() <= (m_capacity.first() >> 3)) {
                rehash_impl(detail::swiss_table_next_capacity(m_capacity.first()));
                states = m_states.first();
                values = m_values.first();
            } else if (empty_mask == 0 && i + 1 == max_probe_time) {
                rehash_impl(m_capacity.first());
                states = m_states.first();
                values = m_values.first();
            }

            auto offset = detail::swiss_table_find_first_non_full(states, h1, m_capacity.first());
            value_type *dest_value = values + offset;

            alloc_traits::construct(m_states.second(), dest_value, std::move(value));
            detail::swiss_table_set_state(states, m_capacity.first(), offset, h2);
            ++m_size.first();

            return std::make_pair(iterator(states + offset, dest_value), true);
        }

        probe.next();
    }

    std::unreachable();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
    requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
        requires std::constructible_from<Key, K>;
        typename Hash::is_transparent;
        typename KeyEqual::is_transparent;
        { hash(key) } -> std::convertible_to<std::size_t>;
        { equal(value, key) } -> std::convertible_to<bool>;
    }
std::pair<typename unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator, bool>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::insert(K &&key) {
    if (m_capacity.first() == 0) {
        rehash_impl(0xF);
    }

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, m_capacity.first());

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            std::size_t offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) [[likely]] {
                return std::make_pair(iterator(states + offset, values + offset), false);
            }
        }

        if (auto empty_mask = group.match_empty(); empty_mask != 0 || i + 1 == max_probe_time) {
            if (m_capacity.first() - m_size.first() <= (m_capacity.first() >> 3)) {
                rehash_impl(detail::swiss_table_next_capacity(m_capacity.first()));
                states = m_states.first();
                values = m_values.first();
            } else if (empty_mask == 0 && i + 1 == max_probe_time) {
                rehash_impl(m_capacity.first());
                states = m_states.first();
                values = m_values.first();
            }

            auto offset = detail::swiss_table_find_first_non_full(states, h1, m_capacity.first());
            value_type *dest_value = values + offset;

            alloc_traits::construct(m_states.second(), dest_value, std::forward<K>(key));
            detail::swiss_table_set_state(states, m_capacity.first(), offset, h2);
            ++m_size.first();

            return std::make_pair(iterator(states + offset, dest_value), true);
        }

        probe.next();
    }

    std::unreachable();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <std::input_iterator InputIt>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::insert(InputIt first, InputIt last) {
    for (; first != last; ++first) {
        insert(*first);
    }
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::insert(
    std::initializer_list<value_type> list) {
    for (const auto &value : list) {
        insert(value);
    }
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::erase(iterator position) {
    return erase(const_iterator(position));
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::erase(const_iterator position) {
    // Destroy the element.
    alloc_traits::destroy(m_states.second(), position.m_value);
    --m_size.first();

    // Maintain states.
    size_type capacity  = m_capacity.first();
    std::int8_t *states = m_states.first();
    auto offset         = static_cast<size_type>(position.m_state - states);

    if (capacity <= detail::swiss_table_group_size) {
        detail::swiss_table_set_state(states, capacity, offset, detail::swiss_table_empty);
        return;
    }

    size_type index_before = ((offset - detail::swiss_table_group_size) & capacity);
    auto empty_after       = detail::swiss_table_control_group(position.m_state).match_empty();
    auto empty_before      = detail::swiss_table_control_group(states + index_before).match_empty();

    // Count how many consecutive non-empty slots we have according to position. If number of
    // consecutive non-empty slots is less than a group, then no probe window would be a full group.
    // Thus, we could safely mark it as empty slot instead of deleted slot.
    if (empty_before != 0 && empty_after != 0 &&
        std::countr_zero(empty_after) + std::countl_zero(empty_before) <
            static_cast<int>(detail::swiss_table_group_size)) {
        detail::swiss_table_set_state(states, capacity, offset, detail::swiss_table_empty);
        return;
    }

    detail::swiss_table_set_state(states, capacity, offset, detail::swiss_table_deleted);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::erase(const_iterator first,
                                                          const_iterator last) {
    if (empty()) {
        return end();
    }

    if (first == begin() && last == end()) {
        clear();
        return end();
    }

    for (; first != last; ++first) {
        erase(first);
    }

    return iterator(last.m_state, last.m_value);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::size_type
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::erase(const key_type &key) {
    iterator iter = find(key);
    if (iter == end()) {
        return 0;
    }
    erase(iter);
    return 1;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
    requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
        typename Hash::is_transparent;
        typename KeyEqual::is_transparent;
        { hash(key) } -> std::convertible_to<std::size_t>;
        { equal(value, key) } -> std::convertible_to<bool>;
    }
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::size_type
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::erase(K &&key) {
    iterator iter = find(key);
    if (iter == end()) {
        return 0;
    }
    erase(iter);
    return 1;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::swap(unordered_flat_set &other) noexcept(
    alloc_traits::is_always_equal::value && std::is_nothrow_swappable_v<hasher> &&
    std::is_nothrow_swappable_v<key_equal>) {
    using std::swap;

    if constexpr (!alloc_traits::is_always_equal::value) {
        if (m_values.second() != other.m_values.second()) {
            swap(m_states.second(), other.m_states.second());
            swap(m_values.second(), other.m_values.second());
        }
    }

    swap(m_capacity.first(), other.m_capacity.first());
    swap(m_size.first(), other.m_size.first());
    swap(m_states.first(), other.m_states.first());
    swap(m_values.first(), other.m_values.first());

    swap(m_capacity.second(), other.m_capacity.second());
    swap(m_size.second(), other.m_size.second());
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::size_type
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::count(const key_type &key) const {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return 0;
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return 1;
            }
        }

        if (group.match_empty() != 0) {
            return 0;
        }
        probe.next();
    }
    return 0;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
    requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
        typename Hash::is_transparent;
        typename KeyEqual::is_transparent;
        { hash(key) } -> std::convertible_to<std::size_t>;
        { equal(value, key) } -> std::convertible_to<bool>;
    }
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::size_type
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::count(const K &key) const {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return 0;
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return 1;
            }
        }

        if (group.match_empty() != 0) {
            return 0;
        }
        probe.next();
    }
    return 0;
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::find(const key_type &key) {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return end();
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return iterator(states + offset, values + offset);
            }
        }

        if (group.match_empty() != 0) {
            return end();
        }
        probe.next();
    }
    return end();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::const_iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::find(const key_type &key) const {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return end();
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return const_iterator(states + offset, values + offset);
            }
        }

        if (group.match_empty() != 0) {
            return end();
        }
        probe.next();
    }
    return end();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
    requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
        typename Hash::is_transparent;
        typename KeyEqual::is_transparent;
        { hash(key) } -> std::convertible_to<std::size_t>;
        { equal(value, key) } -> std::convertible_to<bool>;
    }
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::find(const K &key) {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return end();
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return iterator(states + offset, values + offset);
            }
        }

        if (group.match_empty() != 0) {
            return end();
        }
        probe.next();
    }
    return end();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
template <typename K>
    requires requires(const Key &value, K &&key, const Hash &hash, const KeyEqual &equal) {
        typename Hash::is_transparent;
        typename KeyEqual::is_transparent;
        { hash(key) } -> std::convertible_to<std::size_t>;
        { equal(value, key) } -> std::convertible_to<bool>;
    }
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::const_iterator
unordered_flat_set<Key, Hash, KeyEqual, Allocator>::find(const K &key) const {
    size_type capacity = m_capacity.first();
    if (capacity == 0) {
        return end();
    }

    std::int8_t *states = m_states.first();
    value_type *values  = m_values.first();

    const std::size_t hash = m_capacity.second()(key);
    const std::size_t h1   = (hash >> 7);
    const auto h2          = static_cast<std::int8_t>(hash & 0x7F);

    detail::swiss_table_probe_sequence probe(h1, capacity);
    const size_type max_probe_time = (m_capacity.first() + 1) / detail::swiss_table_group_size;
    for (size_type i = 0; i < max_probe_time; ++i) {
        detail::swiss_table_control_group group(states + probe.offset());
        for (std::uint16_t mask = group.match(h2); mask != 0; mask &= mask - 1) {
            auto offset = probe.offset(static_cast<std::size_t>(std::countr_zero(mask)));
            if (m_size.second()(values[offset], key)) {
                return const_iterator(states + offset, values + offset);
            }
        }

        if (group.match_empty() != 0) {
            return end();
        }
        probe.next();
    }
    return end();
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::rehash(size_type count) {
    count = detail::swiss_table_normalize_capacity(count);
    if (count <= m_capacity.first()) [[unlikely]] {
        return;
    }

    if (count > max_size()) [[unlikely]] {
        throw std::length_error("ciallo::unordered_flat_set");
    }

    rehash_impl(count);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::reserve(size_type count) {
    count = detail::swiss_table_size_to_capacity(count);
    if (count <= m_capacity.first()) [[unlikely]] {
        return;
    }

    if (count > max_size()) [[unlikely]] {
        throw std::length_error("ciallo::unordered_flat_set");
    }

    rehash_impl(count);
}

template <typename Key, typename Hash, typename KeyEqual, typename Allocator>
void unordered_flat_set<Key, Hash, KeyEqual, Allocator>::rehash_impl(size_type count) {
    size_type value_offset     = detail::swiss_table_value_offset<value_type>(count);
    size_type block_count      = detail::swiss_table_block_count<value_type>(count);
    value_storage_type *memory = storage_alloc_traits::allocate(m_values.second(), block_count);

    auto *states = reinterpret_cast<std::int8_t *>(memory);
    auto *values = reinterpret_cast<value_type *>(memory + value_offset);

    std::memset(states, detail::swiss_table_empty, count + detail::swiss_table_group_size);
    states[count] = detail::swiss_table_sentinel;

    destructor dtor(*this, memory, count, 0);
    scope_guard<destructor &> exception_guard(dtor);

    // Move elements.
    if (m_capacity.first() != 0) [[likely]] {
        std::int8_t *from_states = m_states.first();
        value_type *from_values  = m_values.first();
        for (size_type remaining = m_size.first(); remaining != 0;) {
            detail::swiss_table_control_group group(from_states);
            for (std::uint16_t mask = group.match_full(); mask != 0; mask &= mask - 1) {
                value_type &from_value = from_values[std::countr_zero(mask)];

                std::size_t hash = m_capacity.second()(from_value);
                std::size_t h1   = (hash >> 7);
                auto h2          = static_cast<std::int8_t>(hash & 0x7F);

                size_type offset = detail::swiss_table_find_first_non_full(states, h1, count);
                alloc_traits::construct(m_states.second(), values + offset, std::move(from_value));
                detail::swiss_table_set_state(states, count, offset, h2);

                ++dtor.size;
                --remaining;
            }

            from_states += detail::swiss_table_group_size;
            from_values += detail::swiss_table_group_size;
        }
    }

    // Destroy the old set.
    dtor.backing_array = m_states.first();
    std::swap(m_capacity.first(), dtor.capacity);
    std::swap(m_size.first(), dtor.size);
    m_states.first() = states;
    m_values.first() = values;
}

} // namespace ciallo
