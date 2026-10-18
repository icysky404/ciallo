#include "ciallo/container/unordered_flat_set.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <list>
#include <map>
#include <memory>
#include <memory_resource>
#include <random>
#include <ranges>
#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_set>
#include <vector>

using namespace ciallo;

namespace {

struct alloc_stats {
    static inline int allocs            = 0;
    static inline int deallocs          = 0;
    static inline std::size_t last_size = 0;

    static void reset() {
        allocs    = 0;
        deallocs  = 0;
        last_size = 0;
    }
};

template <typename T>
struct counting_allocator {
    using value_type = T;

    counting_allocator() = default;

    template <typename U>
    counting_allocator(const counting_allocator<U> &) noexcept {}

    T *allocate(std::size_t n) {
        ++alloc_stats::allocs;
        alloc_stats::last_size = n * sizeof(T);
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T *p, std::size_t n) noexcept {
        ++alloc_stats::deallocs;
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    bool operator==(const counting_allocator<U> &) const noexcept {
        return true;
    }

    template <typename U>
    bool operator!=(const counting_allocator<U> &) const noexcept {
        return false;
    }
};

template <typename Value>
static std::size_t capacity_from_bytes(std::size_t bytes) {
    if (bytes == 0 || bytes % alignof(Value) != 0) {
        return 0;
    }

    const std::size_t block_count = bytes / alignof(Value);
    for (std::size_t capacity = 15; capacity < (std::size_t{1} << 24);
         capacity             = detail::swiss_table_next_capacity(capacity)) {
        if (detail::swiss_table_block_count<Value>(capacity) == block_count) {
            return capacity;
        }
    }
    return 0;
}

template <typename Set>
static std::vector<typename Set::value_type> sorted_elements(const Set &set) {
    std::vector<typename Set::value_type> result(set.begin(), set.end());
    std::sort(result.begin(), result.end());
    return result;
}

struct alloc_registry {
    struct allocation {
        int owner;
        std::size_t bytes;
    };

    static inline std::map<void *, allocation> live;
    static inline int wrong_owner = 0;
    static inline int unknown_ptr = 0;
    static inline int wrong_size  = 0;

    static void reset() {
        live.clear();
        wrong_owner = 0;
        unknown_ptr = 0;
        wrong_size  = 0;
    }

    static bool balanced() {
        return live.empty() && wrong_owner == 0 && unknown_ptr == 0 && wrong_size == 0;
    }
};

template <typename T, bool POCCA = false, bool POCMA = false, bool POCS = false>
struct owned_allocator {
    using value_type                             = T;
    using propagate_on_container_copy_assignment = std::bool_constant<POCCA>;
    using propagate_on_container_move_assignment = std::bool_constant<POCMA>;
    using propagate_on_container_swap            = std::bool_constant<POCS>;
    using is_always_equal                        = std::false_type;

    int id = 0;

    owned_allocator() = default;
    explicit owned_allocator(int id) noexcept : id(id) {}

    template <typename U>
    struct rebind {
        using other = owned_allocator<U, POCCA, POCMA, POCS>;
    };

    template <typename U>
    owned_allocator(const owned_allocator<U, POCCA, POCMA, POCS> &other) noexcept : id(other.id) {}

    T *allocate(std::size_t n) {
        T *p                    = std::allocator<T>{}.allocate(n);
        alloc_registry::live[p] = {id, n * sizeof(T)};
        return p;
    }

    void deallocate(T *p, std::size_t n) noexcept {
        auto iter = alloc_registry::live.find(p);
        if (iter == alloc_registry::live.end()) {
            ++alloc_registry::unknown_ptr;
        } else {
            if (iter->second.owner != id) {
                ++alloc_registry::wrong_owner;
            }
            if (iter->second.bytes != n * sizeof(T)) {
                ++alloc_registry::wrong_size;
            }
            alloc_registry::live.erase(iter);
        }
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    bool operator==(const owned_allocator<U, POCCA, POCMA, POCS> &other) const noexcept {
        return id == other.id;
    }

    template <typename U>
    bool operator!=(const owned_allocator<U, POCCA, POCMA, POCS> &other) const noexcept {
        return id != other.id;
    }
};

template <typename T>
using tagged_allocator = owned_allocator<T, false, false, false>;

template <typename T>
using pocca_allocator = owned_allocator<T, true, false, false>;

template <typename T>
using pocma_allocator = owned_allocator<T, false, true, false>;

template <typename T>
using pocs_allocator = owned_allocator<T, false, false, true>;

template <typename T>
struct soccc_allocator {
    using value_type                             = T;
    using propagate_on_container_copy_assignment = std::false_type;
    using propagate_on_container_move_assignment = std::false_type;
    using propagate_on_container_swap            = std::false_type;
    using is_always_equal                        = std::false_type;

    int id = 0;

    soccc_allocator() = default;
    explicit soccc_allocator(int id) noexcept : id(id) {}

    template <typename U>
    soccc_allocator(const soccc_allocator<U> &other) noexcept : id(other.id) {}

    soccc_allocator select_on_container_copy_construction() const noexcept {
        return soccc_allocator(id + 100);
    }

    T *allocate(std::size_t n) {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T *p, std::size_t n) noexcept {
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    bool operator==(const soccc_allocator<U> &other) const noexcept {
        return id == other.id;
    }
};

template <typename T>
struct limited_allocator {
    using value_type      = T;
    using is_always_equal = std::true_type;

    limited_allocator() = default;

    template <typename U>
    limited_allocator(const limited_allocator<U> &) noexcept {}

    T *allocate(std::size_t n) {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T *p, std::size_t n) noexcept {
        std::allocator<T>{}.deallocate(p, n);
    }

    constexpr std::size_t max_size() const noexcept {
        return 100;
    }

    template <typename U>
    bool operator==(const limited_allocator<U> &) const noexcept {
        return true;
    }
};

template <typename T>
struct throwing_swap_allocator {
    using value_type      = T;
    using is_always_equal = std::false_type;

    static inline bool armed = false;

    int id = 0;

    throwing_swap_allocator() = default;
    explicit throwing_swap_allocator(int id) noexcept : id(id) {}

    template <typename U>
    throwing_swap_allocator(const throwing_swap_allocator<U> &other) noexcept : id(other.id) {}

    throwing_swap_allocator(const throwing_swap_allocator &other) : id(other.id) {
        if (armed) {
            throw std::runtime_error("throwing_swap_allocator");
        }
    }

    // NOLINTNEXTLINE(performance-noexcept-move-constructor)
    throwing_swap_allocator(throwing_swap_allocator &&other) : id(other.id) {
        if (armed) {
            throw std::runtime_error("throwing_swap_allocator");
        }
    }

    throwing_swap_allocator &operator=(const throwing_swap_allocator &) = default;
    throwing_swap_allocator &operator=(throwing_swap_allocator &&)      = default;

    T *allocate(std::size_t n) {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T *p, std::size_t n) noexcept {
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename U>
    bool operator==(const throwing_swap_allocator<U> &other) const noexcept {
        return id == other.id;
    }
};

struct pinned_hash {
    std::vector<std::pair<int, std::pair<std::size_t, std::size_t>>> table;

    std::size_t operator()(int key) const noexcept {
        for (const auto &[k, v] : table) {
            if (k == key) {
                return (v.first << 7) | (v.second & 0x7F);
            }
        }
        return static_cast<std::size_t>(key) * 0x9E3779B97F4A7C15ull;
    }
};

static pinned_hash make_pinned_hash(
    std::initializer_list<std::pair<int, std::pair<std::size_t, std::size_t>>> entries) {
    return pinned_hash{std::vector<std::pair<int, std::pair<std::size_t, std::size_t>>>(entries)};
}

struct live_key {
    static inline int live = 0;

    int value = 0;

    live_key() {
        ++live;
    }

    explicit live_key(int value) : value(value) {
        ++live;
    }

    live_key(const live_key &other) : value(other.value) {
        ++live;
    }

    live_key(live_key &&other) noexcept : value(other.value) {
        other.value = -1;
        ++live;
    }

    live_key &operator=(const live_key &) = default;
    live_key &operator=(live_key &&)      = default;

    ~live_key() {
        --live;
    }

    friend bool operator==(const live_key &a, const live_key &b) {
        return a.value == b.value;
    }

    friend bool operator<(const live_key &a, const live_key &b) {
        return a.value < b.value;
    }
};

struct live_key_hash {
    std::size_t operator()(const live_key &key) const noexcept {
        return std::hash<int>{}(key.value);
    }
};

struct throwing_key {
    static inline int live               = 0;
    static inline int copies             = 0;
    static inline int moves              = 0;
    static inline int copies_until_throw = -1;
    static inline int moves_until_throw  = -1;

    int value = 0;

    static void reset_counters() {
        copies             = 0;
        moves              = 0;
        copies_until_throw = -1;
        moves_until_throw  = -1;
    }

    throwing_key() {
        ++live;
    }

    explicit throwing_key(int value) : value(value) {
        ++live;
    }

    throwing_key(const throwing_key &other) : value(other.value) {
        ++copies;
        maybe_throw(copies_until_throw);
        ++live;
    }

    // NOLINTNEXTLINE(performance-noexcept-move-constructor)
    throwing_key(throwing_key &&other) : value(other.value) {
        ++moves;
        maybe_throw(moves_until_throw);
        other.value = -1;
        ++live;
    }

    throwing_key &operator=(const throwing_key &) = default;
    throwing_key &operator=(throwing_key &&)      = default;

    ~throwing_key() {
        --live;
    }

    friend bool operator==(const throwing_key &a, const throwing_key &b) {
        return a.value == b.value;
    }

private:
    static void maybe_throw(int &countdown) {
        if (countdown < 0) {
            return;
        }
        if (countdown == 0) {
            countdown = -1;
            throw std::runtime_error("throwing_key");
        }
        --countdown;
    }
};

struct throwing_key_hash {
    std::size_t operator()(const throwing_key &key) const noexcept {
        return std::hash<int>{}(key.value);
    }
};

struct payload_key {
    int id      = 0;
    int payload = 0;

    friend bool operator==(const payload_key &a, const payload_key &b) {
        return a.id == b.id;
    }
};

struct payload_hash {
    std::size_t operator()(const payload_key &key) const noexcept {
        return std::hash<int>{}(key.id);
    }
};

struct unique_ptr_hash {
    std::size_t operator()(const std::unique_ptr<int> &value) const noexcept {
        return value ? std::hash<int>{}(*value) : 0;
    }
};

struct unique_ptr_equal {
    bool operator()(const std::unique_ptr<int> &a, const std::unique_ptr<int> &b) const noexcept {
        if (!a || !b) {
            return !a && !b;
        }
        return *a == *b;
    }
};

struct non_assignable_key {
    const int value;

    explicit non_assignable_key(int value) : value(value) {}

    friend bool operator==(const non_assignable_key &a, const non_assignable_key &b) {
        return a.value == b.value;
    }
};

struct non_assignable_hash {
    std::size_t operator()(const non_assignable_key &key) const noexcept {
        return std::hash<int>{}(key.value);
    }
};

template <std::size_t Alignment>
struct alignas(Alignment) aligned_key {
    int value = 0;

    friend bool operator==(const aligned_key &a, const aligned_key &b) {
        return a.value == b.value;
    }
};

template <std::size_t Alignment>
struct aligned_key_hash {
    std::size_t operator()(const aligned_key<Alignment> &key) const noexcept {
        return std::hash<int>{}(key.value);
    }
};

struct large_key {
    int id             = 0;
    char padding[1020] = {};

    friend bool operator==(const large_key &a, const large_key &b) {
        return a.id == b.id;
    }
};

struct large_key_hash {
    std::size_t operator()(const large_key &key) const noexcept {
        return std::hash<int>{}(key.id);
    }
};

struct empty_key {
    friend bool operator==(const empty_key &, const empty_key &) {
        return true;
    }
};

struct empty_key_hash {
    std::size_t operator()(const empty_key &) const noexcept {
        return 0;
    }
};

struct flaky_hash {
    static inline bool armed = false;

    std::size_t operator()(int value) const {
        if (armed) {
            throw std::runtime_error("flaky_hash");
        }
        return std::hash<int>{}(value);
    }
};

struct flaky_equal {
    static inline bool armed = false;

    bool operator()(int a, int b) const {
        if (armed) {
            throw std::runtime_error("flaky_equal");
        }
        return a == b;
    }
};

struct tracked_text {
    static inline int constructions = 0;

    std::string text;

    tracked_text() = default;

    tracked_text(std::string_view value) : text(value) {
        ++constructions;
    }

    tracked_text(const char *value) : text(value) {
        ++constructions;
    }

    tracked_text(const tracked_text &)                = default;
    tracked_text(tracked_text &&) noexcept            = default;
    tracked_text &operator=(const tracked_text &)     = default;
    tracked_text &operator=(tracked_text &&) noexcept = default;

    operator std::string_view() const noexcept {
        return text;
    }
};

struct transparent_text_hash {
    using is_transparent = void;

    std::size_t operator()(std::string_view value) const noexcept {
        return std::hash<std::string_view>{}(value);
    }
};

struct transparent_text_equal {
    using is_transparent = void;

    bool operator()(std::string_view a, std::string_view b) const noexcept {
        return a == b;
    }
};

using set_t = unordered_flat_set<int>;

template <typename Set, typename Key>
concept can_find = requires(Set &set, const Key &key) { set.find(key); };

template <typename Set, typename Key>
concept can_count = requires(Set &set, const Key &key) { set.count(key); };

template <typename Set, typename Key>
concept can_contains = requires(Set &set, const Key &key) { set.contains(key); };

template <typename Set, typename Key>
concept can_insert = requires(Set &set, Key &&key) { set.insert(std::forward<Key>(key)); };

template <typename Set, typename... Args>
concept can_emplace =
    requires(Set &set, Args &&...args) { set.emplace(std::forward<Args>(args)...); };

template <typename Allocator>
static void check_copy_assign_propagation(bool expect_propagation) {
    using set_type = unordered_flat_set<int, std::hash<int>, std::equal_to<>, Allocator>;

    set_type target(15, Allocator{1});
    target.insert({1, 2, 3});
    set_type source(15, Allocator{2});
    source.insert({10, 20});

    target = source;

    const int expected_id = expect_propagation ? 2 : 1;
    EXPECT_EQ(target.get_allocator().id, expected_id);
    EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
}

template <typename Allocator>
static void check_unequal_move_assign() {
    using set_type = unordered_flat_set<int, std::hash<int>, std::equal_to<>, Allocator>;

    set_type target(15, Allocator{1});
    target.insert({1, 2, 3});
    set_type source(15, Allocator{2});
    source.insert({10, 20});

    target = std::move(source);

    EXPECT_EQ(target.get_allocator().id, 2);
    EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
    EXPECT_TRUE(source.empty());
}

template <typename Allocator>
static void check_equal_move_assign() {
    using set_type = unordered_flat_set<int, std::hash<int>, std::equal_to<>, Allocator>;

    set_type target(15, Allocator{5});
    target.insert({1, 2, 3});
    set_type source(15, Allocator{5});
    source.insert({10, 20});

    target = std::move(source);

    EXPECT_EQ(target.get_allocator().id, 5);
    EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
    EXPECT_TRUE(source.empty());
}

template <typename Allocator>
static void check_swap_keeps_owners() {
    using set_type = unordered_flat_set<int, std::hash<int>, std::equal_to<>, Allocator>;

    set_type a(15, Allocator{1});
    a.insert({1, 2, 3});
    set_type b(15, Allocator{2});
    b.insert({10, 20});

    a.swap(b);

    EXPECT_EQ(a.get_allocator().id, 2);
    EXPECT_EQ(b.get_allocator().id, 1);
    EXPECT_EQ(sorted_elements(a), (std::vector<int>{10, 20}));
    EXPECT_EQ(sorted_elements(b), (std::vector<int>{1, 2, 3}));
}

template <std::size_t Alignment>
static void check_element_alignment(std::size_t reserve_count) {
    using set_type = unordered_flat_set<aligned_key<Alignment>, aligned_key_hash<Alignment>>;

    set_type set;
    set.reserve(reserve_count);
    for (int i = 0; i < 32; ++i) {
        set.insert(aligned_key<Alignment>{i});
    }

    for (const auto &key : set) {
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(std::addressof(key)) % Alignment, 0u)
            << "alignof=" << Alignment << " reserve=" << reserve_count;
    }
}

} // namespace

TEST(unordered_flat_set, default_ctor_is_empty_and_allocation_free) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;

        EXPECT_TRUE(set.empty());
        EXPECT_EQ(set.size(), 0u);
        EXPECT_EQ(set.begin(), set.end());
        EXPECT_EQ(set.find(1), set.end());
        EXPECT_EQ(set.count(1), 0u);
        EXPECT_FALSE(set.contains(1));
        EXPECT_EQ(set.erase(1), 0u);
        EXPECT_EQ(set.load_factor(), 0.0f);

        set.clear();
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(alloc_stats::allocs, 0);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, bucket_count_zero_behaves_like_default) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set(0);

        EXPECT_TRUE(set.empty());
        EXPECT_EQ(set.size(), 0u);
        EXPECT_EQ(set.begin(), set.end());
        EXPECT_EQ(set.find(1), set.end());
        EXPECT_EQ(set.count(1), 0u);
        EXPECT_FALSE(set.contains(1));
        EXPECT_EQ(set.erase(1), 0u);
        EXPECT_EQ(set.load_factor(), 0.0f);
        EXPECT_EQ(alloc_stats::allocs, 0);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, ctor_normalizes_bucket_count) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set(14);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    {
        set_t set(15);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    {
        set_t set(16);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);
    }
    {
        set_t set(17);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);
    }
    {
        set_t set(31);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);
    }
    {
        set_t set(32);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 63u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, ctor_stores_hash_equal_allocator) {
    struct local_hash {
        int id = 0;
        std::size_t operator()(int value) const noexcept {
            return std::hash<int>{}(value);
        }
    };
    struct local_equal {
        int id = 0;
        bool operator()(int a, int b) const noexcept {
            return a == b;
        }
    };

    using set_t = unordered_flat_set<int, local_hash, local_equal, tagged_allocator<int>>;

    set_t set(15, local_hash{3}, local_equal{4}, tagged_allocator<int>{7});

    EXPECT_EQ(set.hash_function().id, 3);
    EXPECT_EQ(set.key_eq().id, 4);
    EXPECT_EQ(set.get_allocator().id, 7);
    EXPECT_TRUE(set.insert(1).second);
}

TEST(unordered_flat_set, ctor_overloads_with_allocator) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

    tagged_allocator<int> alloc{9};

    set_t a(15, alloc);
    set_t b(15, std::hash<int>{}, alloc);
    set_t c(alloc);

    EXPECT_EQ(a.get_allocator().id, 9);
    EXPECT_EQ(b.get_allocator().id, 9);
    EXPECT_EQ(c.get_allocator().id, 9);

    EXPECT_TRUE(a.insert(1).second);
    EXPECT_TRUE(b.insert(2).second);
    EXPECT_TRUE(c.insert(3).second);
}

TEST(unordered_flat_set, ctor_huge_bucket_count_throws_length_error) {
    using set_t = unordered_flat_set<int>;

    EXPECT_THROW(
        {
            set_t set((std::numeric_limits<std::size_t>::max)());
            (void)set;
        },
        std::length_error);

    const auto too_big = set_t{}.max_size() + 1;
    EXPECT_THROW(
        {
            set_t set(too_big);
            (void)set;
        },
        std::length_error);
}

TEST(unordered_flat_set, range_ctor_deduplicates) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();

    std::vector<int> values{1, 1, 2, 2, 3, 3, 3};
    {
        set_t set(values.begin(), values.end());
        EXPECT_EQ(set.size(), 3u);
        EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }

    {
        set_t set(values.begin(), values.begin());
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }

    std::vector<int> duplicates(1000, 7);
    {
        set_t set(duplicates.begin(), duplicates.end());
        EXPECT_EQ(set.size(), 1u);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(1000));
    }

    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, range_ctor_respects_explicit_bucket_count) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    std::vector<int> values{1, 2, 3};

    alloc_stats::reset();
    {
        set_t set(values.begin(), values.end(), 100);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
        EXPECT_EQ(set.size(), 3u);
    }

    std::vector<int> many(100, 1);
    {
        set_t set(many.begin(), many.end(), 10);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
        EXPECT_EQ(set.size(), 1u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, range_ctor_requires_forward_iterator) {
    using set_t = unordered_flat_set<int>;

    static_assert(
        std::constructible_from<set_t, std::vector<int>::iterator, std::vector<int>::iterator>);
    static_assert(
        std::constructible_from<set_t, std::list<int>::iterator, std::list<int>::iterator>);
    static_assert(
        std::constructible_from<set_t, std::array<int, 3>::iterator, std::array<int, 3>::iterator>);
    static_assert(
        !std::constructible_from<set_t, std::istream_iterator<int>, std::istream_iterator<int>>);
}

TEST(unordered_flat_set, initializer_list_ctor) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set({1, 2, 2, 3});
        EXPECT_EQ(set.size(), 3u);
        EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    {
        set_t set(std::initializer_list<int>{});
        EXPECT_TRUE(set.empty());
    }
    {
        set_t set({1, 2, 3}, 100);
        EXPECT_EQ(set.size(), 3u);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_ctor_copies_contents) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t source;
        source.rehash(1000);
        source.insert({1, 2, 3});
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 1023u);

        set_t copy(source);
        EXPECT_EQ(copy.size(), 3u);
        EXPECT_EQ(sorted_elements(copy), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);

        copy.insert(4);
        EXPECT_EQ(source.size(), 3u);
        EXPECT_EQ(copy.size(), 4u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_ctor_of_empty_allocates_one_buffer) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t source;
        EXPECT_EQ(alloc_stats::allocs, 0);

        set_t copy(source);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
        EXPECT_TRUE(copy.empty());
        EXPECT_TRUE(source.empty());

        EXPECT_TRUE(copy.insert(1).second);
        EXPECT_EQ(copy.size(), 1u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, move_ctor_steals_buffer) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    static_assert(std::is_nothrow_move_constructible_v<set_t>);

    alloc_stats::reset();
    {
        set_t source;
        source.insert({1, 2, 3});
        EXPECT_EQ(alloc_stats::allocs, 1);

        set_t moved(std::move(source));

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(sorted_elements(moved), (std::vector<int>{1, 2, 3}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(source.begin(), source.end());

        EXPECT_TRUE(source.insert(4).second);
        EXPECT_EQ(source.size(), 1u);
        EXPECT_EQ(alloc_stats::allocs, 2);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, destructor_destroys_elements_and_releases) {
    using set_t =
        unordered_flat_set<live_key, live_key_hash, std::equal_to<>, counting_allocator<live_key>>;

    live_key::live = 0;
    alloc_stats::reset();

    {
        set_t set;
        set.insert(live_key(1));
        set.insert(live_key(2));
        set.insert(live_key(3));
        EXPECT_EQ(live_key::live, 3);
        EXPECT_EQ(alloc_stats::allocs, 1);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::deallocs, 1);

    { set_t set; }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_assign_same_bucket_count) {
    using set_t =
        unordered_flat_set<live_key, live_key_hash, std::equal_to<>, counting_allocator<live_key>>;

    live_key::live = 0;
    alloc_stats::reset();
    {
        set_t target;
        set_t source;
        for (int i = 0; i < 5; ++i) {
            target.insert(live_key(i));
            source.insert(live_key(i + 10));
        }
        EXPECT_EQ(live_key::live, 10);

        target = source;

        EXPECT_EQ(target.size(), 5u);
        EXPECT_EQ(live_key::live, 10);
        for (int i = 0; i < 5; ++i) {
            EXPECT_EQ(target.count(live_key(i)), 0u);
            EXPECT_EQ(target.count(live_key(i + 10)), 1u);
        }
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_assign_reuses_large_enough_buffer) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t target;
        target.rehash(1000);
        target.insert({1, 2, 3});

        set_t source;
        source.insert({10, 20, 30});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = source;

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_FLOAT_EQ(target.load_factor(), static_cast<float>(3.0 / 1024.0));
        EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20, 30}));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_assign_grows_buffer) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t target;
        target.insert(0);

        set_t source;
        source.reserve(100);
        for (int i = 0; i < 100; ++i) {
            source.insert(i);
        }

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = source;

        EXPECT_EQ(alloc_stats::allocs, allocs_before + 1);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before + 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(source.size()));
        EXPECT_EQ(target.size(), 100u);
        for (int i = 0; i < 100; ++i) {
            EXPECT_TRUE(target.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_assign_from_and_to_empty) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t target;
        target.insert({1, 2, 3});
        set_t empty;

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = empty;

        EXPECT_TRUE(target.empty());
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    {
        set_t target;
        set_t source;
        source.insert({1, 2, 3});

        const int allocs_before = alloc_stats::allocs;

        target = source;

        EXPECT_EQ(allocs_before + 1, alloc_stats::allocs);
        EXPECT_EQ(sorted_elements(target), (std::vector<int>{1, 2, 3}));
    }
    {
        set_t a;
        set_t b;

        const int allocs_before = alloc_stats::allocs;

        a = b;

        EXPECT_EQ(allocs_before + 1, alloc_stats::allocs);
        EXPECT_TRUE(a.empty());
        EXPECT_TRUE(b.empty());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, copy_assign_self) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.insert({1, 2, 3});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        set = set;

        EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, move_assign_equal_allocator_steals) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    static_assert(std::is_nothrow_move_assignable_v<set_t>);

    alloc_stats::reset();
    {
        set_t target;
        target.insert({1, 2, 3});
        set_t source;
        source.insert({10, 20});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = std::move(source);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before + 1);
        EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(source.begin(), source.end());
        EXPECT_TRUE(source.insert(30).second);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, move_assign_self) {
    set_t set;
    set.insert({1, 2, 3});

    set = std::move(set);

    EXPECT_EQ(set.size(), 3u);
    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_set, move_assign_unequal_non_propagating_allocator) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

    alloc_registry::reset();
    {
        set_t target(15, tagged_allocator<int>{3});
        target.insert({1, 2, 3});
        set_t source(15, tagged_allocator<int>{2});
        source.insert({10, 20});

        target = std::move(source);

        EXPECT_EQ(target.get_allocator().id, 2);
        EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(target.size(), 2u);
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, move_assign_unequal_propagating_allocator) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, pocma_allocator<int>>;

    alloc_registry::reset();
    {
        set_t target(15, pocma_allocator<int>{3});
        target.insert({1, 2, 3});
        set_t source(15, pocma_allocator<int>{2});
        source.insert({10, 20});

        target = std::move(source);

        EXPECT_EQ(target.get_allocator().id, 2);
        EXPECT_EQ(sorted_elements(target), (std::vector<int>{10, 20}));
        EXPECT_TRUE(source.empty());
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, initializer_list_assign_replaces_content) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.insert({1, 2, 3});

        set = {4, 5, 5, 6};

        EXPECT_EQ(sorted_elements(set), (std::vector<int>{4, 5, 6}));

        const std::size_t capacity_before = capacity_from_bytes<int>(alloc_stats::last_size);
        set                               = std::initializer_list<int>{};

        EXPECT_TRUE(set.empty());
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(capacity_before, 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, initializer_list_assign_on_default_ctor) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;

        set = {1, 2, 3};

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, swap_both_non_empty) {
    set_t a;
    set_t b;

    for (int i = 0; i < 3; ++i) {
        a.insert(i);
    }
    b.rehash(1000);
    for (int i = 0; i < 100; ++i) {
        b.insert(i + 10);
    }

    a.swap(b);

    EXPECT_EQ(a.size(), 100u);
    EXPECT_EQ(b.size(), 3u);
    EXPECT_FLOAT_EQ(a.load_factor(), static_cast<float>(100.0 / 1024.0));
    EXPECT_FLOAT_EQ(b.load_factor(), static_cast<float>(3.0 / 16.0));
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(a.contains(i + 10));
    }
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(b.contains(i));
    }
}

TEST(unordered_flat_set, swap_with_empty) {
    set_t non_empty;
    set_t empty;
    non_empty.insert({1, 2, 3});

    non_empty.swap(empty);

    EXPECT_TRUE(non_empty.empty());
    EXPECT_EQ(non_empty.begin(), non_empty.end());
    EXPECT_EQ(non_empty.load_factor(), 0.0f);
    EXPECT_EQ(sorted_elements(empty), (std::vector<int>{1, 2, 3}));

    EXPECT_TRUE(non_empty.insert(4).second);
    EXPECT_EQ(non_empty.size(), 1u);
    EXPECT_TRUE(non_empty.contains(4));
}

TEST(unordered_flat_set, swap_self) {
    set_t set;
    set.insert({1, 2, 3});

    set.swap(set);

    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_set, swap_unequal_allocators_keeps_buffer_owner) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

    alloc_registry::reset();
    {
        set_t a(15, tagged_allocator<int>{1});
        a.insert({1, 2, 3});
        set_t b(15, tagged_allocator<int>{2});
        b.insert({10, 20});

        a.swap(b);

        EXPECT_EQ(a.get_allocator().id, 2);
        EXPECT_EQ(b.get_allocator().id, 1);
        EXPECT_EQ(sorted_elements(a), (std::vector<int>{10, 20}));
        EXPECT_EQ(sorted_elements(b), (std::vector<int>{1, 2, 3}));
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, std_swap_uses_move_operations) {
    set_t a;
    set_t b;
    a.insert({1, 2, 3});
    b.insert({10, 20});

    std::swap(a, b);

    EXPECT_EQ(sorted_elements(a), (std::vector<int>{10, 20}));
    EXPECT_EQ(sorted_elements(b), (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_set, swap_is_noexcept_for_std_allocator) {
    using set_t = unordered_flat_set<int>;
    static_assert(noexcept(std::declval<set_t &>().swap(std::declval<set_t &>())));
}

TEST(unordered_flat_set, load_factor_follows_size_over_bucket_count) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        EXPECT_EQ(set.load_factor(), 0.0f);

        for (int i = 1; i <= 300; ++i) {
            set.insert(i);

            const std::size_t capacity = capacity_from_bytes<int>(alloc_stats::last_size);
            ASSERT_NE(capacity, 0u);
            EXPECT_FLOAT_EQ(set.load_factor(),
                            static_cast<float>(static_cast<double>(i) / (capacity + 1)));
            EXPECT_LE(set.load_factor(), set.max_load_factor());
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, max_load_factor_is_seven_eighths) {
    set_t set;
    EXPECT_EQ(set.max_load_factor(), 0.875f);
}

TEST(unordered_flat_set, max_load_factor_setter_is_noop) {
    set_t set;

#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 4996)
#endif
    set.max_load_factor(0.1f);
#if defined(__clang__)
#    pragma clang diagnostic pop
#elif defined(__GNUC__)
#    pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#    pragma warning(pop)
#endif

    EXPECT_EQ(set.max_load_factor(), 0.875f);
}

TEST(unordered_flat_set, growth_points_are_at_seven_eighths) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 14; ++i) {
            set.insert(i);
        }
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);

        set.insert(14);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);

        for (int i = 15; i < 28; ++i) {
            set.insert(i);
        }
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);

        set.insert(28);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 63u);

        for (int i = 29; i < 56; ++i) {
            set.insert(i);
        }
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 63u);

        set.insert(56);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 127u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, rehash_grows_and_preserves_elements) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.insert({1, 2, 3});

        set.rehash(100);

        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 127u);
        EXPECT_EQ(set.size(), 3u);
        for (int i = 1; i <= 3; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, rehash_smaller_or_equal_is_noop) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.insert({1, 2, 3});
        set.rehash(100);

        const int allocs_before       = alloc_stats::allocs;
        const int deallocs_before     = alloc_stats::deallocs;
        const std::size_t size_before = alloc_stats::last_size;

        set.rehash(10);
        set.rehash(127);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(alloc_stats::last_size, size_before);
        EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, rehash_zero_on_default_allocates) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;

        set.rehash(0);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(set.begin(), set.end());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, rehash_huge_throws_length_error) {
    using set_t = unordered_flat_set<int>;

    set_t set;
    set.insert({1, 2, 3});

    EXPECT_THROW(set.rehash((std::numeric_limits<std::size_t>::max)()), std::length_error);
    EXPECT_EQ(set.size(), 3u);
    EXPECT_TRUE(set.contains(1));
    EXPECT_TRUE(set.contains(2));
    EXPECT_TRUE(set.contains(3));

    EXPECT_THROW(set.rehash(set.max_size() + 1), std::length_error);
    EXPECT_EQ(set.size(), 3u);
    EXPECT_TRUE(set.insert(4).second);
}

TEST(unordered_flat_set, reserve_matches_size_to_capacity) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{14}, std::size_t{15},
                          std::size_t{16}, std::size_t{28}, std::size_t{29}, std::size_t{100}}) {
        alloc_stats::reset();
        {
            set_t set;
            set.reserve(n);

            EXPECT_EQ(alloc_stats::allocs, 1);
            EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                      detail::swiss_table_size_to_capacity(n));
        }
        EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
    }
}

TEST(unordered_flat_set, reserve_then_insert_never_reallocates) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    for (std::size_t n : {std::size_t{14}, std::size_t{28}, std::size_t{100}}) {
        alloc_stats::reset();
        {
            set_t set;
            set.reserve(n);
            ASSERT_EQ(alloc_stats::allocs, 1);

            for (std::size_t i = 0; i < n; ++i) {
                set.insert(static_cast<int>(i));
            }

            EXPECT_EQ(alloc_stats::allocs, 1);
            EXPECT_EQ(set.size(), n);
            EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size),
                      detail::swiss_table_size_to_capacity(n));
        }
        EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
    }
}

TEST(unordered_flat_set, reserve_never_shrinks) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.rehash(1000);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 1023u);

        const int allocs_before = alloc_stats::allocs;

        set.reserve(1);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 1023u);

        for (int i = 0; i < 100; ++i) {
            set.insert(i);
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_FLOAT_EQ(set.load_factor(), static_cast<float>(100.0 / 1024.0));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, reserve_size_max_throws_length_error) {
    using set_t = unordered_flat_set<int>;

    set_t set;
    set.insert({1, 2, 3});

    EXPECT_THROW(set.reserve((std::numeric_limits<std::size_t>::max)()), std::length_error);
    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
    EXPECT_TRUE(set.insert(4).second);
}

TEST(unordered_flat_set, max_size_is_bounded_by_allocator) {
    using default_set = unordered_flat_set<int>;
    using limited_set =
        unordered_flat_set<int, std::hash<int>, std::equal_to<>, limited_allocator<int>>;

    default_set set;
    const std::size_t expected =
        (std::min<std::size_t>)((std::numeric_limits<std::size_t>::max)() / sizeof(int),
                                static_cast<std::size_t>(
                                    (std::numeric_limits<std::ptrdiff_t>::max)()));
    EXPECT_EQ(set.max_size(), expected);

    limited_set limited;
    EXPECT_EQ(limited.max_size(), 100u);
    EXPECT_THROW(limited.reserve(101), std::length_error);
    EXPECT_TRUE(limited.empty());
}

TEST(unordered_flat_set, clear_destroys_elements_and_keeps_capacity) {
    using set_t =
        unordered_flat_set<live_key, live_key_hash, std::equal_to<>, counting_allocator<live_key>>;

    static_assert(noexcept(std::declval<set_t &>().clear()));

    live_key::live = 0;
    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 100; ++i) {
            set.insert(live_key(i));
        }
        EXPECT_EQ(live_key::live, 100);

        const std::size_t capacity_before = capacity_from_bytes<live_key>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        set.clear();

        EXPECT_EQ(live_key::live, 0);
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(set.begin(), set.end());
        EXPECT_EQ(set.load_factor(), 0.0f);
        EXPECT_EQ(capacity_from_bytes<live_key>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);

        for (int i = 0; i < 10; ++i) {
            set.insert(live_key(i));
        }
        EXPECT_EQ(set.size(), 10u);
        EXPECT_EQ(live_key::live, 10);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, clear_on_empty_and_default_is_safe) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.clear();
        EXPECT_EQ(alloc_stats::allocs, 0);

        set.rehash(0);
        set.clear();
        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_TRUE(set.empty());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_lvalue_returns_iterator_and_true) {
    set_t set;
    const int value = 42;

    const auto result = set.insert(value);

    EXPECT_TRUE(result.second);
    EXPECT_EQ(*result.first, value);
    EXPECT_EQ(result.first, set.find(value));
    EXPECT_EQ(set.size(), 1u);
}

TEST(unordered_flat_set, insert_rvalue_moves_not_copies) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    {
        set_t set;
        throwing_key source(7);

        const auto result = set.insert(std::move(source));

        EXPECT_TRUE(result.second);
        EXPECT_EQ(result.first->value, 7);
        EXPECT_EQ(throwing_key::moves, 1);
        EXPECT_EQ(throwing_key::copies, 0);
        EXPECT_EQ(source.value, -1);
        EXPECT_EQ(set.size(), 1u);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
}

TEST(unordered_flat_set, duplicate_insert_returns_existing_iterator) {
    using set_t = unordered_flat_set<payload_key, payload_hash>;

    set_t set;
    const auto first = set.insert(payload_key{1, 10});
    ASSERT_TRUE(first.second);

    payload_key duplicate{1, 20};
    auto result = set.insert(duplicate);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first, first.first);
    EXPECT_EQ(result.first->payload, 10);

    result = set.insert(payload_key{1, 30});
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->payload, 10);

    result = set.emplace(1, 40);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->payload, 10);

    std::vector<payload_key> values{{1, 50}};
    set.insert(values.begin(), values.end());
    EXPECT_EQ(set.size(), 1u);
    EXPECT_EQ(set.begin()->payload, 10);

    set.insert({payload_key{1, 60}});
    EXPECT_EQ(set.size(), 1u);
    EXPECT_EQ(set.begin()->payload, 10);
}

TEST(unordered_flat_set, insert_transparent_key_constructs_in_place) {
    using set_t = unordered_flat_set<tracked_text, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    set_t set;

    const auto result = set.insert("hello");

    EXPECT_TRUE(result.second);
    EXPECT_EQ(tracked_text::constructions, 1);
    EXPECT_EQ(set.size(), 1u);

    tracked_text::constructions = 0;
    EXPECT_EQ(set.count(std::string_view("hello")), 1u);
    EXPECT_TRUE(set.contains(std::string_view("hello")));
    EXPECT_NE(set.find(std::string_view("hello")), set.end());
    EXPECT_EQ(tracked_text::constructions, 0);

    const auto inserted = set.insert(std::string_view("world"));
    EXPECT_TRUE(inserted.second);
    EXPECT_EQ(tracked_text::constructions, 1);
}

TEST(unordered_flat_set, emplace_forwards_arguments) {
    struct pair_hash {
        std::size_t operator()(const std::pair<int, int> &value) const noexcept {
            return std::hash<int>{}(value.first);
        }
    };
    struct pair_equal {
        bool operator()(const std::pair<int, int> &a, const std::pair<int, int> &b) const noexcept {
            return a.first == b.first;
        }
    };

    using pair_set = unordered_flat_set<std::pair<int, int>, pair_hash, pair_equal>;

    pair_set set;
    auto result = set.emplace(1, 2);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->first, 1);
    EXPECT_EQ(result.first->second, 2);

    result = set.emplace(1, 3);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second, 2);

    using move_only_set =
        unordered_flat_set<std::unique_ptr<int>, unique_ptr_hash, unique_ptr_equal>;
    move_only_set move_only;
    auto move_result = move_only.emplace(std::make_unique<int>(42));
    EXPECT_TRUE(move_result.second);
    EXPECT_EQ(**move_result.first, 42);

    auto probe = std::make_unique<int>(42);
    EXPECT_NE(move_only.find(probe), move_only.end());

    auto duplicate = move_only.emplace(std::make_unique<int>(42));
    EXPECT_FALSE(duplicate.second);
}

TEST(unordered_flat_set, insert_range_deduplicates) {
    set_t set;
    std::vector<int> values{1, 1, 2, 3, 3};
    set.insert(values.begin(), values.end());
    EXPECT_EQ(set.size(), 3u);

    std::list<int> more{3, 4, 4, 5};
    set.insert(more.begin(), more.end());
    EXPECT_EQ(set.size(), 5u);
    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3, 4, 5}));

    std::istringstream stream("6 6 7");
    set.insert(std::istream_iterator<int>(stream), std::istream_iterator<int>());
    EXPECT_EQ(set.size(), 7u);
    EXPECT_TRUE(set.contains(6));
    EXPECT_TRUE(set.contains(7));

    const std::size_t size_before = set.size();
    set.insert(values.begin(), values.begin());
    EXPECT_EQ(set.size(), size_before);
}

TEST(unordered_flat_set, insert_initializer_list) {
    set_t set;
    static_assert(std::is_void_v<decltype(set.insert(std::initializer_list<int>{1, 2}))>);

    set.insert({1, 1, 2});

    EXPECT_EQ(set.size(), 2u);
    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2}));
}

TEST(unordered_flat_set, insert_twice_in_a_row_only_one_copy) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t set;
        set.insert(throwing_key(7));
        const auto allocs_before = alloc_stats::allocs;

        throwing_key::reset_counters();
        const auto &stored = *set.begin();
        const auto result  = set.insert(stored);

        EXPECT_FALSE(result.second);
        EXPECT_EQ(result.first, set.begin());
        EXPECT_EQ(throwing_key::copies, 0);
        EXPECT_EQ(throwing_key::moves, 0);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(set.size(), 1u);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_that_triggers_growth_returns_valid_iterator) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 14; ++i) {
            set.insert(i);
        }
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);

        const auto result = set.insert(14);

        EXPECT_TRUE(result.second);
        EXPECT_EQ(*result.first, 14);
        EXPECT_EQ(result.first, set.find(14));
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);
        EXPECT_EQ(set.size(), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_first_element_allocates_one_buffer) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        EXPECT_TRUE(set.insert(1).second);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_keys_with_h2_boundaries) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    set_t set(15, make_pinned_hash({{1, {0, 0}}, {2, {0, 127}}}));

    EXPECT_TRUE(set.insert(1).second);
    EXPECT_TRUE(set.insert(2).second);

    EXPECT_TRUE(set.contains(1));
    EXPECT_TRUE(set.contains(2));
    EXPECT_EQ(*set.find(1), 1);
    EXPECT_EQ(*set.find(2), 2);

    EXPECT_EQ(set.erase(1), 1u);
    EXPECT_EQ(set.erase(2), 1u);
    EXPECT_TRUE(set.empty());
}

TEST(unordered_flat_set, insert_into_completely_full_probe_window) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    pinned_hash hash;
    hash.table.push_back({100, {0, 100}});
    hash.table.push_back({101, {0, 99}});
    for (int i = 0; i < 16; ++i) {
        hash.table.push_back({i, {static_cast<std::size_t>(i), static_cast<std::size_t>(i + 1)}});
    }

    set_t set;
    set.reserve(28);
    for (int i = 0; i < 16; ++i) {
        EXPECT_TRUE(set.insert(i).second);
    }
    ASSERT_EQ(set.size(), 16u);

    EXPECT_TRUE(set.insert(100).second);
    EXPECT_TRUE(set.contains(100));
    for (int i = 0; i < 16; ++i) {
        EXPECT_TRUE(set.contains(i));
    }

    EXPECT_EQ(set.find(101), set.end());
    EXPECT_EQ(set.count(101), 0u);
    EXPECT_FALSE(set.contains(101));
}

TEST(unordered_flat_set, insert_at_last_bucket_wraps_around) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    {
        pinned_hash hash;
        for (int i = 0; i < 10; ++i) {
            hash.table.push_back({i, {14, static_cast<std::size_t>(i + 1)}});
        }

        set_t set(15, hash);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
    }

    {
        pinned_hash hash;
        for (int i = 0; i < 20; ++i) {
            hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
        }

        set_t set;
        set.reserve(28);
        for (int i = 0; i < 20; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_EQ(set.size(), 20u);
        for (int i = 0; i < 20; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
    }
}

TEST(unordered_flat_set, insert_many_collisions_constant_hash) {
    struct constant_hash {
        std::size_t operator()(int) const noexcept {
            return 0;
        }
    };

    using set_t = unordered_flat_set<int, constant_hash>;

    set_t set;
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(set.insert(i).second);
    }

    EXPECT_EQ(set.size(), 1000u);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(set.contains(i));
    }

    for (int i = 0; i < 1000; ++i) {
        EXPECT_EQ(set.erase(i), 1u);
    }
    EXPECT_TRUE(set.empty());
}

TEST(unordered_flat_set, insert_after_mass_erase_reuses_tombstones) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 100; ++i) {
            set.insert(i);
        }
        const std::size_t capacity_before = capacity_from_bytes<int>(alloc_stats::last_size);

        for (int i = 0; i < 50; ++i) {
            EXPECT_EQ(set.erase(i), 1u);
        }

        for (int i = 100; i < 150; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }

        EXPECT_EQ(set.size(), 100u);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), capacity_before);
        for (int i = 50; i < 150; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_duplicate_does_not_grow) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 100000; ++i) {
            set.insert(42);
        }

        EXPECT_EQ(set.size(), 1u);
        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, find_count_contains_agree) {
    set_t set;

    EXPECT_EQ(set.find(1), set.end());
    EXPECT_EQ(set.count(1), 0u);
    EXPECT_FALSE(set.contains(1));

    set.insert(1);

    EXPECT_NE(set.find(1), set.end());
    EXPECT_EQ(set.count(1), 1u);
    EXPECT_TRUE(set.contains(1));

    EXPECT_EQ(set.find(2), set.end());
    EXPECT_EQ(set.count(2), 0u);
    EXPECT_FALSE(set.contains(2));
}

TEST(unordered_flat_set, const_overloads_return_const_iterator) {
    using set_t = unordered_flat_set<int>;

    static_assert(
        std::is_same_v<decltype(std::declval<const set_t &>().find(1)), set_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const set_t &>().begin()), set_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const set_t &>().end()), set_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const set_t &>().cbegin()), set_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const set_t &>().cend()), set_t::const_iterator>);

    set_t mutable_set;
    mutable_set.insert(1);
    const set_t &set = mutable_set;

    EXPECT_EQ(*set.find(1), 1);
    EXPECT_NE(set.begin(), set.end());
    EXPECT_NE(set.cbegin(), set.cend());
}

TEST(unordered_flat_set, heterogeneous_lookup_with_transparent_hash) {
    using set_t = unordered_flat_set<tracked_text, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    set_t set;
    set.insert("alpha");
    set.insert("beta");

    tracked_text::constructions = 0;

    EXPECT_NE(set.find(std::string_view("alpha")), set.end());
    EXPECT_EQ(set.count(std::string_view("alpha")), 1u);
    EXPECT_TRUE(set.contains(std::string_view("alpha")));
    EXPECT_EQ(set.erase(std::string_view("alpha")), 1u);
    EXPECT_FALSE(set.contains(std::string_view("alpha")));
    EXPECT_EQ(set.size(), 1u);
    EXPECT_EQ(tracked_text::constructions, 0);

    const set_t &const_set = set;
    EXPECT_NE(const_set.find(std::string_view("beta")), const_set.end());
}

TEST(unordered_flat_set, heterogeneous_lookup_requires_transparent_hasher) {
    using opaque_set = unordered_flat_set<std::string>;
    using transparent_set =
        unordered_flat_set<tracked_text, transparent_text_hash, transparent_text_equal>;

    static_assert(!can_find<opaque_set, std::string_view>);
    static_assert(!can_count<opaque_set, std::string_view>);
    static_assert(!can_contains<opaque_set, std::string_view>);
    static_assert(can_find<transparent_set, std::string_view>);
    static_assert(can_count<transparent_set, std::string_view>);
    static_assert(can_contains<transparent_set, std::string_view>);
}

TEST(unordered_flat_set, lookup_absent_key_through_tombstones) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 100; ++i) {
            set.insert(i);
        }
        for (int i = 0; i < 50; ++i) {
            set.erase(i);
        }

        for (int i = 1000; i < 1100; ++i) {
            EXPECT_EQ(set.find(i), set.end());
            EXPECT_EQ(set.count(i), 0u);
            EXPECT_FALSE(set.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, lookup_absent_key_through_full_window) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    pinned_hash hash;
    hash.table.push_back({200, {0, 99}});
    for (int i = 0; i < 16; ++i) {
        hash.table.push_back({i, {static_cast<std::size_t>(i), static_cast<std::size_t>(i + 1)}});
    }

    set_t set;
    set.reserve(28);
    for (int i = 0; i < 16; ++i) {
        set.insert(i);
    }

    EXPECT_EQ(set.find(200), set.end());
    EXPECT_EQ(set.count(200), 0u);
    EXPECT_FALSE(set.contains(200));
}

TEST(unordered_flat_set, lookup_after_growth_and_rehash) {
    set_t set;
    for (int i = 0; i < 300; ++i) {
        set.insert(i);
    }
    for (int i = 0; i < 300; ++i) {
        EXPECT_TRUE(set.contains(i));
    }

    set.rehash(1000);
    for (int i = 0; i < 300; ++i) {
        EXPECT_TRUE(set.contains(i));
    }

    for (int i = 300; i < 400; ++i) {
        EXPECT_FALSE(set.contains(i));
    }
}

TEST(unordered_flat_set, find_returns_iterator_to_stored_element) {
    set_t set;
    const auto inserted = set.insert(42);

    const auto found = set.find(42);

    EXPECT_EQ(found, inserted.first);
    EXPECT_EQ(*found, 42);
    EXPECT_EQ(std::addressof(*found), std::addressof(*inserted.first));
}

TEST(unordered_flat_set, erase_iterator_removes_one) {
    set_t set;
    set.insert({1, 2, 3});

    static_assert(std::is_void_v<decltype(set.erase(set.begin()))>);

    const auto position = set.find(2);
    ASSERT_NE(position, set.end());
    set.erase(position);

    EXPECT_EQ(set.size(), 2u);
    EXPECT_FALSE(set.contains(2));
    EXPECT_TRUE(set.contains(1));
    EXPECT_TRUE(set.contains(3));
}

TEST(unordered_flat_set, erase_const_iterator_overload) {
    set_t set;
    set.insert({1, 2, 3});

    set.erase(std::as_const(set).begin());
    EXPECT_EQ(set.size(), 2u);

    set.erase(set.cbegin());
    EXPECT_EQ(set.size(), 1u);
}

TEST(unordered_flat_set, erase_key_returns_count) {
    set_t set;

    EXPECT_EQ(set.erase(1), 0u);

    set.insert(1);
    EXPECT_EQ(set.erase(1), 1u);
    EXPECT_EQ(set.erase(1), 0u);
    EXPECT_FALSE(set.contains(1));
}

TEST(unordered_flat_set, erase_transparent_key) {
    using set_t = unordered_flat_set<tracked_text, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    set_t set;
    set.insert("alpha");
    set.insert("beta");

    tracked_text::constructions = 0;
    EXPECT_EQ(set.erase(std::string_view("alpha")), 1u);
    EXPECT_EQ(tracked_text::constructions, 0);
    EXPECT_EQ(set.size(), 1u);
    EXPECT_TRUE(set.contains(std::string_view("beta")));
}

TEST(unordered_flat_set, erase_range_single_element) {
    set_t set;
    set.insert({1, 2, 3});

    auto first = set.begin();
    auto last  = first;
    ++last;

    const auto result = set.erase(first, last);

    EXPECT_EQ(result, last);
    EXPECT_EQ(set.size(), 2u);
    EXPECT_EQ(std::distance(result, set.end()), static_cast<std::ptrdiff_t>(set.size()));
}

TEST(unordered_flat_set, erase_whole_range_uses_clear) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 10; ++i) {
            set.insert(i);
        }
        const std::size_t capacity_before = capacity_from_bytes<int>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        const auto result = set.erase(set.begin(), set.end());

        EXPECT_EQ(result, set.end());
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, erase_empty_range_is_noop) {
    set_t set;
    set.insert({1, 2, 3});

    const auto first  = set.begin();
    const auto result = set.erase(first, first);

    EXPECT_EQ(result, first);
    EXPECT_EQ(set.size(), 3u);
}

TEST(unordered_flat_set, erase_range_ending_at_end) {
    set_t set;
    set.insert({1, 2, 3, 4, 5});

    auto middle = set.begin();
    std::advance(middle, 3);

    const auto result = set.erase(middle, set.end());

    EXPECT_EQ(result, set.end());
    EXPECT_EQ(set.size(), 3u);
    EXPECT_EQ(std::distance(result, set.end()), 0);
}

TEST(unordered_flat_set, erase_range_on_empty_container) {
    {
        set_t set;
        EXPECT_EQ(set.erase(set.begin(), set.end()), set.end());
    }
    {
        set_t set;
        set.rehash(0);
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(set.erase(set.begin(), set.end()), set.end());
    }
}

TEST(unordered_flat_set, erase_while_iterating_with_postincrement) {
    set_t set;
    for (int i = 0; i < 20; ++i) {
        set.insert(i);
    }

    for (auto iter = set.begin(); iter != set.end();) {
        if (*iter % 2 == 0) {
            set.erase(iter++);
        } else {
            ++iter;
        }
    }

    EXPECT_EQ(set.size(), 10u);
    EXPECT_EQ(std::distance(set.begin(), set.end()), static_cast<std::ptrdiff_t>(set.size()));
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(set.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_set, erase_all_one_by_one) {
    set_t set;
    set.insert({1, 2, 3, 4, 5});

    std::size_t expected = 5;
    while (!set.empty()) {
        set.erase(set.begin());
        --expected;
        EXPECT_EQ(set.size(), expected);
    }

    EXPECT_EQ(set.begin(), set.end());
}

TEST(unordered_flat_set, erase_on_capacity_15_marks_empty) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 10; ++i) {
            set.insert(i);
        }
        ASSERT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);

        for (int i = 0; i < 10; ++i) {
            EXPECT_EQ(set.erase(i), 1u);
        }
        EXPECT_TRUE(set.empty());
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);

        for (int i = 10; i < 20; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_EQ(set.size(), 10u);
        for (int i = 10; i < 20; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, erase_on_capacity_31_marks_deleted) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        set.reserve(28);
        ASSERT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);

        for (int i = 0; i < 20; ++i) {
            set.insert(i);
        }
        for (int i = 5; i < 15; ++i) {
            EXPECT_EQ(set.erase(i), 1u);
        }

        for (int i = 5; i < 15; ++i) {
            EXPECT_FALSE(set.contains(i));
        }
        for (int i = 0; i < 5; ++i) {
            EXPECT_TRUE(set.contains(i));
        }
        for (int i = 15; i < 20; ++i) {
            EXPECT_TRUE(set.contains(i));
        }

        for (int i = 5; i < 15; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_EQ(set.size(), 20u);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 31u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, erase_last_bucket_crosses_mirror) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    pinned_hash hash;
    for (int i = 0; i < 10; ++i) {
        hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
    }

    set_t set;
    set.reserve(28);
    for (int i = 0; i < 10; ++i) {
        set.insert(i);
    }

    for (int i = 0; i < 10; i += 2) {
        EXPECT_EQ(set.erase(i), 1u);
    }

    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(set.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_set, erase_then_insert_same_key_cycles) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 1000; ++i) {
            EXPECT_TRUE(set.insert(42).second);
            EXPECT_EQ(set.size(), 1u);
            EXPECT_EQ(set.erase(42), 1u);
            EXPECT_EQ(set.size(), 0u);
        }

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, erase_does_not_deallocate) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 100; ++i) {
            set.insert(i);
        }
        const std::size_t capacity_before = capacity_from_bytes<int>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;
        const int deallocs_before         = alloc_stats::deallocs;

        for (int i = 0; i < 100; ++i) {
            set.erase(i);
        }

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), capacity_before);

        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, iteration_over_empty) {
    {
        set_t set;
        int visits = 0;
        for ([[maybe_unused]] int value : set) {
            ++visits;
        }
        EXPECT_EQ(visits, 0);
        EXPECT_EQ(set.begin(), set.end());
    }
    {
        set_t set;
        set.insert({1, 2, 3});
        set.clear();
        int visits = 0;
        for ([[maybe_unused]] int value : set) {
            ++visits;
        }
        EXPECT_EQ(visits, 0);
        EXPECT_EQ(set.begin(), set.end());
    }
}

TEST(unordered_flat_set, iteration_over_single_element) {
    set_t set;
    set.insert(7);

    auto iter = set.begin();
    ASSERT_NE(iter, set.end());
    EXPECT_EQ(*iter, 7);

    const auto old = iter++;
    EXPECT_EQ(*old, 7);
    EXPECT_EQ(old, set.begin());
    EXPECT_EQ(iter, set.end());
}

TEST(unordered_flat_set, iteration_visits_every_element_once) {
    set_t set;
    std::vector<int> expected{3, 1, 4, 1, 5, 9, 2, 6};
    for (int value : expected) {
        set.insert(value);
    }

    std::vector<int> visited;
    for (int value : set) {
        visited.push_back(value);
    }
    std::sort(visited.begin(), visited.end());
    std::sort(expected.begin(), expected.end());
    expected.erase(std::unique(expected.begin(), expected.end()), expected.end());

    EXPECT_EQ(visited, expected);
    EXPECT_EQ(std::distance(set.begin(), set.end()), static_cast<std::ptrdiff_t>(set.size()));
}

TEST(unordered_flat_set, iterator_to_const_iterator_conversion) {
    set_t set;
    set.insert(7);

    const set_t::const_iterator const_iter = set.begin();

    EXPECT_EQ(*const_iter, *set.begin());
    EXPECT_EQ(const_iter, set.cbegin());
}

TEST(unordered_flat_set, range_for_on_const_and_non_const) {
    set_t mutable_set;
    mutable_set.insert({1, 2, 3});
    const set_t &set = mutable_set;

    std::vector<int> from_mutable;
    for (int value : mutable_set) {
        from_mutable.push_back(value);
    }
    std::vector<int> from_const;
    for (int value : set) {
        from_const.push_back(value);
    }

    std::sort(from_mutable.begin(), from_mutable.end());
    std::sort(from_const.begin(), from_const.end());
    EXPECT_EQ(from_mutable, from_const);
    EXPECT_EQ(from_const, (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_set, iterator_models_forward_iterator) {
    using set_t = unordered_flat_set<int>;

    static_assert(std::forward_iterator<set_t::iterator>);
    static_assert(std::forward_iterator<set_t::const_iterator>);
    static_assert(std::ranges::forward_range<set_t>);
    static_assert(std::ranges::sized_range<set_t>);
    static_assert(
        std::is_same_v<typename set_t::iterator::iterator_category, std::forward_iterator_tag>);
}

TEST(unordered_flat_set, iteration_skips_deleted_and_empty_states) {
    set_t set;
    for (int i = 0; i < 100; ++i) {
        set.insert(i);
    }
    for (int i = 0; i < 100; i += 2) {
        set.erase(i);
    }

    std::size_t visits = 0;
    for (int value : set) {
        EXPECT_EQ(value % 2, 1);
        ++visits;
    }

    EXPECT_EQ(visits, set.size());
    EXPECT_EQ(visits, 50u);
}

TEST(unordered_flat_set, iteration_handles_h2_boundary_values) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    set_t set(15, make_pinned_hash({{1, {3, 0}}, {2, {7, 127}}}));

    set.insert(1);
    set.insert(2);

    std::vector<int> visited;
    for (int value : set) {
        visited.push_back(value);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited, (std::vector<int>{1, 2}));
}

TEST(unordered_flat_set, iteration_across_mirror_tail) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    pinned_hash hash;
    for (int i = 0; i < 10; ++i) {
        hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
    }

    set_t set;
    set.reserve(28);
    for (int i = 0; i < 10; ++i) {
        set.insert(i);
    }

    std::vector<int> visited;
    for (int value : set) {
        visited.push_back(value);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited.size(), 10u);
    EXPECT_EQ(visited, (std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
}

TEST(unordered_flat_set, iteration_after_clear_and_rehash) {
    set_t set;
    set.insert({1, 2, 3});
    set.clear();
    EXPECT_EQ(set.begin(), set.end());

    set.rehash(1000);
    EXPECT_EQ(set.begin(), set.end());

    for (int i = 0; i < 10; ++i) {
        set.insert(i);
    }

    std::vector<int> visited;
    for (int value : set) {
        visited.push_back(value);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited, (std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
}

TEST(unordered_flat_set, default_iterator_equality_is_state_based) {
    using set_t = unordered_flat_set<int>;

    EXPECT_EQ(set_t::iterator{}, set_t::iterator{});
    EXPECT_EQ(set_t::const_iterator{}, set_t::const_iterator{});

    set_t set;
    EXPECT_EQ(set.begin(), set_t::iterator{});
    EXPECT_EQ(set.end(), set_t::iterator{});
    EXPECT_EQ(set.cbegin(), set_t::const_iterator{});
    EXPECT_EQ(set.cend(), set_t::const_iterator{});
}

TEST(unordered_flat_set, operator_arrow_matches_dereference) {
    using set_t = unordered_flat_set<payload_key, payload_hash>;

    set_t set;
    set.insert(payload_key{1, 10});
    set.insert(payload_key{2, 20});

    for (auto iter = set.begin(); iter != set.end(); ++iter) {
        EXPECT_EQ(iter.operator->(), std::addressof(*iter));
        EXPECT_EQ(iter->id, (*iter).id);
        EXPECT_EQ(iter->payload, (*iter).payload);
    }
}

TEST(unordered_flat_set, default_allocator_is_value_initialized) {
    set_t set;
    EXPECT_EQ(set.get_allocator(), set_t::allocator_type{});
}

TEST(unordered_flat_set, ctor_and_range_ctor_keep_allocator) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

    tagged_allocator<int> alloc{7};
    std::vector<int> values{1, 2, 3};

    set_t direct(15, alloc);
    set_t with_hash(15, std::hash<int>{}, alloc);
    set_t alloc_only(alloc);
    set_t from_range(values.begin(), values.end(), 15, alloc);
    set_t from_range_with_hash(values.begin(), values.end(), 15, std::hash<int>{}, alloc);
    set_t from_list({1, 2, 3}, 15, alloc);
    set_t from_list_with_hash({1, 2, 3}, 15, std::hash<int>{}, alloc);

    EXPECT_EQ(direct.get_allocator().id, 7);
    EXPECT_EQ(with_hash.get_allocator().id, 7);
    EXPECT_EQ(alloc_only.get_allocator().id, 7);
    EXPECT_EQ(from_range.get_allocator().id, 7);
    EXPECT_EQ(from_range_with_hash.get_allocator().id, 7);
    EXPECT_EQ(from_list.get_allocator().id, 7);
    EXPECT_EQ(from_list_with_hash.get_allocator().id, 7);

    EXPECT_TRUE(direct.insert(4).second);
    EXPECT_TRUE(alloc_only.insert(4).second);
    EXPECT_EQ(from_range.size(), 3u);
    EXPECT_EQ(from_list.size(), 3u);
}

TEST(unordered_flat_set, copy_ctor_uses_soccc) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, soccc_allocator<int>>;

    set_t source(15, soccc_allocator<int>{7});
    source.insert({1, 2, 3});

    set_t copy(source);

    EXPECT_EQ(copy.get_allocator().id, 107);
    EXPECT_EQ(sorted_elements(copy), (std::vector<int>{1, 2, 3}));

    set_t target(15, soccc_allocator<int>{3});
    target = source;

    EXPECT_EQ(target.get_allocator().id, 3);
    EXPECT_EQ(sorted_elements(target), (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_set, copy_assign_propagates_only_with_pocca) {
    alloc_registry::reset();
    {
        check_copy_assign_propagation<pocca_allocator<int>>(true);
        check_copy_assign_propagation<tagged_allocator<int>>(false);
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, move_assign_propagates_only_with_pocma) {
    alloc_registry::reset();
    {
        check_unequal_move_assign<pocma_allocator<int>>();
        check_unequal_move_assign<tagged_allocator<int>>();
        check_equal_move_assign<tagged_allocator<int>>();
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, swap_propagates_only_with_pocs) {
    alloc_registry::reset();
    {
        check_swap_keeps_owners<pocs_allocator<int>>();
        check_swap_keeps_owners<tagged_allocator<int>>();
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_set, no_foreign_or_double_deallocation) {
    alloc_registry::reset();
    {
        using set_t =
            unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

        set_t a(15, tagged_allocator<int>{1});
        a.insert({1, 2, 3});
        set_t b(15, tagged_allocator<int>{2});
        b.insert({10, 20, 30, 40});

        set_t copy(a);
        b = a;
        b = std::move(copy);
        a.swap(b);

        EXPECT_EQ(sorted_elements(a), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(sorted_elements(b), (std::vector<int>{1, 2, 3}));
    }

    EXPECT_TRUE(alloc_registry::live.empty());
    EXPECT_EQ(alloc_registry::wrong_owner, 0);
    EXPECT_EQ(alloc_registry::unknown_ptr, 0);
    EXPECT_EQ(alloc_registry::wrong_size, 0);
}

TEST(unordered_flat_set, deallocation_uses_original_allocation_size) {
    alloc_registry::reset();
    {
        using set_t =
            unordered_flat_set<int, std::hash<int>, std::equal_to<>, tagged_allocator<int>>;

        set_t set(15, tagged_allocator<int>{1});
        set.rehash(1000);
        set.insert({1, 2, 3});
        set.rehash(10000);
        set.insert({4, 5, 6});
    }

    EXPECT_EQ(alloc_registry::wrong_size, 0);
    EXPECT_EQ(alloc_registry::wrong_owner, 0);
    EXPECT_EQ(alloc_registry::unknown_ptr, 0);
    EXPECT_TRUE(alloc_registry::live.empty());
}

TEST(unordered_flat_set, every_path_returns_to_zero_allocation) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t a;
        a.reserve(100);
        for (int i = 0; i < 100; ++i) {
            a.insert(i);
        }

        set_t b(a);
        set_t c(std::move(b));
        set_t d;
        d = c;
        set_t e;
        e = std::move(d);
        e.swap(c);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, pmr_style_resources_are_isolated) {
    using pmr_alloc = std::pmr::polymorphic_allocator<int>;
    using pmr_set   = unordered_flat_set<int, std::hash<int>, std::equal_to<>, pmr_alloc>;

    std::pmr::monotonic_buffer_resource resource1;
    std::pmr::monotonic_buffer_resource resource2;

    pmr_set a(15, pmr_alloc(&resource1));
    a.insert({1, 2, 3});
    pmr_set b(15, pmr_alloc(&resource2));
    b.insert({10, 20});

    EXPECT_EQ(a.get_allocator().resource(), &resource1);
    EXPECT_EQ(b.get_allocator().resource(), &resource2);

    pmr_set moved(std::move(a));
    EXPECT_EQ(moved.get_allocator().resource(), &resource1);
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(sorted_elements(moved), (std::vector<int>{1, 2, 3}));

    pmr_set copy(moved);
    EXPECT_EQ(copy.get_allocator().resource(), std::pmr::get_default_resource());
    EXPECT_EQ(sorted_elements(copy), (std::vector<int>{1, 2, 3}));

    EXPECT_TRUE(copy.insert(4).second);
    EXPECT_EQ(copy.size(), 4u);
}

TEST(unordered_flat_set, non_trivial_destructor_balance) {
    using set_t =
        unordered_flat_set<live_key, live_key_hash, std::equal_to<>, counting_allocator<live_key>>;

    live_key::live = 0;
    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 10; ++i) {
            set.insert(live_key(i));
        }
        EXPECT_EQ(live_key::live, 10);

        set.erase(set.begin());
        EXPECT_EQ(live_key::live, 9);

        set.erase(live_key(5));
        EXPECT_EQ(live_key::live, 8);

        set.clear();
        EXPECT_EQ(live_key::live, 0);

        for (int i = 0; i < 4; ++i) {
            set.insert(live_key(i));
        }
        EXPECT_EQ(live_key::live, 4);

        set_t copy(set);
        EXPECT_EQ(live_key::live, 8);

        copy = set;
        EXPECT_EQ(live_key::live, 8);

        set_t moved(std::move(copy));
        EXPECT_EQ(live_key::live, 8);
        EXPECT_TRUE(copy.empty());

        set = std::move(moved);
        EXPECT_EQ(live_key::live, 4);
        EXPECT_TRUE(moved.empty());
        EXPECT_EQ(set.size(), 4u);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, move_only_key) {
    using set_t = unordered_flat_set<std::unique_ptr<int>, unique_ptr_hash, unique_ptr_equal>;

    set_t set;
    EXPECT_TRUE(set.insert(std::make_unique<int>(1)).second);
    EXPECT_TRUE(set.emplace(std::make_unique<int>(2)).second);

    auto probe = std::make_unique<int>(1);
    EXPECT_NE(set.find(probe), set.end());
    EXPECT_EQ(set.erase(probe), 1u);
    EXPECT_FALSE(set.contains(probe));

    set.rehash(100);

    set_t moved(std::move(set));
    EXPECT_EQ(moved.size(), 1u);
    auto probe2 = std::make_unique<int>(2);
    EXPECT_NE(moved.find(probe2), moved.end());

    set_t assigned;
    assigned = std::move(moved);
    EXPECT_EQ(assigned.size(), 1u);
    EXPECT_TRUE(moved.empty());
    EXPECT_NE(assigned.find(probe2), assigned.end());
}

TEST(unordered_flat_set, non_assignable_key) {
    using set_t = unordered_flat_set<non_assignable_key, non_assignable_hash>;

    static_assert(!std::is_copy_assignable_v<non_assignable_key>);
    static_assert(std::is_copy_constructible_v<non_assignable_key>);

    set_t set;
    EXPECT_TRUE(set.insert(non_assignable_key(1)).second);
    EXPECT_TRUE(set.insert(non_assignable_key(2)).second);

    set_t copy(set);
    EXPECT_EQ(copy.size(), 2u);

    copy.rehash(100);
    EXPECT_EQ(copy.size(), 2u);
    EXPECT_TRUE(copy.contains(non_assignable_key(1)));
    EXPECT_TRUE(copy.contains(non_assignable_key(2)));

    set_t assigned;
    assigned = copy;
    EXPECT_EQ(assigned.size(), 2u);
    EXPECT_TRUE(assigned.contains(non_assignable_key(1)));
}

TEST(unordered_flat_set, string_key_with_sso_and_long_values) {
    using string_set = unordered_flat_set<std::string>;

    string_set set;
    const std::string long_value(200, 'x');

    EXPECT_TRUE(set.insert("abc").second);
    EXPECT_TRUE(set.insert(long_value).second);

    EXPECT_TRUE(set.contains("abc"));
    EXPECT_TRUE(set.contains(long_value));

    EXPECT_EQ(set.erase("abc"), 1u);
    EXPECT_FALSE(set.contains("abc"));

    set.rehash(1000);
    EXPECT_TRUE(set.contains(long_value));
    EXPECT_EQ(set.size(), 1u);
}

TEST(unordered_flat_set, large_key) {
    using set_t = unordered_flat_set<large_key, large_key_hash>;

    set_t set;
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(set.insert(large_key{i, {}}).second);
    }

    EXPECT_EQ(set.size(), 1000u);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(set.contains(large_key{i, {}}));
    }

    set.rehash(2000);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(set.contains(large_key{i, {}}));
    }

    for (int i = 0; i < 1000; i += 2) {
        EXPECT_EQ(set.erase(large_key{i, {}}), 1u);
    }
    EXPECT_EQ(set.size(), 500u);
}

TEST(unordered_flat_set, over_aligned_key) {
    for (std::size_t reserve_count :
         {std::size_t{0}, std::size_t{14}, std::size_t{28}, std::size_t{100}}) {
        check_element_alignment<16>(reserve_count);
        check_element_alignment<32>(reserve_count);
        check_element_alignment<64>(reserve_count);
    }
}

TEST(unordered_flat_set, empty_key_type_is_single_element) {
    using set_t = unordered_flat_set<empty_key, empty_key_hash>;

    set_t set;
    for (int i = 0; i < 10; ++i) {
        set.insert(empty_key{});
    }

    EXPECT_EQ(set.size(), 1u);
    EXPECT_NE(set.find(empty_key{}), set.end());
    EXPECT_TRUE(set.contains(empty_key{}));
    EXPECT_EQ(set.erase(empty_key{}), 1u);
    EXPECT_TRUE(set.empty());
}

TEST(unordered_flat_set, narrow_key_types) {
    {
        unordered_flat_set<bool> set;
        EXPECT_TRUE(set.insert(true).second);
        EXPECT_TRUE(set.insert(false).second);
        EXPECT_EQ(set.size(), 2u);
        EXPECT_TRUE(set.contains(true));
        EXPECT_TRUE(set.contains(false));
        EXPECT_EQ(set.erase(true), 1u);
        EXPECT_FALSE(set.contains(true));
    }
    {
        unordered_flat_set<char> set;
        for (char i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_TRUE(set.contains(char{5}));
        EXPECT_EQ(set.erase(char{5}), 1u);
        EXPECT_EQ(set.size(), 9u);
    }
    {
        unordered_flat_set<short> set;
        for (short i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.insert(i).second);
        }
        EXPECT_TRUE(set.contains(short{5}));
        EXPECT_EQ(set.erase(short{5}), 1u);
        EXPECT_EQ(set.size(), 9u);
    }
}

TEST(unordered_flat_set, key_with_throwing_hash_or_equal) {
    using set_t = unordered_flat_set<int, flaky_hash, flaky_equal>;

    flaky_hash::armed  = false;
    flaky_equal::armed = false;

    set_t set;
    set.insert(42);

    flaky_hash::armed = true;
    EXPECT_THROW((void)set.find(42), std::runtime_error);
    EXPECT_THROW((void)set.count(42), std::runtime_error);
    EXPECT_THROW((void)set.contains(42), std::runtime_error);
    flaky_hash::armed = false;

    EXPECT_EQ(set.size(), 1u);
    EXPECT_NE(set.find(42), set.end());

    flaky_equal::armed = true;
    EXPECT_THROW((void)set.find(42), std::runtime_error);
    EXPECT_THROW((void)set.erase(42), std::runtime_error);
    flaky_equal::armed = false;

    EXPECT_EQ(set.size(), 1u);
    EXPECT_NE(set.find(42), set.end());
    EXPECT_TRUE(set.insert(43).second);
}

TEST(unordered_flat_set, copy_ctor_strong_guarantee) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t source;
        for (int i = 0; i < 10; ++i) {
            source.insert(throwing_key(i));
        }
        ASSERT_EQ(throwing_key::live, 10);
        ASSERT_EQ(alloc_stats::allocs, 1);

        throwing_key::copies_until_throw = 3;
        EXPECT_THROW(
            {
                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
                set_t copy(source);
                (void)copy;
            },
            std::runtime_error);

        throwing_key::reset_counters();

        EXPECT_EQ(throwing_key::live, 10);
        EXPECT_EQ(source.size(), 10u);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(source.contains(throwing_key(i)));
        }
        EXPECT_EQ(alloc_stats::allocs, 2);
        EXPECT_EQ(alloc_stats::deallocs, 1);
    }
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, range_ctor_strong_guarantee) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();

    std::vector<throwing_key> values;
    values.reserve(8);
    for (int i = 0; i < 8; ++i) {
        values.emplace_back(i);
    }
    ASSERT_EQ(throwing_key::live, 8);

    throwing_key::copies_until_throw = 2;
    EXPECT_THROW(
        {
            set_t set(values.begin(), values.end());
            (void)set;
        },
        std::runtime_error);

    throwing_key::reset_counters();

    EXPECT_EQ(throwing_key::live, 8);
    EXPECT_EQ(alloc_stats::allocs, 1);
    EXPECT_EQ(alloc_stats::deallocs, 1);
}

TEST(unordered_flat_set, insert_weak_guarantee) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 5; ++i) {
            set.insert(throwing_key(i));
        }
        const int allocs_before = alloc_stats::allocs;

        throwing_key candidate(99);
        throwing_key::copies_until_throw = 0;

        EXPECT_THROW(set.insert(candidate), std::runtime_error);

        throwing_key::reset_counters();

        EXPECT_EQ(set.size(), 5u);
        EXPECT_EQ(std::distance(set.begin(), set.end()), static_cast<std::ptrdiff_t>(set.size()));
        for (int i = 0; i < 5; ++i) {
            EXPECT_TRUE(set.contains(throwing_key(i)));
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, rehash_weak_guarantee) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 10; ++i) {
            set.insert(throwing_key(i));
        }
        EXPECT_EQ(throwing_key::live, 10);

        throwing_key::moves_until_throw = 4;
        EXPECT_THROW(set.rehash(1000), std::runtime_error);
        throwing_key::reset_counters();

        EXPECT_EQ(throwing_key::live, 10);
        EXPECT_EQ(set.size(), 10u);
        EXPECT_EQ(std::distance(set.begin(), set.end()), static_cast<std::ptrdiff_t>(set.size()));
        EXPECT_FLOAT_EQ(set.load_factor(), static_cast<float>(10.0 / 16.0));

        set.clear();
        EXPECT_EQ(throwing_key::live, 0);
        for (int i = 0; i < 10; ++i) {
            set.insert(throwing_key(i));
        }

        set.rehash(1000);
        EXPECT_EQ(set.size(), 10u);
        EXPECT_FLOAT_EQ(set.load_factor(), static_cast<float>(10.0 / 1024.0));
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.contains(throwing_key(i)));
        }
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, insert_growth_path_exception) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 14; ++i) {
            set.insert(throwing_key(i));
        }
        ASSERT_EQ(set.size(), 14u);

        throwing_key::moves_until_throw = 7;
        EXPECT_THROW(set.insert(throwing_key(14)), std::runtime_error);
        throwing_key::reset_counters();

        EXPECT_EQ(throwing_key::live, 14);
        EXPECT_EQ(set.size(), 14u);
        EXPECT_EQ(std::distance(set.begin(), set.end()), static_cast<std::ptrdiff_t>(set.size()));

        set.clear();
        EXPECT_EQ(throwing_key::live, 0);
        for (int i = 0; i < 15; ++i) {
            EXPECT_TRUE(set.insert(throwing_key(i)).second);
        }
        EXPECT_EQ(set.size(), 15u);
        EXPECT_FLOAT_EQ(set.load_factor(), static_cast<float>(15.0 / 32.0));
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, length_error_leaves_container_usable) {
    set_t set;
    set.insert({1, 2, 3});

    EXPECT_THROW(set.rehash((std::numeric_limits<std::size_t>::max)()), std::length_error);

    EXPECT_EQ(sorted_elements(set), (std::vector<int>{1, 2, 3}));
    EXPECT_TRUE(set.insert(4).second);
    EXPECT_EQ(set.size(), 4u);
}

TEST(unordered_flat_set, copy_assign_weak_guarantee) {
    using set_t = unordered_flat_set<throwing_key, throwing_key_hash, std::equal_to<>,
                                     counting_allocator<throwing_key>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        set_t target;
        for (int i = 0; i < 5; ++i) {
            target.insert(throwing_key(i));
        }

        set_t source;
        for (int i = 0; i < 10; ++i) {
            source.insert(throwing_key(100 + i));
        }
        ASSERT_EQ(throwing_key::live, 15);

        throwing_key::copies_until_throw = 4;
        EXPECT_THROW(target = source, std::runtime_error);
        throwing_key::reset_counters();

        EXPECT_EQ(std::distance(target.begin(), target.end()),
                  static_cast<std::ptrdiff_t>(target.size()));
        EXPECT_LE(target.size(), 10u);
        EXPECT_EQ(throwing_key::live, 10 + static_cast<int>(target.size()));

        target = source;
        EXPECT_EQ(target.size(), 10u);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(target.contains(throwing_key(100 + i)));
        }
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, exception_during_swap_no_effect) {
    using set_t =
        unordered_flat_set<int, std::hash<int>, std::equal_to<>, throwing_swap_allocator<int>>;

    throwing_swap_allocator<int>::armed = false;
    {
        set_t a(15, throwing_swap_allocator<int>{1});
        a.insert({1, 2, 3});
        set_t b(15, throwing_swap_allocator<int>{2});
        b.insert({10, 20});

        throwing_swap_allocator<int>::armed = true;
        EXPECT_THROW(a.swap(b), std::runtime_error);
        throwing_swap_allocator<int>::armed = false;

        EXPECT_EQ(sorted_elements(a), (std::vector<int>{1, 2, 3}));
        EXPECT_EQ(sorted_elements(b), (std::vector<int>{10, 20}));
        EXPECT_EQ(a.get_allocator().id, 1);
        EXPECT_EQ(b.get_allocator().id, 2);
    }
}

TEST(unordered_flat_set, differential_against_std_unordered_set) {
    set_t set;
    std::unordered_set<int> reference;
    std::mt19937 engine(123456789);

    for (int step = 0; step < 200000; ++step) {
        const int op  = static_cast<int>(engine() % 100);
        const int key = static_cast<int>(engine() % 1000);

        if (op < 55) {
            const bool inserted = set.insert(key).second;
            const bool expected = reference.insert(key).second;
            EXPECT_EQ(inserted, expected);
        } else if (op < 95) {
            EXPECT_EQ(set.erase(key), reference.erase(key));
        } else if (op < 99) {
            EXPECT_EQ(set.contains(key), reference.contains(key));
        } else {
            set.clear();
            reference.clear();
        }

        EXPECT_EQ(set.size(), reference.size());
        EXPECT_EQ(set.contains(key), reference.contains(key));

        if (step % 1000 == 0) {
            std::vector<int> actual(set.begin(), set.end());
            std::vector<int> expected(reference.begin(), reference.end());
            std::sort(actual.begin(), actual.end());
            std::sort(expected.begin(), expected.end());
            EXPECT_EQ(actual, expected);
        }
    }

    std::vector<int> actual(set.begin(), set.end());
    std::vector<int> expected(reference.begin(), reference.end());
    std::sort(actual.begin(), actual.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(actual, expected);
}

TEST(unordered_flat_set, adversarial_pinned_hash_layouts) {
    using set_t = unordered_flat_set<int, pinned_hash>;

    pinned_hash hash;
    hash.table.push_back({1, {5, 1}});
    hash.table.push_back({2, {5, 2}});
    hash.table.push_back({3, {5, 127}});
    hash.table.push_back({4, {6, 42}});
    hash.table.push_back({5, {7, 42}});
    hash.table.push_back({6, {8, 42}});
    hash.table.push_back({7, {9, 50}});
    hash.table.push_back({8, {9, 50}});
    for (int i = 0; i < 16; ++i) {
        hash.table.push_back(
            {10 + i, {static_cast<std::size_t>(i), static_cast<std::size_t>(i + 1)}});
    }
    hash.table.push_back({30, {0, 100}});
    for (int i = 0; i < 10; ++i) {
        hash.table.push_back({40 + i, {30, static_cast<std::size_t>(i + 20)}});
    }

    {
        set_t set;
        set.reserve(28);

        for (int key = 1; key <= 8; ++key) {
            EXPECT_TRUE(set.insert(key).second);
        }
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(set.insert(10 + i).second);
        }
        EXPECT_TRUE(set.insert(30).second);

        for (int key = 1; key <= 8; ++key) {
            EXPECT_TRUE(set.contains(key));
        }
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(set.contains(10 + i));
        }
        EXPECT_TRUE(set.contains(30));

        for (int key = 1; key <= 8; ++key) {
            EXPECT_EQ(set.erase(key), 1u);
        }
        for (int i = 0; i < 16; i += 2) {
            EXPECT_EQ(set.erase(10 + i), 1u);
        }
        EXPECT_EQ(set.erase(30), 1u);
        EXPECT_EQ(set.size(), 8u);
    }

    {
        set_t set;
        set.reserve(28);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.insert(40 + i).second);
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(set.contains(40 + i));
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_EQ(set.erase(40 + i), 1u);
        }
        EXPECT_TRUE(set.empty());
    }
}

TEST(unordered_flat_set, growth_sweep_1_to_300) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;

        for (int i = 1; i <= 300; ++i) {
            set.insert(i);

            const std::size_t capacity = capacity_from_bytes<int>(alloc_stats::last_size);
            EXPECT_EQ(capacity, detail::swiss_table_size_to_capacity(static_cast<std::size_t>(i)));
            EXPECT_EQ(set.size(), static_cast<std::size_t>(i));
            EXPECT_EQ(std::distance(set.begin(), set.end()),
                      static_cast<std::ptrdiff_t>(set.size()));
            EXPECT_LE(set.load_factor(), set.max_load_factor());

            for (int j = 1; j <= i; ++j) {
                ASSERT_TRUE(set.contains(j)) << "i=" << i << " j=" << j;
            }
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, tombstone_storm) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        std::vector<bool> present(100, false);
        std::size_t live_count = 0;
        std::mt19937 engine(987654321);

        for (int step = 0; step < 100000; ++step) {
            const int key = static_cast<int>(engine() % 100);
            if (engine() & 1) {
                if (set.insert(key).second) {
                    ASSERT_FALSE(present[static_cast<std::size_t>(key)]);
                    present[static_cast<std::size_t>(key)] = true;
                    ++live_count;
                }
            } else {
                const auto erased = set.erase(key);
                EXPECT_EQ(erased, present[static_cast<std::size_t>(key)] ? 1u : 0u);
                if (erased != 0) {
                    present[static_cast<std::size_t>(key)] = false;
                    --live_count;
                }
            }

            ASSERT_EQ(set.size(), live_count);

            if (step % 1000 == 0) {
                for (int i = 0; i < 100; ++i) {
                    EXPECT_EQ(set.contains(i), present[static_cast<std::size_t>(i)]);
                }
            }
        }

        EXPECT_LE(capacity_from_bytes<int>(alloc_stats::last_size), 127u);
        EXPECT_LE(set.load_factor(), set.max_load_factor());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, clear_insert_cycles) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t set;
        for (int i = 0; i < 50; ++i) {
            set.insert(i);
        }
        const std::size_t capacity_before = capacity_from_bytes<int>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        for (int round = 0; round < 5; ++round) {
            set.clear();
            EXPECT_TRUE(set.empty());
            EXPECT_EQ(capacity_from_bytes<int>(alloc_stats::last_size), capacity_before);

            for (int i = 0; i < 50; ++i) {
                EXPECT_TRUE(set.insert(i).second);
            }
            EXPECT_EQ(set.size(), 50u);
            for (int i = 0; i < 50; ++i) {
                EXPECT_TRUE(set.contains(i));
            }
            EXPECT_EQ(alloc_stats::allocs, allocs_before);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, move_copy_churn) {
    using set_t = unordered_flat_set<int, std::hash<int>, std::equal_to<>, counting_allocator<int>>;

    alloc_stats::reset();
    {
        set_t base;
        for (int i = 0; i < 100; ++i) {
            base.insert(i);
        }

        for (int round = 0; round < 50; ++round) {
            set_t copy(base);
            set_t moved(std::move(copy));
            set_t assigned;
            assigned = base;
            set_t moved_assigned;
            moved_assigned = std::move(assigned);

            EXPECT_EQ(moved.size(), 100u);
            EXPECT_EQ(moved_assigned.size(), 100u);
            EXPECT_TRUE(moved.contains(round));
            EXPECT_TRUE(moved_assigned.contains(round));
        }

        EXPECT_EQ(base.size(), 100u);
        for (int i = 0; i < 100; ++i) {
            EXPECT_TRUE(base.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_set, large_set_smoke) {
    set_t set;
    constexpr int count = 100000;

    for (int i = 0; i < count; ++i) {
        set.insert(i);
    }
    EXPECT_EQ(set.size(), static_cast<std::size_t>(count));

    for (int i = 0; i < count; ++i) {
        ASSERT_TRUE(set.contains(i)) << "i=" << i;
    }

    for (int i = 0; i < count; i += 2) {
        set.erase(i);
    }
    EXPECT_EQ(set.size(), static_cast<std::size_t>(count / 2));
    for (int i = 0; i < count; ++i) {
        EXPECT_EQ(set.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_set, typedefs_are_correct) {
    using set_t = unordered_flat_set<int>;

    static_assert(std::is_same_v<set_t::key_type, int>);
    static_assert(std::is_same_v<set_t::value_type, int>);
    static_assert(
        std::is_same_v<set_t::size_type, std::allocator_traits<set_t::allocator_type>::size_type>);
    static_assert(std::is_same_v<set_t::difference_type,
                                 std::allocator_traits<set_t::allocator_type>::difference_type>);
    static_assert(std::is_same_v<set_t::iterator::pointer, set_t::const_pointer>);
    static_assert(std::is_same_v<set_t::iterator::reference, set_t::const_reference>);
    static_assert(std::is_same_v<set_t::const_iterator::pointer, set_t::const_pointer>);
    static_assert(std::is_same_v<set_t::const_iterator::reference, set_t::const_reference>);
}

TEST(unordered_flat_set, move_operations_are_noexcept) {
    using set_t = unordered_flat_set<int>;

    static_assert(std::is_nothrow_move_constructible_v<set_t>);
    static_assert(std::is_nothrow_move_assignable_v<set_t>);
    static_assert(noexcept(std::declval<set_t &>().swap(std::declval<set_t &>())));
}

TEST(unordered_flat_set, erase_return_types) {
    using set_t = unordered_flat_set<int>;

    static_assert(
        std::is_void_v<decltype(std::declval<set_t &>().erase(std::declval<set_t::iterator>()))>);
    static_assert(std::is_void_v<decltype(std::declval<set_t &>().erase(
                      std::declval<set_t::const_iterator>()))>);
    static_assert(std::is_same_v<decltype(std::declval<set_t &>().erase(
                                     std::declval<set_t::const_iterator>(),
                                     std::declval<set_t::const_iterator>())),
                                 set_t::iterator>);
}

TEST(unordered_flat_set, emplace_requires_constructible) {
    using set_t = unordered_flat_set<int>;

    static_assert(can_emplace<set_t, int>);
    static_assert(!can_emplace<set_t, int, int, int>);
}

TEST(unordered_flat_set, insert_transparent_requires_constraint) {
    using opaque_set = unordered_flat_set<std::string>;
    using transparent_set =
        unordered_flat_set<tracked_text, transparent_text_hash, transparent_text_equal>;

    static_assert(!can_insert<opaque_set, std::string_view>);
    static_assert(can_insert<transparent_set, std::string_view>);
    static_assert(!can_insert<opaque_set, int>);
}

TEST(unordered_flat_set, bucket_count_zero_is_not_a_length_error) {
    using set_t = unordered_flat_set<int>;

    EXPECT_NO_THROW({
        set_t set(0);
        (void)set;
    });
}

TEST(unordered_flat_set, object_size_stays_compressed) {
    using set_t = unordered_flat_set<int>;

    EXPECT_LE(sizeof(set_t), 5 * sizeof(void *));
}
