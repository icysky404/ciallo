#include "ciallo/container/unordered_flat_map.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <list>
#include <map>
#include <memory>
#include <memory_resource>
#include <random>
#include <ranges>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
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

struct tracked_value {
    static inline int constructions = 0;
    static inline int assignments   = 0;
    static inline int defaults      = 0;

    int value = 0;

    static void reset_counters() {
        constructions = 0;
        assignments   = 0;
        defaults      = 0;
    }

    tracked_value() {
        ++defaults;
    }

    explicit tracked_value(int value) : value(value) {
        ++constructions;
    }

    tracked_value(const tracked_value &other) : value(other.value) {
        ++constructions;
    }

    tracked_value(tracked_value &&other) noexcept : value(other.value) {
        ++constructions;
        other.value = -1;
    }

    tracked_value &operator=(const tracked_value &other) {
        value = other.value;
        ++assignments;
        return *this;
    }

    tracked_value &operator=(tracked_value &&other) noexcept {
        value = other.value;
        ++assignments;
        other.value = -1;
        return *this;
    }

    tracked_value &operator=(int new_value) {
        value = new_value;
        ++assignments;
        return *this;
    }
};

using map_t     = unordered_flat_map<int, int>;
using map_value = std::pair<const int, int>;

template <typename Map, typename Key>
concept can_find = requires(Map &map, const Key &key) { map.find(key); };

template <typename Map, typename Key>
concept can_count = requires(Map &map, const Key &key) { map.count(key); };

template <typename Map, typename Key>
concept can_contains = requires(Map &map, const Key &key) { map.contains(key); };

template <typename Map, typename Key>
concept can_at = requires(Map &map, const Key &key) { map.at(key); };

template <typename Map, typename Key>
concept can_subscript = requires(Map &map, Key &&key) { map[std::forward<Key>(key)]; };

template <typename Map, typename Key>
concept can_insert = requires(Map &map, Key &&key) { map.insert(std::forward<Key>(key)); };

template <typename Map, typename Key, typename Mapped>
concept can_insert_or_assign = requires(Map &map, Key &&key, Mapped &&mapped) {
    map.insert_or_assign(std::forward<Key>(key), std::forward<Mapped>(mapped));
};

template <typename Map, typename Key, typename... Args>
concept can_try_emplace = requires(Map &map, Key &&key, Args &&...args) {
    map.try_emplace(std::forward<Key>(key), std::forward<Args>(args)...);
};

template <typename Map, typename... Args>
concept can_emplace =
    requires(Map &map, Args &&...args) { map.emplace(std::forward<Args>(args)...); };

} // namespace

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

template <typename Map>
static std::vector<std::pair<typename Map::key_type, typename Map::mapped_type>>
sorted_entries(const Map &map) {
    std::vector<std::pair<typename Map::key_type, typename Map::mapped_type>> result;
    result.reserve(map.size());
    for (const auto &[key, value] : map) {
        result.emplace_back(key, value);
    }
    std::sort(result.begin(), result.end());
    return result;
}

static pinned_hash make_pinned_hash(
    std::initializer_list<std::pair<int, std::pair<std::size_t, std::size_t>>> entries) {
    return pinned_hash{std::vector<std::pair<int, std::pair<std::size_t, std::size_t>>>(entries)};
}

template <typename Allocator>
static void check_copy_assign_propagation(bool expect_propagation) {
    using map_type = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, Allocator>;

    map_type target(15, Allocator{1});
    target.insert({{1, 10}, {2, 20}, {3, 30}});
    map_type source(15, Allocator{2});
    source.insert({{10, 100}, {20, 200}});

    target = source;

    const int expected_id = expect_propagation ? 2 : 1;
    EXPECT_EQ(target.get_allocator().id, expected_id);
    EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
}

template <typename Allocator>
static void check_unequal_move_assign() {
    using map_type = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, Allocator>;

    map_type target(15, Allocator{1});
    target.insert({{1, 10}, {2, 20}, {3, 30}});
    map_type source(15, Allocator{2});
    source.insert({{10, 100}, {20, 200}});

    target = std::move(source);

    EXPECT_EQ(target.get_allocator().id, 2);
    EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
    EXPECT_TRUE(source.empty());
}

template <typename Allocator>
static void check_equal_move_assign() {
    using map_type = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, Allocator>;

    map_type target(15, Allocator{5});
    target.insert({{1, 10}, {2, 20}, {3, 30}});
    map_type source(15, Allocator{5});
    source.insert({{10, 100}, {20, 200}});

    target = std::move(source);

    EXPECT_EQ(target.get_allocator().id, 5);
    EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
    EXPECT_TRUE(source.empty());
}

template <typename Allocator>
static void check_swap_keeps_owners() {
    using map_type = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, Allocator>;

    map_type a(15, Allocator{1});
    a.insert({{1, 10}, {2, 20}, {3, 30}});
    map_type b(15, Allocator{2});
    b.insert({{10, 100}, {20, 200}});

    a.swap(b);

    EXPECT_EQ(a.get_allocator().id, 2);
    EXPECT_EQ(b.get_allocator().id, 1);
    EXPECT_EQ(sorted_entries(a), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
    EXPECT_EQ(sorted_entries(b), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
}

template <std::size_t Alignment>
static void check_element_alignment(std::size_t reserve_count) {
    using map_type = unordered_flat_map<aligned_key<Alignment>, int, aligned_key_hash<Alignment>>;

    map_type map;
    map.reserve(reserve_count);
    for (int i = 0; i < 32; ++i) {
        map.insert({aligned_key<Alignment>{i}, i});
    }

    for (const auto &entry : map) {
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(std::addressof(entry)) % Alignment, 0u)
            << "alignof=" << Alignment << " reserve=" << reserve_count;
    }
}

TEST(unordered_flat_map, default_ctor_is_empty_and_allocation_free) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;

        EXPECT_TRUE(map.empty());
        EXPECT_EQ(map.size(), 0u);
        EXPECT_EQ(map.begin(), map.end());
        EXPECT_EQ(map.find(1), map.end());
        EXPECT_EQ(map.count(1), 0u);
        EXPECT_FALSE(map.contains(1));
        EXPECT_EQ(map.erase(1), 0u);
        EXPECT_EQ(map.load_factor(), 0.0f);
        EXPECT_THROW((void)map.at(1), std::out_of_range);

        map.clear();
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(alloc_stats::allocs, 0);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, bucket_count_zero_behaves_like_default) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map(0);

        EXPECT_TRUE(map.empty());
        EXPECT_EQ(map.size(), 0u);
        EXPECT_EQ(map.begin(), map.end());
        EXPECT_EQ(map.find(1), map.end());
        EXPECT_EQ(map.count(1), 0u);
        EXPECT_FALSE(map.contains(1));
        EXPECT_EQ(map.erase(1), 0u);
        EXPECT_EQ(map.load_factor(), 0.0f);
        EXPECT_EQ(alloc_stats::allocs, 0);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, ctor_normalizes_bucket_count) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map(14);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    {
        map_t map(15);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    {
        map_t map(16);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
    }
    {
        map_t map(17);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
    }
    {
        map_t map(31);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
    }
    {
        map_t map(32);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 63u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, ctor_stores_hash_equal_allocator) {
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

    using map_t =
        unordered_flat_map<int, int, local_hash, local_equal, tagged_allocator<map_value>>;

    map_t map(15, local_hash{3}, local_equal{4}, tagged_allocator<map_value>{7});

    EXPECT_EQ(map.hash_function().id, 3);
    EXPECT_EQ(map.key_eq().id, 4);
    EXPECT_EQ(map.get_allocator().id, 7);
    EXPECT_TRUE(map.insert({1, 10}).second);
}

TEST(unordered_flat_map, ctor_overloads_with_allocator) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, tagged_allocator<map_value>>;

    tagged_allocator<map_value> alloc{9};

    map_t a(15, alloc);
    map_t b(15, std::hash<int>{}, alloc);
    map_t c(alloc);

    EXPECT_EQ(a.get_allocator().id, 9);
    EXPECT_EQ(b.get_allocator().id, 9);
    EXPECT_EQ(c.get_allocator().id, 9);

    EXPECT_TRUE(a.insert({1, 10}).second);
    EXPECT_TRUE(b.insert({2, 20}).second);
    EXPECT_TRUE(c.insert({3, 30}).second);
}

TEST(unordered_flat_map, ctor_huge_bucket_count_throws_length_error) {
    using map_t = unordered_flat_map<int, int>;

    EXPECT_THROW(
        {
            map_t map((std::numeric_limits<std::size_t>::max)());
            (void)map;
        },
        std::length_error);

    const auto too_big = map_t{}.max_size() + 1;
    EXPECT_THROW(
        {
            map_t map(too_big);
            (void)map;
        },
        std::length_error);

    std::vector<std::pair<int, int>> values{{1, 10}};
    EXPECT_THROW(
        {
            map_t map(values.begin(), values.end(), too_big);
            (void)map;
        },
        std::length_error);
}

TEST(unordered_flat_map, range_ctor_deduplicates) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();

    std::vector<std::pair<int, int>> values{{1, 10}, {1, 11}, {2, 20}, {2, 21}, {3, 30}};
    {
        map_t map(values.begin(), values.end());
        EXPECT_EQ(map.size(), 3u);
        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }

    {
        map_t map(values.begin(), values.begin());
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }

    std::vector<std::pair<int, int>> duplicates(1000, {7, 70});
    {
        map_t map(duplicates.begin(), duplicates.end());
        EXPECT_EQ(map.size(), 1u);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(1000));
    }

    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, range_ctor_respects_explicit_bucket_count) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    std::vector<std::pair<int, int>> values{{1, 10}, {2, 20}, {3, 30}};

    alloc_stats::reset();
    {
        map_t map(values.begin(), values.end(), 100);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
        EXPECT_EQ(map.size(), 3u);
    }

    std::vector<std::pair<int, int>> many(100, {1, 10});
    {
        map_t map(many.begin(), many.end(), 10);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
        EXPECT_EQ(map.size(), 1u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, range_ctor_requires_forward_iterator) {
    using map_t = unordered_flat_map<int, int>;

    using pair_iterator = std::vector<std::pair<int, int>>::iterator;
    static_assert(std::constructible_from<map_t, pair_iterator, pair_iterator>);
    static_assert(std::constructible_from<map_t, std::list<std::pair<int, int>>::iterator,
                                          std::list<std::pair<int, int>>::iterator>);
    static_assert(std::constructible_from<map_t, std::array<std::pair<int, int>, 3>::iterator,
                                          std::array<std::pair<int, int>, 3>::iterator>);
    static_assert(
        !std::constructible_from<map_t, std::istream_iterator<int>, std::istream_iterator<int>>);
}

TEST(unordered_flat_map, initializer_list_ctor) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map({{1, 10}, {2, 20}, {2, 21}, {3, 30}});
        EXPECT_EQ(map.size(), 3u);
        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    {
        map_t map(std::initializer_list<map_value>{});
        EXPECT_TRUE(map.empty());
    }
    {
        map_t map({{1, 10}, {2, 20}, {3, 30}}, 100);
        EXPECT_EQ(map.size(), 3u);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(100));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_ctor_copies_contents) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t source;
        source.rehash(1000);
        source.insert({{1, 10}, {2, 20}, {3, 30}});
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 1023u);

        map_t copy(source);
        EXPECT_EQ(copy.size(), 3u);
        EXPECT_EQ(sorted_entries(copy),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        copy.insert({4, 40});
        EXPECT_EQ(source.size(), 3u);
        EXPECT_EQ(copy.size(), 4u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_ctor_of_empty_allocates_one_buffer) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t source;
        EXPECT_EQ(alloc_stats::allocs, 0);

        map_t copy(source);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
        EXPECT_TRUE(copy.empty());
        EXPECT_TRUE(source.empty());

        EXPECT_TRUE(copy.insert({1, 10}).second);
        EXPECT_EQ(copy.size(), 1u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, move_ctor_steals_buffer) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    static_assert(std::is_nothrow_move_constructible_v<map_t>);

    alloc_stats::reset();
    {
        map_t source;
        source.insert({{1, 10}, {2, 20}, {3, 30}});
        EXPECT_EQ(alloc_stats::allocs, 1);

        map_t moved(std::move(source));

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(sorted_entries(moved),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(source.begin(), source.end());

        EXPECT_TRUE(source.insert({4, 40}).second);
        EXPECT_EQ(source.size(), 1u);
        EXPECT_EQ(alloc_stats::allocs, 2);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, destructor_destroys_elements_and_releases) {
    using map_t = unordered_flat_map<live_key, int, live_key_hash, std::equal_to<>,
                                     counting_allocator<std::pair<const live_key, int>>>;

    live_key::live = 0;
    alloc_stats::reset();

    {
        map_t map;
        map.insert({live_key(1), 10});
        map.insert({live_key(2), 20});
        map.insert({live_key(3), 30});
        EXPECT_EQ(live_key::live, 3);
        EXPECT_EQ(alloc_stats::allocs, 1);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::deallocs, 1);

    { map_t map; }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_assign_same_bucket_count) {
    using map_t = unordered_flat_map<live_key, int, live_key_hash, std::equal_to<>,
                                     counting_allocator<std::pair<const live_key, int>>>;

    live_key::live = 0;
    alloc_stats::reset();
    {
        map_t target;
        map_t source;
        for (int i = 0; i < 5; ++i) {
            target.insert({live_key(i), i});
            source.insert({live_key(i + 10), i + 10});
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

TEST(unordered_flat_map, copy_assign_reuses_large_enough_buffer) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t target;
        target.rehash(1000);
        target.insert({{1, 10}, {2, 20}, {3, 30}});

        map_t source;
        source.insert({{10, 100}, {20, 200}, {30, 300}});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = source;

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_FLOAT_EQ(target.load_factor(), static_cast<float>(3.0 / 1024.0));
        EXPECT_EQ(sorted_entries(target),
                  (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}, {30, 300}}));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_assign_grows_buffer) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t target;
        target.insert({0, 0});

        map_t source;
        source.reserve(100);
        for (int i = 0; i < 100; ++i) {
            source.insert({i, i});
        }

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = source;

        EXPECT_EQ(alloc_stats::allocs, allocs_before + 1);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before + 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                  detail::swiss_table_size_to_capacity(source.size()));
        EXPECT_EQ(target.size(), 100u);
        for (int i = 0; i < 100; ++i) {
            EXPECT_TRUE(target.contains(i));
            EXPECT_EQ(target.at(i), i);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_assign_from_and_to_empty) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t target;
        target.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t empty;

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = empty;

        EXPECT_TRUE(target.empty());
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    {
        map_t target;
        map_t source;
        source.insert({{1, 10}, {2, 20}, {3, 30}});

        const int allocs_before = alloc_stats::allocs;

        target = source;

        EXPECT_EQ(allocs_before + 1, alloc_stats::allocs);
        EXPECT_EQ(sorted_entries(target),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    }
    {
        map_t a;
        map_t b;

        const int allocs_before = alloc_stats::allocs;

        a = b;

        EXPECT_EQ(allocs_before + 1, alloc_stats::allocs);
        EXPECT_TRUE(a.empty());
        EXPECT_TRUE(b.empty());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, copy_assign_self) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.insert({{1, 10}, {2, 20}, {3, 30}});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        map = map;

        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, move_assign_equal_allocator_steals) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    static_assert(std::is_nothrow_move_assignable_v<map_t>);

    alloc_stats::reset();
    {
        map_t target;
        target.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t source;
        source.insert({{10, 100}, {20, 200}});

        const int allocs_before   = alloc_stats::allocs;
        const int deallocs_before = alloc_stats::deallocs;

        target = std::move(source);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before + 1);
        EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(source.begin(), source.end());
        EXPECT_TRUE(source.insert({30, 300}).second);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, move_assign_self) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    map = std::move(map);

    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(sorted_entries(map), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
}

TEST(unordered_flat_map, move_assign_unequal_non_propagating_allocator) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, tagged_allocator<map_value>>;

    alloc_registry::reset();
    {
        map_t target(15, tagged_allocator<map_value>{3});
        target.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t source(15, tagged_allocator<map_value>{2});
        source.insert({{10, 100}, {20, 200}});

        target = std::move(source);

        EXPECT_EQ(target.get_allocator().id, 2);
        EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
        EXPECT_TRUE(source.empty());
        EXPECT_EQ(target.size(), 2u);
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, move_assign_unequal_propagating_allocator) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, pocma_allocator<map_value>>;

    alloc_registry::reset();
    {
        map_t target(15, pocma_allocator<map_value>{3});
        target.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t source(15, pocma_allocator<map_value>{2});
        source.insert({{10, 100}, {20, 200}});

        target = std::move(source);

        EXPECT_EQ(target.get_allocator().id, 2);
        EXPECT_EQ(sorted_entries(target), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
        EXPECT_TRUE(source.empty());
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, initializer_list_assign_replaces_content) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.insert({{1, 10}, {2, 20}, {3, 30}});

        map = {{4, 40}, {5, 50}, {5, 55}, {6, 60}};

        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{4, 40}, {5, 50}, {6, 60}}));

        const std::size_t capacity_before = capacity_from_bytes<map_value>(alloc_stats::last_size);
        map                               = std::initializer_list<map_value>{};

        EXPECT_TRUE(map.empty());
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(capacity_before, 15u);

        map = {{10, 100}, {11, 110}, {12, 120}, {13, 130}, {14, 140},
               {15, 150}, {16, 160}, {17, 170}, {18, 180}, {19, 190},
               {20, 200}, {21, 210}, {22, 220}, {23, 230}, {24, 240}};

        EXPECT_EQ(map.size(), 15u);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
        for (int i = 0; i < 15; ++i) {
            EXPECT_EQ(map.at(10 + i), (10 + i) * 10);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, initializer_list_assign_on_default_ctor) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;

        map = {{1, 10}, {2, 20}, {3, 30}};

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, swap_both_non_empty) {
    map_t a;
    map_t b;

    for (int i = 0; i < 3; ++i) {
        a.insert({i, i});
    }
    b.rehash(1000);
    for (int i = 0; i < 100; ++i) {
        b.insert({i + 10, i + 10});
    }

    a.swap(b);

    EXPECT_EQ(a.size(), 100u);
    EXPECT_EQ(b.size(), 3u);
    EXPECT_FLOAT_EQ(a.load_factor(), static_cast<float>(100.0 / 1024.0));
    EXPECT_FLOAT_EQ(b.load_factor(), static_cast<float>(3.0 / 16.0));
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(a.contains(i + 10));
        EXPECT_EQ(a.at(i + 10), i + 10);
    }
    for (int i = 0; i < 3; ++i) {
        EXPECT_TRUE(b.contains(i));
        EXPECT_EQ(b.at(i), i);
    }
}

TEST(unordered_flat_map, swap_with_empty) {
    map_t non_empty;
    map_t empty;
    non_empty.insert({{1, 10}, {2, 20}, {3, 30}});

    non_empty.swap(empty);

    EXPECT_TRUE(non_empty.empty());
    EXPECT_EQ(non_empty.begin(), non_empty.end());
    EXPECT_EQ(non_empty.load_factor(), 0.0f);
    EXPECT_EQ(sorted_entries(empty), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));

    EXPECT_TRUE(non_empty.insert({4, 40}).second);
    EXPECT_EQ(non_empty.size(), 1u);
    EXPECT_TRUE(non_empty.contains(4));
}

TEST(unordered_flat_map, swap_self) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    map.swap(map);

    EXPECT_EQ(sorted_entries(map), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
}

TEST(unordered_flat_map, swap_unequal_allocators_keeps_buffer_owner) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, tagged_allocator<map_value>>;

    alloc_registry::reset();
    {
        map_t a(15, tagged_allocator<map_value>{1});
        a.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t b(15, tagged_allocator<map_value>{2});
        b.insert({{10, 100}, {20, 200}});

        a.swap(b);

        EXPECT_EQ(a.get_allocator().id, 2);
        EXPECT_EQ(b.get_allocator().id, 1);
        EXPECT_EQ(sorted_entries(a), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
        EXPECT_EQ(sorted_entries(b), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, std_swap_uses_move_operations) {
    map_t a;
    map_t b;
    a.insert({{1, 10}, {2, 20}, {3, 30}});
    b.insert({{10, 100}, {20, 200}});

    std::swap(a, b);

    EXPECT_EQ(sorted_entries(a), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
    EXPECT_EQ(sorted_entries(b), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
}

TEST(unordered_flat_map, swap_is_noexcept_for_std_allocator) {
    using map_t = unordered_flat_map<int, int>;
    static_assert(noexcept(std::declval<map_t &>().swap(std::declval<map_t &>())));
}

TEST(unordered_flat_map, load_factor_follows_size_over_bucket_count) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        EXPECT_EQ(map.load_factor(), 0.0f);

        for (int i = 1; i <= 300; ++i) {
            map.insert({i, i});

            const std::size_t capacity = capacity_from_bytes<map_value>(alloc_stats::last_size);
            ASSERT_NE(capacity, 0u);
            EXPECT_FLOAT_EQ(map.load_factor(),
                            static_cast<float>(static_cast<double>(i) / (capacity + 1)));
            EXPECT_LE(map.load_factor(), map.max_load_factor());
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, max_load_factor_is_seven_eighths) {
    map_t map;
    EXPECT_EQ(map.max_load_factor(), 0.875f);
}

TEST(unordered_flat_map, max_load_factor_setter_is_noop) {
    map_t map;

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
    map.max_load_factor(0.1f);
#if defined(__clang__)
#    pragma clang diagnostic pop
#elif defined(__GNUC__)
#    pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#    pragma warning(pop)
#endif

    EXPECT_EQ(map.max_load_factor(), 0.875f);
}

TEST(unordered_flat_map, growth_points_are_at_seven_eighths) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 14; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        const int key14 = 14;
        map.insert_or_assign(key14, 14);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);

        for (int i = 15; i < 28; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);

        map.insert_or_assign(28, 28);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 63u);

        for (int i = 29; i < 56; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 63u);

        map.try_emplace(56, 56);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 127u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, rehash_grows_and_preserves_elements) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.insert({{1, 10}, {2, 20}, {3, 30}});

        map.rehash(100);

        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 127u);
        EXPECT_EQ(map.size(), 3u);
        for (int i = 1; i <= 3; ++i) {
            EXPECT_TRUE(map.contains(i));
            EXPECT_EQ(map.at(i), i * 10);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, rehash_smaller_or_equal_is_noop) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.insert({{1, 10}, {2, 20}, {3, 30}});
        map.rehash(100);

        const int allocs_before       = alloc_stats::allocs;
        const int deallocs_before     = alloc_stats::deallocs;
        const std::size_t size_before = alloc_stats::last_size;

        map.rehash(10);
        map.rehash(127);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(alloc_stats::last_size, size_before);
        EXPECT_EQ(sorted_entries(map),
                  (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, rehash_zero_on_default_allocates) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;

        map.rehash(0);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(map.begin(), map.end());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, rehash_huge_throws_length_error) {
    using map_t = unordered_flat_map<int, int>;

    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    EXPECT_THROW(map.rehash((std::numeric_limits<std::size_t>::max)()), std::length_error);
    EXPECT_EQ(map.size(), 3u);
    EXPECT_TRUE(map.contains(1));
    EXPECT_TRUE(map.contains(2));
    EXPECT_TRUE(map.contains(3));

    EXPECT_THROW(map.rehash(map.max_size() + 1), std::length_error);
    EXPECT_EQ(map.size(), 3u);
    EXPECT_TRUE(map.insert({4, 40}).second);
}

TEST(unordered_flat_map, reserve_matches_size_to_capacity) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    for (std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{14}, std::size_t{15},
                          std::size_t{16}, std::size_t{28}, std::size_t{29}, std::size_t{100}}) {
        alloc_stats::reset();
        {
            map_t map;
            map.reserve(n);

            EXPECT_EQ(alloc_stats::allocs, 1);
            EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                      detail::swiss_table_size_to_capacity(n));
        }
        EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
    }
}

TEST(unordered_flat_map, reserve_then_insert_never_reallocates) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    for (std::size_t n : {std::size_t{14}, std::size_t{28}, std::size_t{100}}) {
        alloc_stats::reset();
        {
            map_t map;
            map.reserve(n);
            ASSERT_EQ(alloc_stats::allocs, 1);

            for (std::size_t i = 0; i < n; ++i) {
                map.insert({static_cast<int>(i), static_cast<int>(i)});
            }

            EXPECT_EQ(alloc_stats::allocs, 1);
            EXPECT_EQ(map.size(), n);
            EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size),
                      detail::swiss_table_size_to_capacity(n));
        }
        EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
    }
}

TEST(unordered_flat_map, reserve_never_shrinks) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.rehash(1000);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 1023u);

        const int allocs_before = alloc_stats::allocs;

        map.reserve(1);

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 1023u);

        for (int i = 0; i < 100; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_FLOAT_EQ(map.load_factor(), static_cast<float>(100.0 / 1024.0));
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, reserve_size_max_throws_length_error) {
    using map_t = unordered_flat_map<int, int>;

    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    EXPECT_THROW(map.reserve((std::numeric_limits<std::size_t>::max)()), std::length_error);
    EXPECT_EQ(sorted_entries(map), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    EXPECT_TRUE(map.insert({4, 40}).second);
}

TEST(unordered_flat_map, max_size_is_bounded_by_allocator) {
    using default_map = unordered_flat_map<int, int>;
    using limited_map =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, limited_allocator<map_value>>;

    default_map map;
    const std::size_t expected =
        (std::min<std::size_t>)((std::numeric_limits<std::size_t>::max)() /
                                    sizeof(default_map::value_type),
                                static_cast<std::size_t>(
                                    (std::numeric_limits<std::ptrdiff_t>::max)()));
    EXPECT_EQ(map.max_size(), expected);

    limited_map limited;
    EXPECT_EQ(limited.max_size(), 100u);
    EXPECT_THROW(limited.reserve(101), std::length_error);
    EXPECT_TRUE(limited.empty());
}

TEST(unordered_flat_map, clear_destroys_elements_and_keeps_capacity) {
    using value_type = std::pair<const live_key, int>;
    using map_t      = unordered_flat_map<live_key, int, live_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    static_assert(noexcept(std::declval<map_t &>().clear()));

    live_key::live = 0;
    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 100; ++i) {
            map.insert({live_key(i), i});
        }
        EXPECT_EQ(live_key::live, 100);

        const std::size_t capacity_before = capacity_from_bytes<value_type>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        map.clear();

        EXPECT_EQ(live_key::live, 0);
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(map.begin(), map.end());
        EXPECT_EQ(map.load_factor(), 0.0f);
        EXPECT_EQ(capacity_from_bytes<value_type>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);

        for (int i = 0; i < 10; ++i) {
            map.insert({live_key(i), i});
        }
        EXPECT_EQ(map.size(), 10u);
        EXPECT_EQ(live_key::live, 10);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, clear_on_empty_and_default_is_safe) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.clear();
        EXPECT_EQ(alloc_stats::allocs, 0);

        map.rehash(0);
        map.clear();
        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_TRUE(map.empty());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_lvalue_returns_iterator_and_true) {
    map_t map;
    const map_t::value_type value{42, 420};

    const auto result = map.insert(value);

    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->first, value.first);
    EXPECT_EQ(result.first->second, value.second);
    EXPECT_EQ(result.first, map.find(value.first));
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, insert_rvalue_moves_not_copies) {
    using map_t = unordered_flat_map<int, throwing_key>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    {
        map_t map;
        throwing_key source(7);

        const auto result = map.insert(map_t::value_type{1, std::move(source)});

        EXPECT_TRUE(result.second);
        EXPECT_EQ(result.first->first, 1);
        EXPECT_EQ(result.first->second.value, 7);
        EXPECT_EQ(throwing_key::moves, 2);
        EXPECT_EQ(throwing_key::copies, 0);
        EXPECT_EQ(source.value, -1);
        EXPECT_EQ(map.size(), 1u);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
}

TEST(unordered_flat_map, duplicate_insert_returns_existing_iterator) {
    map_t map;
    const auto first = map.insert({1, 10});
    ASSERT_TRUE(first.second);

    map_t::value_type duplicate{1, 20};
    auto result = map.insert(duplicate);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first, first.first);
    EXPECT_EQ(result.first->second, 10);

    result = map.insert({1, 30});
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second, 10);

    result = map.emplace(1, 40);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second, 10);

    std::vector<std::pair<int, int>> values{{1, 50}};
    map.insert(values.begin(), values.end());
    EXPECT_EQ(map.size(), 1u);
    EXPECT_EQ(map.begin()->second, 10);

    map.insert({{1, 60}});
    EXPECT_EQ(map.size(), 1u);
    EXPECT_EQ(map.begin()->second, 10);
}

TEST(unordered_flat_map, insert_transparent_key_constructs_in_place) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;

    const auto result = map.insert(std::pair<std::string_view, int>{"hello", 1});

    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->second, 1);
    EXPECT_EQ(tracked_text::constructions, 1);
    EXPECT_EQ(map.size(), 1u);

    tracked_text::constructions = 0;
    EXPECT_EQ(map.count(std::string_view("hello")), 1u);
    EXPECT_TRUE(map.contains(std::string_view("hello")));
    EXPECT_NE(map.find(std::string_view("hello")), map.end());
    EXPECT_EQ(tracked_text::constructions, 0);

    tracked_text::constructions = 0;
    const auto duplicate        = map.insert(std::pair<std::string_view, int>{"hello", 2});
    EXPECT_FALSE(duplicate.second);
    EXPECT_EQ(duplicate.first->second, 1);
    EXPECT_EQ(tracked_text::constructions, 0);

    const auto inserted = map.insert(std::pair<std::string_view, int>{"world", 2});
    EXPECT_TRUE(inserted.second);
    EXPECT_EQ(tracked_text::constructions, 1);
}

TEST(unordered_flat_map, emplace_forwards_arguments) {
    map_t map;
    auto result = map.emplace(1, 2);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->first, 1);
    EXPECT_EQ(result.first->second, 2);

    result = map.emplace(1, 3);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second, 2);

    using move_only_map = unordered_flat_map<int, std::unique_ptr<int>>;
    move_only_map move_only;
    auto move_result = move_only.emplace(42, std::make_unique<int>(42));
    EXPECT_TRUE(move_result.second);
    EXPECT_EQ(*move_result.first->second, 42);

    auto duplicate = move_only.emplace(42, std::make_unique<int>(7));
    EXPECT_FALSE(duplicate.second);
    EXPECT_EQ(*duplicate.first->second, 42);
}

TEST(unordered_flat_map, insert_range_deduplicates) {
    map_t map;
    std::vector<std::pair<int, int>> values{{1, 10}, {1, 11}, {2, 20}, {3, 30}, {3, 31}};
    map.insert(values.begin(), values.end());
    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(map.at(1), 10);
    EXPECT_EQ(map.at(3), 30);

    std::list<std::pair<int, int>> more{{3, 32}, {4, 40}, {4, 41}, {5, 50}};
    map.insert(more.begin(), more.end());
    EXPECT_EQ(map.size(), 5u);
    EXPECT_EQ(sorted_entries(map),
              (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}, {4, 40}, {5, 50}}));

    const std::size_t size_before = map.size();
    map.insert(values.begin(), values.begin());
    EXPECT_EQ(map.size(), size_before);
}

TEST(unordered_flat_map, insert_initializer_list) {
    map_t map;
    static_assert(std::is_void_v<decltype(map.insert(std::initializer_list<map_value>{}))>);

    map.insert({{1, 10}, {1, 11}, {2, 20}});

    EXPECT_EQ(map.size(), 2u);
    EXPECT_EQ(sorted_entries(map), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}}));
}

TEST(unordered_flat_map, insert_twice_in_a_row_only_one_copy) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t map;
        map.insert(map_t::value_type{throwing_key(7), 70});
        const auto allocs_before = alloc_stats::allocs;

        throwing_key::reset_counters();
        const auto &stored = *map.begin();
        const auto result  = map.insert(stored);

        EXPECT_FALSE(result.second);
        EXPECT_EQ(result.first, map.begin());
        EXPECT_EQ(throwing_key::copies, 0);
        EXPECT_EQ(throwing_key::moves, 0);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(map.size(), 1u);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_that_triggers_growth_returns_valid_iterator) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 14; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        const auto result = map.insert({14, 14});

        EXPECT_TRUE(result.second);
        EXPECT_EQ(result.first->first, 14);
        EXPECT_EQ(result.first->second, 14);
        EXPECT_EQ(result.first, map.find(14));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
        EXPECT_EQ(map.size(), 15u);
    }
    {
        map_t map;
        for (int i = 0; i < 14; ++i) {
            map.insert({i, i});
        }
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        const map_t::value_type value{14, 14};
        const auto result = map.insert(value);

        EXPECT_TRUE(result.second);
        EXPECT_EQ(result.first->first, 14);
        EXPECT_EQ(result.first->second, 14);
        EXPECT_EQ(result.first, map.find(14));
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
        EXPECT_EQ(map.size(), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_first_element_allocates_one_buffer) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        EXPECT_TRUE(map.insert({1, 10}).second);

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_keys_with_h2_boundaries) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    map_t map(15, make_pinned_hash({{1, {0, 0}}, {2, {0, 127}}}));

    EXPECT_TRUE(map.insert({1, 10}).second);
    EXPECT_TRUE(map.insert({2, 20}).second);

    EXPECT_TRUE(map.contains(1));
    EXPECT_TRUE(map.contains(2));
    EXPECT_EQ(map.find(1)->first, 1);
    EXPECT_EQ(map.find(1)->second, 10);
    EXPECT_EQ(map.find(2)->first, 2);
    EXPECT_EQ(map.find(2)->second, 20);

    EXPECT_EQ(map.erase(1), 1u);
    EXPECT_EQ(map.erase(2), 1u);
    EXPECT_TRUE(map.empty());
}

TEST(unordered_flat_map, insert_into_completely_full_probe_window) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    pinned_hash hash;
    hash.table.push_back({100, {0, 100}});
    hash.table.push_back({101, {0, 99}});
    hash.table.push_back({102, {0, 98}});
    for (int i = 0; i < 16; ++i) {
        hash.table.push_back({i, {static_cast<std::size_t>(i), static_cast<std::size_t>(i + 1)}});
    }

    map_t map(0, hash);
    map.reserve(28);
    for (int i = 0; i < 16; ++i) {
        EXPECT_TRUE(map.insert({i, i}).second);
    }
    ASSERT_EQ(map.size(), 16u);

    const map_t::value_type value{100, 100};
    EXPECT_TRUE(map.insert(value).second);
    EXPECT_TRUE(map.insert({102, 102}).second);
    EXPECT_TRUE(map.contains(100));
    EXPECT_TRUE(map.contains(102));
    for (int i = 0; i < 16; ++i) {
        EXPECT_TRUE(map.contains(i));
    }

    EXPECT_EQ(map.find(101), map.end());
    EXPECT_EQ(map.count(101), 0u);
    EXPECT_FALSE(map.contains(101));
}

TEST(unordered_flat_map, insert_at_last_bucket_wraps_around) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    {
        pinned_hash hash;
        for (int i = 0; i < 10; ++i) {
            hash.table.push_back({i, {14, static_cast<std::size_t>(i + 1)}});
        }

        map_t map(15, hash);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.contains(i));
        }
    }

    {
        pinned_hash hash;
        for (int i = 0; i < 20; ++i) {
            hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
        }

        map_t map(0, hash);
        map.reserve(28);
        for (int i = 0; i < 20; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_EQ(map.size(), 20u);
        for (int i = 0; i < 20; ++i) {
            EXPECT_TRUE(map.contains(i));
        }
    }
}

TEST(unordered_flat_map, insert_many_collisions_constant_hash) {
    struct constant_hash {
        std::size_t operator()(int) const noexcept {
            return 0;
        }
    };

    using map_t = unordered_flat_map<int, int, constant_hash>;

    map_t map;
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(map.insert({i, i}).second);
    }

    EXPECT_EQ(map.size(), 1000u);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(map.contains(i));
        EXPECT_EQ(map.at(i), i);
    }

    for (int i = 0; i < 1000; ++i) {
        EXPECT_EQ(map.erase(i), 1u);
    }
    EXPECT_TRUE(map.empty());
}

TEST(unordered_flat_map, insert_after_mass_erase_reuses_tombstones) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 100; ++i) {
            map.insert({i, i});
        }
        const std::size_t capacity_before = capacity_from_bytes<map_value>(alloc_stats::last_size);

        for (int i = 0; i < 50; ++i) {
            EXPECT_EQ(map.erase(i), 1u);
        }

        for (int i = 100; i < 150; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }

        EXPECT_EQ(map.size(), 100u);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), capacity_before);
        for (int i = 50; i < 150; ++i) {
            EXPECT_TRUE(map.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_duplicate_does_not_grow) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 100000; ++i) {
            map.insert({42, 42});
        }

        EXPECT_EQ(map.size(), 1u);
        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_or_assign_inserts_then_assigns) {
    map_t map;
    const int key = 1;

    auto result = map.insert_or_assign(key, 10);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->first, 1);
    EXPECT_EQ(result.first->second, 10);
    EXPECT_EQ(result.first, map.find(1));

    result = map.insert_or_assign(key, 20);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second, 20);
    EXPECT_EQ(map.at(1), 20);
    EXPECT_EQ(map.size(), 1u);

    result = map.insert_or_assign(2, 30);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(map.at(2), 30);
    EXPECT_EQ(map.size(), 2u);
}

TEST(unordered_flat_map, insert_or_assign_constructs_or_assigns_mapped) {
    using map_t = unordered_flat_map<int, tracked_value>;

    tracked_value::reset_counters();
    map_t map;

    auto result = map.insert_or_assign(1, 10);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(tracked_value::constructions, 1);
    EXPECT_EQ(tracked_value::assignments, 0);

    result = map.insert_or_assign(1, 20);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(tracked_value::constructions, 1);
    EXPECT_EQ(tracked_value::assignments, 1);
    EXPECT_EQ(map.at(1).value, 20);
}

TEST(unordered_flat_map, insert_or_assign_transparent_key) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;

    auto result = map.insert_or_assign(std::string_view("alpha"), 1);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(tracked_text::constructions, 1);
    EXPECT_EQ(map.at(std::string_view("alpha")), 1);

    tracked_text::constructions = 0;
    result                      = map.insert_or_assign(std::string_view("alpha"), 2);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(tracked_text::constructions, 0);
    EXPECT_EQ(map.at(std::string_view("alpha")), 2);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, insert_or_assign_move_only_mapped) {
    using map_t = unordered_flat_map<int, std::unique_ptr<int>>;

    map_t map;
    auto result = map.insert_or_assign(1, std::make_unique<int>(10));
    EXPECT_TRUE(result.second);
    EXPECT_EQ(*map.at(1), 10);

    result = map.insert_or_assign(1, std::make_unique<int>(20));
    EXPECT_FALSE(result.second);
    EXPECT_EQ(*map.at(1), 20);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, try_emplace_constructs_mapped_in_place) {
    using map_t = unordered_flat_map<int, tracked_value>;

    tracked_value::reset_counters();
    map_t map;

    auto result = map.try_emplace(1, 10);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(result.first->second.value, 10);
    EXPECT_EQ(tracked_value::constructions, 1);
    EXPECT_EQ(tracked_value::defaults, 0);

    result = map.try_emplace(1, 20);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(result.first->second.value, 10);
    EXPECT_EQ(tracked_value::constructions, 1);
    EXPECT_EQ(tracked_value::defaults, 0);
    EXPECT_EQ(map.size(), 1u);

    result = map.try_emplace(2);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(tracked_value::defaults, 1);
    EXPECT_EQ(map.size(), 2u);
}

TEST(unordered_flat_map, try_emplace_forwards_arguments) {
    using map_t = unordered_flat_map<int, std::string>;

    map_t map;
    auto result = map.try_emplace(1, 3, 'x');
    EXPECT_TRUE(result.second);
    EXPECT_EQ(map.at(1), "xxx");

    result = map.try_emplace(1, 5, 'y');
    EXPECT_FALSE(result.second);
    EXPECT_EQ(map.at(1), "xxx");
}

TEST(unordered_flat_map, try_emplace_transparent_key) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;

    auto result = map.try_emplace(std::string_view("alpha"), 1);
    EXPECT_TRUE(result.second);
    EXPECT_EQ(tracked_text::constructions, 1);
    EXPECT_EQ(map.at(std::string_view("alpha")), 1);

    tracked_text::constructions = 0;
    result                      = map.try_emplace(std::string_view("alpha"), 2);
    EXPECT_FALSE(result.second);
    EXPECT_EQ(tracked_text::constructions, 0);
    EXPECT_EQ(map.at(std::string_view("alpha")), 1);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, try_emplace_rvalue_key_moves_not_copies) {
    using map_t = unordered_flat_map<throwing_key, int, throwing_key_hash>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    {
        map_t map;
        throwing_key source(7);

        const auto result = map.try_emplace(std::move(source), 70);

        EXPECT_TRUE(result.second);
        EXPECT_EQ(result.first->first.value, 7);
        EXPECT_EQ(result.first->second, 70);
        EXPECT_EQ(throwing_key::moves, 1);
        EXPECT_EQ(throwing_key::copies, 0);
        EXPECT_EQ(source.value, -1);
        EXPECT_EQ(map.size(), 1u);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
}

TEST(unordered_flat_map, find_count_contains_agree) {
    map_t map;
    const map_t &const_map = map;

    EXPECT_EQ(map.find(1), map.end());
    EXPECT_EQ(const_map.find(1), const_map.end());
    EXPECT_EQ(map.count(1), 0u);
    EXPECT_FALSE(map.contains(1));

    map.insert({1, 10});

    EXPECT_NE(map.find(1), map.end());
    EXPECT_EQ(const_map.find(1)->second, 10);
    EXPECT_EQ(map.find(1)->second, 10);
    EXPECT_EQ(map.count(1), 1u);
    EXPECT_TRUE(map.contains(1));

    EXPECT_EQ(map.find(2), map.end());
    EXPECT_EQ(map.count(2), 0u);
    EXPECT_FALSE(map.contains(2));
}

TEST(unordered_flat_map, const_overloads_return_const_iterator) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(
        std::is_same_v<decltype(std::declval<const map_t &>().find(1)), map_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const map_t &>().begin()), map_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const map_t &>().end()), map_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const map_t &>().cbegin()), map_t::const_iterator>);
    static_assert(
        std::is_same_v<decltype(std::declval<const map_t &>().cend()), map_t::const_iterator>);
    static_assert(std::is_same_v<decltype(std::declval<map_t &>().at(1)), int &>);
    static_assert(std::is_same_v<decltype(std::declval<const map_t &>().at(1)), const int &>);

    map_t mutable_map;
    mutable_map.insert({1, 10});
    const map_t &map = mutable_map;

    EXPECT_EQ(map.find(1)->second, 10);
    EXPECT_NE(map.begin(), map.end());
    EXPECT_NE(map.cbegin(), map.cend());
}

TEST(unordered_flat_map, heterogeneous_lookup_with_transparent_hash) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;
    map_t empty_map;
    const map_t &const_empty_map = empty_map;

    EXPECT_EQ(empty_map.find(std::string_view("alpha")), empty_map.end());
    EXPECT_EQ(empty_map.count(std::string_view("alpha")), 0u);
    EXPECT_FALSE(empty_map.contains(std::string_view("alpha")));
    EXPECT_EQ(const_empty_map.find(std::string_view("alpha")), const_empty_map.end());
    EXPECT_EQ(const_empty_map.count(std::string_view("alpha")), 0u);

    map.insert({"alpha", 1});
    map.insert({"beta", 2});

    tracked_text::constructions = 0;

    EXPECT_NE(map.find(std::string_view("alpha")), map.end());
    EXPECT_EQ(map.find(std::string_view("alpha"))->second, 1);
    EXPECT_EQ(map.count(std::string_view("alpha")), 1u);
    EXPECT_TRUE(map.contains(std::string_view("alpha")));
    EXPECT_EQ(map.at(std::string_view("alpha")), 1);
    map.at(std::string_view("alpha")) = 10;
    EXPECT_EQ(map.at(std::string_view("alpha")), 10);
    EXPECT_EQ(map.erase(std::string_view("alpha")), 1u);
    EXPECT_FALSE(map.contains(std::string_view("alpha")));
    EXPECT_EQ(map.size(), 1u);

    EXPECT_EQ(map.find(std::string_view("gamma")), map.end());
    EXPECT_EQ(map.count(std::string_view("gamma")), 0u);
    EXPECT_FALSE(map.contains(std::string_view("gamma")));
    EXPECT_THROW((void)map.at(std::string_view("gamma")), std::out_of_range);
    EXPECT_EQ(map.erase(std::string_view("gamma")), 0u);
    EXPECT_EQ(tracked_text::constructions, 0);

    const map_t &const_map = map;
    EXPECT_NE(const_map.find(std::string_view("beta")), const_map.end());
    EXPECT_EQ(const_map.at(std::string_view("beta")), 2);
    EXPECT_EQ(const_map.find(std::string_view("gamma")), const_map.end());
    EXPECT_EQ(const_map.count(std::string_view("gamma")), 0u);
    EXPECT_THROW((void)const_map.at(std::string_view("gamma")), std::out_of_range);
}

TEST(unordered_flat_map, heterogeneous_lookup_requires_transparent_hasher) {
    using default_map = unordered_flat_map<std::string, int>;
    using opaque_map  = unordered_flat_map<std::string, int, std::hash<std::string>>;
    using transparent_map =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    static_assert(can_find<default_map, std::string_view>);
    static_assert(can_count<default_map, std::string_view>);
    static_assert(can_contains<default_map, std::string_view>);
    static_assert(can_at<default_map, std::string_view>);
    static_assert(can_subscript<default_map, std::string_view>);
    static_assert(can_insert<default_map, std::pair<std::string_view, int>>);
    static_assert(can_insert_or_assign<default_map, std::string_view, int>);
    static_assert(can_try_emplace<default_map, std::string_view, int>);
    static_assert(!can_find<opaque_map, std::string_view>);
    static_assert(!can_count<opaque_map, std::string_view>);
    static_assert(!can_contains<opaque_map, std::string_view>);
    static_assert(!can_at<opaque_map, std::string_view>);
    static_assert(!can_subscript<opaque_map, std::string_view>);
    static_assert(!can_insert<opaque_map, std::pair<std::string_view, int>>);
    static_assert(!can_insert_or_assign<opaque_map, std::string_view, int>);
    static_assert(!can_try_emplace<opaque_map, std::string_view, int>);
    static_assert(can_find<transparent_map, std::string_view>);
    static_assert(can_count<transparent_map, std::string_view>);
    static_assert(can_contains<transparent_map, std::string_view>);
    static_assert(can_at<transparent_map, std::string_view>);
    static_assert(can_subscript<transparent_map, std::string_view>);
    static_assert(can_insert<transparent_map, std::pair<std::string_view, int>>);
    static_assert(can_insert_or_assign<transparent_map, std::string_view, int>);
    static_assert(can_try_emplace<transparent_map, std::string_view, int>);
}

TEST(unordered_flat_map, at_returns_mapped_value) {
    map_t map;
    map.insert({{1, 10}, {2, 20}});

    EXPECT_EQ(map.at(1), 10);
    map.at(1) = 11;
    EXPECT_EQ(map.at(1), 11);

    const map_t &const_map = map;
    EXPECT_EQ(const_map.at(2), 20);

    EXPECT_EQ(std::addressof(map.at(1)), std::addressof(map.find(1)->second));
}

TEST(unordered_flat_map, at_missing_key_throws_out_of_range) {
    map_t map;

    EXPECT_THROW((void)map.at(1), std::out_of_range);

    map.insert({1, 10});

    EXPECT_THROW((void)map.at(2), std::out_of_range);

    const map_t &const_map = map;
    EXPECT_THROW((void)const_map.at(2), std::out_of_range);

    EXPECT_EQ(map.at(1), 10);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, at_transparent_key) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;
    map.insert({"alpha", 1});
    map.insert({"beta", 2});

    tracked_text::constructions = 0;

    EXPECT_EQ(map.at(std::string_view("alpha")), 1);
    map.at(std::string_view("alpha")) = 3;
    EXPECT_EQ(map.at(std::string_view("alpha")), 3);

    const map_t &const_map = map;
    EXPECT_EQ(const_map.at(std::string_view("beta")), 2);
    EXPECT_THROW((void)const_map.at(std::string_view("gamma")), std::out_of_range);
    EXPECT_EQ(tracked_text::constructions, 0);
}

TEST(unordered_flat_map, operator_subscript_default_constructs) {
    map_t map;

    int &first = map[1];
    EXPECT_EQ(first, 0);
    EXPECT_EQ(map.size(), 1u);
    EXPECT_EQ(map.find(1)->second, 0);

    first = 10;
    EXPECT_EQ(map.at(1), 10);

    map[1] = 20;
    EXPECT_EQ(map.at(1), 20);
    EXPECT_EQ(map.size(), 1u);

    map[2] += 5;
    EXPECT_EQ(map.at(2), 5);
    EXPECT_EQ(map.size(), 2u);
}

TEST(unordered_flat_map, operator_subscript_default_constructs_mapped) {
    using map_t = unordered_flat_map<int, tracked_value>;

    tracked_value::reset_counters();
    map_t map;

    tracked_value &first = map[1];
    (void)first;
    EXPECT_EQ(tracked_value::defaults, 1);
    EXPECT_EQ(tracked_value::constructions, 0);
    EXPECT_EQ(map.size(), 1u);

    tracked_value &again = map[1];
    (void)again;
    EXPECT_EQ(tracked_value::defaults, 1);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, operator_subscript_transparent_key) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;

    map[std::string_view("alpha")] = 1;
    EXPECT_EQ(tracked_text::constructions, 1);
    EXPECT_EQ(map.at(std::string_view("alpha")), 1);

    tracked_text::constructions = 0;
    EXPECT_EQ(map[std::string_view("alpha")], 1);
    EXPECT_EQ(tracked_text::constructions, 0);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, lookup_absent_key_through_tombstones) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 100; ++i) {
            map.insert({i, i});
        }
        for (int i = 0; i < 50; ++i) {
            map.erase(i);
        }

        for (int i = 1000; i < 1100; ++i) {
            EXPECT_EQ(map.find(i), map.end());
            EXPECT_EQ(map.count(i), 0u);
            EXPECT_FALSE(map.contains(i));
            EXPECT_THROW((void)map.at(i), std::out_of_range);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, lookup_absent_key_through_full_window) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    pinned_hash hash;
    hash.table.push_back({200, {0, 99}});
    for (int i = 0; i < 16; ++i) {
        hash.table.push_back({i, {static_cast<std::size_t>(i), static_cast<std::size_t>(i + 1)}});
    }

    map_t map(0, hash);
    map.reserve(28);
    for (int i = 0; i < 16; ++i) {
        map.insert({i, i});
    }

    EXPECT_EQ(map.find(200), map.end());
    EXPECT_EQ(map.count(200), 0u);
    EXPECT_FALSE(map.contains(200));

    const map_t &const_map = map;
    EXPECT_EQ(const_map.find(200), const_map.end());
    EXPECT_EQ(const_map.count(200), 0u);
}

TEST(unordered_flat_map, lookup_after_growth_and_rehash) {
    map_t map;
    for (int i = 0; i < 300; ++i) {
        map.insert({i, i});
    }
    for (int i = 0; i < 300; ++i) {
        EXPECT_TRUE(map.contains(i));
        EXPECT_EQ(map.at(i), i);
    }

    map.rehash(1000);
    for (int i = 0; i < 300; ++i) {
        EXPECT_TRUE(map.contains(i));
        EXPECT_EQ(map.at(i), i);
    }

    for (int i = 300; i < 400; ++i) {
        EXPECT_FALSE(map.contains(i));
    }
}

TEST(unordered_flat_map, find_returns_iterator_to_stored_element) {
    map_t map;
    const auto inserted = map.insert({42, 420});

    const auto found = map.find(42);

    EXPECT_EQ(found, inserted.first);
    EXPECT_EQ(found->first, 42);
    EXPECT_EQ(found->second, 420);
    EXPECT_EQ(std::addressof(*found), std::addressof(*inserted.first));
}

TEST(unordered_flat_map, erase_iterator_removes_one) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    static_assert(std::is_void_v<decltype(map.erase(map.begin()))>);

    const auto position = map.find(2);
    ASSERT_NE(position, map.end());
    map.erase(position);

    EXPECT_EQ(map.size(), 2u);
    EXPECT_FALSE(map.contains(2));
    EXPECT_TRUE(map.contains(1));
    EXPECT_TRUE(map.contains(3));
}

TEST(unordered_flat_map, erase_const_iterator_overload) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    map.erase(std::as_const(map).begin());
    EXPECT_EQ(map.size(), 2u);

    map.erase(map.cbegin());
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, erase_key_returns_count) {
    map_t map;

    EXPECT_EQ(map.erase(1), 0u);

    map.insert({1, 10});
    EXPECT_EQ(map.erase(1), 1u);
    EXPECT_EQ(map.erase(1), 0u);
    EXPECT_FALSE(map.contains(1));
}

TEST(unordered_flat_map, erase_transparent_key) {
    using map_t =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    tracked_text::constructions = 0;
    map_t map;
    map.insert({"alpha", 1});
    map.insert({"beta", 2});

    tracked_text::constructions = 0;
    EXPECT_EQ(map.erase(std::string_view("alpha")), 1u);
    EXPECT_EQ(tracked_text::constructions, 0);
    EXPECT_EQ(map.size(), 1u);
    EXPECT_TRUE(map.contains(std::string_view("beta")));
}

TEST(unordered_flat_map, erase_range_single_element) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    auto first = map.begin();
    auto last  = first;
    ++last;

    const auto result = map.erase(first, last);

    EXPECT_EQ(result, last);
    EXPECT_EQ(map.size(), 2u);
    EXPECT_EQ(std::distance(result, map.end()), static_cast<std::ptrdiff_t>(map.size()));
}

TEST(unordered_flat_map, erase_whole_range_uses_clear) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 10; ++i) {
            map.insert({i, i});
        }
        const std::size_t capacity_before = capacity_from_bytes<map_value>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        const auto result = map.erase(map.begin(), map.end());

        EXPECT_EQ(result, map.end());
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), capacity_before);
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, erase_empty_range_is_noop) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    const auto first  = map.begin();
    const auto result = map.erase(first, first);

    EXPECT_EQ(result, first);
    EXPECT_EQ(map.size(), 3u);
}

TEST(unordered_flat_map, erase_range_ending_at_end) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}, {4, 40}, {5, 50}});

    auto middle = map.begin();
    std::advance(middle, 3);

    const auto result = map.erase(middle, map.end());

    EXPECT_EQ(result, map.end());
    EXPECT_EQ(map.size(), 3u);
    EXPECT_EQ(std::distance(result, map.end()), 0);
}

TEST(unordered_flat_map, erase_range_on_empty_container) {
    {
        map_t map;
        EXPECT_EQ(map.erase(map.begin(), map.end()), map.end());
    }
    {
        map_t map;
        map.rehash(0);
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(map.erase(map.begin(), map.end()), map.end());
    }
}

TEST(unordered_flat_map, erase_while_iterating_with_postincrement) {
    map_t map;
    for (int i = 0; i < 20; ++i) {
        map.insert({i, i});
    }

    for (auto iter = map.begin(); iter != map.end();) {
        if (iter->first % 2 == 0) {
            map.erase(iter++);
        } else {
            ++iter;
        }
    }

    EXPECT_EQ(map.size(), 10u);
    EXPECT_EQ(std::distance(map.begin(), map.end()), static_cast<std::ptrdiff_t>(map.size()));
    for (int i = 0; i < 20; ++i) {
        EXPECT_EQ(map.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_map, erase_all_one_by_one) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}, {4, 40}, {5, 50}});

    std::size_t expected = 5;
    while (!map.empty()) {
        map.erase(map.begin());
        --expected;
        EXPECT_EQ(map.size(), expected);
    }

    EXPECT_EQ(map.begin(), map.end());
}

TEST(unordered_flat_map, erase_on_capacity_15_marks_empty) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 10; ++i) {
            map.insert({i, i});
        }
        ASSERT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        for (int i = 0; i < 10; ++i) {
            EXPECT_EQ(map.erase(i), 1u);
        }
        EXPECT_TRUE(map.empty());
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);

        for (int i = 10; i < 20; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_EQ(map.size(), 10u);
        for (int i = 10; i < 20; ++i) {
            EXPECT_TRUE(map.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, erase_on_capacity_31_marks_deleted) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        map.reserve(28);
        ASSERT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);

        for (int i = 0; i < 20; ++i) {
            map.insert({i, i});
        }
        for (int i = 5; i < 15; ++i) {
            EXPECT_EQ(map.erase(i), 1u);
        }

        for (int i = 5; i < 15; ++i) {
            EXPECT_FALSE(map.contains(i));
        }
        for (int i = 0; i < 5; ++i) {
            EXPECT_TRUE(map.contains(i));
        }
        for (int i = 15; i < 20; ++i) {
            EXPECT_TRUE(map.contains(i));
        }

        for (int i = 5; i < 15; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_EQ(map.size(), 20u);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 31u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, erase_last_bucket_crosses_mirror) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    pinned_hash hash;
    for (int i = 0; i < 10; ++i) {
        hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
    }

    map_t map(0, hash);
    map.reserve(28);
    for (int i = 0; i < 10; ++i) {
        map.insert({i, i});
    }

    for (int i = 0; i < 10; i += 2) {
        EXPECT_EQ(map.erase(i), 1u);
    }

    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(map.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_map, erase_then_insert_same_key_cycles) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 1000; ++i) {
            EXPECT_TRUE(map.insert({42, 42}).second);
            EXPECT_EQ(map.size(), 1u);
            EXPECT_EQ(map.erase(42), 1u);
            EXPECT_EQ(map.size(), 0u);
        }

        EXPECT_EQ(alloc_stats::allocs, 1);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), 15u);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, erase_does_not_deallocate) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 100; ++i) {
            map.insert({i, i});
        }
        const std::size_t capacity_before = capacity_from_bytes<map_value>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;
        const int deallocs_before         = alloc_stats::deallocs;

        for (int i = 0; i < 100; ++i) {
            map.erase(i);
        }

        EXPECT_EQ(alloc_stats::allocs, allocs_before);
        EXPECT_EQ(alloc_stats::deallocs, deallocs_before);
        EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), capacity_before);

        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, iteration_over_empty) {
    {
        map_t map;
        int visits = 0;
        for ([[maybe_unused]] const auto &entry : map) {
            ++visits;
        }
        EXPECT_EQ(visits, 0);
        EXPECT_EQ(map.begin(), map.end());
    }
    {
        map_t map;
        map.insert({{1, 10}, {2, 20}, {3, 30}});
        map.clear();
        int visits = 0;
        for ([[maybe_unused]] const auto &entry : map) {
            ++visits;
        }
        EXPECT_EQ(visits, 0);
        EXPECT_EQ(map.begin(), map.end());
    }
}

TEST(unordered_flat_map, iteration_over_single_element) {
    map_t map;
    map.insert({7, 70});

    auto iter = map.begin();
    ASSERT_NE(iter, map.end());
    EXPECT_EQ(iter->first, 7);
    EXPECT_EQ(iter->second, 70);

    const auto old = iter++;
    EXPECT_EQ(old->first, 7);
    EXPECT_EQ(old->second, 70);
    EXPECT_EQ(old, map.begin());
    EXPECT_EQ(iter, map.end());
}

TEST(unordered_flat_map, iteration_visits_every_element_once) {
    map_t map;
    std::vector<int> expected{3, 1, 4, 1, 5, 9, 2, 6};
    for (int value : expected) {
        map.insert({value, value * 10});
    }

    std::vector<int> visited;
    for (const auto &[key, value] : map) {
        EXPECT_EQ(value, key * 10);
        visited.push_back(key);
    }
    std::sort(visited.begin(), visited.end());
    std::sort(expected.begin(), expected.end());
    expected.erase(std::unique(expected.begin(), expected.end()), expected.end());

    EXPECT_EQ(visited, expected);
    EXPECT_EQ(std::distance(map.begin(), map.end()), static_cast<std::ptrdiff_t>(map.size()));
}

TEST(unordered_flat_map, iterator_to_const_iterator_conversion) {
    map_t map;
    map.insert({7, 70});

    const map_t::const_iterator const_iter = map.begin();

    EXPECT_EQ(const_iter->first, map.begin()->first);
    EXPECT_EQ(const_iter->second, map.begin()->second);
    EXPECT_EQ(const_iter, map.cbegin());
}

TEST(unordered_flat_map, range_for_on_const_and_non_const) {
    map_t mutable_map;
    mutable_map.insert({{1, 10}, {2, 20}, {3, 30}});
    const map_t &map = mutable_map;

    std::vector<int> from_mutable;
    for (const auto &entry : mutable_map) {
        from_mutable.push_back(entry.first);
    }
    std::vector<int> from_const;
    for (const auto &entry : map) {
        from_const.push_back(entry.first);
    }

    std::sort(from_mutable.begin(), from_mutable.end());
    std::sort(from_const.begin(), from_const.end());
    EXPECT_EQ(from_mutable, from_const);
    EXPECT_EQ(from_const, (std::vector<int>{1, 2, 3}));
}

TEST(unordered_flat_map, iterator_models_forward_iterator) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(std::forward_iterator<map_t::iterator>);
    static_assert(std::forward_iterator<map_t::const_iterator>);
    static_assert(std::ranges::forward_range<map_t>);
    static_assert(std::ranges::sized_range<map_t>);
    static_assert(
        std::is_same_v<typename map_t::iterator::iterator_category, std::forward_iterator_tag>);
}

TEST(unordered_flat_map, iteration_skips_deleted_and_empty_states) {
    map_t map;
    for (int i = 0; i < 100; ++i) {
        map.insert({i, i});
    }
    for (int i = 0; i < 100; i += 2) {
        map.erase(i);
    }

    std::size_t visits = 0;
    for (const auto &entry : map) {
        EXPECT_EQ(entry.first % 2, 1);
        ++visits;
    }

    EXPECT_EQ(visits, map.size());
    EXPECT_EQ(visits, 50u);
}

TEST(unordered_flat_map, iteration_handles_h2_boundary_values) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    map_t map(15, make_pinned_hash({{1, {3, 0}}, {2, {7, 127}}}));

    map.insert({1, 10});
    map.insert({2, 20});

    std::vector<int> visited;
    for (const auto &entry : map) {
        visited.push_back(entry.first);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited, (std::vector<int>{1, 2}));
}

TEST(unordered_flat_map, iteration_across_mirror_tail) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

    pinned_hash hash;
    for (int i = 0; i < 10; ++i) {
        hash.table.push_back({i, {30, static_cast<std::size_t>(i + 1)}});
    }

    map_t map(0, hash);
    map.reserve(28);
    for (int i = 0; i < 10; ++i) {
        map.insert({i, i});
    }

    std::vector<int> visited;
    for (const auto &entry : map) {
        visited.push_back(entry.first);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited.size(), 10u);
    EXPECT_EQ(visited, (std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
}

TEST(unordered_flat_map, iteration_after_clear_and_rehash) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});
    map.clear();
    EXPECT_EQ(map.begin(), map.end());

    map.rehash(1000);
    EXPECT_EQ(map.begin(), map.end());

    for (int i = 0; i < 10; ++i) {
        map.insert({i, i});
    }

    std::vector<int> visited;
    for (const auto &entry : map) {
        visited.push_back(entry.first);
    }
    std::sort(visited.begin(), visited.end());

    EXPECT_EQ(visited, (std::vector<int>{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
}

TEST(unordered_flat_map, default_iterator_equality_is_state_based) {
    using map_t = unordered_flat_map<int, int>;

    EXPECT_EQ(map_t::iterator{}, map_t::iterator{});
    EXPECT_EQ(map_t::const_iterator{}, map_t::const_iterator{});

    map_t map;
    EXPECT_EQ(map.begin(), map_t::iterator{});
    EXPECT_EQ(map.end(), map_t::iterator{});
    EXPECT_EQ(map.cbegin(), map_t::const_iterator{});
    EXPECT_EQ(map.cend(), map_t::const_iterator{});
}

TEST(unordered_flat_map, operator_arrow_matches_dereference) {
    map_t map;
    map.insert({{1, 10}, {2, 20}});

    for (auto iter = map.begin(); iter != map.end(); ++iter) {
        EXPECT_EQ(iter.operator->(), std::addressof(*iter));
        EXPECT_EQ(iter->first, (*iter).first);
        EXPECT_EQ(iter->second, (*iter).second);
    }
}

TEST(unordered_flat_map, default_allocator_is_value_initialized) {
    map_t map;
    EXPECT_EQ(map.get_allocator(), map_t::allocator_type{});
}

TEST(unordered_flat_map, ctor_and_range_ctor_keep_allocator) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, tagged_allocator<map_value>>;

    tagged_allocator<map_value> alloc{7};
    std::vector<std::pair<int, int>> values{{1, 10}, {2, 20}, {3, 30}};

    map_t direct(15, alloc);
    map_t with_hash(15, std::hash<int>{}, alloc);
    map_t alloc_only(alloc);
    map_t from_range(values.begin(), values.end(), 15, alloc);
    map_t from_range_with_hash(values.begin(), values.end(), 15, std::hash<int>{}, alloc);
    map_t from_list({{1, 10}, {2, 20}, {3, 30}}, 15, alloc);
    map_t from_list_with_hash({{1, 10}, {2, 20}, {3, 30}}, 15, std::hash<int>{}, alloc);

    EXPECT_EQ(direct.get_allocator().id, 7);
    EXPECT_EQ(with_hash.get_allocator().id, 7);
    EXPECT_EQ(alloc_only.get_allocator().id, 7);
    EXPECT_EQ(from_range.get_allocator().id, 7);
    EXPECT_EQ(from_range_with_hash.get_allocator().id, 7);
    EXPECT_EQ(from_list.get_allocator().id, 7);
    EXPECT_EQ(from_list_with_hash.get_allocator().id, 7);

    EXPECT_TRUE(direct.insert({4, 40}).second);
    EXPECT_TRUE(alloc_only.insert({4, 40}).second);
    EXPECT_EQ(from_range.size(), 3u);
    EXPECT_EQ(from_list.size(), 3u);
}

TEST(unordered_flat_map, copy_ctor_uses_soccc) {
    using map_t =
        unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, soccc_allocator<map_value>>;

    map_t source(15, soccc_allocator<map_value>{7});
    source.insert({{1, 10}, {2, 20}, {3, 30}});

    map_t copy(source);

    EXPECT_EQ(copy.get_allocator().id, 107);
    EXPECT_EQ(sorted_entries(copy), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));

    map_t target(15, soccc_allocator<map_value>{3});
    target = source;

    EXPECT_EQ(target.get_allocator().id, 3);
    EXPECT_EQ(sorted_entries(target),
              (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
}

TEST(unordered_flat_map, copy_assign_propagates_only_with_pocca) {
    alloc_registry::reset();
    {
        check_copy_assign_propagation<pocca_allocator<map_value>>(true);
        check_copy_assign_propagation<tagged_allocator<map_value>>(false);
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, move_assign_propagates_only_with_pocma) {
    alloc_registry::reset();
    {
        check_unequal_move_assign<pocma_allocator<map_value>>();
        check_unequal_move_assign<tagged_allocator<map_value>>();
        check_equal_move_assign<tagged_allocator<map_value>>();
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, swap_propagates_only_with_pocs) {
    alloc_registry::reset();
    {
        check_swap_keeps_owners<pocs_allocator<map_value>>();
        check_swap_keeps_owners<tagged_allocator<map_value>>();
    }
    EXPECT_TRUE(alloc_registry::balanced());
}

TEST(unordered_flat_map, no_foreign_or_double_deallocation) {
    alloc_registry::reset();
    {
        using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                         tagged_allocator<map_value>>;

        map_t a(15, tagged_allocator<map_value>{1});
        a.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t b(15, tagged_allocator<map_value>{2});
        b.insert({{10, 100}, {20, 200}, {30, 300}, {40, 400}});

        map_t copy(a);
        b = a;
        b = std::move(copy);
        a.swap(b);

        EXPECT_EQ(sorted_entries(a), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(sorted_entries(b), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    }

    EXPECT_TRUE(alloc_registry::live.empty());
    EXPECT_EQ(alloc_registry::wrong_owner, 0);
    EXPECT_EQ(alloc_registry::unknown_ptr, 0);
    EXPECT_EQ(alloc_registry::wrong_size, 0);
}

TEST(unordered_flat_map, deallocation_uses_original_allocation_size) {
    alloc_registry::reset();
    {
        using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                         tagged_allocator<map_value>>;

        map_t map(15, tagged_allocator<map_value>{1});
        map.rehash(1000);
        map.insert({{1, 10}, {2, 20}, {3, 30}});
        map.rehash(10000);
        map.insert({{4, 40}, {5, 50}, {6, 60}});
    }

    EXPECT_EQ(alloc_registry::wrong_size, 0);
    EXPECT_EQ(alloc_registry::wrong_owner, 0);
    EXPECT_EQ(alloc_registry::unknown_ptr, 0);
    EXPECT_TRUE(alloc_registry::live.empty());
}

TEST(unordered_flat_map, every_path_returns_to_zero_allocation) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t a;
        a.reserve(100);
        for (int i = 0; i < 100; ++i) {
            a.insert({i, i});
        }

        map_t b(a);
        map_t c(std::move(b));
        map_t d;
        d = c;
        map_t e;
        e = std::move(d);
        e.swap(c);
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, pmr_style_resources_are_isolated) {
    using pmr_alloc = std::pmr::polymorphic_allocator<map_value>;
    using pmr_map   = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>, pmr_alloc>;

    std::pmr::monotonic_buffer_resource resource1;
    std::pmr::monotonic_buffer_resource resource2;

    pmr_map a(15, pmr_alloc(&resource1));
    a.insert({{1, 10}, {2, 20}, {3, 30}});
    pmr_map b(15, pmr_alloc(&resource2));
    b.insert({{10, 100}, {20, 200}});

    EXPECT_EQ(a.get_allocator().resource(), &resource1);
    EXPECT_EQ(b.get_allocator().resource(), &resource2);

    pmr_map moved(std::move(a));
    EXPECT_EQ(moved.get_allocator().resource(), &resource1);
    EXPECT_TRUE(a.empty());
    EXPECT_EQ(sorted_entries(moved), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));

    pmr_map copy(moved);
    EXPECT_EQ(copy.get_allocator().resource(), std::pmr::get_default_resource());
    EXPECT_EQ(sorted_entries(copy), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));

    EXPECT_TRUE(copy.insert({4, 40}).second);
    EXPECT_EQ(copy.size(), 4u);
}

TEST(unordered_flat_map, non_trivial_destructor_balance) {
    using value_type = std::pair<const live_key, int>;
    using map_t      = unordered_flat_map<live_key, int, live_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    live_key::live = 0;
    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 10; ++i) {
            map.insert({live_key(i), i});
        }
        EXPECT_EQ(live_key::live, 10);

        map.erase(map.begin());
        EXPECT_EQ(live_key::live, 9);

        map.erase(live_key(5));
        EXPECT_EQ(live_key::live, 8);

        map.clear();
        EXPECT_EQ(live_key::live, 0);

        for (int i = 0; i < 4; ++i) {
            map.insert({live_key(i), i});
        }
        EXPECT_EQ(live_key::live, 4);

        map_t copy(map);
        EXPECT_EQ(live_key::live, 8);

        copy = map;
        EXPECT_EQ(live_key::live, 8);

        map_t moved(std::move(copy));
        EXPECT_EQ(live_key::live, 8);
        EXPECT_TRUE(copy.empty());

        map = std::move(moved);
        EXPECT_EQ(live_key::live, 4);
        EXPECT_TRUE(moved.empty());
        EXPECT_EQ(map.size(), 4u);
    }
    EXPECT_EQ(live_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, move_only_mapped) {
    using map_t = unordered_flat_map<int, std::unique_ptr<int>>;

    map_t map;
    EXPECT_TRUE(map.try_emplace(1, std::make_unique<int>(10)).second);
    EXPECT_TRUE(map.insert_or_assign(2, std::make_unique<int>(20)).second);

    EXPECT_EQ(*map.at(1), 10);
    EXPECT_EQ(*map.at(2), 20);

    auto found = map.find(1);
    ASSERT_NE(found, map.end());
    EXPECT_EQ(*found->second, 10);

    map.rehash(100);
    EXPECT_EQ(map.size(), 2u);
    EXPECT_EQ(*map.at(1), 10);

    map_t moved(std::move(map));
    EXPECT_EQ(moved.size(), 2u);
    EXPECT_TRUE(map.empty());

    map_t assigned;
    assigned = std::move(moved);
    EXPECT_EQ(assigned.size(), 2u);
    EXPECT_TRUE(moved.empty());
    EXPECT_EQ(*assigned.at(2), 20);
}

TEST(unordered_flat_map, non_assignable_key) {
    using map_t = unordered_flat_map<non_assignable_key, int, non_assignable_hash>;

    static_assert(!std::is_copy_assignable_v<non_assignable_key>);
    static_assert(std::is_copy_constructible_v<non_assignable_key>);

    map_t map;
    EXPECT_TRUE(map.insert({non_assignable_key(1), 10}).second);
    EXPECT_TRUE(map.insert({non_assignable_key(2), 20}).second);

    map_t copy(map);
    EXPECT_EQ(copy.size(), 2u);

    copy.rehash(100);
    EXPECT_EQ(copy.size(), 2u);
    EXPECT_TRUE(copy.contains(non_assignable_key(1)));
    EXPECT_TRUE(copy.contains(non_assignable_key(2)));
    EXPECT_EQ(copy.at(non_assignable_key(1)), 10);

    map_t assigned;
    assigned = copy;
    EXPECT_EQ(assigned.size(), 2u);
    EXPECT_TRUE(assigned.contains(non_assignable_key(1)));
}

TEST(unordered_flat_map, string_key_with_sso_and_long_values) {
    using map_t = unordered_flat_map<std::string, int>;

    map_t map;
    const std::string long_value(200, 'x');

    EXPECT_TRUE(map.insert({"abc", 1}).second);
    EXPECT_TRUE(map.insert({long_value, 2}).second);

    EXPECT_TRUE(map.contains("abc"));
    EXPECT_TRUE(map.contains(long_value));
    EXPECT_EQ(map.at("abc"), 1);
    EXPECT_EQ(map.at(long_value), 2);

    EXPECT_EQ(map.erase("abc"), 1u);
    EXPECT_FALSE(map.contains("abc"));

    map.rehash(1000);
    EXPECT_TRUE(map.contains(long_value));
    EXPECT_EQ(map.at(long_value), 2);
    EXPECT_EQ(map.size(), 1u);
}

TEST(unordered_flat_map, large_key) {
    using map_t = unordered_flat_map<large_key, int, large_key_hash>;

    map_t map;
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(map.insert({large_key{i, {}}, i}).second);
    }

    EXPECT_EQ(map.size(), 1000u);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(map.contains(large_key{i, {}}));
        EXPECT_EQ(map.at(large_key{i, {}}), i);
    }

    map.rehash(2000);
    for (int i = 0; i < 1000; ++i) {
        EXPECT_TRUE(map.contains(large_key{i, {}}));
    }

    for (int i = 0; i < 1000; i += 2) {
        EXPECT_EQ(map.erase(large_key{i, {}}), 1u);
    }
    EXPECT_EQ(map.size(), 500u);
}

TEST(unordered_flat_map, over_aligned_key) {
    for (std::size_t reserve_count :
         {std::size_t{0}, std::size_t{14}, std::size_t{28}, std::size_t{100}}) {
        check_element_alignment<16>(reserve_count);
        check_element_alignment<32>(reserve_count);
        check_element_alignment<64>(reserve_count);
    }
}

TEST(unordered_flat_map, empty_key_type_is_single_element) {
    using map_t = unordered_flat_map<empty_key, int, empty_key_hash>;

    map_t map;
    for (int i = 0; i < 10; ++i) {
        map.insert({empty_key{}, i});
    }

    EXPECT_EQ(map.size(), 1u);
    EXPECT_NE(map.find(empty_key{}), map.end());
    EXPECT_TRUE(map.contains(empty_key{}));
    EXPECT_EQ(map.at(empty_key{}), 0);
    EXPECT_EQ(map.erase(empty_key{}), 1u);
    EXPECT_TRUE(map.empty());
}

TEST(unordered_flat_map, narrow_key_types) {
    {
        unordered_flat_map<bool, int> map;
        EXPECT_TRUE(map.insert({true, 1}).second);
        EXPECT_TRUE(map.insert({false, 0}).second);
        EXPECT_EQ(map.size(), 2u);
        EXPECT_EQ(map.at(true), 1);
        EXPECT_EQ(map.at(false), 0);
        EXPECT_EQ(map.erase(true), 1u);
        EXPECT_FALSE(map.contains(true));
    }
    {
        unordered_flat_map<char, int> map;
        for (char i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_TRUE(map.contains(char{5}));
        EXPECT_EQ(map.at(char{5}), 5);
        EXPECT_EQ(map.erase(char{5}), 1u);
        EXPECT_EQ(map.size(), 9u);
    }
    {
        unordered_flat_map<short, int> map;
        for (short i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.insert({i, i}).second);
        }
        EXPECT_TRUE(map.contains(short{5}));
        EXPECT_EQ(map.at(short{5}), 5);
        EXPECT_EQ(map.erase(short{5}), 1u);
        EXPECT_EQ(map.size(), 9u);
    }
}

TEST(unordered_flat_map, key_with_throwing_hash_or_equal) {
    using map_t = unordered_flat_map<int, int, flaky_hash, flaky_equal>;

    flaky_hash::armed  = false;
    flaky_equal::armed = false;

    map_t map;
    map.insert({42, 420});

    flaky_hash::armed = true;
    EXPECT_THROW((void)map.find(42), std::runtime_error);
    EXPECT_THROW((void)map.count(42), std::runtime_error);
    EXPECT_THROW((void)map.contains(42), std::runtime_error);
    EXPECT_THROW((void)map.at(42), std::runtime_error);
    flaky_hash::armed = false;

    EXPECT_EQ(map.size(), 1u);
    EXPECT_NE(map.find(42), map.end());

    flaky_equal::armed = true;
    EXPECT_THROW((void)map.find(42), std::runtime_error);
    EXPECT_THROW(map.erase(42), std::runtime_error);
    flaky_equal::armed = false;

    EXPECT_EQ(map.size(), 1u);
    EXPECT_NE(map.find(42), map.end());
    EXPECT_TRUE(map.insert({43, 430}).second);
}

TEST(unordered_flat_map, copy_ctor_strong_guarantee) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t source;
        for (int i = 0; i < 10; ++i) {
            source.insert(map_t::value_type{throwing_key(i), i});
        }
        ASSERT_EQ(throwing_key::live, 10);
        ASSERT_EQ(alloc_stats::allocs, 1);

        throwing_key::copies_until_throw = 3;
        EXPECT_THROW(
            {
                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
                map_t copy(source);
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

TEST(unordered_flat_map, range_ctor_strong_guarantee) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();

    std::vector<map_t::value_type> values;
    values.reserve(8);
    for (int i = 0; i < 8; ++i) {
        values.emplace_back(throwing_key(i), i);
    }
    ASSERT_EQ(throwing_key::live, 8);

    throwing_key::copies_until_throw = 2;
    EXPECT_THROW(
        {
            map_t map(values.begin(), values.end());
            (void)map;
        },
        std::runtime_error);

    throwing_key::reset_counters();

    EXPECT_EQ(throwing_key::live, 8);
    EXPECT_EQ(alloc_stats::allocs, 1);
    EXPECT_EQ(alloc_stats::deallocs, 1);
}

TEST(unordered_flat_map, insert_weak_guarantee) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 5; ++i) {
            map.insert(map_t::value_type{throwing_key(i), i});
        }
        const int allocs_before = alloc_stats::allocs;

        throwing_key candidate(99);
        map_t::value_type value{std::move(candidate), 990};
        throwing_key::copies_until_throw = 0;

        EXPECT_THROW(map.insert(value), std::runtime_error);

        throwing_key::reset_counters();

        EXPECT_EQ(map.size(), 5u);
        EXPECT_EQ(std::distance(map.begin(), map.end()), static_cast<std::ptrdiff_t>(map.size()));
        for (int i = 0; i < 5; ++i) {
            EXPECT_TRUE(map.contains(throwing_key(i)));
        }
        EXPECT_EQ(alloc_stats::allocs, allocs_before);
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, rehash_weak_guarantee) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 10; ++i) {
            map.insert(map_t::value_type{throwing_key(i), i});
        }
        EXPECT_EQ(throwing_key::live, 10);

        throwing_key::copies_until_throw = 4;
        EXPECT_THROW(map.rehash(1000), std::runtime_error);
        throwing_key::reset_counters();

        EXPECT_EQ(throwing_key::live, 10);
        EXPECT_EQ(map.size(), 10u);
        EXPECT_EQ(std::distance(map.begin(), map.end()), static_cast<std::ptrdiff_t>(map.size()));
        EXPECT_FLOAT_EQ(map.load_factor(), static_cast<float>(10.0 / 16.0));

        map.clear();
        EXPECT_EQ(throwing_key::live, 0);
        for (int i = 0; i < 10; ++i) {
            map.insert(map_t::value_type{throwing_key(i), i});
        }

        map.rehash(1000);
        EXPECT_EQ(map.size(), 10u);
        EXPECT_FLOAT_EQ(map.load_factor(), static_cast<float>(10.0 / 1024.0));
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.contains(throwing_key(i)));
        }
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, insert_growth_path_exception) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 14; ++i) {
            map.insert(map_t::value_type{throwing_key(i), i});
        }
        ASSERT_EQ(map.size(), 14u);

        throwing_key::copies_until_throw = 7;
        EXPECT_THROW(map.insert(map_t::value_type{throwing_key(14), 14}), std::runtime_error);
        throwing_key::reset_counters();

        EXPECT_EQ(throwing_key::live, 14);
        EXPECT_EQ(map.size(), 14u);
        EXPECT_EQ(std::distance(map.begin(), map.end()), static_cast<std::ptrdiff_t>(map.size()));

        map.clear();
        EXPECT_EQ(throwing_key::live, 0);
        for (int i = 0; i < 15; ++i) {
            EXPECT_TRUE(map.insert(map_t::value_type{throwing_key(i), i}).second);
        }
        EXPECT_EQ(map.size(), 15u);
        EXPECT_FLOAT_EQ(map.load_factor(), static_cast<float>(15.0 / 32.0));
    }
    throwing_key::reset_counters();
    EXPECT_EQ(throwing_key::live, 0);
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, length_error_leaves_container_usable) {
    map_t map;
    map.insert({{1, 10}, {2, 20}, {3, 30}});

    EXPECT_THROW(map.rehash((std::numeric_limits<std::size_t>::max)()), std::length_error);

    EXPECT_EQ(sorted_entries(map), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
    EXPECT_TRUE(map.insert({4, 40}).second);
    EXPECT_EQ(map.size(), 4u);
}

TEST(unordered_flat_map, copy_assign_weak_guarantee) {
    using value_type = std::pair<const throwing_key, int>;
    using map_t      = unordered_flat_map<throwing_key, int, throwing_key_hash, std::equal_to<>,
                                          counting_allocator<value_type>>;

    throwing_key::live = 0;
    throwing_key::reset_counters();
    alloc_stats::reset();
    {
        map_t target;
        for (int i = 0; i < 5; ++i) {
            target.insert(map_t::value_type{throwing_key(i), i});
        }

        map_t source;
        for (int i = 0; i < 10; ++i) {
            source.insert(map_t::value_type{throwing_key(100 + i), 100 + i});
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

TEST(unordered_flat_map, exception_during_swap_no_effect) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     throwing_swap_allocator<map_value>>;

    throwing_swap_allocator<map_value>::armed = false;
    {
        map_t a(15, throwing_swap_allocator<map_value>{1});
        a.insert({{1, 10}, {2, 20}, {3, 30}});
        map_t b(15, throwing_swap_allocator<map_value>{2});
        b.insert({{10, 100}, {20, 200}});

        throwing_swap_allocator<map_value>::armed = true;
        EXPECT_THROW(a.swap(b), std::runtime_error);
        throwing_swap_allocator<map_value>::armed = false;

        EXPECT_EQ(sorted_entries(a), (std::vector<std::pair<int, int>>{{1, 10}, {2, 20}, {3, 30}}));
        EXPECT_EQ(sorted_entries(b), (std::vector<std::pair<int, int>>{{10, 100}, {20, 200}}));
        EXPECT_EQ(a.get_allocator().id, 1);
        EXPECT_EQ(b.get_allocator().id, 2);
    }
}

TEST(unordered_flat_map, differential_against_std_unordered_map) {
    map_t map;
    std::unordered_map<int, int> reference;
    std::mt19937 engine(123456789);

    for (int step = 0; step < 200000; ++step) {
        const int op  = static_cast<int>(engine() % 100);
        const int key = static_cast<int>(engine() % 1000);

        if (op < 40) {
            const int value     = key * 2;
            const bool inserted = map.insert({key, value}).second;
            const bool expected = reference.insert({key, value}).second;
            EXPECT_EQ(inserted, expected);
        } else if (op < 65) {
            const int value     = key + 1000;
            const bool assigned = map.insert_or_assign(key, value).second;
            const bool expected = reference.insert_or_assign(key, value).second;
            EXPECT_EQ(assigned, expected);
        } else if (op < 85) {
            const int value     = key + 2000;
            const bool inserted = map.try_emplace(key, value).second;
            const bool expected = reference.try_emplace(key, value).second;
            EXPECT_EQ(inserted, expected);
        } else if (op < 97) {
            EXPECT_EQ(map.erase(key), reference.erase(key));
        } else if (op < 99) {
            EXPECT_EQ(map.contains(key), reference.contains(key));
        } else {
            map.clear();
            reference.clear();
        }

        EXPECT_EQ(map.size(), reference.size());
        EXPECT_EQ(map.contains(key), reference.contains(key));
        if (map.contains(key)) {
            EXPECT_EQ(map.at(key), reference.at(key));
        }

        if (step % 1000 == 0) {
            std::vector<std::pair<int, int>> expected(reference.begin(), reference.end());
            std::sort(expected.begin(), expected.end());
            EXPECT_EQ(sorted_entries(map), expected);
        }
    }

    std::vector<std::pair<int, int>> expected(reference.begin(), reference.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(sorted_entries(map), expected);
}

TEST(unordered_flat_map, adversarial_pinned_hash_layouts) {
    using map_t = unordered_flat_map<int, int, pinned_hash>;

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
        map_t map(0, hash);
        map.reserve(28);

        for (int key = 1; key <= 8; ++key) {
            EXPECT_TRUE(map.insert({key, key * 10}).second);
        }
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(map.insert({10 + i, (10 + i) * 10}).second);
        }
        EXPECT_TRUE(map.insert({30, 300}).second);

        for (int key = 1; key <= 8; ++key) {
            EXPECT_TRUE(map.contains(key));
            EXPECT_EQ(map.at(key), key * 10);
        }
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(map.contains(10 + i));
        }
        EXPECT_TRUE(map.contains(30));

        for (int key = 1; key <= 8; ++key) {
            EXPECT_EQ(map.erase(key), 1u);
        }
        for (int i = 0; i < 16; i += 2) {
            EXPECT_EQ(map.erase(10 + i), 1u);
        }
        EXPECT_EQ(map.erase(30), 1u);
        EXPECT_EQ(map.size(), 8u);
    }

    {
        map_t map(0, hash);
        map.reserve(28);
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.insert({40 + i, i}).second);
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_TRUE(map.contains(40 + i));
        }
        for (int i = 0; i < 10; ++i) {
            EXPECT_EQ(map.erase(40 + i), 1u);
        }
        EXPECT_TRUE(map.empty());
    }

    for (int i = 0; i < 16; ++i) {
        hash.table.push_back({200 + i, {0, static_cast<std::size_t>(i)}});
    }
    hash.table.push_back({216, {0, 100}});

    {
        std::vector<std::pair<int, int>> values;
        values.reserve(17);
        for (int i = 0; i < 16; ++i) {
            values.emplace_back(200 + i, i);
        }
        values.emplace_back(216, 216);

        map_t map(values.begin(), values.end(), 0, hash);
        EXPECT_EQ(map.size(), 17u);
        for (int i = 0; i < 16; ++i) {
            EXPECT_TRUE(map.contains(200 + i));
            EXPECT_EQ(map.at(200 + i), i);
        }
        EXPECT_TRUE(map.contains(216));
    }
}

TEST(unordered_flat_map, growth_sweep_1_to_300) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;

        for (int i = 1; i <= 300; ++i) {
            map.insert({i, i});

            const std::size_t capacity = capacity_from_bytes<map_value>(alloc_stats::last_size);
            EXPECT_EQ(capacity, detail::swiss_table_size_to_capacity(static_cast<std::size_t>(i)));
            EXPECT_EQ(map.size(), static_cast<std::size_t>(i));
            EXPECT_EQ(std::distance(map.begin(), map.end()),
                      static_cast<std::ptrdiff_t>(map.size()));
            EXPECT_LE(map.load_factor(), map.max_load_factor());

            for (int j = 1; j <= i; ++j) {
                ASSERT_TRUE(map.contains(j)) << "i=" << i << " j=" << j;
                ASSERT_EQ(map.at(j), j) << "i=" << i << " j=" << j;
            }
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, tombstone_storm) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        std::vector<bool> present(100, false);
        std::size_t live_count = 0;
        std::mt19937 engine(987654321);

        for (int step = 0; step < 100000; ++step) {
            const int key = static_cast<int>(engine() % 100);
            if (engine() & 1) {
                if (map.insert({key, key * 10}).second) {
                    ASSERT_FALSE(present[static_cast<std::size_t>(key)]);
                    present[static_cast<std::size_t>(key)] = true;
                    ++live_count;
                }
            } else {
                const auto erased = map.erase(key);
                EXPECT_EQ(erased, present[static_cast<std::size_t>(key)] ? 1u : 0u);
                if (erased != 0) {
                    present[static_cast<std::size_t>(key)] = false;
                    --live_count;
                }
            }

            ASSERT_EQ(map.size(), live_count);

            if (step % 1000 == 0) {
                for (int i = 0; i < 100; ++i) {
                    EXPECT_EQ(map.contains(i), present[static_cast<std::size_t>(i)]);
                    if (present[static_cast<std::size_t>(i)]) {
                        EXPECT_EQ(map.at(i), i * 10);
                    }
                }
            }
        }

        EXPECT_LE(capacity_from_bytes<map_value>(alloc_stats::last_size), 127u);
        EXPECT_LE(map.load_factor(), map.max_load_factor());
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, clear_insert_cycles) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t map;
        for (int i = 0; i < 50; ++i) {
            map.insert({i, i});
        }
        const std::size_t capacity_before = capacity_from_bytes<map_value>(alloc_stats::last_size);
        const int allocs_before           = alloc_stats::allocs;

        for (int round = 0; round < 5; ++round) {
            map.clear();
            EXPECT_TRUE(map.empty());
            EXPECT_EQ(capacity_from_bytes<map_value>(alloc_stats::last_size), capacity_before);

            for (int i = 0; i < 50; ++i) {
                EXPECT_TRUE(map.insert({i, i}).second);
            }
            EXPECT_EQ(map.size(), 50u);
            for (int i = 0; i < 50; ++i) {
                EXPECT_TRUE(map.contains(i));
            }
            EXPECT_EQ(alloc_stats::allocs, allocs_before);
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, move_copy_churn) {
    using map_t = unordered_flat_map<int, int, std::hash<int>, std::equal_to<>,
                                     counting_allocator<map_value>>;

    alloc_stats::reset();
    {
        map_t base;
        for (int i = 0; i < 100; ++i) {
            base.insert({i, i});
        }

        for (int round = 0; round < 50; ++round) {
            map_t copy(base);
            map_t moved(std::move(copy));
            map_t assigned;
            assigned = base;
            map_t moved_assigned;
            moved_assigned = std::move(assigned);

            EXPECT_EQ(moved.size(), 100u);
            EXPECT_EQ(moved_assigned.size(), 100u);
            EXPECT_TRUE(moved.contains(round));
            EXPECT_TRUE(moved_assigned.contains(round));
            EXPECT_EQ(moved.at(round), round);
            EXPECT_EQ(moved_assigned.at(round), round);
        }

        EXPECT_EQ(base.size(), 100u);
        for (int i = 0; i < 100; ++i) {
            EXPECT_TRUE(base.contains(i));
        }
    }
    EXPECT_EQ(alloc_stats::allocs, alloc_stats::deallocs);
}

TEST(unordered_flat_map, large_map_smoke) {
    map_t map;
    constexpr int count = 100000;

    for (int i = 0; i < count; ++i) {
        map.insert({i, i});
    }
    EXPECT_EQ(map.size(), static_cast<std::size_t>(count));

    for (int i = 0; i < count; ++i) {
        ASSERT_TRUE(map.contains(i)) << "i=" << i;
        ASSERT_EQ(map.at(i), i) << "i=" << i;
    }

    for (int i = 0; i < count; i += 2) {
        map.erase(i);
    }
    EXPECT_EQ(map.size(), static_cast<std::size_t>(count / 2));
    for (int i = 0; i < count; ++i) {
        EXPECT_EQ(map.contains(i), i % 2 != 0);
    }
}

TEST(unordered_flat_map, typedefs_are_correct) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(std::is_same_v<map_t::key_type, int>);
    static_assert(std::is_same_v<map_t::mapped_type, int>);
    static_assert(std::is_same_v<map_t::value_type, std::pair<const int, int>>);
    static_assert(
        std::is_same_v<map_t::size_type, std::allocator_traits<map_t::allocator_type>::size_type>);
    static_assert(std::is_same_v<map_t::difference_type,
                                 std::allocator_traits<map_t::allocator_type>::difference_type>);
    static_assert(std::is_same_v<map_t::iterator::pointer, map_t::pointer>);
    static_assert(std::is_same_v<map_t::iterator::reference, map_t::reference>);
    static_assert(std::is_same_v<map_t::const_iterator::pointer, map_t::const_pointer>);
    static_assert(std::is_same_v<map_t::const_iterator::reference, map_t::const_reference>);
}

TEST(unordered_flat_map, move_operations_are_noexcept) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(std::is_nothrow_move_constructible_v<map_t>);
    static_assert(std::is_nothrow_move_assignable_v<map_t>);
    static_assert(noexcept(std::declval<map_t &>().swap(std::declval<map_t &>())));
}

TEST(unordered_flat_map, erase_return_types) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(
        std::is_void_v<decltype(std::declval<map_t &>().erase(std::declval<map_t::iterator>()))>);
    static_assert(std::is_void_v<decltype(std::declval<map_t &>().erase(
                      std::declval<map_t::const_iterator>()))>);
    static_assert(std::is_same_v<decltype(std::declval<map_t &>().erase(
                                     std::declval<map_t::const_iterator>(),
                                     std::declval<map_t::const_iterator>())),
                                 map_t::iterator>);
}

TEST(unordered_flat_map, emplace_requires_constructible) {
    using map_t = unordered_flat_map<int, int>;

    static_assert(can_emplace<map_t, int, int>);
    static_assert(!can_emplace<map_t, int, int, int>);
}

TEST(unordered_flat_map, insert_transparent_requires_constraint) {
    using default_map = unordered_flat_map<std::string, int>;
    using opaque_map  = unordered_flat_map<std::string, int, std::hash<std::string>>;
    using transparent_map =
        unordered_flat_map<tracked_text, int, transparent_text_hash, transparent_text_equal>;

    static_assert(can_insert<default_map, std::pair<std::string_view, int>>);
    static_assert(can_insert<transparent_map, std::pair<std::string_view, int>>);
    static_assert(!can_insert<opaque_map, std::pair<std::string_view, int>>);
    static_assert(!can_insert<opaque_map, int>);
}

TEST(unordered_flat_map, bucket_count_zero_is_not_a_length_error) {
    using map_t = unordered_flat_map<int, int>;

    EXPECT_NO_THROW({
        map_t map(0);
        (void)map;
    });
}

TEST(unordered_flat_map, object_size_stays_compressed) {
    using map_t = unordered_flat_map<int, int>;

    EXPECT_LE(sizeof(map_t), 5 * sizeof(void *));
}
