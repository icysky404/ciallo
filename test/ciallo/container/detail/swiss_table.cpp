#include "ciallo/container/detail/swiss_table.hpp"

#include <gtest/gtest.h>

using namespace ciallo::detail;

TEST(swiss_table, control_group) {
    // Match H2 hash.
    constexpr std::int8_t mixed_bytes[16] = {-128, -2, -1, 0,   1,   2,   3,  42,
                                             63,   64, 65, 126, 127, 127, 64, 42};
    swiss_table_control_group group(mixed_bytes);
    for (int hash = -128; hash <= 127; ++hash) {
        std::uint16_t mask = group.match(static_cast<std::int8_t>(hash));
        for (std::size_t offset = 0; offset < 16; ++offset) {
            EXPECT_EQ((mask >> offset) & 1, mixed_bytes[offset] == hash);
        }
    }

    EXPECT_EQ(group.match(-128), 0x0001);
    EXPECT_EQ(group.match(-2), 0x0002);
    EXPECT_EQ(group.match(-1), 0x0004);
    EXPECT_EQ(group.match(0), 0x0008);
    EXPECT_EQ(group.match(42), 0x8080);
    EXPECT_EQ(group.match(127), 0x3000);

    // Match empty slots.
    alignas(16) std::int8_t bytes[16];
    std::ranges::fill(bytes, swiss_table_empty);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty(), 0xFFFF);
    bytes[15] = swiss_table_sentinel;
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty(), 0x7FFF);

    std::ranges::fill(bytes, swiss_table_deleted);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty(), 0);
    std::ranges::fill(bytes, 0);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty(), 0);
    std::ranges::fill(bytes, swiss_table_sentinel);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty(), 0);

    EXPECT_EQ(swiss_table_control_group(mixed_bytes).match_empty(), group.match(swiss_table_empty));

    // Match full slots.
    std::ranges::fill(bytes, 0);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0xFFFF);
    std::ranges::fill(bytes, 1);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0xFFFF);
    std::ranges::fill(bytes, 127);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0xFFFF);

    std::ranges::fill(bytes, swiss_table_empty);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0);
    std::ranges::fill(bytes, swiss_table_deleted);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0);
    std::ranges::fill(bytes, swiss_table_sentinel);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full(), 0);

    EXPECT_EQ(swiss_table_control_group(mixed_bytes).match_full(), 0xFFF8);

    // Match non-full slots.
    std::ranges::fill(bytes, swiss_table_empty);
    EXPECT_EQ(swiss_table_control_group(bytes).match_non_full(), 0xFFFF);
    std::ranges::fill(bytes, swiss_table_deleted);
    EXPECT_EQ(swiss_table_control_group(bytes).match_non_full(), 0xFFFF);
    std::ranges::fill(bytes, swiss_table_sentinel);
    EXPECT_EQ(swiss_table_control_group(bytes).match_non_full(), 0xFFFF);

    std::ranges::fill(bytes, 0);
    EXPECT_EQ(swiss_table_control_group(bytes).match_non_full(), 0);
    std::ranges::fill(bytes, 127);
    EXPECT_EQ(swiss_table_control_group(bytes).match_non_full(), 0);

    EXPECT_EQ(swiss_table_control_group(mixed_bytes).match_non_full(), 0x0007);

    // Match empty or deleted.
    std::ranges::fill(bytes, -128);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty_or_deleted(), 0xFFFF);
    std::ranges::fill(bytes, -2);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty_or_deleted(), 0xFFFF);

    std::ranges::fill(bytes, -1);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty_or_deleted(), 0);
    std::ranges::fill(bytes, -0);
    EXPECT_EQ(swiss_table_control_group(bytes).match_empty_or_deleted(), 0);

    EXPECT_EQ(swiss_table_control_group(mixed_bytes).match_empty_or_deleted(), 0x0003);

    // Match full or sentinel.
    std::ranges::fill(bytes, 0);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full_or_sentinel(), 0xFFFF);
    std::ranges::fill(bytes, 127);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full_or_sentinel(), 0xFFFF);
    std::ranges::fill(bytes, -1);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full_or_sentinel(), 0xFFFF);

    std::ranges::fill(bytes, -2);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full_or_sentinel(), 0);
    std::ranges::fill(bytes, -128);
    EXPECT_EQ(swiss_table_control_group(bytes).match_full_or_sentinel(), 0);

    EXPECT_EQ(swiss_table_control_group(mixed_bytes).match_empty_or_deleted(), 0x0003);

    // A single distinguishing flag at each position stays at its own bit.
    for (std::size_t i = 0; i < 16; ++i) {
        std::ranges::fill(bytes, 0);
        bytes[i] = swiss_table_empty;

        swiss_table_control_group with_empty(bytes);
        EXPECT_EQ(with_empty.match_empty(), 1 << i);
        EXPECT_EQ(with_empty.match_empty_or_deleted(), 1 << i);
        EXPECT_EQ(with_empty.match_non_full(), 1 << i);
        EXPECT_EQ(with_empty.match_full(), 0xFFFF ^ (1 << i));
        EXPECT_EQ(with_empty.match_full_or_sentinel(), 0xFFFF ^ (1 << i));

        bytes[i] = swiss_table_deleted;
        swiss_table_control_group with_deleted(bytes);
        EXPECT_EQ(with_deleted.match_empty(), 0);
        EXPECT_EQ(with_deleted.match_empty_or_deleted(), 1 << i);
        EXPECT_EQ(with_deleted.match_non_full(), 1 << i);
        EXPECT_EQ(with_deleted.match_full(), 0xFFFF ^ (1 << i));
        EXPECT_EQ(with_deleted.match_full_or_sentinel(), 0xFFFF ^ (1 << i));

        bytes[i] = 1;
        swiss_table_control_group with_full(bytes);
        EXPECT_EQ(with_full.match_empty(), 0);
        EXPECT_EQ(with_full.match_empty_or_deleted(), 0);
        EXPECT_EQ(with_full.match_non_full(), 0);
        EXPECT_EQ(with_full.match_full(), 0xFFFF);
        EXPECT_EQ(with_full.match_full_or_sentinel(), 0xFFFF);

        std::ranges::fill(bytes, swiss_table_deleted);
        bytes[i] = -1;
        swiss_table_control_group with_sentinel(bytes);
        EXPECT_EQ(with_sentinel.match_full_or_sentinel(), 1 << i);
        EXPECT_EQ(with_sentinel.match_empty_or_deleted(), 0xFFFF ^ (1 << i));
        EXPECT_EQ(with_sentinel.match_full(), 0);
        EXPECT_EQ(with_sentinel.match_non_full(), 0xFFFF);
    }

    // Partitions.
    constexpr std::int8_t partition_groups[6][16] = {
        {-128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128, -128,
         -128},
        {-2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2},
        {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
        {127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127},
        {-128, -2, -1, 0, 1, 2, 3, 42, 63, 64, 65, 126, 127, 127, 64, 42},
    };

    for (auto i : partition_groups) {
        swiss_table_control_group group(i);
        EXPECT_EQ(group.match_full() | group.match_non_full(), 0xFFFF);
        EXPECT_EQ(group.match_full() & group.match_non_full(), 0);
        EXPECT_EQ(group.match_empty_or_deleted() | group.match_full_or_sentinel(), 0xFFFF);
        EXPECT_EQ(group.match_empty_or_deleted() & group.match_full_or_sentinel(), 0);
        EXPECT_EQ(group.match_empty_or_deleted(), group.match_empty() | group.match(-2));
        EXPECT_EQ(group.match_full_or_sentinel(), group.match_full() | group.match(-1));
        EXPECT_EQ(group.match_non_full(), group.match_empty() | group.match(-2) | group.match(-1));
    }
}
