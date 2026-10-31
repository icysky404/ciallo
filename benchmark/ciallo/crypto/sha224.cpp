#include "ciallo/crypto/sha2.hpp"

#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
#include <random>
#include <vector>

/// @brief
///   Generate deterministic pseudo-random data for the benchmark input.
[[nodiscard]] static std::vector<std::uint8_t> make_benchmark_data(std::size_t size) {
    std::random_device device;
    std::mt19937_64 engine(device());

    std::vector<std::uint8_t> data(size);
    for (std::uint8_t &byte : data) {
        byte = static_cast<std::uint8_t>(engine());
    }
    return data;
}

/// @brief
///   Measure SHA224 throughput for inputs of the size given by @c state.range(0).
static void sha224_benchmark(benchmark::State &state) {
    const auto size = static_cast<std::size_t>(state.range(0));
    const auto data = make_benchmark_data(size);

    std::array<std::uint8_t, 28> value = {};
    for (auto _ : state) {
        value = ciallo::sha224(data.data(), data.size());
        benchmark::DoNotOptimize(value);
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(size));
}

// Small inputs: dominated by call overhead and tail handling.  Arg(0) covers the empty message.
BENCHMARK(sha224_benchmark)->Arg(0)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Name("sha224/small");

// Medium inputs: the block loop is exercised.
BENCHMARK(sha224_benchmark)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)->Name("sha224/medium");

// Large inputs: sustained throughput.
BENCHMARK(sha224_benchmark)->Arg(1 << 16)->Arg(1 << 20)->Arg(1 << 24)->Name("sha224/large");
