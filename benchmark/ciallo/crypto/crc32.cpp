#include "ciallo/crypto/crc32.hpp"

#include <benchmark/benchmark.h>

#include <random>
#include <vector>

/// @brief
///   Generate deterministic pseudo-random data for the benchmark input.
/// @param size
///   Number of bytes to generate.
/// @return
///   Vector containing @p size pseudo-random bytes.
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
///   Measure CRC32 throughput for inputs of the size given by @c state.range(0).
static void crc32_benchmark(benchmark::State &state) {
    const auto size = static_cast<std::size_t>(state.range(0));
    const auto data = make_benchmark_data(size);

    std::uint32_t value = 0;
    for (auto _ : state) {
        value = ciallo::crc32(data.data(), data.size());
        benchmark::DoNotOptimize(value);
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(size));
}

// Small inputs: dominated by call overhead and tail handling.
BENCHMARK(crc32_benchmark)->Arg(8)->Arg(16)->Arg(32)->Arg(64)->Name("crc32/small");

// Medium inputs: the vectorized main loop is exercised.
BENCHMARK(crc32_benchmark)->Arg(256)->Arg(1024)->Arg(4096)->Arg(16384)->Name("crc32/medium");

// Large inputs: sustained throughput.
BENCHMARK(crc32_benchmark)->Arg(1 << 16)->Arg(1 << 20)->Arg(1 << 24)->Name("crc32/large");
