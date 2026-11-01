#include "ciallo/crypto/chacha20.hpp"

#include <benchmark/benchmark.h>

#include <array>
#include <cstdint>
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
///   Generate a deterministic pseudo-random key or nonce for the benchmark.
/// @tparam Size
///   Number of bytes to generate.
/// @return
///   Array containing @p Size pseudo-random bytes.
template <std::size_t Size>
[[nodiscard]] static std::array<std::uint8_t, Size> make_benchmark_secret() {
    std::random_device device;
    std::mt19937_64 engine(device());

    std::array<std::uint8_t, Size> secret = {};
    for (std::uint8_t &byte : secret) {
        byte = static_cast<std::uint8_t>(engine());
    }
    return secret;
}

/// @brief
///   Measure ChaCha20 throughput for inputs of the size given by @c state.range(0).
static void chacha20_benchmark(benchmark::State &state) {
    const auto size = static_cast<std::size_t>(state.range(0));
    const auto data = make_benchmark_data(size);

    const auto key   = make_benchmark_secret<32>();
    const auto nonce = make_benchmark_secret<12>();

    std::vector<std::uint8_t> output(size);
    for (auto _ : state) {
        ciallo::chacha20(data.data(), data.size(), key.data(), nonce.data(), 0, output.data());
        benchmark::DoNotOptimize(output);
    }

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(size));
}

// Small inputs: dominated by call overhead and tail handling.
BENCHMARK(chacha20_benchmark)
    ->Arg(0)
    ->Arg(8)
    ->Arg(16)
    ->Arg(32)
    ->Arg(64)
    ->Arg(128)
    ->Arg(256)
    ->Name("chacha20/small");

// Medium inputs: the vectorized block loop is exercised.
BENCHMARK(chacha20_benchmark)->Arg(1024)->Arg(4096)->Arg(16384)->Name("chacha20/medium");

// Large inputs: sustained throughput.
BENCHMARK(chacha20_benchmark)->Arg(1 << 16)->Arg(1 << 20)->Arg(1 << 24)->Name("chacha20/large");
