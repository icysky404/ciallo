#pragma once

#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#    include <xmmintrin.h>
#elif defined(_M_ARM) || defined(_M_ARM64)
#    include <intrin.h>
#endif

namespace ciallo {

/// @brief
///   Pause several instructions in spin loop.
inline auto spin_wait() noexcept -> void {
#if defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM64EC) || defined(__i386) ||               \
    defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
    _mm_pause();
#elif defined(_M_ARM) || defined(_M_ARM64) || defined(__arm__) || defined(__aarch64__)
#    if defined(_MSC_VER) && !defined(__GNUC__) && !defined(__clang__)
    __yield();
#    elif defined(__has_builtin) && __has_builtin(__builtin_arm_yield)
    __builtin_arm_yield();
#    elif defined(__has_builtin) && __has_builtin(__builtin_aarch64_yield)
    __builtin_aarch64_yield();
#    else
    __asm__ volatile("yield" ::: "memory");
#    endif
#else
#    error "unsupported architecture"
#endif
}

} // namespace ciallo
