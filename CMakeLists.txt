cmake_minimum_required(VERSION 3.21)

project(ciallo LANGUAGES CXX VERSION 0.0.1)

option(CIALLO_SHARED_LIBRARY "Build ciallo as shared library." OFF)
option(CIALLO_INSTALL_TARGET "Install ciallo targets." ON)
option(CIALLO_BUILD_TESTS "Build unit tests for ciallo." OFF)
option(CIALLO_BUILD_BENCHMARK "Build benchmarks for ciallo." OFF)
option(CIALLO_ENABLE_ASAN "Build with AddressSanitizer." OFF)

# Generate configuration header.
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/configuration.hpp.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/ciallo/configuration.hpp
    @ONLY
)

# Build ciallo library.
file(GLOB_RECURSE CIALLO_HEADER_FILES "include/*.hpp")
file(GLOB_RECURSE CIALLO_SOURCE_FILES "src/*.cpp")

source_group(
    TREE    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PREFIX  include
    FILES   ${CIALLO_HEADER_FILES}
)

source_group(
    TREE    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    PREFIX  src
    FILES   ${CIALLO_SOURCE_FILES}
)

if(CIALLO_SHARED_LIBRARY)
    add_library(ciallo SHARED ${CIALLO_SOURCE_FILES} ${CIALLO_HEADER_FILES})
    add_library(ciallo::ciallo ALIAS ciallo)
    add_library(ciallo::shared ALIAS ciallo)

    target_compile_definitions(
        ciallo
        PRIVATE "CIALLO_BUILD_SHARED_LIBRARY=1"
    )

    set_target_properties(
        ciallo
        PROPERTIES  POSITION_INDEPENDENT_CODE ON
                    CXX_VISIBILITY_PRESET hidden
                    VISIBILITY_INLINES_HIDDEN ON
    )
else()
    add_library(ciallo STATIC ${CIALLO_SOURCE_FILES} ${CIALLO_HEADER_FILES})
    add_library(ciallo::ciallo ALIAS ciallo)
    add_library(ciallo::static ALIAS ciallo)
endif()

target_compile_features(ciallo PUBLIC cxx_std_23)

# Include directories.
target_include_directories(
    ciallo
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Compile options.
if(MSVC)
    target_compile_options(
        ciallo
        PRIVATE "/W4" "/permissive-" "/volatile:iso" "/wd4324" "/wd4251"
    )

    if(CIALLO_ENABLE_ASAN)
        message(FATAL_ERROR "AddressSanitizer is not supported for MSVC.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(
        ciallo
        PRIVATE "-Wall" "-Wextra" "-pedantic" "-Winline" "-Wundef" "-Wreorder"
                "-Wshadow" "-Wold-style-cast"
    )

    if(CIALLO_ENABLE_ASAN)
        target_compile_options(ciallo PRIVATE "-fsanitize=address" "-fno-omit-frame-pointer")
        target_link_options(ciallo PUBLIC "-fsanitize=address")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    include(CheckCXXCompilerFlag)
    target_compile_options(
        ciallo
        PRIVATE "-Wall" "-Wextra" "-pedantic" "-Winline" "-Wundef" "-Wreorder"
                "-Wold-style-cast"
    )

    check_cxx_compiler_flag("-Wno-class-memaccess" HAVE_WNO_CLASS_MEMACCESS)
    if(HAVE_WNO_CLASS_MEMACCESS)
        target_compile_options(
            ciallo
            PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-class-memaccess>
        )
    endif()

    check_cxx_compiler_flag("-Wno-cast-function-type" HAVE_WNO_CAST_FUNCTION_TYPE)
    if(HAVE_WNO_CAST_FUNCTION_TYPE)
        target_compile_options(
            ciallo
            PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wno-cast-function-type>
        )
    endif()

    if(CIALLO_ENABLE_ASAN)
        target_compile_options(ciallo PRIVATE "-fsanitize=address" "-fno-omit-frame-pointer")
        target_link_options(ciallo PUBLIC "-fsanitize=address")
    endif()
endif()

# Generate install target.
if(CIALLO_INSTALL_TARGET)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(
        TARGETS ciallo
        EXPORT  ciallo-targets
    )

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ciallo-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/ciallo-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ciallo
    )

    write_basic_package_version_file(
        ciallo-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    install(
        FILES   ${CMAKE_CURRENT_BINARY_DIR}/ciallo-config.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/ciallo-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/ciallo
    )

    install(
        DIRECTORY   ${CMAKE_CURRENT_SOURCE_DIR}/include/ciallo
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Install common package specification if supported.
    if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.3")
        install(
            PACKAGE_INFO    ciallo
            EXPORT          ciallo-targets
            VERSION         ${ciallo_VERSION}
        )
    endif()
endif()

# Build unit tests.
if(CIALLO_BUILD_TESTS)
    include(cmake/CPM.cmake)
    CPMAddPackage(
        googletest
        VERSION 1.18.0
        URL https://github.com/google/googletest/releases/download/v1.18.0/googletest-1.18.0.tar.gz
        URL_HASH SHA256=6e3191c1455468b3fc35a417fb565c1c5071aee1b7e7f85e30cf48a98d37d8b5
        OPTIONS "INSTALL_GTEST OFF"
                "GTEST_HAS_ABSL OFF"
    )

    include(CTest)

    file(GLOB_RECURSE CIALLO_TEST_SOURCE_FILES "test/*.cpp")
    add_executable(ciallo-test ${CIALLO_TEST_SOURCE_FILES})
    add_executable(ciallo::test ALIAS ciallo-test)

    # Enable AddressSanitizer for the library, tests, and benchmarks.
    if(CIALLO_ENABLE_ASAN)
        if(MSVC)
            message(FATAL_ERROR "AddressSanitizer is not supported for MSVC.")
        else()
            target_compile_options(ciallo-test PRIVATE "-fsanitize=address" "-fno-omit-frame-pointer")
            target_link_options(ciallo-test PRIVATE "-fsanitize=address")
        endif()
    endif()

    target_link_libraries(
        ciallo-test
        PRIVATE ciallo GTest::gtest
    )

    include(GoogleTest)
    gtest_discover_tests(ciallo-test)
endif()

# Build benchmarks.
if(CIALLO_BUILD_BENCHMARK)
    include(cmake/CPM.cmake)
    CPMAddPackage(
        NAME benchmark
        VERSION 1.9.5
        URL https://github.com/google/benchmark/archive/refs/tags/v1.9.5.tar.gz
        URL_HASH SHA256=9631341c82bac4a288bef951f8b26b41f69021794184ece969f8473977eaa340
        OPTIONS "BENCHMARK_ENABLE_TESTING OFF"
                "BENCHMARK_ENABLE_INSTALL OFF"
                "BENCHMARK_ENABLE_WERROR OFF"
    )

    file(GLOB_RECURSE CIALLO_BENCHMARK_SOURCE_FILES "benchmark/*.cpp")

    add_executable(ciallo-benchmark ${CIALLO_BENCHMARK_SOURCE_FILES})
    add_executable(ciallo::benchmark ALIAS ciallo-benchmark)

    target_link_libraries(
        ciallo-benchmark
        PRIVATE ciallo benchmark::benchmark
    )
endif()
