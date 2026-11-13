cmake_minimum_required(VERSION 3.16)
project(netsim VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(NETSIM_BUILD_TESTS "Build unit tests (downloads GoogleTest)" ON)
option(NETSIM_SANITIZE "Enable ASan + UBSan" OFF)

add_library(netsim STATIC
  src/ip.cpp
  src/packet.cpp
  src/routing_table.cpp
  src/ospf.cpp
  src/bgp.cpp
  src/router.cpp
  src/network.cpp
  src/pcap.cpp)
target_include_directories(netsim PUBLIC include)
target_compile_options(netsim PRIVATE -Wall -Wextra -Wpedantic)

if(NETSIM_SANITIZE)
  target_compile_options(netsim PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(netsim PUBLIC -fsanitize=address,undefined)
endif()

add_executable(netsim_demo apps/demo.cpp)
target_link_libraries(netsim_demo PRIVATE netsim)

add_executable(netsim_bench apps/benchmark.cpp)
target_link_libraries(netsim_bench PRIVATE netsim)

if(NETSIM_BUILD_TESTS)
  enable_testing()
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)

  add_executable(netsim_tests
    tests/test_ip.cpp
    tests/test_packet.cpp
    tests/test_routing_table.cpp
    tests/test_ospf.cpp
    tests/test_bgp.cpp
    tests/test_router.cpp)
  target_link_libraries(netsim_tests PRIVATE netsim GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(netsim_tests)
endif()
