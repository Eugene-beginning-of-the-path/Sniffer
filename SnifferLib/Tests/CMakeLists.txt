cmake_minimum_required(VERSION 3.2)
project(SniffTestProject VERSION 0.0.1)

add_executable(snifferTest testMain.cpp)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()

target_link_libraries(snifferTest
  GTest::gtest_main
  SniffLib
)

include(GoogleTest)
gtest_discover_tests(snifferTest)

target_include_directories(snifferTest PRIVATE 
${CMAKE_CURRENT_SOURCE_DIR}/../Parser/include
)
