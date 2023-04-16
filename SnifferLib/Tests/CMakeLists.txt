add_executable(SnifferTest testMain.cpp)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

enable_testing()

target_link_libraries(SnifferTest
  GTest::gtest_main
  SniffLib
)
#${CMAKE_CURRENT_SOURCE_DIR}/../../build/SnifferLib/libSnifferLib.a

# ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../usr/local/lib/libPacket++.a
# ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../usr/local/lib/libPcap++.a
# ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../usr/local/lib/libCommon++.a
# -lpcap 

include(GoogleTest)
gtest_discover_tests(SnifferTest)

target_include_directories(SnifferTest PRIVATE 
${CMAKE_CURRENT_SOURCE_DIR}/../Parser/include
)

# ${CMAKE_CURRENT_SOURCE_DIR}/../../../PcapPlusPlus/Common++/header
# ${CMAKE_CURRENT_SOURCE_DIR}/../../../PcapPlusPlus/Packet++/header
# ${CMAKE_CURRENT_SOURCE_DIR}/../../../PcapPlusPlus/Pcap++/header
# ${CMAKE_CURRENT_SOURCE_DIR}/../Statistic/include
# ${CMAKE_CURRENT_SOURCE_DIR}/../Logger