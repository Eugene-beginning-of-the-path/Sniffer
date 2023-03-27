add_executable(app main.cpp)

target_include_directories(app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Common++/header
app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Packet++/header
app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Pcap++/header)

target_link_libraries(app
${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libPacket++.a
${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libPcap++.a
${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libCommon++.a)