add_executable(app main.cpp)

target_include_directories(app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Common++/header)
target_include_directories(app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Packet++/header)
target_include_directories(app PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Pcap++/header)


target_link_libraries(app ${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libPacket++.a)
target_link_libraries(app ${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libPcap++.a)
#target_link_libraries(app ${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libCommon++.a)
#target_link_libraries(app ${CMAKE_SOURCE_DIR}/../../../../usr/local/lib/libpqxx.a)
target_link_libraries(app -lpcap Pcap++ Packet++ Common++)

#target_link_libraries(app -lpcap Pcap++ Packet++ Common++ pcap pthread)

#-lpcap
#-static-libstdc++
#${PCAPPP_LIBS}