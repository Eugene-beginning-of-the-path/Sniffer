set(SOURCES 
Parser/src/parser.cpp 
Statistic/src/packetStats.cpp)

set(HEADERS 
Parser/include/parser.h
Statistic/include/packetStats.h)

add_library(SniffLib STATIC ${SOURCES} ${HEADERS})

target_include_directories(SniffLib PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Common++/header)
target_include_directories(SniffLib PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Packet++/header)
target_include_directories(SniffLib PUBLIC ${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Pcap++/header)
target_include_directories(SniffLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Parser/include)
target_include_directories(SniffLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/Statistic/include)

target_link_libraries(SniffLib ${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libPacket++.a)
target_link_libraries(SniffLib ${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libPcap++.a)
#target_link_libraries(SniffLib ${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libCommon++.a)
#target_link_libraries(SniffLib ${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libpqxx.a)
target_link_libraries(SniffLib -lpcap Pcap++ Packet++ Common++)

#target_link_libraries(app -lpcap Pcap++ Packet++ Common++ pcap pthread)

#-lpcap
#-static-libstdc++
#${PCAPPP_LIBS}