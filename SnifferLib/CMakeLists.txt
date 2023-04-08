cmake_minimum_required(VERSION 3.2)
project(SniffLibProject VERSION 0.1.1)

set(SOURCES 
Parser/src/parser.cpp 
Statistic/src/packetStats.cpp)

set(HEADERS 
Parser/include/parser.h
Statistic/include/packetStats.h)

add_library(SniffLib STATIC ${SOURCES} ${HEADERS})
set_target_properties(
    SniffLib PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
)


#including PcapPlusPlus headers:
target_include_directories(SniffLib PUBLIC 
${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Common++/header
${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Packet++/header
${CMAKE_SOURCE_DIR}/../PcapPlusPlus/Pcap++/header
)

#including headers of my library:
target_include_directories(SniffLib PUBLIC 
${CMAKE_CURRENT_SOURCE_DIR}/Parser/include
${CMAKE_CURRENT_SOURCE_DIR}/Statistic/include
)

#includeing header of spdlob library (Logger)
target_include_directories(SniffLib PUBLIC 
${CMAKE_CURRENT_SOURCE_DIR}/Logger
)

#linking libraries of PcapPlusPlus (Packet++, Pcap++, Common++)
target_link_libraries(SniffLib 
${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libPacket++.a
${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libPcap++.a
${CMAKE_SOURCE_DIR}/../../../../../usr/local/lib/libCommon++.a
-lpcap 
)
