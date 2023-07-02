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

#including headers of my library:
target_include_directories(SniffLib PUBLIC 
${CMAKE_CURRENT_SOURCE_DIR}/Parser/include
${CMAKE_CURRENT_SOURCE_DIR}/Statistic/include
)

##includeing header of spdlob library (Logger)
#target_include_directories(SniffLib PUBLIC 
#${CMAKE_CURRENT_SOURCE_DIR}/Logger
#)

include(FetchContent)
set (PATH_INSTLL_EXTRNL ${CMAKE_BINARY_DIR}/external)
FetchContent_Declare(PcapPlusPlus
	GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
	SOURCE_DIR ${PATH_INSTLL_EXTRNL}/PcapPlusPlus
	GIT_TAG master)
FetchContent_MakeAvailable(PcapPlusPlus)

FetchContent_Declare(spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog.git
	SOURCE_DIR ${PATH_INSTLL_EXTRNL}/spdlog
	GIT_TAG v1.x)
FetchContent_MakeAvailable(spdlog)

target_link_libraries(SniffLib 
    Pcap++
	Packet++
	Common++

	spdlog
)

add_subdirectory(Tests)
