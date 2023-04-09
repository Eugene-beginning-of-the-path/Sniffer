cmake_minimum_required(VERSION 3.2)
project(SniffAppProject VERSION 1.0.0)

add_executable(snifferApp main.cpp ${CMAKE_CURRENT_SOURCE_DIR}/Convert/src/convertParam.cpp)

target_include_directories(
    snifferApp PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/../SnifferLib/Parser/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../SnifferLib/Statistic/include
    ${CMAKE_CURRENT_SOURCE_DIR}/Convert/include
)   

target_link_libraries(snifferApp PRIVATE SniffLib)