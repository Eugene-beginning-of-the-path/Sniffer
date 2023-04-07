add_executable(snifferApp main.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../Convert/src/convertParam.cpp)

target_include_directories(snifferApp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../SnifferLib/Parser/include)
target_include_directories(snifferApp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../SnifferLib/Statistic/include)
target_include_directories(snifferApp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../Convert/include)

target_link_libraries(snifferApp PRIVATE SniffLib)