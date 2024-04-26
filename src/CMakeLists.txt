file(GLOB PH_SRC *.cpp)

add_library(PatternHunter ${PH_SRC})
target_include_directories(PatternHunter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(PatternHunter capstone TBS)

add_subdirectory(CLI)