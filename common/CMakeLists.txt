project(common)

add_library(${PROJECT_NAME} STATIC lib/clay-renderer.c clay-shared.c)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC raylib)
