cmake_minimum_required(VERSION 3.15)
project(advanced-electronic-signature)

find_package(raylib 5.5 REQUIRED)

set(CMAKE_C_STANDARD 11)

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} raylib m)

# Checks if OSX and links appropriate frameworks (only required on MacOS)
if (APPLE)
    target_link_libraries(${PROJECT_NAME} "-framework IOKit")
    target_link_libraries(${PROJECT_NAME} "-framework Cocoa")
    target_link_libraries(${PROJECT_NAME} "-framework OpenGL")
endif()
