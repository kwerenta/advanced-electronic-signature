project(pin-app)

add_executable(${PROJECT_NAME} main.c)

target_link_libraries(${PROJECT_NAME} common raylib nfd)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../common/lib/nativefiledialog/src/include)

# Checks if not Windows and links appropriate libraries
if (NOT WIN32)
  target_link_libraries(${PROJECT_NAME} m)
endif()

# Checks if OSX and links appropriate frameworks (only required on MacOS)
if (APPLE)
  target_link_libraries(${PROJECT_NAME} "-framework IOKit")
  target_link_libraries(${PROJECT_NAME} "-framework Cocoa")
  target_link_libraries(${PROJECT_NAME} "-framework OpenGL")
endif()

