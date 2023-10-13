


add_executable(example example.c)

target_link_libraries(example zlog)
# target_include_directories(
#                 example PRIVATE
#                 "${CMAKE_CURRENT_SOURCE_DIR}/../src/")
