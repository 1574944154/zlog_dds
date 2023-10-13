
project(zlog_for_dds)

cmake_minimum_required(VERSION 3.16)

set(module_name zlog)

add_library(${module_name} SHARED
    src/buf.c
    src/category_table.c
    src/category.c
    src/conf.c
    src/event.c
    src/format.c
    src/level_list.c
    src/level.c
    src/mdc.c
    src/record_table.c
    src/record.c
    src/rotater.c
    src/rule.c
    src/spec.c
    src/thread.c
    src/zc_arraylist.c
    src/zc_hashtable.c
    src/zc_profile.c
    src/zc_util.c
    src/zlog.c
)

target_include_directories(${module_name} PUBLIC src)

install(
    TARGETS ${module_name}
    EXPORT "${module_name}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}" COMPONENT lib
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lib
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}" COMPONENT lib
)

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/zlog.h
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT dev)
  