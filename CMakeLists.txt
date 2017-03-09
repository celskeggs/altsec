cmake_minimum_required(VERSION 3.6)
project(altsec)

find_package(PkgConfig)

pkg_check_modules(libnotify REQUIRED IMPORTED_TARGET libnotify)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES main.c)
add_executable(altsec ${SOURCE_FILES})
target_link_libraries(altsec PkgConfig::libnotify)

install(TARGETS altsec RUNTIME DESTINATION bin)
