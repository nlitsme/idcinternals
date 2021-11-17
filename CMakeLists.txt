cmake_minimum_required(VERSION 3.10)
project(dbdump)
set(CMAKE_CXX_STANDARD 17)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(DARWIN TRUE)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(FREEBSD TRUE)
endif()

# checking if we are called in the correct way:
#  with a -B argument.  and without a cache file in the source directory.
if (CMAKE_CACHEFILE_DIR STREQUAL "${CMAKE_SOURCE_DIR}")
    message(FATAL_ERROR "\nUnexpected CMakeCache.txt file in the source directory. Please remove it.")
    return()
endif()

if (EXISTS ${CMAKE_BINARY_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "\nRun cmake with an explicit -B buildpath")
    return()
endif()

if(MSVC)
    # /MP = multithreaded build
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP")
    # /utf-8 = utf8 source and execution
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8")
endif()

if (WIN32)
    add_definitions(NOMINMAX NOGDI)
endif()

find_path(IDASDK_PATH NAMES include/netnode.hpp PATHS $ENV{IDASDK} $ENV{HOME}/src/idasdk76)
if (IDASDK_PATH STREQUAL IDASDK_PATH-NOTFOUND)
    message(FATAL_ERROR "IDASDK not found.")
endif()

add_library(idasdk INTERFACE)
target_include_directories(idasdk INTERFACE ${IDASDK_PATH}/include)
target_compile_definitions(idasdk INTERFACE MAXSTR=1024)
if (LINUX)
    target_compile_definitions(idasdk INTERFACE __LINUX__=1)
    target_link_libraries(idasdk INTERFACE ${IDASDK_PATH}/lib/x64_linux_gcc_64/libida64.so)
elseif (DARWIN)
    target_compile_definitions(idasdk INTERFACE __MAC__=1)
    target_link_libraries(idasdk INTERFACE ${IDASDK_PATH}/lib/x64_mac_clang_64/libida64.dylib)
elseif (WIN32)
    target_compile_definitions(idasdk INTERFACE __NT__=1)
    target_link_libraries(idasdk INTERFACE ${IDASDK_PATH}/lib/x64_win_vc_64/ida.lib)
endif()
# this prevents idasdk:fpro.h to redefine all stdio stuff to 'dont_use_XXX'
target_compile_definitions(idasdk INTERFACE USE_STANDARD_FILE_FUNCTIONS)
# this prevents idasdk:pro.h to redefine all string functions to 'dont_use_XXX'
target_compile_definitions(idasdk INTERFACE USE_DANGEROUS_FUNCTIONS)
# disallow obsolete sdk functions.
target_compile_definitions(idasdk INTERFACE NO_OBSOLETE_FUNCS)





add_library(dbdump MODULE pluginreg.cpp dumper.cpp)
target_compile_definitions(dbdump PUBLIC __IDP__)
target_compile_definitions(dbdump PUBLIC __DEFINE_ROOT_NODE__)
target_link_libraries(dbdump idasdk)
set_target_properties(dbdump PROPERTIES PREFIX "")
