cmake_minimum_required(VERSION 3.20)
project(DS3Probe LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Статический CRT (/MT): DLL запускается на любой машине без vcredist (аудит, 6.9)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Версия DLL в логе: SHA коммита (в GitHub Actions - из GITHUB_SHA, локально - из git)
set(DS3PROBE_GIT_SHA "unknown")
if(DEFINED ENV{GITHUB_SHA} AND NOT "$ENV{GITHUB_SHA}" STREQUAL "")
    string(SUBSTRING "$ENV{GITHUB_SHA}" 0 7 DS3PROBE_GIT_SHA)
else()
    find_package(Git QUIET)
    if(GIT_FOUND)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --short=7 HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _ds3_sha
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
        if(_ds3_sha)
            set(DS3PROBE_GIT_SHA "${_ds3_sha}")
        endif()
    endif()
endif()
message(STATUS "DS3Probe git sha: ${DS3PROBE_GIT_SHA}")

add_library(dinput8 SHARED
    src/DS3Probe.cpp
    include/safetyhook/Zydis.c
    include/safetyhook/safetyhook.cpp
)

target_include_directories(dinput8 PRIVATE
    include
    include/safetyhook
    src
)

target_compile_definitions(dinput8 PRIVATE DS3PROBE_GIT_SHA="${DS3PROBE_GIT_SHA}")

target_compile_options(dinput8 PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/std:c++latest>
    $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
)

set_target_properties(dinput8 PROPERTIES
    OUTPUT_NAME "dinput8"
    PREFIX ""
    SUFFIX ".dll"
)

target_link_options(dinput8 PRIVATE
    "/DEF:${CMAKE_SOURCE_DIR}/src/dinput8.def"
)
