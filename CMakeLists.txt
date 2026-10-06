cmake_minimum_required(VERSION 3.20)
project(DS3Probe LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

target_compile_options(dinput8 PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/std:c++latest>
)

set_target_properties(dinput8 PROPERTIES
    OUTPUT_NAME "dinput8"
    PREFIX ""
    SUFFIX ".dll"
)

target_link_options(dinput8 PRIVATE
    "/DEF:${CMAKE_SOURCE_DIR}/src/dinput8.def"
)
