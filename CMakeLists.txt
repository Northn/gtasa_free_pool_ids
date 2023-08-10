cmake_minimum_required(VERSION 3.25)
project(gtasa_free_pool_ids)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SHARED_LIBRARY_SUFFIX ".asi")

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # MSVC-only flags
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
elseif (MSVC)
    # Both MSVC and MSVC-like command-line interface compilers (Clang-cl)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 /EHsc")
endif ()

add_subdirectory(third-party/kthook)

add_library(${PROJECT_NAME} SHARED
        library.cpp
        )
target_link_libraries(${PROJECT_NAME} PRIVATE kthook)
target_include_directories(${PROJECT_NAME} PRIVATE third-party/kthook/include)
