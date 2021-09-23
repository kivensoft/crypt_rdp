cmake_minimum_required(VERSION 3.0.0)
project(encryptrdp VERSION 0.1.0)

# 设置c和c++标准版本
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 全局宏定义  -D_POSIX_C_SOURCE
# add_definitions(-DFMT_HEADER_ONLY -DMG_ENABLE_LOG=0)

# 设置c和c++编译选项
set(CMAKE_C_FLAGS "-Wall -fPIC")
set(CMAKE_CXX_FLAGS "-Wall -fPIC -fno-rtti -fno-exceptions")
set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O2 -flto")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -flto")

# 设置include和lib的目录
include_directories("include")
link_directories(AFTER "lib")

# 针对调试版本和发行版本设置编译标志和链接标志
if (CMAKE_BUILD_TYPE AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
    add_definitions(-DNDEBUG)
    add_link_options(-static -s)
else ()
    add_definitions(-DDEBUG)
    # target_link_libraries(${PROJECT_NAME} PUBLIC fmt_${OSN}_x64 spdlog_${OSN}_x64)
endif ()

include(CTest)
enable_testing()

add_executable(crypt_rdp main.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

# 或者用 make VERBOSE=1 来显示编译详情
if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_link_libraries(crypt_rdp PUBLIC crypt32)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
    # target_link_libraries(${PROJECT_NAME} PUBLIC pthread)
endif()
