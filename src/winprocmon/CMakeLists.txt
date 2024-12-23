# 设置cmake最低版本
cmake_minimum_required(VERSION 3.10)

# 设置项目名称与版本号
project(winprocmon VERSION 1.0.0)

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -Wextra")
endif(CMAKE_COMPILER_IS_GNUCC)

if(MSVC)
    string(REPLACE "/MD" "/MT" CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
    set(XLINK "/MANIFEST:NO")
endif(MSVC)


# 添加可运行文件（exe）
add_executable(winprocmon main.c  version.rc)

# 添加目标链接库
target_link_libraries(winprocmon -lpsapi)

# 设置目标链接属性
set_target_properties(winprocmon PROPERTIES LINK_FLAGS "${CMAKE_CREATE_WIN32_EXE} ${XLINK}")