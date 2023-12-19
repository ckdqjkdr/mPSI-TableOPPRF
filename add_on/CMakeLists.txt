cmake_minimum_required(VERSION 2.8)
project(add_on)

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -std=c++11 -g -ggdb -maes -mpclmul -mbmi2 -msse4.1 -Wno-ignored-attributes")


INCLUDE_DIRECTORIES($ENV{HOME}/libscapi/build/NTL/include $ENV{HOME} $ENV{HOME}/libscapi/install/include
        $ENV{HOME}/libscapi/install/include/OTExtensionBristol ${CMAKE_CURRENT_SOURCE_DIR}/../frontend ${CMAKE_CURRENT_SOURCE_DIR}/../add_on)

set(SOURCE_FILES main.cpp add_on.cpp)


link_directories(/usr/ssl/lib/ $ENV{HOME}/libscapi/install/lib )


add_executable(add_on ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(add_on $ENV{HOME}/libscapi/install/lib/libntl.a
        $ENV{HOME}/libscapi/libscapi.a gmp OTExtensionBristol libsimpleot.a
        boost_system boost_thread pthread crypto dl ssl z libOTe libOPRF)
