cmake_minimum_required(VERSION 2.8)
project(tcp-client)
set(EXE_NAME tcp-client)
set(CMAKE_PREFIX_PATH ${PROJECT_SOURCE_DIR}/deps/cmake)
set(CMAKE_C_STANDARD 99)
aux_source_directory(./src SOURCE_FILES)
#优先static
SET(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})

#数学库
list(APPEND DEPS_LIB m)

add_executable(${EXE_NAME} ${SOURCE_FILES})

#多线程支持
find_package(Threads REQUIRED)
if (THREADS_HAVE_PTHREAD_ARG)
    target_compile_options(PUBLIC ${EXE_NAME} "-pthread")
endif ()
if (CMAKE_THREAD_LIBS_INIT)
    list(APPEND DEPS_LIB ${CMAKE_THREAD_LIBS_INIT})
endif ()

find_package(FindPCAP)
if (PCAP_FOUND)
    include_directories(${PCAP_INCLUDE_DIR})
    list(APPEND DEPS_LIB ${PCAP_LIBRARY})
else ()
    message(FATAL_ERROR "libpcap not found!")
endif ()
find_package(FindLibNet)
if (LIBNET_FOUND)
    include_directories(${LIBNET_INCLUDE_DIR})
    list(APPEND DEPS_LIB ${LIBNET_LIBRARIES})
else ()
    message(FATAL_ERROR "libnet not found!")
endif ()
target_link_libraries(${EXE_NAME} ${DEPS_LIB})

