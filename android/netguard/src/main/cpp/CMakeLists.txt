# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.18.1)

# Declares and names the project.

project("netguard")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( netguard
             SHARED
        ../../../../../src/netguard/netguard.c
        ../../../../../src/netguard/session.c
        ../../../../../src/netguard/ip.c
        ../../../../../src/netguard/tls.c
        ../../../../../src/netguard/tls_parser.c
        ../../../../../src/netguard/tcp.c
        ../../../../../src/netguard/udp.c
        ../../../../../src/netguard/icmp.c
        ../../../../../src/netguard/dns.c
        ../../../../../src/netguard/dhcp.c
        ../../../../../src/netguard/pcap.c
        ../../../../../src/netguard/memory.c
        ../../../../../src/netguard/socks5.c
        ../../../../../src/netguard/util.c
        ../../../../../src/netguard/fd_util.c
        ../../../../../src/netguard/android.c
        ../../../../../src/netguard/uid_mapping.c
        ../../../../../src/netguard/tun.c
             )

include_directories(../../../../../src/netguard/include)

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       netguard

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

#Ensure 16KB compatibility
target_link_options(
  netguard 
  PRIVATE 
  "-Wl,-z,common-page-size=16384"
  "-Wl,-z,max-page-size=16384")

# Makefile requires this to be with "/" to link correctly
file(TO_CMAKE_PATH ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} OUT_PATH_CMAKE)
add_custom_target(libwg-go.so WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src/wireguard" COMMENT "Building wireguard-go" VERBATIM COMMAND make
        ANDROID_ARCH_NAME=${ANDROID_ARCH_NAME}
        ANDROID_C_COMPILER=${ANDROID_C_COMPILER}
        ANDROID_TOOLCHAIN_ROOT=${ANDROID_TOOLCHAIN_ROOT}
        ANDROID_LLVM_TRIPLE=${ANDROID_LLVM_TRIPLE}
        ANDROID_SYSROOT=${ANDROID_SYSROOT}
        ANDROID_PACKAGE_NAME=${ANDROID_PACKAGE_NAME}
        GRADLE_USER_HOME=${GRADLE_USER_HOME}
        CFLAGS=${CMAKE_C_FLAGS}\ -Wno-unused-command-line-argument
        LDFLAGS=${CMAKE_SHARED_LINKER_FLAGS}\ -fuse-ld=gold\ -Wl,-z,max-page-size=16384\ -Wl,-z,common-page-size=16384
        DESTDIR=${OUT_PATH_CMAKE}
        BUILDDIR=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/../generated-src
        )

add_dependencies(libwg-go.so netguard)
