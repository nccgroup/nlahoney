# Install script for directory: /home/ollie/freerdp/FreeRDP/winpr/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/winpr3/winpr" TYPE FILE FILES
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/asn1.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/bcrypt.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/bitstream.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/clipboard.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/cmdline.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/collections.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/comm.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/credentials.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/credui.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/crt.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/crypto.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/debug.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/dsparse.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/endian.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/environment.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/error.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/file.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/handle.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/heap.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/image.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/ini.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/input.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/interlocked.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/intrin.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/io.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/library.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/locale.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/memory.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/midl.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/ndr.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/nt.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/ntlm.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/pack.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/path.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/pipe.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/platform.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/pool.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/print.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/registry.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/rpc.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/sam.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/schannel.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/security.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/shell.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/smartcard.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/spec.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/ssl.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/sspi.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/sspicli.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/stream.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/string.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/strlst.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/synch.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/sysinfo.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/tchar.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/thread.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/timezone.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/user.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/version.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/windows.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/winhttp.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/winpr.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/winsock.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/wlog.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/wnd.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/wtsapi.h"
    "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/wtypes.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/winpr3/winpr" TYPE FILE FILES "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/version.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/winpr3/winpr" TYPE FILE FILES "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/wtypes.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/winpr3/winpr" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/winpr/include/winpr/tools" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

