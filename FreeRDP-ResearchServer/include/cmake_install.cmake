# Install script for directory: /home/ollie/freerdp/FreeRDP/include

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE FILE FILES
    "/home/ollie/freerdp/FreeRDP/include/freerdp/addin.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/altsec.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/api.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/assistance.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/autodetect.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/build-config.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/client.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/codecs.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/constants.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/display.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/dvc.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/error.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/event.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/extension.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/freerdp.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/graphics.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/heartbeat.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/input.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/license.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/listener.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/log.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/message.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/metrics.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/peer.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/pointer.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/primary.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/primitives.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/rail.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/scancode.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/secondary.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/session.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/settings.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/svc.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/transport_io.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/types.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/update.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/version.h"
    "/home/ollie/freerdp/FreeRDP/include/freerdp/window.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE FILE FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/version.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE FILE FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/build-config.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/cache" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/codec" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/crypto" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/gdi" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/locale" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/utils" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/client" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/server" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/freerdp3/freerdp" TYPE DIRECTORY FILES "/home/ollie/freerdp/FreeRDP/include/freerdp/channels" FILES_MATCHING REGEX "/[^/]*\\.h$")
endif()

