# This file will be configured to contain variables for CPack. These variables
# should be set in the CMake list file of the project before CPack module is
# included. The list of available CPACK_xxx variables and their associated
# documentation may be obtained using
#  cpack --help-variable-list
#
# Some variables are common to all generators (e.g. CPACK_PACKAGE_NAME)
# and some are specific to a generator
# (e.g. CPACK_NSIS_EXTRA_INSTALL_COMMANDS). The generator specific variables
# usually begin with CPACK_<GENNAME>_xxxx.


set(CPACK_BINARY_7Z "")
set(CPACK_BINARY_BUNDLE "")
set(CPACK_BINARY_CYGWIN "")
set(CPACK_BINARY_DEB "OFF")
set(CPACK_BINARY_DRAGNDROP "")
set(CPACK_BINARY_FREEBSD "OFF")
set(CPACK_BINARY_IFW "OFF")
set(CPACK_BINARY_NSIS "OFF")
set(CPACK_BINARY_NUGET "")
set(CPACK_BINARY_OSXX11 "")
set(CPACK_BINARY_PACKAGEMAKER "")
set(CPACK_BINARY_PRODUCTBUILD "")
set(CPACK_BINARY_RPM "OFF")
set(CPACK_BINARY_STGZ "ON")
set(CPACK_BINARY_TBZ2 "OFF")
set(CPACK_BINARY_TGZ "ON")
set(CPACK_BINARY_TXZ "OFF")
set(CPACK_BINARY_TZ "ON")
set(CPACK_BINARY_WIX "")
set(CPACK_BINARY_ZIP "ON")
set(CPACK_BINARY_ZIP "ON")
set(CPACK_BUILD_SOURCE_DIRS "/home/ollie/freerdp/FreeRDP;/home/ollie/freerdp/FreeRDP")
set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_COMPONENTS_ALL "client;server;libraries;headers;symbols;tools")
set(CPACK_COMPONENTS_ALL_SET_BY_USER "TRUE")
set(CPACK_COMPONENT_CLIENT_DISPLAY_NAME "Client")
set(CPACK_COMPONENT_CLIENT_GROUP "Applications")
set(CPACK_COMPONENT_GROUP_APPLICATIONS_DESCRIPTION "Applications")
set(CPACK_COMPONENT_GROUP_DEVELOPMENT_DESCRIPTION "Development")
set(CPACK_COMPONENT_GROUP_RUNTIME_DESCRIPTION "Runtime")
set(CPACK_COMPONENT_HEADERS_DISPLAY_NAME "Headers")
set(CPACK_COMPONENT_HEADERS_GROUP "Development")
set(CPACK_COMPONENT_LIBRARIES_DISPLAY_NAME "Libraries")
set(CPACK_COMPONENT_LIBRARIES_GROUP "Runtime")
set(CPACK_COMPONENT_SERVER_DISPLAY_NAME "Server")
set(CPACK_COMPONENT_SERVER_GROUP "Applications")
set(CPACK_COMPONENT_SYMBOLS_DISPLAY_NAME "Symbols")
set(CPACK_COMPONENT_SYMBOLS_GROUP "Development")
set(CPACK_COMPONENT_TOOLS_DISPLAY_NAME "Tools")
set(CPACK_COMPONENT_TOOLS_GROUP "Applications")
set(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
set(CPACK_COMPONENT_UNSPECIFIED_REQUIRED "TRUE")
set(CPACK_DEBIAN_ARCHITECTURE "x86_64")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "marcandre.moreau@gmail.com")
set(CPACK_DEFAULT_PACKAGE_DESCRIPTION_FILE "/usr/share/cmake-3.16/Templates/CPack.GenericDescription.txt")
set(CPACK_GENERATOR "STGZ;TGZ;TZ;ZIP")
set(CPACK_INSTALL_CMAKE_PROJECTS "/home/ollie/freerdp/FreeRDP;FreeRDP;ALL;/")
set(CPACK_INSTALL_PREFIX "/usr/local")
set(CPACK_MODULE_PATH "/home/ollie/freerdp/FreeRDP/cmake/")
set(CPACK_NSIS_DISPLAY_NAME "FreeRDP")
set(CPACK_NSIS_INSTALLER_ICON_CODE "")
set(CPACK_NSIS_INSTALLER_MUI_ICON_CODE "")
set(CPACK_NSIS_INSTALL_ROOT "$PROGRAMFILES")
set(CPACK_NSIS_MODIFY_PATH "ON")
set(CPACK_NSIS_MUI_ICON "/home/ollie/freerdp/FreeRDP/resources\\FreeRDP_Icon_96px.ico")
set(CPACK_NSIS_MUI_UNICON "/home/ollie/freerdp/FreeRDP/resource\\FreeRDP_Icon_96px.ico")
set(CPACK_NSIS_PACKAGE_NAME "FreeRDP")
set(CPACK_OUTPUT_CONFIG_FILE "/home/ollie/freerdp/FreeRDP/CPackConfig.cmake")
set(CPACK_PACKAGE_CONTACT "Marc-Andre Moreau")
set(CPACK_PACKAGE_DEFAULT_LOCATION "/")
set(CPACK_PACKAGE_DESCRIPTION_FILE "/home/ollie/freerdp/FreeRDP/LICENSE.txt")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FreeRDP: A Remote Desktop Protocol Implementation")
set(CPACK_PACKAGE_EXECUTABLES "xfreerdp;xfreerdp-server")
set(CPACK_PACKAGE_FILE_NAME "freerdp-3.0.0-dev-Linux-x86_64")
set(CPACK_PACKAGE_ICON "/home/ollie/freerdp/FreeRDP/resources\\FreeRDP_Install.bmp")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "FreeRDP")
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "FreeRDP")
set(CPACK_PACKAGE_NAME "FreeRDP")
set(CPACK_PACKAGE_RELOCATABLE "true")
set(CPACK_PACKAGE_VENDOR "FreeRDP")
set(CPACK_PACKAGE_VERSION "3.0.0-dev")
set(CPACK_PACKAGE_VERSION_MAJOR "3")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_PROJECT_CONFIG_FILE "/home/ollie/freerdp/FreeRDP/CMakeCPackOptions.cmake")
set(CPACK_RESOURCE_FILE_LICENSE "/home/ollie/freerdp/FreeRDP/LICENSE.txt")
set(CPACK_RESOURCE_FILE_README "/usr/share/cmake-3.16/Templates/CPack.GenericDescription.txt")
set(CPACK_RESOURCE_FILE_WELCOME "/usr/share/cmake-3.16/Templates/CPack.GenericWelcome.txt")
set(CPACK_SET_DESTDIR "OFF")
set(CPACK_SOURCE_7Z "")
set(CPACK_SOURCE_CYGWIN "")
set(CPACK_SOURCE_GENERATOR "TBZ2;TGZ;TXZ;TZ")
set(CPACK_SOURCE_IGNORE_FILES "/\\.git/;/\\.gitignore;/CMakeCache.txt")
set(CPACK_SOURCE_OUTPUT_CONFIG_FILE "/home/ollie/freerdp/FreeRDP/CPackSourceConfig.cmake")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "freerdp-3.0.0-dev-Linux-x86_64")
set(CPACK_SOURCE_RPM "OFF")
set(CPACK_SOURCE_TBZ2 "ON")
set(CPACK_SOURCE_TGZ "ON")
set(CPACK_SOURCE_TXZ "ON")
set(CPACK_SOURCE_TZ "ON")
set(CPACK_SOURCE_ZIP "OFF")
set(CPACK_SYSTEM_NAME "Linux-x86_64")
set(CPACK_TOPLEVEL_TAG "Linux-x86_64")
set(CPACK_WIX_SIZEOF_VOID_P "8")

if(NOT CPACK_PROPERTIES_FILE)
  set(CPACK_PROPERTIES_FILE "/home/ollie/freerdp/FreeRDP/CPackProperties.cmake")
endif()

if(EXISTS ${CPACK_PROPERTIES_FILE})
  include(${CPACK_PROPERTIES_FILE})
endif()
