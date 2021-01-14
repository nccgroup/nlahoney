

####### Expanded from @PACKAGE_INIT@ by configure_package_config_file() #######
####### Any changes to this file will be overwritten by the next CMake run ####
####### The input file was FreeRDP-ShadowConfig.cmake.in                            ########

get_filename_component(PACKAGE_PREFIX_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../" ABSOLUTE)

macro(set_and_check _var _file)
  set(${_var} "${_file}")
  if(NOT EXISTS "${_file}")
    message(FATAL_ERROR "File or directory ${_file} referenced by variable ${_var} does not exist !")
  endif()
endmacro()

macro(check_required_components _NAME)
  foreach(comp ${${_NAME}_FIND_COMPONENTS})
    if(NOT ${_NAME}_${comp}_FOUND)
      if(${_NAME}_FIND_REQUIRED_${comp})
        set(${_NAME}_FOUND FALSE)
      endif()
    endif()
  endforeach()
endmacro()

####################################################################################

set(FreeRDP-Shadow_VERSION_MAJOR "3")
set(FreeRDP-Shadow_VERSION_MINOR "0")
set(FreeRDP-Shadow_VERSION_REVISION "0")

set_and_check(FreeRDP-Shadow_INCLUDE_DIR "${PACKAGE_PREFIX_DIR}/include/freerdp3/")

include("${CMAKE_CURRENT_LIST_DIR}/FreeRDP-ShadowTargets.cmake")
