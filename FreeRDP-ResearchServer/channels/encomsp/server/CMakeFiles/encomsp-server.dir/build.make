# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ollie/freerdp/FreeRDP

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ollie/freerdp/FreeRDP

# Include any dependencies generated for this target.
include channels/encomsp/server/CMakeFiles/encomsp-server.dir/depend.make

# Include the progress variables for this target.
include channels/encomsp/server/CMakeFiles/encomsp-server.dir/progress.make

# Include the compile flags for this target's objects.
include channels/encomsp/server/CMakeFiles/encomsp-server.dir/flags.make

channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.o: channels/encomsp/server/CMakeFiles/encomsp-server.dir/flags.make
channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.o: channels/encomsp/server/encomsp_main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ollie/freerdp/FreeRDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.o"
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/encomsp-server.dir/encomsp_main.c.o   -c /home/ollie/freerdp/FreeRDP/channels/encomsp/server/encomsp_main.c

channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/encomsp-server.dir/encomsp_main.c.i"
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ollie/freerdp/FreeRDP/channels/encomsp/server/encomsp_main.c > CMakeFiles/encomsp-server.dir/encomsp_main.c.i

channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/encomsp-server.dir/encomsp_main.c.s"
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ollie/freerdp/FreeRDP/channels/encomsp/server/encomsp_main.c -o CMakeFiles/encomsp-server.dir/encomsp_main.c.s

# Object files for target encomsp-server
encomsp__server_OBJECTS = \
"CMakeFiles/encomsp-server.dir/encomsp_main.c.o"

# External object files for target encomsp-server
encomsp__server_EXTERNAL_OBJECTS =

channels/encomsp/server/libencomsp-server.a: channels/encomsp/server/CMakeFiles/encomsp-server.dir/encomsp_main.c.o
channels/encomsp/server/libencomsp-server.a: channels/encomsp/server/CMakeFiles/encomsp-server.dir/build.make
channels/encomsp/server/libencomsp-server.a: channels/encomsp/server/CMakeFiles/encomsp-server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ollie/freerdp/FreeRDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libencomsp-server.a"
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && $(CMAKE_COMMAND) -P CMakeFiles/encomsp-server.dir/cmake_clean_target.cmake
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/encomsp-server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
channels/encomsp/server/CMakeFiles/encomsp-server.dir/build: channels/encomsp/server/libencomsp-server.a

.PHONY : channels/encomsp/server/CMakeFiles/encomsp-server.dir/build

channels/encomsp/server/CMakeFiles/encomsp-server.dir/clean:
	cd /home/ollie/freerdp/FreeRDP/channels/encomsp/server && $(CMAKE_COMMAND) -P CMakeFiles/encomsp-server.dir/cmake_clean.cmake
.PHONY : channels/encomsp/server/CMakeFiles/encomsp-server.dir/clean

channels/encomsp/server/CMakeFiles/encomsp-server.dir/depend:
	cd /home/ollie/freerdp/FreeRDP && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/channels/encomsp/server /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/channels/encomsp/server /home/ollie/freerdp/FreeRDP/channels/encomsp/server/CMakeFiles/encomsp-server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : channels/encomsp/server/CMakeFiles/encomsp-server.dir/depend

