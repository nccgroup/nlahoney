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
include channels/remdesk/server/CMakeFiles/remdesk-server.dir/depend.make

# Include the progress variables for this target.
include channels/remdesk/server/CMakeFiles/remdesk-server.dir/progress.make

# Include the compile flags for this target's objects.
include channels/remdesk/server/CMakeFiles/remdesk-server.dir/flags.make

channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.o: channels/remdesk/server/CMakeFiles/remdesk-server.dir/flags.make
channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.o: channels/remdesk/server/remdesk_main.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ollie/freerdp/FreeRDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.o"
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/remdesk-server.dir/remdesk_main.c.o   -c /home/ollie/freerdp/FreeRDP/channels/remdesk/server/remdesk_main.c

channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/remdesk-server.dir/remdesk_main.c.i"
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ollie/freerdp/FreeRDP/channels/remdesk/server/remdesk_main.c > CMakeFiles/remdesk-server.dir/remdesk_main.c.i

channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/remdesk-server.dir/remdesk_main.c.s"
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ollie/freerdp/FreeRDP/channels/remdesk/server/remdesk_main.c -o CMakeFiles/remdesk-server.dir/remdesk_main.c.s

# Object files for target remdesk-server
remdesk__server_OBJECTS = \
"CMakeFiles/remdesk-server.dir/remdesk_main.c.o"

# External object files for target remdesk-server
remdesk__server_EXTERNAL_OBJECTS =

channels/remdesk/server/libremdesk-server.a: channels/remdesk/server/CMakeFiles/remdesk-server.dir/remdesk_main.c.o
channels/remdesk/server/libremdesk-server.a: channels/remdesk/server/CMakeFiles/remdesk-server.dir/build.make
channels/remdesk/server/libremdesk-server.a: channels/remdesk/server/CMakeFiles/remdesk-server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ollie/freerdp/FreeRDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C static library libremdesk-server.a"
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && $(CMAKE_COMMAND) -P CMakeFiles/remdesk-server.dir/cmake_clean_target.cmake
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/remdesk-server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
channels/remdesk/server/CMakeFiles/remdesk-server.dir/build: channels/remdesk/server/libremdesk-server.a

.PHONY : channels/remdesk/server/CMakeFiles/remdesk-server.dir/build

channels/remdesk/server/CMakeFiles/remdesk-server.dir/clean:
	cd /home/ollie/freerdp/FreeRDP/channels/remdesk/server && $(CMAKE_COMMAND) -P CMakeFiles/remdesk-server.dir/cmake_clean.cmake
.PHONY : channels/remdesk/server/CMakeFiles/remdesk-server.dir/clean

channels/remdesk/server/CMakeFiles/remdesk-server.dir/depend:
	cd /home/ollie/freerdp/FreeRDP && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/channels/remdesk/server /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/channels/remdesk/server /home/ollie/freerdp/FreeRDP/channels/remdesk/server/CMakeFiles/remdesk-server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : channels/remdesk/server/CMakeFiles/remdesk-server.dir/depend

