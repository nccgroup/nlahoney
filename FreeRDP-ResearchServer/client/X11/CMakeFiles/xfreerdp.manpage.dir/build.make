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

# Utility rule file for xfreerdp.manpage.

# Include the progress variables for this target.
include client/X11/CMakeFiles/xfreerdp.manpage.dir/progress.make

client/X11/CMakeFiles/xfreerdp.manpage: client/X11/xfreerdp.1


client/X11/xfreerdp.1: client/X11/xfreerdp.1.xml
client/X11/xfreerdp.1: client/X11/xfreerdp-examples.1.xml
client/X11/xfreerdp.1: client/X11/xfreerdp-channels.1.xml
client/X11/xfreerdp.1: client/X11/xfreerdp-envvar.1.xml
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --blue --bold --progress-dir=/home/ollie/freerdp/FreeRDP/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Generating xfreerdp.1"
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /usr/bin/cc -I/usr/include -I/home/ollie/freerdp/FreeRDP -I/home/ollie/freerdp/FreeRDP/include -I/home/ollie/freerdp/FreeRDP/include -I/home/ollie/freerdp/FreeRDP/winpr/include -I/home/ollie/freerdp/FreeRDP/winpr/include -I/home/ollie/freerdp/FreeRDP/rdtk/include -I/home/ollie/freerdp/FreeRDP/rdtk/include -I/usr/include -I/usr/include -I/home/ollie/freerdp/FreeRDP/client/X11/.. /home/ollie/freerdp/FreeRDP/client/X11/generate_argument_docbook.c -o /home/ollie/freerdp/FreeRDP/client/X11/generate_argument_docbook
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /home/ollie/freerdp/FreeRDP/client/X11/generate_argument_docbook
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /usr/bin/cmake -E copy /home/ollie/freerdp/FreeRDP/client/X11/xfreerdp-channels.1.xml /home/ollie/freerdp/FreeRDP/client/X11
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /usr/bin/cmake -E copy /home/ollie/freerdp/FreeRDP/client/X11/xfreerdp-examples.1.xml /home/ollie/freerdp/FreeRDP/client/X11
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /usr/bin/cmake -E copy /home/ollie/freerdp/FreeRDP/client/X11/xfreerdp-envvar.1.xml /home/ollie/freerdp/FreeRDP/client/X11
	cd /home/ollie/freerdp/FreeRDP/client/X11 && /usr/bin/xsltproc /usr/share/xml/docbook/stylesheet/docbook-xsl/manpages/docbook.xsl xfreerdp.1.xml

xfreerdp.manpage: client/X11/CMakeFiles/xfreerdp.manpage
xfreerdp.manpage: client/X11/xfreerdp.1
xfreerdp.manpage: client/X11/CMakeFiles/xfreerdp.manpage.dir/build.make

.PHONY : xfreerdp.manpage

# Rule to build all files generated by this target.
client/X11/CMakeFiles/xfreerdp.manpage.dir/build: xfreerdp.manpage

.PHONY : client/X11/CMakeFiles/xfreerdp.manpage.dir/build

client/X11/CMakeFiles/xfreerdp.manpage.dir/clean:
	cd /home/ollie/freerdp/FreeRDP/client/X11 && $(CMAKE_COMMAND) -P CMakeFiles/xfreerdp.manpage.dir/cmake_clean.cmake
.PHONY : client/X11/CMakeFiles/xfreerdp.manpage.dir/clean

client/X11/CMakeFiles/xfreerdp.manpage.dir/depend:
	cd /home/ollie/freerdp/FreeRDP && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/client/X11 /home/ollie/freerdp/FreeRDP /home/ollie/freerdp/FreeRDP/client/X11 /home/ollie/freerdp/FreeRDP/client/X11/CMakeFiles/xfreerdp.manpage.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : client/X11/CMakeFiles/xfreerdp.manpage.dir/depend

