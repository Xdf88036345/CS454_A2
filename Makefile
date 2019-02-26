#
# Starter makefile for WatDFS (CS 454).
# You may change this file.
#

# make --- produces libwatdfs.a and watdfs_server.
# make watdfs_client --- produces watdfs_client which links libwatdfs.a and
# libwatdfsmain.a.
# make all --- produces libwatdfs.a watdfs_server watdfs_client
# make clean --- removes object files, dependency files, libwatdfs.a and
# watdfs_server.

# this make file uses C++ by default
CXX = g++

# Add the required fuse library includes.
CXXFLAGS += $(shell pkg-config --cflags fuse)
CXXFLAGS += -g -Wall -std=c++1y -MMD
# If you want to print while debugging your own local tests, you can  add a
# pre-processor definition to your FLAGS here (see watdfs_client.c for more
# details). Important: you MUST disable any printing prior to submission.
# e.g. uncomment to print during your local tests, comment in your submission.
# CXXFLAGS += -DPRINT_ERR

# Add fuse libraries.
LDFLAGS += $(shell pkg-config --libs fuse)

# Add files you want to go into your client library here.
WATDFS_CLI_FILES= watdfs_client.c
WATDFS_CLI_OBJS= watdfs_client.o

# Add files you want to go into your server here.
WATDFS_SERVER_FILES = watdfs_server.c
WATDFS_SERVER_OBJS = watdfs_server.o
# E.g. for A3 add rw_lock.c and rw_lock.o to the
# WATDFS_SERVER_FILES and WATDFS_SERVER_OBJS respectively.

# Dependencies for the client executable.
WATDFS_CLIENT_LIBS = libwatdfsmain.a libwatdfs.a librpc.a

OBJECTS = $(WATDFS_SERVER_OBJS) $(WATDFS_CLI_OBJS)
DEPENDS = $(OBJECTS:.o=.d)

# targets
.DEFAULT_GOAL = default_goal

default_goal: libwatdfs.a watdfs_server

# By default make libwatdfs.a and watdfs_server.
all: libwatdfs.a watdfs_server watdfs_client

# This compiles object files, by default it looks for .c files
# so you may want to change this depending on your file naming scheme.
%.o: %.c
	$(CXX) $(CXXFLAGS) -c $(LDFLAGS) -L. -lrpc $<

# Make the client library.
libwatdfs.a: $(WATDFS_CLI_OBJS)
	ar rc $@ $^

# Make the server executable.
watdfs_server: $(WATDFS_SERVER_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) -L. -lrpc -o $@

# Make the client executable.
watdfs_client: $(WATDFS_CLIENT_LIBS)
	$(CXX) $(CXXFLAGS) -o watdfs_client -L. -lwatdfsmain -lwatdfs -lrpc $(LDFLAGS)

# Add dependencies so object files are tracked in the correct order.
depend:
	makedepend -f- -- $(CXXFLAGS) -- $(WATDFS_SERVER_FILES) $(WATDFS_CLI_FILES) > .depend

-include $(DEPENDS)

# Clean up extra dependencies and objects.
clean:
	/bin/rm -f $(DEPENDS) $(OBJECTS) watdfs_server libwatdfs.a watdfs_client

