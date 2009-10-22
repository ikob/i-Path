#!/bin/sh
export CLASSPATH=./java-getopt-1.0.13.jar:.
export LD_LIBRARY_PATH=.
java jperf $*
