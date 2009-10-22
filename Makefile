.SUFFIXES:
.SUFFIXES: .java .class .h .c

CC = gcc

JC = javac

JH = javah

JCLASSPATH = -cp ./java-getopt-1.0.13.jar:.

JHFLAGS = -jni

CFLAGS = -shared -fPIC

JNIHDRS = SIRENSSocket.h SIRENSServerSocket.h

JNICSRC = SIRENSImpl.c

JNILIB = libSIRENSImpl.jnilib

JNICLASSES = SIRENSSocket.class SIRENSServerSocket.class

JCLASSES = jperf.class jperfServer.class jperfClient.class SIRENSReqIndex.class jperfParam.class $(JNICLASSES)

JNIBASES = SIRENSSocket SIRENSServerSocket

JNISRCS = SIRENSSocket.java SIRENSServerSocket.java

JSRCS = jperf.java jperfServer.java jperfClient.java SIRENSReqIndex.java jperfParam.java $(JNISRCS)

HDRS = -I/System/Library/Frameworks/JavaVM.framework/Headers -I../SIRENSNKE

all: $(JCLASSES) $(JNILIB)

clean:;	@rm -f $(JCLASSES) $(JNILIB) $(JNIHDRS)

$(JCLASSES): $(JSRCS)
	@$(JC) $(JCLASSPATH) $(JSRCS)

#$(JNICLASSES): $(JNISRCS)
#	@$(JC) $(JCLASSPATH) $(JNISRCS)

$(JNIHDRS): $(JNICLASSES)
	@$(JH) $(JHFLAGS) $(JNIBASES)

$(JNILIB): $(JNISRC) $(JNICSRC) $(JNIHDRS)
	@$(CC) $(CFLAGS) $(HDRS) $(JNICSRC) -o $(JNILIB)
