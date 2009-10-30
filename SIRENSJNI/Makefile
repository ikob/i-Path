.SUFFIXES:
.SUFFIXES: .java .class .h .c

CC = gcc

JC = javac

JARC = jar

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

JAR = SIRENSSocket-0.0.2-macos10.6.1.jar

HDRS = -I/System/Library/Frameworks/JavaVM.framework/Headers -I../SIRENSNKE

all: $(JCLASSES) $(JNILIB) $(JAR)

clean:;	@rm -f $(JCLASSES) $(JNILIB) $(JNIHDRS) $(JAR)

$(JCLASSES): $(JSRCS)
	@$(JC) $(JCLASSPATH) $(JSRCS)

#$(JNICLASSES): $(JNISRCS)
#	@$(JC) $(JCLASSPATH) $(JNISRCS)

$(JNIHDRS): $(JNICLASSES)
	@$(JH) $(JHFLAGS) $(JNIBASES)

$(JNILIB): $(JNISRC) $(JNICSRC) $(JNIHDRS)
	@$(CC) $(CFLAGS) $(HDRS) $(JNICSRC) -o $(JNILIB)

$(JAR): $(JNICLASSES) $(JNILIB)
	@$(JARC) cvf $(JAR) $(JNICLASSES) $(JNILIB)
