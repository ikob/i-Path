/*
 * Copyright (c) 2009, 2010
 * National Institute of Advanced Industrial Science and Technology (AIST).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the acknowledgement as bellow:
 *
 *    This product includes software developed by AIST.
 *
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 * $ $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__APPLE__)
#include <sys/mbuf.h>
#endif

#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_sirens.h>

#include <jni.h>

#include "SIRENSSocket.h"
#include "SIRENSServerSocket.h"
static int getFd(JNIEnv *, jobject);
void setSockoptSIRENSIDX(JNIEnv *, jobject, jint, jobject, jobject, jobject, jobject, jobject, jobject);
void getSockoptSIRENSSDATA(JNIEnv *, jobject, jint, jint, jint, jobject);

JNIEXPORT void JNICALL
Java_SIRENSSocket_getSockoptSIRENSSDATA(JNIEnv *env, jobject this,
	jint dir, jint mode, jint probe, jobject array)
{
    getSockoptSIRENSSDATA(env, this, dir, mode, probe, array);
}
JNIEXPORT void JNICALL
Java_SIRENSServerSocket_getSockoptSIRENSSDATA(JNIEnv *env, jobject this,
	jint dir, jint mode, jint probe, jobject array)
{
    getSockoptSIRENSSDATA(env, this, dir, mode, probe, array);
}
JNIEXPORT void JNICALL
Java_SIRENSServerSocket_setSockoptSIRENSIDX(JNIEnv *env, jobject this,
	jint srsmax, jobject jmode, jobject jprobe,
	jobject jqttlmax, jobject jqttlmin, jobject jsttlmax, jobject jsttlmin)
{
    setSockoptSIRENSIDX(env, this, srsmax, jmode, jprobe, jqttlmax, jqttlmin, jsttlmax, jsttlmin);
}
JNIEXPORT void JNICALL
Java_SIRENSSocket_setSockoptSIRENSIDX(JNIEnv *env, jobject this,
	jint srsmax, jobject jmode, jobject jprobe,
	jobject jqttlmax, jobject jqttlmin, jobject jsttlmax, jobject jsttlmin)
{
    setSockoptSIRENSIDX(env, this, srsmax, jmode, jprobe, jqttlmax, jqttlmin, jsttlmax, jsttlmin);
}
void getSockoptSIRENSSDATA(JNIEnv *env, jobject this,
	jint dir, jint mode, jint probe, jobject array)
{
    jint fd;
#if 0
    jint *res_p;
#else
    jlong *res_p;
#endif
    jboolean isCopy = JNI_TRUE;
    char *dreqbuf;
    int len = IPSIRENS_DREQSIZE(256);
    union u_sr_data *sr_dataq;
    struct sr_dreq *dreq;
    int rc, i;
    dreqbuf = (char *)malloc(IPSIRENS_DREQSIZE(256));
    dreq = (struct sr_dreq *)dreqbuf;
    sr_dataq = (union u_sr_data *)((char *)dreq + sizeof(struct sr_dreq));
    dreq->dir = dir;
    dreq->mode = mode;
    dreq->probe = probe;
    fd = getFd(env, this);
    rc = getsockopt(fd, IPPROTO_IP, IPSIRENS_SDATA, dreqbuf, &len);
    if(rc < 0) {
        jclass jcls = (*env)->FindClass(env, "Ljava/io/IOException;");
	char buf[64];
        if (jcls==NULL) return;
	strerror_r(errno, buf, 64);
        (*env)->ThrowNew(env, jcls, buf);
        (*env)->DeleteLocalRef(env, jcls);
	return;
    }
#if 0
    res_p = (*env)->GetIntArrayElements(env, array, &isCopy);
    for(i = 0 ; i < 256 ; i++){
        res_p[i] = ntohl(sr_dataq[i].set);
    }
    (*env)->SetIntArrayRegion(env, array, 0, 256, res_p);
#else
    res_p = (*env)->GetLongArrayElements(env, array, &isCopy);
    for(i = 0 ; i < 256 ; i++){
        res_p[i] = ntohl(sr_dataq[i].set);
    }
    (*env)->SetLongArrayRegion(env, array, 0, 256, res_p);
#endif
    return;
}
void setSockoptSIRENSIDX(JNIEnv *env, jobject this,
	jint srsmax, jobject jmode, jobject jprobe,
	jobject jqttlmax, jobject jqttlmin, jobject jsttlmax, jobject jsttlmin)
{
    struct sr_ireq *ireq; 
    struct srreq_index *sri;
    jboolean isCopy = JNI_TRUE;
    int i, rc;
    jint len, fd;
    jfieldID pdsi_fdID;
    jfieldID IO_fd_fdID;
    int *mode_p, *probe_p, *qttlmax_p, *qttlmin_p, *sttlmax_p, *sttlmin_p;

    fd = getFd(env, this);

    ireq = (struct sr_ireq *)malloc(IPSIRENS_IREQSIZE (IPSIRENS_IREQMAX));
    sri = (struct srreq_index *)(ireq + 1);
    len = (*env)->GetArrayLength(env, jmode);

    mode_p = (*env)->GetIntArrayElements(env, jmode, &isCopy);
    probe_p = (*env)->GetIntArrayElements(env, jprobe, &isCopy);
    qttlmax_p = (*env)->GetIntArrayElements(env, jqttlmax, &isCopy);
    qttlmin_p = (*env)->GetIntArrayElements(env, jqttlmin, &isCopy);
    sttlmax_p = (*env)->GetIntArrayElements(env, jsttlmax, &isCopy);
    sttlmin_p = (*env)->GetIntArrayElements(env, jsttlmin, &isCopy);

    ireq->sr_nindex = len;
    ireq->sr_smax = srsmax;

    for( i = 0 ; i < len ; i++){
        sri[i].mode =  mode_p[i];
	sri[i].probe = probe_p[i];
	sri[i].qttl_max = qttlmax_p[i];
	sri[i].qttl_min = qttlmin_p[i];
        sri[i].sttl_max = sttlmax_p[i];
        sri[i].sttl_min = sttlmin_p[i];
    }
    rc = setsockopt(fd, IPPROTO_IP, IPSIRENS_IDX, ireq, IPSIRENS_IREQSIZE(len));
    if(rc < 0) {
        jclass jcls = (*env)->FindClass(env, "Ljava/io/IOException;");
	char buf[64];
        if (jcls==NULL) return;
	strerror_r(errno, buf, 64);
        (*env)->ThrowNew(env, jcls, buf);
        (*env)->DeleteLocalRef(env, jcls);
    }
    return;
}
/* brought from sample http://www.velocityreviews.com/forums/t140746-passing-java-socket-fd-to-c-hack.html */
static int getFd(JNIEnv *env, jobject sock)
{
    JNIEnv e = *env;
    jclass clazz;
    jfieldID fid;
    jobject impl;
    jobject fdesc;

/* get the SocketImpl from the Socket */
    if (!(clazz = e->GetObjectClass(env,sock)) ||
        !(fid = e->GetFieldID(env,clazz,"impl","Ljava/net/SocketImpl;")) ||
        !(impl = e->GetObjectField(env,sock,fid))) return -1;

/* get the FileDescriptor from the SocketImpl */
    if (!(clazz = e->GetObjectClass(env,impl)) ||
        !(fid = e->GetFieldID(env,clazz,"fd","Ljava/io/FileDescriptor;")) ||
        !(fdesc = e->GetObjectField(env,impl,fid))) return -1;

/* get the fd from the FileDescriptor */
    if (!(clazz = e->GetObjectClass(env,fdesc)) ||
        !(fid = e->GetFieldID(env,clazz,"fd","I"))) return -1;

/* return the descriptor */
    return e->GetIntField(env,fdesc,fid);
}
