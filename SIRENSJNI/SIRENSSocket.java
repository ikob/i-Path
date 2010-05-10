/*
 * Copyright (c) 2009, 2010 Katsushi Kobayashi
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
 *    This product includes software developed by K. Kobayashi and H. Shimokawa
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
import java.io.*;
import java.net.*;

public class SIRENSSocket extends Socket {
    public native void setSockoptSIRENSIDX (int srsmax, int[] mode, int[] probe, int[] qttlmax, int[] qttlmin, int[] sttlmax, int[] sttlmin) throws IOException;
    public native void getSockoptSIRENSSDATA(int dir, int mode, int probe, long [] array) throws IOException;
    static {
        System.loadLibrary("SIRENSImpl");
    }
    SIRENSSocket() {
        super();
    }
    SIRENSSocket(Proxy proxy) {
        super( proxy);
    }
    protected SIRENSSocket(SocketImpl impl) throws SocketException {
        super( impl);
    }
    SIRENSSocket(InetAddress host, int port) throws IOException {
        super(host, port);
    }
//    SIRENSSocket(InetAddress host, int port, boolean stream) throws IOException {
//        super(host, port, stream);
//    }
    SIRENSSocket(String host, int port) throws IOException {
        super(host, port);
    }
//    SIRENSSocket(String host, int port, boolean stream) throws IOException{
//        super(host, port, stream);
//    }
    SIRENSSocket(String host, int port, InetAddress localAddr, int localPort) throws IOException{
        super(host, port, localAddr, localPort);
    }
    public void setSIRENSIDX( int srmax, SIRENSReqIndex[] SRIndice )
    throws IOException
    {
            int i;
            int[] mode = new int[ SRIndice.length ];
            int[] probe = new int[ SRIndice.length ];
            int[] qttlmax = new int[ SRIndice.length ];
            int[] qttlmin = new int[ SRIndice.length ];
            int[] sttlmax = new int[ SRIndice.length ];
            int[] sttlmin = new int[ SRIndice.length ];
            for( i = 0 ; i < SRIndice.length ; i ++) {
                mode[i] = SRIndice[i].mode;
                probe[i] = SRIndice[i].probe;
                qttlmin[i] = SRIndice[i].qttlmin;
                qttlmax[i] = SRIndice[i].qttlmax;
                sttlmin[i] = SRIndice[i].sttlmin;
                sttlmax[i] = SRIndice[i].sttlmax;
            }
            setSockoptSIRENSIDX(srmax, mode, probe, qttlmax, qttlmin, sttlmax, sttlmin);
    }
}
