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
import gnu.getopt.Getopt;

public class jperfServer extends Thread {
	jperfParam param = new jperfParam();
	SIRENSSocket tSocket = null;
	jperfServer(jperfParam param, SIRENSSocket tSocket) {
		this.param = param;
		this.tSocket = tSocket;
	}
	public void run () {
		try {
			this.server();
		} catch (IOException e) {
			System.exit(1);
		}
	}
	public void server() throws IOException {
		System.out.println("Start remote port " + tSocket.getPort() + " local port " + tSocket.getLocalPort());
		if(param.wmax != 0){
			tSocket.setReceiveBufferSize(param.wmax);
		}
		param.wmax = tSocket.getReceiveBufferSize();
	
		System.out.println("SO_RCVBUF size:" + param.inttosip(param.wmax));

		DataOutputStream out = new DataOutputStream(tSocket.getOutputStream());
		DataInputStream in = new DataInputStream(tSocket.getInputStream());

		byte [] rbuffer = new byte[param.bufsize];

		param.oldtime = System.currentTimeMillis();
		param.starttime = System.currentTimeMillis();
		param.newtime = 0;
		int i = 0;
		param.count = 0;
		try {
			while(true){
				in.readFully(rbuffer, 0, param.bufsize);
				param.count += param.bufsize;
				if(param.interval != 0 ){
					param.newtime = System.currentTimeMillis();
					if(param.oldtime + param.interval * 1000 <  param.newtime){
						param.printStatus(param.oldtime, param.oldcount);
						param.oldtime = param.newtime;
						param.oldcount = param.count;
					}
				}
				i = i + 1;
			}
		} catch (EOFException e) {
			if(param.interval != 0 ){
				if(param.oldtime + param.interval * 1000 <  param.newtime){
					param.printStatus(param.oldtime, param.oldcount);
				}
			}
			param.printStatus(param.starttime, 0);
			out.close();
			in.close();
			tSocket.close();
			tSocket.close();
		}
	}
}
