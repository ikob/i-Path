/*
 * Copyright (c) 2009 Katsushi Kobayashi
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
//import gnu.getopt.Getopt;

public class jperfClient extends Thread {
	jperfParam param;
	jperfClient( jperfParam param) {
		this.param = param;
	}
	public void run() {
		try {
			this.client();
		} catch (IOException e) {
			System.exit(1);
		}
	}
	public void client() throws IOException {
	        SIRENSSocket clientSocket = null;
		try {
			clientSocket = new SIRENSSocket(param.target, param.port);
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host: " + param.target + ".");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
				+ "the connection to: " + param.target);
			System.exit(1);
		}
		if(param.wmax != 0){
			try {
				clientSocket.setSendBufferSize(param.wmax);
			} catch (IOException e) {
				System.err.println("Couldn't set buffersize ");
			}
		}
		if(param.sirens == true) {
			try {
		        	SIRENSReqIndex[] SRIndice = new SIRENSReqIndex[2];
				SRIndice[0] = new SIRENSReqIndex(3, 1, 64, 0, 64, 0);
				SRIndice[1] = new SIRENSReqIndex(3, 2, 64, 0, 64, 0);
				clientSocket.setSIRENSIDX( 1, SRIndice );
			} catch (IOException e) {
				System.out.println("Cound not  setup SIRENS");
				param.sirens = false;
			}
		}

		try {
			param.wmax = clientSocket.getSendBufferSize();
		} catch (IOException e) {
			System.err.println("Couldn't get buffersize ");
		}

		System.out.println("Start remote port " + clientSocket.getPort() + " local port " + clientSocket.getLocalPort());
		System.out.println("SO_SNDBUF size:" + param.inttosip(param.wmax));
		DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
		DataInputStream in = new DataInputStream(clientSocket.getInputStream());
	
		byte wbuffer [] = new byte[param.bufsize];
		
		param.oldtime = System.currentTimeMillis();
		param.starttime = System.currentTimeMillis();
		int i = 0;
		int[][] array = new int[4][256];
		int[][] parray = new int[4][256];
		int[] tarray;
		while( true ) {
			param.newtime = System.currentTimeMillis();
			if(param.starttime + 1000 * param.duration < param.newtime ) break;
			if(param.interval != 0 ){
				if(param.oldtime + param.interval * 1000 <  param.newtime){
					param.printStatus(param.oldtime, param.oldcount);
					param.printSIRENSStatus(clientSocket);
					param.oldtime = param.newtime;
					param.oldcount = param.count;
				}
			}
			try {
				out.write(wbuffer, 0, param.bufsize);
				param.count += param.bufsize;
				i = i +1;
			} catch (EOFException e) {
				param.printStatus(param.starttime, 0);
				out.close();
				in.close();
				clientSocket.close();
			}
		}
		if(param.interval != 0 ){
			if(param.oldtime + param.interval * 1000 <  param.newtime){
				param.printStatus(param.oldtime, param.oldcount);
			}
		}
		param.printStatus(param.starttime, 0);
		out.close();
		in.close();
		clientSocket.close();
	}
}
