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

public class jperfThread extends Thread {
	public long interval = 0;
	public long duration = 10;
	public int bufsize = 8192;
	String target = null;
	long count = 0;
	long oldcount = 0;
	long oldtime = 0;
	long starttime = 0;
	int wmax = 0;
	int port = 4444;
	jperfThread() {
		this.target = null;
	}
	jperfThread(String target) {
		this.target = target;
	}
	public void run(){
		try {
			if(this.target == null)
				this.server();
			else
				this.client(this.target);
		} catch (IOException e ) {
			System.err.println("IO exception " + target);
			System.exit(1);
		}
	}

	public void server() throws IOException {
		SIRENSServerSocket serverSocket = null;
		SIRENSSocket tSocket = null;

		try {
			serverSocket = new SIRENSServerSocket(port);
		} catch (IOException e) {
			System.err.println("Could not listen on port: " + port);
			System.exit(1);
		}

	        SIRENSReqIndex[] SRIndice = new SIRENSReqIndex[2];
		SRIndice[0] = new SIRENSReqIndex(3, 1, 64, 0, 64, 0);
		SRIndice[1] = new SIRENSReqIndex(3, 2, 64, 0, 64, 0);

		serverSocket.setSIRENSIDX( 1, SRIndice );

		tSocket = serverSocket.accept();

		System.out.println("Start remote port " + tSocket.getPort() + " local port " + tSocket.getLocalPort());
		if(wmax != 0){
			tSocket.setReceiveBufferSize(wmax);
		}
		wmax = tSocket.getReceiveBufferSize();

		System.out.println("SO_RCVBUF size:" + inttokmg(wmax));

		DataOutputStream out = new DataOutputStream(tSocket.getOutputStream());
		DataInputStream in = new DataInputStream(tSocket.getInputStream());

		byte [] rbuffer = new byte[this.bufsize];

		oldtime = System.currentTimeMillis();
		starttime = System.currentTimeMillis();
		long newtime = 0;
		int i = 0;
		count = 0;
		try {
			while(true){
				in.readFully(rbuffer, 0, this.bufsize);
				count += this.bufsize;
				if(interval != 0 ){
					newtime = System.currentTimeMillis();
					if(oldtime + interval * 1000 <  newtime){
						this.printStatus(oldtime, oldcount);
						oldtime = newtime;
						oldcount = count;
					}
				}
				i = i + 1;
			}
		} catch (EOFException e) {
			if(interval != 0 ){
				if(oldtime + interval * 1000 <  newtime){
					this.printStatus(oldtime, oldcount);
				}
			}
			this.printStatus(starttime, 0);
			out.close();
			in.close();
			tSocket.close();
			tSocket.close();
		}
	}

	public void client(String servername) throws IOException {
	        SIRENSSocket clientSocket = null;
		try {
			clientSocket = new SIRENSSocket(servername, port);
		} catch (UnknownHostException e) {
			System.err.println("Don't know about host: " + servername + ".");
			System.exit(1);
		} catch (IOException e) {
			System.err.println("Couldn't get I/O for "
				+ "the connection to: taranis.");
			System.exit(1);
		}
		if(wmax != 0){
			clientSocket.setSendBufferSize(wmax);
		}
	        SIRENSReqIndex[] SRIndice = new SIRENSReqIndex[2];
		SRIndice[0] = new SIRENSReqIndex(3, 1, 64, 0, 64, 0);
		SRIndice[1] = new SIRENSReqIndex(3, 2, 64, 0, 64, 0);

		clientSocket.setSIRENSIDX( 1, SRIndice );

		wmax = clientSocket.getSendBufferSize();

		System.out.println("Start remote port " + clientSocket.getPort() + " local port " + clientSocket.getLocalPort());
		System.out.println("SO_SNDBUF size:" + inttokmg(wmax));
		DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());
		DataInputStream in = new DataInputStream(clientSocket.getInputStream());
	
		byte wbuffer [] = new byte[this.bufsize];
	
		oldtime = System.currentTimeMillis();
		starttime = System.currentTimeMillis();
		int i = 0;
		count = 0;
		long newtime = 0;
                int[][] array = new int[4][256];
                int[][] parray = new int[4][256];
		int[] tarray;
		while( true ) {
			newtime = System.currentTimeMillis();
			if(starttime + 1000 * duration < newtime ) break;
			if(interval != 0 ){
				if(oldtime + interval * 1000 <  newtime){
					this.printStatus(oldtime, oldcount);
					clientSocket.getSockoptSIRENSSDATA(1, 3, 1, array[0]);
					for( int j = 0 ; j < 256 ; j++){
       						if(array[0][j] != 0xffffffff)
			        			System.out.printf("%10d\n", array[0][j]);
					}
					tarray = array[0];
					array[0] = parray[0];
					parray[0] = tarray;
					clientSocket.getSockoptSIRENSSDATA(2, 3, 1, array[1]);
					for( int j = 0 ; j < 256 ; j++){
       						if(array[1][j] != 0xffffffff)
			        			System.out.printf("%10d\n", array[1][j]);
					}
					tarray = array[1];
					array[1] = parray[1];
					parray[1] = tarray;
					clientSocket.getSockoptSIRENSSDATA(1, 3, 2, array[2]);
					for( int j = 0 ; j < 256 ; j++){
       						if(array[2][j] != 0xffffffff && newtime - starttime >= 2000)
			        			System.out.printf("%10d\n", array[2][j] - parray[2][j]);
					}
					tarray = array[2];
					array[2] = parray[2];
					parray[2] = tarray;
					clientSocket.getSockoptSIRENSSDATA(2, 3, 2, array[3]);
					for( int j = 0 ; j < 256 ; j++){
       						if(array[3][j] != 0xffffffff && newtime - starttime >= 2000)
			        			System.out.printf("%10d\n", array[3][j] - parray[3][j]);
					}
					tarray = array[3];
					array[3] = parray[3];
					parray[3] = tarray;
					oldtime = newtime;
					oldcount = count;
				}
			}
			try {
				out.write(wbuffer, 0, this.bufsize);
				count += this.bufsize;
				i = i +1;
			} catch (EOFException e) {
				this.printStatus(starttime, 0);
				out.close();
				in.close();
				clientSocket.close();
			}
		}
		if(interval != 0 ){
			if(oldtime + interval * 1000 <  newtime){
				this.printStatus(oldtime, oldcount);
			}
		}
		this.printStatus(starttime, 0);
		out.close();
		in.close();
		clientSocket.close();
	}

	void printStatus( long basetime, long basecount ){
		long currtime = System.currentTimeMillis();
		if(currtime == basetime) return;
		System.out.printf("%d- %d sec %sBytes %sbits/sec\n",
			(basetime - starttime) / 1000,
			(currtime - starttime) / 1000,
			inttokmg(count - basecount),
			inttokmg((count - basecount) * 8 * 1000 / (currtime - basetime)));
	}
	String inttokmg ( long data) {
		Long temp = new Long(data);
		if(data < 1000){
			return(temp.toString());
		}else if (data < 1000000 ){
			return(String.format("%7.2f K", temp.doubleValue() / 1000));
		}else if (data < 1000000000 ){
			return(String.format("%7.2f M", temp.doubleValue() / 1000000));
		}else{
			return(String.format("%7.2f G", temp.doubleValue() / 1000000000));
		}
	}
	String inttokmg ( int data) {
		Integer temp = new Integer(data);
		if(data < 1000){
			return(temp.toString());
		}else if (data < 1000000 ){
			return(String.format("%7.2f K", temp.doubleValue() / 1000));
		}else if (data < 1000000000 ){
			return(String.format("%7.2f M", temp.doubleValue() / 1000000));
		}else{
			return(String.format("%7.2f G", temp.doubleValue() / 1000000000));
		}
	}
}
