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
import java.io.*;
import java.net.*;
import gnu.getopt.Getopt;

public class jperf {
	final static String usage = "jperf [-b bufsize] [-i interval] [-p port] [-t duration] [-w wmax] [-Q] [-s|-c host]";
	static long starttime;
	static long count = 0;
	static long oldcount = 0;
	public static void main(String[] args){
		jperfParam param = new jperfParam();
		Getopt options = new Getopt("jperf", args, "b:c:i:p:st:w:Q");
		int c;
		String hostname = null;
		boolean server = false; 
		while(( c = options.getopt()) != -1) {
			switch(c){
			case 'c':
				if(server == true){
					System.err.println(usage);
					System.exit(1);
				}
				param.target = options.getOptarg();
				break;
			case 's':
				if(param.target != null){
					System.err.println(usage);
					System.exit(1);
				}
				server = true;
				break;
			case 'b':
				param.bufsize = parseUnit(options.getOptarg());
				break;
			case 'i':
				param.interval = Integer.parseInt(options.getOptarg());
				break;
			case 'p':
				param.port = parseUnit(options.getOptarg());
				break;
			case 't':
				param.duration = Integer.parseInt(options.getOptarg());
				break;
			case 'w':
				param.wmax = parseUnit(options.getOptarg());
				break;
			case 'Q':
				param.sirens = true;
				break;
			default:
				System.err.println(usage);
				System.exit(1);
				break;
			}
		}
		if(param.target == null){
			SIRENSServerSocket serverSocket = null;

			try {
				serverSocket = new SIRENSServerSocket(param.port);
			} catch (IOException e) {
				System.err.println("Could not listen on port: " + param.port);
				System.exit(1);
			}

	       		SIRENSReqIndex[] SRIndice = new SIRENSReqIndex[2];
			SRIndice[0] = new SIRENSReqIndex(3, 1, 64, 0, 64, 0);
			SRIndice[1] = new SIRENSReqIndex(3, 2, 64, 0, 64, 0);
			while(true) {
				try {
					SIRENSSocket tSocket = null;
					tSocket = serverSocket.accept();
			if(param.sirens == true){
				try {	
					tSocket.setSIRENSIDX( 1, SRIndice );
				} catch (IOException e) {
					System.err.println("Could setup SIRENS ");
					param.sirens = false;
				}
			}
					jperfServer sserver = new jperfServer(param, tSocket);
					sserver.start();
				}catch(IOException e){
					System.exit(1);
				}
			}
		}else{
			jperfClient client = new jperfClient(param);
			client.start();
		}
	}
	static int parseUnit (String str){
		int scale = 1;
		try {
			return(Integer.parseInt(str));
		} catch (NumberFormatException e){
			switch(str.charAt(str.length() - 1)){
				case 'k':
				case 'K':
					scale = 1000;
					break;
				case 'm':
				case 'M':
					scale = 1000000;
					break;
				default:
					System.err.println("jperf [-s|-c host]");
					System.exit(1);
					break;
			}
		}
		try {
			return(scale * Integer.parseInt(str.substring(0, str.length() - 1)));
		} catch (NumberFormatException e){
			System.err.println("jperf [-s|-c host]");
			System.exit(1);
		}
		return(-1);
	}
	static void printStatus( long basetime, long basecount ){
		long currtime = System.currentTimeMillis();
		if(currtime == basetime) return;
		System.out.printf("%d- %d sec %sBytes %sbits/sec\n",
			(basetime - starttime) / 1000,
			(currtime - starttime) / 1000,
			inttokmg(count - basecount),
			inttokmg((count - basecount) * 8 * 1000 / (currtime - basetime)));
	}
	static String inttokmg ( long data) {
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
	static String inttokmg ( int data) {
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
