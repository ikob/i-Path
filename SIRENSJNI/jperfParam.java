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

public class jperfParam {
	public long interval = 0;
	public long duration = 10;
	public int bufsize = 8192;
	String target = null;
	long count = 0;
	long oldcount = 0;
	long oldtime = 0;
	long newtime = 0;
	long starttime = 0;
	int wmax = 0;
	int port = 4444;
	boolean sirens = false;

	long[][] parray = new long[4][256];
	long[][] array = new long[4][256];

	public void printStatus(long basetime, long basecount){
		long currtime = System.currentTimeMillis();
		if(currtime == basetime) return;
		System.out.printf("%d- %d sec %sBytes %sbits/sec\n",
			(basetime - starttime) / 1000,
			(currtime - starttime) / 1000,
			inttosip(count - basecount),
			inttosip((count - basecount) * 8 * 1000 / (currtime - basetime)));
	}
	String inttosip ( long data) {
		Long temp = new Long(data);
		if(data < 1000){
			return(String.format("      %3d ", temp));
		}else if (data < 1000000 ){
			return(String.format("%7.2f K", temp.doubleValue() / 1000));
		}else if (data < 1000000000 ){
			return(String.format("%7.2f M", temp.doubleValue() / 1000000));
		}else{
			return(String.format("%7.2f G", temp.doubleValue() / 1000000000));
		}
	}
	String inttosip ( int data) {
		Integer temp = new Integer(data);
		if(data < 1000){
			return(String.format("      %3d ", temp));
		}else if (data < 1000000 ){
			return(String.format("%7.2f K", temp.doubleValue() / 1000));
		}else if (data < 1000000000 ){
			return(String.format("%7.2f M", temp.doubleValue() / 1000000));
		}else{
			return(String.format("%7.2f G", temp.doubleValue() / 1000000000));
		}
	}
	public void printSIRENSStatus (SIRENSSocket socket){
		if(sirens == false) return;
		long []tarray;
		long currtime = System.currentTimeMillis();
		try {
			socket.getSockoptSIRENSSDATA(1, 3, 1, array[0]);
		} catch (IOException e) {
			System.out.printf("Not support SIRENS\n");
			return;
		}
		try {
			socket.getSockoptSIRENSSDATA(2, 3, 1, array[1]);
		} catch (IOException e) {
			System.out.printf("Not support SIRENS\n");
			return;
		}
		try {
			socket.getSockoptSIRENSSDATA(1, 3, 2, array[2]);
		} catch (IOException e) {
			System.out.printf("Not support SIRENS\n");
			return;
		}
		try {
			socket.getSockoptSIRENSSDATA(2, 3, 2, array[3]);
		} catch (IOException e) {
			System.out.printf("Not support SIRENS\n");
			return;
		}
		for( int j = 0 ; j < 256 ; j++){
       			if(array[0][j] != 0xffffffffL)
	       			System.out.printf("%10sbps\n", inttosip(array[0][j] * 1000000 ));
		}
		for( int j = 0 ; j < 256 ; j++){
       			if(array[1][j] != 0xffffffffL)
				System.out.printf("%10sbps\n", inttosip(array[1][j] * 1000000));
			}
		for( int j = 0 ; j < 256 ; j++){
       			if(array[2][j] != 0xffffffffL && currtime - starttime >= 2000)
	       			System.out.printf("%10sbps\n", inttosip((array[2][j] - parray[2][j]) / (currtime - oldtime) * 8 * 1000));
		}
		for( int j = 0 ; j < 256 ; j++){
       			if(array[3][j] != 0xffffffffL && currtime - starttime >= 2000)
	       			System.out.printf("%10sbps\n", inttosip((array[3][j] - parray[3][j]) / (currtime - oldtime) * 8 * 1000));
		}
		tarray = array[0];
		array[0] = parray[0];
		parray[0] = tarray;
		tarray = array[1];
		array[1] = parray[1];
		parray[1] = tarray;
		tarray = array[2];
		array[2] = parray[2];
		parray[2] = tarray;
		tarray = array[3];
		array[3] = parray[3];
		parray[3] = tarray;
	}
};
