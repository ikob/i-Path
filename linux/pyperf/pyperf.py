#!/usr/bin/env python
"""
 Copyright (c) 2009, 2010
 National Institute of Advanced Industrial Science and Technology (AIST).
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. All advertising materials mentioning features or use of this software
    must display the acknowledgement as bellow:

    This product includes software developed by AIST.

 4. The name of the author may not be used to endorse or promote products
    derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
"""
import socket
import getopt
import sys

from datetime import *
import struct

usage = "usage: pyperf [-b buffer] [-i interval] [-p port] [-t time] [-w window] [-Q] [-s | -c host]"

class Param:
	def __init__(self):
		self.buffer = 8192
		self.target = ""
		self.port = 4444
		self.duration = timedelta(seconds = 10)
		self.interval = 0
		self.wmax = 0
		self.sirens = False
		self.count = 0
		self.starttime = datetime.utcnow()
		self.now = datetime.utcnow()
		self.array = 4 * [ 256 * long() ]
		self.parray = 4 * [ 256 * long() ]

	def printstatus(self, basetime, basecount):
		tdn = (self.now - self.starttime)
		tdb = (basetime - self.starttime)
		duration = (self.now - basetime).seconds + (self.now - basetime).microseconds / 1000000
		print "%4.1f - %4.1f sec %s Bytes %s bps" % (tdb.seconds + tdb.microseconds/1000000, tdn.seconds + tdn.microseconds/1000000, inttosip(self.count - basecount), inttosip((self.count - basecount) * 8 / duration))

	def printSIRENSstatus(self, s):
		if self.sirens == False:
			return

		dreq = struct.pack("@BBBB", 3, 1, 1, 0)
		rc = s.setsockopt(socket.IPPROTO_IP, 96, dreq)
		self.array[0] = s.getsockopt(socket.IPPROTO_IP, 96, 1024)
		cur = 0
		while cur < 256:
			data = struct.unpack("!L", self.array[0][4*cur:4*(cur+1)])
			if data[0] != 0xffffffff :
				print "<- %d %5u Mbps" % (cur,  data[0])
			cur += 1

		dreq = struct.pack("@BBBB", 3, 1, 2, 0)
		s.setsockopt(socket.IPPROTO_IP, 96, dreq)
		self.array[1] = s.getsockopt(socket.IPPROTO_IP, 96, 1024)
		cur = 0
		while cur < 256:
			data = struct.unpack("!L", self.array[1][4*cur:4*(cur+1)])
			if data[0] != 0xffffffff :
				print "-> %d %5u Mbps" % (cur,  data[0])
			cur += 1

		dreq = struct.pack("@BBBB", 3, 2, 1, 0)
		s.setsockopt(socket.IPPROTO_IP, 96, dreq)
		self.array[2] = s.getsockopt(socket.IPPROTO_IP, 96, 1024)
		cur = 0
		while cur < 256:
			data = struct.unpack("!L", self.array[2][4*cur:4*(cur+1)])
			if data[0] != 0xffffffff and (self.now - self.starttime).seconds >= 2:
				pdata = struct.unpack("!L", self.parray[2][4*cur:4*(cur+1)])
				print "<- %d %10sBytes" % (cur, inttosip(data[0] - pdata[0]))
			cur += 1

		dreq = struct.pack("@BBBB", 3, 2, 2, 0)
		s.setsockopt(socket.IPPROTO_IP, 96, dreq)
		self.array[3] = s.getsockopt(socket.IPPROTO_IP, 96, 1024)
		cur = 0
		while cur < 256:
			data = struct.unpack("!L", self.array[3][4*cur:4*(cur+1)])
			if data[0] != 0xffffffff and (self.now - self.starttime).seconds >= 2:
				pdata = struct.unpack("!L", self.parray[3][4*cur:4*(cur+1)])
				print "-> %d %10sBytes" % (cur, inttosip(data[0] - pdata[0]))
			cur += 1
		tarray = self.array
		self.array = self.parray
		self.parray = tarray

def inttosip(data):
	if data < 1000:
		return ("        %3d" % (data))
	elif data < 1000000:
		return ("%7.2f K" % (data / 1000))
	elif data < 1000000000:
		return ("%7.2f M" % (data / 1000000))
	else:
		return ("%7.2f G" % (data / 1000000000))
		
def main():
	if len(sys.argv) < 2:
		print usage
		sys.exit(1)
	try:
		opts, args = getopt.getopt(sys.argv[1:], "b:c:i:p:st:w:Q", ["buffer", "client", "interval", "port", "server", "time", "window", "SIRENS"])
	except getopt.GetoptError:
		print usage
		sys.exit(1)
	f_server = False
	param = Param()

	for o, a in opts:
		if o in ("-b", "--buffer"):
			param.buffer = int(a)
		if o in ("-c", "--client"):
			if f_server == True:
				sys.exit(1)
			param.target = a
		if o in ("-i", "--interval"):
			param.interval = timedelta(seconds = int(a))
		if o in ("-p", "--port"):
			param.port = a
		if o in ("-s", "--server"):
			if param.target != "":
				sys.exit(1)
			f_server = True
		if o in ("-t", "--time"):
			param.duration = timedelta(seconds = int(a))
		if o in ("-w", "--window"):
			param.wmax = int(a)
		if o in ("-Q", "--SIRENS"):
			param.sirens = True
	if param.target != "":
		print "client", param.target
		client(param)
		sys.exit(0)
	if f_server == True:
		print "server"
		server(param)
		sys.exit(0)

def server(param):
	ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	buf = param.buffer * "0"
	if param.wmax != 0:
		rc = ss.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, param.wmax)
	param.wmax = ss.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
	print "SO_SNDBUF size: ", param.wmax

        if param.interval == 0:
		param.interval = param.duration

	ss.bind(("", int(param.port)))

	ss.listen(5)

	while 1:
		(cs, address) = ss.accept()
		if param.sirens == True:
			ireq = struct.pack("@BBBBBBBBBBBBBB", 2, 1, 3, 1, 0, 64, 0, 64, 3, 2, 0, 64, 0, 64)
			print "len=", len(ireq)
			rc = cs.setsockopt(socket.IPPROTO_IP, 97, ireq)
		server_run(cs, param)

def server_run(cs, param):
	while 1:
		buf = cs.recv(param.buffer)
		if not buf:
			break
		param.count += len(buf)
	cs.close()
	print "count = ", param.count 
	param.count = 0;

def client(param):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((param.target, int(param.port)))
	buf = param.buffer * "0"
	oldcount = 0

	if param.wmax != 0:
		rc = s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, param.wmax)
	param.wmax = s.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
	print "SO_SNDBUF size: ", param.wmax

	if param.sirens == True:
		ireq = struct.pack("@BBBBBBBBBBBBBB", 2, 1, 3, 1, 0, 64, 0, 64, 3, 2, 0, 64, 0, 64)
		print "len=", len(ireq)
		rc = s.setsockopt(socket.IPPROTO_IP, 97, ireq)

        if param.interval == 0:
		param.interval = param.duration

	param.starttime = datetime.utcnow()
	oldtime = param.starttime

	now = param.starttime
	while now < param.starttime + param.duration:
		now = datetime.utcnow()
		if now > oldtime + param.interval:
			param.now = now
			param.printstatus(oldtime, oldcount)
			param.printSIRENSstatus(s)
			oldtime = now
			oldcount = param.count
		s.sendall(buf)
		param.count += param.buffer
	print "count = ", param.count 

if __name__ == "__main__":
	main()
