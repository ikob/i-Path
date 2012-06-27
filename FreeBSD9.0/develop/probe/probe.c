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
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <net/if.h>
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

#include <netinet/ip_sirens.h>
#define UDP_TEST 1
#undef UDP_TEST
#define BUFSIZE 1500
#define IPDEFHOP 16
main(int argc, char *argv[])
{
	int s;
	const char *scmd = "send";
	struct in_addr ip;
	struct hostent *dest_host;
	int cflag = 0;
	int ch;
	char *tp, *otp;

	if(argc != 2 ){
		printf("USAGE: %s IPADDR\n", argv[0]);
		exit(1);
	}

	otp = tp = (char *)strtok(argv[0], "/");
	while( tp != NULL){
		otp = tp;
		tp = (char *)strtok(NULL, "/");
	}
	if(strncmp(scmd, otp, strlen(scmd)) == 0){
		cflag = 1;
	}
	switch(cflag){
	case 1:
		send_sr(argv[1]);
		break;
	case 0:
		recv_sr(argv[1]);
		break;
	default:
		printf("Error\n");
		exit(1);
		break;
	}
	exit(0);
}
int send_sr ( const char *dst)
{
	int s;
	char sbuf[BUFSIZE];
	struct sockaddr_in dest_addr;
	struct ipopt_sr *opt_sr;
	u_char sr_ttl;
	int hincl = 1, hlen;
	struct ip *ip;

	bzero((char *) &dest_addr, sizeof(dest_addr));
	
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

	bzero(sbuf, 1500);
#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, 255)) < 0){   
#else
	if((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
#endif
		perror("socket");
		exit(1);
	}
#ifdef UDP_TEST
	dest_addr.sin_port = htons(8000);
	sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
#else
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	ip = (struct ip *)sbuf;
	hlen = sizeof(struct ip) + sizeof(struct ipopt_sr);
	ip->ip_ttl = IPDEFTTL;
	ip->ip_v = IPVERSION;
	ip->ip_hl = hlen >> 2;
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_p = 255;
	ip->ip_src.s_addr = INADDR_ANY;
	ip->ip_dst = dest_addr.sin_addr;
	ip->ip_len = 100;
	ip->ip_sum = 0x8888;

	opt_sr = (struct ipopt_sr *)(ip + 1);
	bzero(opt_sr, sizeof(struct ipopt_sr));

	opt_sr->req_mode = SIRENS_TTL;
	opt_sr->len = sizeof(struct ipopt_sr);
	opt_sr->type = IPOPT_SIRENS;

	opt_sr->req_probe = SIRENS_LINK | SIRENS_DIR_IN;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_OBYTES |SIRENS_DIR_IN;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_IBYTES | SIRENS_DIR_IN;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_QMAX | SIRENS_DIR_IN;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_LINK | SIRENS_DIR_OUT;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_OBYTES |SIRENS_DIR_OUT;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_IBYTES | SIRENS_DIR_OUT;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	opt_sr->req_probe = SIRENS_QMAX | SIRENS_DIR_OUT;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - IPDEFHOP ; sr_ttl--){ 
		opt_sr->req_ttl = sr_ttl; 
		sendto(s, sbuf, 100,0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		usleep(100000);
	}
#endif
	close(s);
}
int recv_sr ( const char *dst)
{
	int s;
	char rbuf[BUFSIZE];
	struct sockaddr_in from_addr;
	struct ip *iph;
	struct ipopt_sr *opt_sr;
	u_char sr_ttl;
	int sin_len, rcnt, off;

	bzero((char *) &from_addr, sizeof(from_addr));
	
	from_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &from_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, 255)) < 0){   
#else
	if((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
#endif
		perror("socket");
		exit(1);
	}
#ifdef UDP_TEST
	sin_len = sizeof(from_addr);
	rcnt = recvfrom(s, rbuf, BUFSIZE, 0, (struct sockaddr *)&from_addr, &sin_len);
	printf("success %4d %08x %08x %08x %08x\n", rcnt, rbuf[0], rbuf[1], rbuf[2], rbuf[3]);
#else
	sin_len = sizeof(from_addr);
	while(1){ 
		rcnt = recvfrom(s, rbuf, BUFSIZE,0, (struct sockaddr *)&from_addr, &sin_len);
		if(rcnt > 0 ){
			int i ;
			long * rb;
			rb = (long *)rbuf;
			iph = (struct ip *)rbuf;
			off = iph->ip_hl << 2;
			opt_sr = (struct ipopt_sr *)(iph + 1);
			printf("recvd len:%4d IP TTL:%4d SIRENS TTL:%4d mode:%s probe:%s = %4d\n", rcnt, iph->ip_ttl, opt_sr->req_ttl, sirens_mode_s[opt_sr->req_mode], sirens_probe_s[opt_sr->req_probe & ~SIRENS_DIR_IN], ntohl(opt_sr->req.data.set));
#if 0
			for(i = 0 ; i < rcnt/4 ; i ++){
				printf("%08x ", ntohl(rb[i]));
				if(!(i % 8)){
					printf("\n");
				}
			}
#endif
		}
	}
#endif
	close(s);
}
