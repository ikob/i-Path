#include <stdlib.h>
#include <strings.h>
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

	otp = tp = strtok(argv[0], "/");
	while( tp != NULL){
		otp = tp;
		tp = strtok(NULL, "/");
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
	struct srhdr *srh;
	u_char sr_ttl;

	bzero((char *) &dest_addr, sizeof(dest_addr));
	
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

	bzero(sbuf, 1500);
#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, IPPROTO_SIRENS)) < 0){   
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
	srh = (struct srhdr *)sbuf;
	bzero(srh, sizeof(struct srhdr));
	srh->req_mode = SIRENS_TTL;
	srh->req_probe = SIRENS_LINK;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, sbuf, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_OBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, sbuf, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_IBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, sbuf, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_QMAX;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, sbuf, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
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
	struct srhdr *srh;
	u_char sr_ttl;
	int sin_len, rcnt, off;

	bzero((char *) &from_addr, sizeof(from_addr));
	
	from_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &from_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, IPPROTO_SIRENS)) < 0){   
#else
	if((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
#endif
		perror("socket");
		exit(1);
	}
#ifdef UDP_TEST
	sin_len = sizeof(from_addr);
	rcnt = recvfrom(s, rbuf, BUFSIZE, 0, (struct sockaddr *)&from_addr, &sin_len);
	printf("success %4d %08x %08x %08x %08x\n", len, rbuf[0], rbuf[1], rbuf[2], rbuf[3]);
#else
	sin_len = sizeof(from_addr);
	while(1){ 
		rcnt = recvfrom(s, rbuf, BUFSIZE,0, (struct sockaddr *)&from_addr, &sin_len);
		if(rcnt > 0 ){
			iph = (struct ip *)rbuf;
			off = iph->ip_hl << 2;
			srh = (struct srhdr *)(rbuf + off);
			printf("recvd len:%4d IP TTL:%4d SIRENS TTL:%4d mode:%s probe:%s = %4d\n", rcnt, iph->ip_ttl, srh->req_ttl, sirens_mode_s[srh->req_mode], sirens_probe_s[srh->req_probe], ntohl(srh->req.data.set));
		}
	}
#endif
	close(s);
}
