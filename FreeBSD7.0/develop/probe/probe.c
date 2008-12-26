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
//#undef UDP_TEST
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
		if( tp != NULL ) puts(tp);
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
	char data[1500];
	struct sockaddr_in dest_addr;
	struct srhdr *srh;
	u_char sr_ttl;

	bzero((char *) &dest_addr, sizeof(dest_addr));
	
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

	bzero(data, 1500);
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
	sendto(s, data, 100,0, &dest_addr, sizeof(dest_addr));
#else
	srh = (struct srhdr *)data;
	bzero(srh, sizeof(struct srhdr));
	srh->req_mode = SIRENS_TTL;
	srh->req_probe = SIRENS_LINK;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_OBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_IBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_QMAX;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}
#endif
	close(s);
}
int recv_sr ( const char *dst)
{
	int s;
	char data[1500];
	struct sockaddr_in dest_addr;
	struct srhdr *srh;
	u_char sr_ttl;
	int len, sin_len;

	bzero((char *) &dest_addr, sizeof(dest_addr));
	
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(dst, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", dst);

	bzero(data, 1500);
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
	sin_len = sizeof(dest_addr);
	len = recvfrom(s, data, sizeof(data),0, &dest_addr, &sin_len);
	printf("success %4d %08x %08x %08x %08x\n", len, data[0], data[1], data[2], data[3]);
#else
	srh = (struct srhdr *)data;
	bzero(srh, sizeof(struct srhdr));
	srh->req_mode = SIRENS_TTL;
	srh->req_probe = SIRENS_LINK;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_OBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_IBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_QMAX;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(*srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}
#endif
	close(s);
}
