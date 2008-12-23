#include <stdlib.h>
#include <strings.h>
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
#include <netdb.h>
#define UDP_TEST 1
#undef UDP_TEST
main()
{
	int s;
	const char *ipstr = "192.50.74.65";
	char data[1500];
	struct sockaddr_in dest_addr;
	struct in_addr ip;
	struct hostent *dest_host;
	struct srhdr *srh;
	u_char sr_ttl;
       
#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, IPPROTO_SIRENS)) < 0){   
#else
	if((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
#endif
		perror("socket");
		exit(1);
	}
	bzero((char *) &dest_addr, sizeof(dest_addr));
	
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(ipstr, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", ipstr);

	bzero(data, 1500);
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
		sendto(s, data, sizeof(srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_OBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_IBYTES;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}

	srh->req_probe = SIRENS_QMAX;
	for( sr_ttl = IPDEFTTL ; sr_ttl > IPDEFTTL - 2 ; sr_ttl--){ 
		srh->req_ttl = sr_ttl; 
		sendto(s, data, sizeof(srh),0, &dest_addr, sizeof(dest_addr));
		usleep(100000);
	}
#endif
	close(s);
}

