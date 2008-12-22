#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>
#define UDP_TEST 1
#undef UDP_TEST
main()
{
	int s;
	const char *ipstr = "192.50.74.68";
	char data[1500];
	struct sockaddr_in dest_addr;
	struct in_addr ip;
	struct hostent *dest_host;
       
#ifndef UDP_TEST
	if((s = socket (AF_INET, SOCK_RAW, IPPROTO_SIRENS)) < 0){   
#else
	if((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0){
#endif
		perror("socket");
		exit(1);
	}
	bzero((char *) &dest_addr, sizeof(dest_addr));
	bzero(data, 1500);
	{
		int i;
		long *p = (long *)data;
		for( i = 0 ; i < 100 ; i++){
			*p = htonl(i);
			p++;
		}
	}
	dest_addr.sin_family = AF_INET;
	if (!inet_aton(ipstr, &dest_addr.sin_addr))
		errx(1, "can't parse IP address %s", ipstr);

#ifdef UDP_TEST
	dest_addr.sin_port = htons(8000);
#endif
	sendto(s, data, 100,0, &dest_addr, sizeof(dest_addr));
	close(s);
}

