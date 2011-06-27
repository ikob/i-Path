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

#ifndef _NETINET_SIRENS_H_
#define _NETINET_SIRENS_H_

/*
 * SIRENS protocol header.
 */
#define IPOPT_SIRENS   94 /* [RFC4727] spcified in RFC3692 style experiment */

/*
 * SIRENS data storage
 */
union u_sr_data {
	uint32_t link;
	uint32_t loss;
	uint32_t queue;
	uint32_t mtu;
	struct {
		uint16_t lamda;
		uint16_t phy;
	} loc;
	uint32_t set;
};

/*
 * SIRENS IP option header
 */
struct ipopt_sr {
	uint8_t type; /* always 94 */
	uint8_t len; /* 12 */
	uint8_t res_probe; /* responce data type */
	uint8_t res_ttl; /* responce data TTL */
	
	uint8_t req_mode; /* request mode, {min, max, TTL} =  {1, 2, 3} */
	uint8_t req_probe; /* request data type */
	uint8_t res_mode; /* responce mode */
	uint8_t req_ttl; /* request data TTL */
	union u_sr_data req_data; /* SIRENS request data storage */
#define SIRENSRESLEN 8
	/*	res[SIRENSRESLEN]; */
};
#if defined(KERNEL) || defined(__KERNEL__)
#if defined(__FreeBSD__)
/*
 * SIRENS packet tag.
 */
struct sirens_tag {
	struct m_tag    tag;
	u_char type; /* always 94 */
	u_char len; /* more than 12 */
	u_char res_probe;
	u_char res_ttl;
	
	u_char req_mode;
	u_char req_probe;
	u_char res_mode;
	u_char req_ttl;
	union u_sr_data req_data;
	union u_sr_data res[SIRENSRESLEN];
};
#endif /* defined(__FreeBSD__) */
#endif /* defined(KERNEL) || defined(__KERNEL__) */
/*
 * SIRENS data cached in end systems
 */
struct sr_hopdata{
	struct timeval tv;
	union u_sr_data val;
};

#define SIRENS_DISABLE 0x00
#define SIRENS_MIN 0x01
#define SIRENS_MAX 0x02
#define SIRENS_TTL 0x03

#define SIRENS_BID 0xC0
#define SIRENS_SND 0x80
#define SIRENS_RCV 0x40

#if !defined(KERNEL) && !defined(__KERNEL__)
static char *sirens_mode_s[] = {
	"disable",
	"minimal",
	"maximum",
	"ttl",
};
#endif /* !defined(KERNEL) && !defined(__KERNEL__) */

enum SIRENS_PROBE {
	SIRENS_DUMMY,
	SIRENS_LINK,		/* Link BW (bps) */
	SIRENS_OBYTES,		/* output byte count */
	SIRENS_IBYTES,		/* input byte count */
	SIRENS_DROPS,		/* drop packets count */
	SIRENS_ERRORS,		/* error count */
	SIRENS_QMAX,		/* maximum used queue length */
	SIRENS_QLEN,		/* output queue length limit */
	SIRENS_MTU,		/* MTU size */
	SIRENS_LOCATION,	/* Geographical location */
	SIRENS_PMAX = 256,
};
#if !defined(KERNEL) && !defined(__KERNEL__)
static char *sirens_probe_s[] = {
	"dummy",
	"link",
	"obytes",
	"ibytes",
	"drops",
	"errors",
	"qmax",
	"qlen",
	"mtu",
	"location",
};
#endif /* !defined(KERNEL) && !defined(__KERNEL__) */
#define		IPSR_VAR_VALID 0x00000001
#define		IPSR_VAR_INVAL 0x00000000
/* SIRENS STORAGE */
struct sr_var{
	uint32_t flag;
       	uint32_t data;
};
struct sr_storage {
	struct sr_var array[SIRENS_PMAX];
};
#ifndef WIN32
struct if_srvarreq {
#if defined(__linux__)
	char    ifrname[IFNAMSIZ];		/* if name, e.g. "en0" */
#else
	char    ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
#endif
	int	sr_probe;
	struct sr_var sr_var;
};
#else /* !WIN32 */
struct if_srvarreq {
	int if_index;
	int	sr_probe;
	struct sr_var sr_var;
};
#endif /* !WIN32 */

#define SIRENS_DIR_IN	0x80
#define SIRENS_DIR_OUT	0x00
#define SIRENS_DSIZE	32

#define IPOPTSIRENSLEN(i) (sizeof (struct ipopt_sr) + sizeof(union u_sr_data) * i)
#define MAXIPOPTSIRENSLEN IPOPTSIRENSLEN(SIRENSRESLEN)
#define IPOPTLENTORESLEN(j) ((j - sizeof (struct ipopt_sr)) / sizeof(union u_sr_data) )

#if defined(KERNEL) || defined(__KERNEL__)
#if defined(__APPLE__)
caddr_t ip_getsirensoptions __P((struct mbuf *));
int sr_setparam __P((struct ipopt_sr *, ifnet_t, struct sr_storage *));
#endif /* defined(__APPLE__) */
#if defined(__FreeBSD__)
caddr_t ip_getsirensoptions __P((struct mbuf *));
int sr_setparam __P((struct ipopt_sr *, struct ifnet *));
#endif /* defined(__FreeBSD__) */
#if defined(__linux__)
#endif /* defined(__linux__) */
#endif /* defined(KERNEL) || defined(__KERNEL__) */

#if defined(__APPLE__) || defined(__FreeBSD__)
struct ipopt_sr	*ip_sirens_dooptions(struct mbuf *);
#endif /* defined(__APPLE__) || defined(__FreeBSD__) */

#define SIRENSCTL_ENABLE	1
#define SIRENSCTL_INPKTS	2	/* statistics (read-only) */
#define SIRENSCTL_HDROP		3
#define SIRENSCTL_OUTPKTS	4
#define SIRENSCTL_UPDATE	5
#define SIRENSCTL_THROUGH	6
#define SIRENSCTL_MAXID		7

/* (sg)etsockopt for SIRENS data storage access */
#if defined(__linux__)
#define IPSIRENS_SRVAR		95
#endif /* defined(__linux__) */
#define IPSIRENS_SDATAX		96
#define IPSIRENS_IDX		97
#define IPSIRENS_SDATA		98
#define IPSIRENS_ADATA		99
#define IPSIRENS_STDATA		100
#define IPSIRENS_STDATAX	101
#define IPSIRENS_IREQMAX	8
#define IPSIRENS_DREQMAX	16
struct sr_ireq{
	u_char sr_nindex;
	u_char sr_smax;
/*
	struct srreq_index	sr_indexp[];
*/
};
struct srreq_index
{
	u_char mode;
	u_char probe;
	u_char qttl_min;
	u_char qttl_max;
	u_char sttl_min;
	u_char sttl_max;
};
#define IPSIRENS_IREQSIZE(i) (sizeof(struct sr_ireq) + i * sizeof(struct srreq_index))
struct sr_dreq{
	u_char mode;
	u_char probe;
	u_char dir;
	u_char dummy;
/*
	union u_sr_data    sr_data[]
*/
};
#define IPSIRENS_DTREQSIZE(i) (sizeof(struct sr_dreq) + i * sizeof(struct sr_hopdata))
#define IPSIRENS_DREQSIZE(i) (sizeof(struct sr_dreq) + i * sizeof(union u_sr_data))
#define IPSIRENS_DREQCNT(i) ((i - sizeof(struct sr_dreq)) / sizeof(union u_sr_data))

#if defined(__APPLE__) || defined(__FreeBSD__)
#define SIOCSSRVAR _IOWR('i', 222, struct if_srvarreq)
#define SIOCGSRVAR _IOWR('i', 223, struct if_srvarreq)
#endif /* defined(__APPLE__) || defined(__FreeBSD__) */

#endif /* _NETINET_SIRENS_H_ */
