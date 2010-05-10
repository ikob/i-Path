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
 *    This product includes software developed by K. Kobayashi
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

#define SIRENS_DISABLE 0x00
#define SIRENS_MIN 0x01
#define SIRENS_MAX 0x02
#define SIRENS_TTL 0x03

#define SIRENS_BID 0xC0
#define SIRENS_SND 0x80
#define SIRENS_RCV 0x40

#ifndef _KERNEL
static char *sirens_mode_s[] = {
	"disable",
	"minimal",
	"maximum",
	"ttl",
};
#endif /* _KERNEL */

enum SIRENS_PROBE {
	SIRENS_DUMMY,
	SIRENS_LINK,
	SIRENS_OBYTES,
	SIRENS_IBYTES,
	SIRENS_DROPS,
	SIRENS_ERRORS,
	SIRENS_QMAX,
	SIRENS_QLEN,
	SIRENS_MTU,
	SIRENS_LOCATON,
/*
	SIRENS_PMAX
*/
};
#define SIRENS_PMAX 256
#ifndef _KERNEL
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
#endif /* _KERNEL */
#define		IPSR_VAR_VALID 0x00000001
#define		IPSR_VAR_INVAL 0x00000000
/* SIRENS STORAGE */
struct sr_var{
	u_long flag;
       	u_long data;
};
struct sr_storage {
	struct sr_var array[SIRENS_PMAX];
};
#ifndef WIN32
struct if_srvarreq {
	char    ifr_name[IFNAMSIZ];             /* if name, e.g. "en0" */
	int	sr_probe;
	struct sr_var sr_var;
};
#else
struct if_srvarreq {
	int if_index;
	int	sr_probe;
	struct sr_var sr_var;
};
#endif

#define SIRENS_DIR_IN	0x80
#define SIRENS_DIR_OUT	0x00
#define SIRENS_DSIZE	32
/*
 * ext. SIRENS data
 */
union u_sr_data {
	u_long link;
	u_long loss;
	u_long queue;
	u_long mtu;
	struct {
		u_short lamda;
		u_short phy;
	} loc;
	u_long set;
};
struct sr_hopdata{
	struct timeval tv;
	union u_sr_data val;
};
/* SIRENS IP option header */
struct ipopt_sr {
	u_char type; /* always 94 */
	u_char len; /* more than 12 */
	u_char res_probe;
	u_char res_ttl;

	u_char req_mode;
	u_char req_probe;
	u_char res_mode;
	u_char req_ttl;
	union u_sr_data req_data;
#define SIRENSRESLEN 8
/*	res[SIRENSRESLEN]; */
};
/*
 * SIRENS packet tag.
 */
#ifdef _KERNEL
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
#endif /* KERNEL */
#define IPOPTSIRENSLEN(i) (sizeof (struct ipopt_sr) + sizeof(union u_sr_data) * i)
#define MAXIPOPTSIRENSLEN IPOPTSIRENSLEN(SIRENSRESLEN)
#define IPOPTLENTORESLEN(j) ((j - sizeof (struct ipopt_sr)) / sizeof(union u_sr_data) )

#ifdef _KERNEL
caddr_t ip_getsirensoptions __P((struct mbuf *));
#ifdef __APPLE__
int sr_setparam __P((struct ipopt_sr *, ifnet_t));
#else
int sr_setparam __P((struct ipopt_sr *, struct ifnet *));
#endif
#endif /* KERNEL */

struct ipopt_sr	*ip_sirens_dooptions(struct mbuf *);

#define SIRENSCTL_ENABLE	1
#define SIRENSCTL_INPKTS	2	/* statistics (read-only) */
#define SIRENSCTL_HDROP		3
#define SIRENSCTL_OUTPKTS	4
#define SIRENSCTL_UPDATE	5
#define SIRENSCTL_THROUGH	6
#define SIRENSCTL_MAXID		7

/* (sg)etsockopt for SIRENS data storage access */
#define IPSIRENS_SDATAX		96
#define IPSIRENS_IDX		97
#define IPSIRENS_SDATA		98
#define IPSIRENS_ADATA		99
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
#define IPSIRENS_DREQSIZE(i) (sizeof(struct sr_dreq) + i * sizeof(union u_sr_data))
#define IPSIRENS_DREQCNT(i) ((i - sizeof(struct sr_dreq)) / sizeof(union u_sr_data))

#define SIOCSSRVAR _IOWR('i', 222, struct if_srvarreq)
#define SIOCGSRVAR _IOWR('i', 223, struct if_srvarreq)

#endif
