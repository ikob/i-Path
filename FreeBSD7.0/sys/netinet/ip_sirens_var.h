/*
 *	@(#)ip_sirens_var.h
 * $$
 */

#ifndef _NETINET_SIRENS_VAR_H_
#define _NETINET_SIRENS_VAR_H_

struct	sriphdr {
	struct 	ipovly oi_i;		/* overlaid ip structure */
	struct	srhdr oi_s;
};
#define	oi_x1		oi_i.ih_x1
#define	oi_pr		oi_i.ih_pr
#define	oi_len		oi_i.ih_len
#define	oi_src		oi_i.ih_src
#define	oi_dst		oi_i.ih_dst
/*
#define	oi_sport	oi_o.oh_sport
#define	oi_dport	oi_o.oh_dport
#define	oi_ulen		oi_o.oh_ulen
#define	oi_sum		oi_o.oh_sum
*/

struct	srstat {
				/* input statistics: */
	u_long	srs_ipackets;		/* total input packets */
	u_long	srs_hdrops;		/* packet shorter than header */
	u_long	srs_opackets;		/* total output packets */
};

/*
 */
#define SIRENSCTL_STATS		1	/* statistics (read-only) */
#define SIRENSCTL_MAXID		2

#define SIRENSCTL_NAMES { \
	{ 0, 0 }, \
	{ "stats", CTLTYPE_STRUCT }, \
}

#if (defined(__NetBSD__))
/*
 * Names for SIRENS sysctl objects
 */
#define	SIRENSSCTL_IPACKETS		1
#define	SIRENSSCTL_HDROP		2
#define	SIRENSSCTL_OPACKETS		3
#define	SIRENSSCTL_MAXID		4

#define SIRENSSCTL_NAMES { \
	{ 0, 0 }, \
	{ "ipackets", CTLTYPE_INT }, \
	{ "hdrop", CTLTYPE_INT }, \
	{ "opackets", CTLTYPE_INT }, \
}
#endif

extern struct	pr_usrreqs sr_usrreqs;
extern struct	inpcbhead srb;
extern struct	inpcbinfo srbinfo;
extern u_long	srp_sendspace;
extern u_long	srp_recvspace;
extern struct	udpstat srpstat;

void	sirens_init __P((void));
void	sirens_input __P((struct mbuf *, ...));
void	sirens_ctlinput __P((int, struct sockaddr *, void *));

void	sirens_notify __P((struct inpcb *inp, int errno));
int	sirens_shutdown __P((struct socket *so));
#endif

