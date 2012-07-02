/*
 * ip_sirens.c - SIRENS/i-Path cross-layer module.
 *
 * Copyright (c) 2010 National Institute of Advanced Industrial Science
 * and Technology (AIST).
 *
 * Copyright (c) 2011, 2021 RIKEN, Advanced Institute for Computational
 * Science (AICS).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#if defined(__linux__)
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/time.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/net_namespace.h>		/* init_net */
#include <net/inet_hashtables.h>
#include <net/transp_v6.h>		/* LOOPBACK4_IPV6 */
#endif /* defined(__linux__) */

#if defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockopt.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/pfil.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip_options.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include <machine/in_cksum.h>

#define MTAG_SIRENS	1325724131 /* date -u +'%s' */
#define MTAG_SIRENS_OPTION	(1 | MTAG_PERSISTENT) 

#endif /* defined(__FreeBSD__) */

#include "ip_sirens.h"

#define SIRENS_VERSION		"1.0.0"

#define IPSIRENS_OPTMIN		IPSIRENS_STDATA
#define IPSIRENS_OPTMAX		IPSIRENS_ADATA
#define IPSIRENS_HOPNUM		256
#define IPSIRENS_HOPMAX		(IPSIRENS_HOPNUM - 1)
#define IPSIRENS_TIMEOUT	100	/* sec */

#ifndef IPSIRENS_MAX_SK
#define IPSIRENS_MAX_SK		50
#endif

#ifndef IPSIRENS_MAX_ICMP
#define IPSIRENS_MAX_ICMP	50
#endif

#if defined(__linux__)
#define DPRINT(x...) printk(KERN_DEBUG x )
#define SOCKETP struct sock*
#elif defined(__FreeBSD__)
#define DPRINT(x...) printf(x)
#define SOCKETP struct socket*
#endif /* defined(__linux__), elif defined(__FreeBSD__) */

#if defined(__linux__)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
#include <linux/ethtool.h>
static inline int dev_ethtool_get_settings(struct net_device *dev,
					   struct ethtool_cmd *cmd)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_settings)
		return -EOPNOTSUPP;
	return dev->ethtool_ops->get_settings(dev, cmd);
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31) */
#endif /* defined(__linux__) */

struct SRIFEntry {
#if defined(__linux__)
	struct list_head list;
	struct net_device *dev;		/* pointer to the interface */

	struct list_head icmp;		/* pushed ICMP echo request */
#elif defined(__FreeBSD__)
	LIST_ENTRY(SRIFEntry)  list;
	struct ifnet       *ifp;
#endif /* defined(__linux__) defined(__FreeBSD__) */
	struct sr_storage storage;	/* external data of the interface */
};

struct SRSFEntry {
#if defined(__linux__)
	struct list_head list;
	struct sock *sk;			/* pointer to the socket */
	void (*sk_destruct)(struct sock *);	/* socket destructor hook */
#elif defined(__FreeBSD__) || defined(__APPLE__)
        LIST_ENTRY(SRSFEntry) list;
        uint32_t flag;
#if defined (__APPLE__)
        socket_t sk;         /* Pointer to owning socket */
        uint32_t magic;          /* magic value to ensure that system is passing me my buffer */
#elif defined(__FreeBSD__)
        SOCKETP sk;
/*        struct socket *sk;        */ /* Pointer to owning socket */
#endif /* defined(__FreeBSD__) defined(__APPLE__) */
#endif /* defined(__linux__) defined(__FreeBSD__) defined(__APPLE__) */

	u_char sr_qnext;		/* next candidate of req */
	u_char sr_snext;		/* next candidate of res */
	u_char sr_nmax;			/* # of valid IDX */
	u_char sr_qttl;			/* last TTL in req data */
	u_char sr_sttl;			/* last TTL in res data */
	u_char sr_smax;			/* # of res data */
	struct sr_dreq sr_dreq;		/* cache for IPSIRENS_SDATAX */
	struct sr_info {
		u_char mode;
		u_char probe;
		u_char qmin_ttl;	/* ttl min range in req */
		u_char qmax_ttl;	/* ttl max range in req */
		u_char smin_ttl;	/* ttl min range in res */
		u_char smax_ttl;	/* ttl max range in res */
		struct sr_hopdata sr_qdata[IPSIRENS_HOPNUM];	/* req data */
		struct sr_hopdata sr_sdata[IPSIRENS_HOPNUM];	/* res data */
	} inp_sr[IPSIRENS_IREQMAX];		/* probe information */
};

#if defined(__linux__)
struct ICMPEntry {
	struct list_head list;

	uint32_t saddr;			/* source address */
	int reslen;
	char buf[IPOPTSIRENSLEN(1)];	/* SIRENS header cache */
};
#endif /* defined(__linux__) */


/* global lock */
#if defined(__linux__)
static DEFINE_SPINLOCK(sr_lock);
#define LOCK(lp, f) spin_lock_irqsave(lp, f)
#define UNLOCK(lp, f) spin_unlock_irqrestore(lp, f)
#elif defined(__FreeBSD__)
static struct mtx sr_lock;
#define LOCK(lp, f) flags = 0; mtx_lock_flags(lp, flags)
#define UNLOCK(lp, f) flags = 0; mtx_unlock_flags(lp, flags)
#endif /* defined(__linux__) defined(__FreeBSD__) */

/* LISTS */
#if defined(__linux__)
/* per network device information */
LIST_HEAD(sr_iflist);

/* per socket information */
LIST_HEAD(sr_sactive);
LIST_HEAD(sr_spool);
static int sr_max_sk = IPSIRENS_MAX_SK;

/* ICMP information */
LIST_HEAD(sr_icmppool);
static int sr_max_icmp = IPSIRENS_MAX_ICMP;

/* ICMP SIRENS res control */
static int sr_icmp_sirens_res = 1;	/* default enable */
#elif defined(__FreeBSD__)
static struct sr_iflist sr_iflist;
static struct sr_sflist sr_sactive;
static struct sr_sflist sr_spool;

LIST_HEAD(sr_iflist, SRIFEntry);
LIST_HEAD(sr_sflist, SRSFEntry);
static int sr_max_so = IPSIRENS_MAX_SK;
#endif /* defined(__linux__) defined(__FreeBSD__) */

#if defined(__FreeBSD__)
#define list_empty(h) LIST_EMPTY(h)
#define list_first_entry(p, t, field) ((t)LIST_NEXT(p, field))
#endif /* defined(__FreeBSD__) */

static inline struct SRIFEntry *
#if defined(__linux__)
netdev_to_SRIFEntry(struct net_device *ndev)
#elif defined(__FreeBSD__)
ifnet_to_SRIFEntry(struct ifnet *ifp)
#endif /* defined(__linux__) defined(__FreeBSD__) */
{
	struct SRIFEntry *srip;

#if defined (__linux__)
	list_for_each_entry(srip, &sr_iflist, list) {
		if (srip->dev == ndev)
			return srip;
	}
#elif defined (__FreeBSD__)
	LIST_FOREACH(srip, &sr_iflist, list){
		if (srip->ifp == ifp)
			return srip;
	}
#endif /* defined(__linux__), defined(__FreBSD__) */
	return NULL;
}

static inline struct SRIFEntry *
name_to_SRIFEntry(const char *name)
{
	struct SRIFEntry *srip;

#if defined( __linux__)
	list_for_each_entry(srip, &sr_iflist, list) {
		if (strncmp( srip->dev->name, name, IFNAMSIZ) == 0)
			return srip;
	}
#elif defined (__FreeBSD__)
	LIST_FOREACH(srip, &sr_iflist, list){
		if (strncmp( if_name(srip->ifp), name, IFNAMSIZ) == 0)
			return srip;
	}
	
#endif /* defined(__linux__) defined(__FreBSD__) */
	return NULL;
}

static inline struct SRSFEntry *
sock_to_SRSFEntry(
#if defined (__linux__)
    struct sock *sk
#elif defined (__APPLE__)
    socket_t    sk
#elif defined (__FreeBSD__)
    struct socket *so
#endif
)
{
	struct SRSFEntry *srp;

#if defined( __linux__)
	list_for_each_entry(srp, &sr_sactive, list) {
		if (srp->sk == sk)
			return srp;
	}
#elif defined (__FreeBSD__)
	LIST_FOREACH(srp, &sr_sactive, list){
		if (srp->sk == so)
			return srp;
	}
#endif /* defined(__linux__) defined(__FreBSD__) */
	return NULL;
}

#if defined (__linux__)
static inline struct ICMPEntry *
addr_to_ICMPEntry(struct SRIFEntry *srp, uint32_t addr)
{
	struct ICMPEntry *icmp;

	list_for_each_entry(icmp, &(srp->icmp), list) {
		if (icmp->saddr == addr)
			return icmp;
	}

	return NULL;
}
#elif defined (__FreeBSD__)
/* XXX: ICMP reply action shoule be implemented with packet tag ? */
#endif

#if defined (__linux__)
void
sr_sk_destruct_hook(struct sock *sk)
{
	struct SRSFEntry *srp;
	unsigned long flags;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
	if (srp) {
		sk->sk_destruct = srp->sk_destruct;

		list_del(&(srp->list));
		memset(srp, 0, sizeof(*srp));
		list_add(&(srp->list), &sr_spool);
	}
#ifdef SR_DEBUG
	else {
		printk(KERN_DEBUG "%s: missing SRSFEntry: sk=%p\n",
			__FUNCTION__, sk);
	}
#endif /* SR_DEBUG */

	spin_unlock_irqrestore(&sr_lock, flags);

	/*
	 * invoke proper destructor.
	 */
	if (sk->sk_destruct && sk->sk_destruct != &sr_sk_destruct_hook)
		(sk->sk_destruct)(sk);
}
#endif /* __linux__ */

static struct ipopt_sr *
sr_find_sirens(
#if defined(__linux__)
	struct sk_buff *skb
#elif defined(__FreeBSD__)
	struct mbuf *m
#endif /* defined(__linux__) defined(__FreeBSD__) */
	)
{
#if defined(__linux__)
	struct iphdr *iph = ip_hdr(skb);
#elif defined(__FreeBSD__)
	struct ip *iph = mtod(m, struct ip *);
#endif /* __linux__, __FreeBSD__ */
	struct ipopt_sr *opt_sr;
	u_char *cp;
	int opt, optlen, cnt, code;

#if defined(__linux__)
	if (! pskb_may_pull(skb, ip_hdrlen(skb))) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: pskb_may_pull() failed\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		return NULL;
	}
#endif /* defined(__linux__) */

	cp = (u_char *)(iph + 1);
#if defined(__linux__)
	cnt = (iph->ihl << 2) - sizeof (struct iphdr);
#elif defined(__FreeBSD__)
	cnt = (iph->ip_hl << 2) - sizeof (struct ip);
#endif /* defined(__linux__) defined(__FreeBSD__) */
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
#if defined(__linux__)
		if (opt == IPOPT_END)
#elif defined(__FreeBSD__)
		if (opt == IPOPT_EOL)
#endif /* defined(__linux__) defined(__FreeBSD__) */
			break;
#if defined(__linux__)
		if (opt == IPOPT_NOOP)
#elif defined(__FreeBSD__)
		if (opt == IPOPT_NOP)
#endif /* defined(__linux__) defined(__FreeBSD__) */
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)iph;
				goto bad;
			}
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt) {
				code = &cp[IPOPT_OLEN] - (u_char *)iph;
				goto bad;
			}
		}
		switch (opt) {
		default:
		case IPOPT_LSRR:
		case IPOPT_SSRR:
		case IPOPT_RR:
		case IPOPT_TS:
			break;
		case IPOPT_SIRENS:
			opt_sr = (struct ipopt_sr *)cp;

			if (cp[IPOPT_OLEN] < sizeof(struct ipopt_sr) ||
					MAXIPOPTSIRENSLEN < cp[IPOPT_OLEN]) {
				code = &cp[IPOPT_OLEN] - (u_char *)iph;
				goto bad;
			}
			if (opt_sr->len != cp[IPOPT_OLEN]) {
#ifdef SR_DEBUG
				printk(KERN_DEBUG "%s: corrupted SIRENS "
					"header\n", __FUNCTION__);
#endif /* SR_DEBUG */
				goto bad;
			}
			return opt_sr;
		}
		break;
	}
 bad:
	/* FIX ME: we need ICMP error handling ? */
	return NULL;
}

#if defined(__linux__)
static struct ipopt_sr *
sr_insert_sirens(struct sk_buff *skb, u_char reslen)
{
	struct iphdr *iph;
	struct ipopt_sr *opt_sr;
	int opt, optlen, hdrlen, cnt;
	u_char *cp;

	optlen = IPOPTSIRENSLEN(reslen);
	hdrlen = ip_hdrlen(skb);

	if (skb_headroom(skb) < optlen)
		return NULL;

	/*
	 * create SIRENS header room by moving IP header before.
	 */
	cp = skb_network_header(skb);		/* save old iphdr */
	skb_push(skb, optlen);
	skb_reset_network_header(skb);		/* reset iphdr */
	iph = ip_hdr(skb);
	memmove(iph, cp, hdrlen);

	/*
	 * adjust IP header and SIRENS header.
	 */
	iph->ihl += (optlen >> 2);
	iph->tot_len = htons(ntohs(iph->tot_len) + (uint16_t)optlen);
	opt_sr = (struct ipopt_sr *)(((u_char *) iph) + hdrlen);
	opt_sr->type = IPOPT_SIRENS;
	opt_sr->len = optlen;

#ifdef SR_DEBUG
	if (skb_network_header(skb) + ip_hdrlen(skb) !=
					skb_transport_header(skb)) {
		printk(KERN_DEBUG "%s: corrupted IP header [1]\n",
			__FUNCTION__);
	}
#endif /* SR_DEBUG */

	if (hdrlen == sizeof (struct iphdr)) {
#ifdef SR_DEBUG
		if (opt_sr != sr_find_sirens(skb)) {
			printk(KERN_DEBUG "%s: corrupted IP header [2]\n",
				__FUNCTION__);
		}
#endif /* SR_DEBUG */
		return opt_sr;
	}

	/*
	 * IP header has IP options. we must replace IPOPT_END to
	 * IPOPT_NOOP until we see SIRENS header.
	 */
	cp = (u_char *)(iph + 1);
	cnt = (iph->ihl << 2) - sizeof (struct iphdr);
	optlen = 0;
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_SIRENS)
			break;		/* last option */
		if (opt == IPOPT_END) {
			cp[IPOPT_OPTVAL] = IPOPT_NOOP;
			optlen = 1;
		}
		else if (opt == IPOPT_NOOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp))
				return NULL;
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt)
				return NULL;
		}
	}

#ifdef SR_DEBUG
	if (opt_sr != sr_find_sirens(skb)) {
		printk(KERN_DEBUG "%s: corrupted IP header [3]\n",
			__FUNCTION__);
	}
#endif /* SR_DEBUG */
	return opt_sr;
}

static void
sr_push_sirens(struct iphdr *iph, struct ipopt_sr *opt_sr,
	struct net_device *ndev)
{
	struct SRIFEntry *srp;
	struct ICMPEntry *icmp;
	union u_sr_data *res;
	unsigned long flags;

	if (ndev == NULL)
		return;
	srp = netdev_to_SRIFEntry(ndev);
	if (srp == NULL)
		return;

	spin_lock_irqsave(&sr_lock, flags);

	icmp = list_first_entry(&sr_icmppool, struct ICMPEntry, list);
	if (icmp) {
		list_del(&(icmp->list));
		list_add(&(icmp->list), &(srp->icmp));

		icmp->saddr = iph->saddr;
		icmp->reslen = IPOPTLENTORESLEN(opt_sr->len);
		if (icmp->reslen > 1)
			icmp->reslen = 1;
		memcpy(icmp->buf, opt_sr, IPOPTSIRENSLEN(icmp->reslen));

		opt_sr = (struct ipopt_sr *) icmp->buf;
		opt_sr->len = IPOPTSIRENSLEN(icmp->reslen);
		switch(opt_sr->req_mode){
/* flip req and res */
			case SIRENS_TTL:
			case SIRENS_MAX:
			case SIRENS_MIN:
				opt_sr->res_probe = opt_sr->req_probe;
				opt_sr->res_ttl = opt_sr->req_ttl;
				break;
			default:
				break;
		}
		if (sr_icmp_sirens_res == 0) {
			opt_sr->req_mode = SIRENS_DISABLE;
			opt_sr->req_ttl = 0;
			opt_sr->req_probe = 0;
		}
		if (icmp->reslen > 0) {
			res = (union u_sr_data *)(opt_sr + 1);
			*res = opt_sr->req_data;
		}
		opt_sr->req_data.set = -1;
	}
#ifdef SR_DEBUG
	else
		printk(KERN_DEBUG "%s: no memory for ICMP\n", __FUNCTION__);
#endif /* SR_DEBUG */

	spin_unlock_irqrestore(&sr_lock, flags);
}

static struct ipopt_sr *
sr_pop_sirens(struct iphdr *iph, struct sk_buff *skb, struct net_device *ndev)
{
	struct SRIFEntry *srp;
	struct ICMPEntry *icmp;
	struct ipopt_sr *opt_sr = NULL;
	unsigned long flags;

	if (ndev == NULL)
		return NULL;

	srp = netdev_to_SRIFEntry(ndev);
	if (srp == NULL)
		return NULL;

	spin_lock_irqsave(&sr_lock, flags);

	icmp = addr_to_ICMPEntry(srp, iph->daddr);
	if (icmp) {
		opt_sr = sr_insert_sirens(skb, icmp->reslen);
		if (opt_sr)
			memcpy(opt_sr, icmp->buf, IPOPTSIRENSLEN(icmp->reslen));
		list_del(&(icmp->list));
		icmp->saddr = 0;
		list_add(&(icmp->list), &sr_icmppool);
	}

	spin_unlock_irqrestore(&sr_lock, flags);

	return opt_sr;
}
#endif /* defined(__linux__) */
static void
sr_update_reqdata(struct ipopt_sr *opt_sr,
#if defined (__linux__)
	struct net_device *ndev
#elif defined (__FreeBSD__)
	struct ifnet *ifp
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	uint32_t data = ~0;
	struct SRIFEntry *srip;
	struct sr_var *srvar;
#if defined(__linux__)
	struct ethtool_cmd ethcmd;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	const struct net_device_stats *stats;
#else
	struct rtnl_link_stats64 *stats;
	struct rtnl_link_stats64 temp;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) */
#elif defined (__FreeBSD__)
#endif /* defined(__linux__) defined(__FreeBSD__) */
	uint32_t flag;
	unsigned long flags;

	/* getting interface information */
#if defined(__linux__)
	if (ndev == NULL)
		goto update;
#elif defined (__FreeBSD__)
	if (ifp == NULL)
		goto update;
#endif /* defined(__linux__) defined(__FreeBSD__) */

#if defined(__linux__)
	srip = netdev_to_SRIFEntry(ndev);
#elif defined (__FreeBSD__)
	srip = ifnet_to_SRIFEntry(ifp);
#endif /* defined(__linux__) defined(__FreeBSD__) */
	if (srip) {
		LOCK(&sr_lock, flags);

		srvar = &(srip->storage.array[opt_sr->req_probe]);
		flag = srvar->flag;
		data = (uint32_t) srvar->data;

		UNLOCK(&sr_lock, flags);

		if (flag == IPSR_VAR_VALID) {
			/*
			 * we find valid data, update with this value.
			 */
#ifdef SR_DEBUG
			printk(KERN_DEBUG "%s: external data: dev=[%.*s] "
				"probe=0x%x data=%u ttl=%d\n", __FUNCTION__,
				IFNAMSIZ, ndev->name, opt_sr->req_probe, data,
				opt_sr->req_ttl);
#endif /* SR_DEBUG */
			goto update;
		}
		else {
			/*
			 * no valid data. fall down.
			 */
			data = ~0;
		}
	}
#if defined(__linux__)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	stats = dev_get_stats(ndev);
#else
	stats = dev_get_stats(ndev, &temp);
#endif
#endif /* defined(__linux__) */
#if defined(__FreeBSD__)
	IF_AFDATA_LOCK(ifp);
#endif
	switch (opt_sr->req_probe & ~SIRENS_DIR_IN) {
#if defined(__linux__)
	case SIRENS_LINK:
		if (dev_ethtool_get_settings(ndev, &ethcmd) < 0) {
			printk("%s: dev_ethtool_get_settings failed: "
				"dev=[%.*s]\n", __FUNCTION__, IFNAMSIZ,
				ndev->name);
			goto update;
		}
		data = (uint32_t) ethcmd.speed;
		break;
	case SIRENS_OBYTES:
		data = (uint32_t) stats->tx_bytes;
		break;
	case SIRENS_IBYTES:
		data = (uint32_t) stats->rx_bytes;
		break;
	case SIRENS_DROPS:
		data = (uint32_t) (stats->rx_dropped + stats->tx_dropped);
		break;
	case SIRENS_ERRORS:
		data = (uint32_t) (stats->rx_errors + stats->tx_errors);
		break;
	case SIRENS_MTU:
		data = (uint32_t) ndev->mtu;
		break;
	case SIRENS_QMAX:	/* fall down */
	case SIRENS_QLEN:	/* fall down */
#elif defined(__FreeBSD__)
	case SIRENS_LINK:
		data = (uint32_t)(ifp->if_baudrate / 1000000);
		break;
	case SIRENS_OBYTES:
		data = (uint32_t)ifp->if_obytes;
		break;
	case SIRENS_IBYTES:
		data = (uint32_t)ifp->if_ibytes;
		break;
	case SIRENS_DROPS:
		data = (uint32_t)ifp->if_snd.ifq_drops;
		break;
	case SIRENS_ERRORS:
		data = (uint32_t)ifp->if_oerrors;
		break;
	case SIRENS_MTU:
		data = (uint32_t) ifp->if_mtu;
		break;
	case SIRENS_QMAX:
		data = (uint32_t) ifp->if_snd.ifq_maxlen;
		break;
	case SIRENS_QLEN:
		data = (uint32_t) ifp->if_snd.ifq_len;
		break;
#endif /* defined(__linux__) defined(__FreeBSD__) */
	default:
		break;
	}
#if defined(__FreeBSD__)
	IF_AFDATA_UNLOCK(ifp);
#endif
#ifdef SR_DEBUG
	DPRINT("%s: internal data: dev=[%.*s] probe=0x%x data=%u "
		"ttl=%d\n", __FUNCTION__, IFNAMSIZ, ndev->name,
		opt_sr->req_probe, data, opt_sr->req_ttl);
#endif /* SR_DEBUG */

 update:
	switch (opt_sr->req_mode) {
	case SIRENS_TTL:
		opt_sr->req_data.set = htonl(data);
		break;
	case SIRENS_MIN:
		if (opt_sr->req_ttl == 0)
			opt_sr->req_ttl = 0xff;
		else
			opt_sr->req_ttl--;
		if (data == ~0)
			break;
		if (data < ntohl(opt_sr->req_data.set))
			opt_sr->req_data.set = htonl(data);
		break;
	case SIRENS_MAX:
		if (opt_sr->req_ttl == 0)
			opt_sr->req_ttl = 0xff;
		else
			opt_sr->req_ttl--;
		if (data == ~0)
			break;
		if (data > ntohl(opt_sr->req_data.set))
			opt_sr->req_data.set = htonl(data);
		break;
	case SIRENS_EQ:
		if(opt_sr->req_data.set != htonl(data)) break;
	case SIRENS_GE:
		if(opt_sr->req_data.set > htonl(data)) break;
	case SIRENS_LE:
		if(opt_sr->req_data.set < htonl(data)) break;
#if defined(__FreeBSD__)
		if(opt_sr->len != IPOPTSIRENSLEN(1)) break;
		if(ifp == NULL) break;
		IF_ADDR_LOCK(ifp);
		{
			struct ifaddr *ifa;
			struct in_ifaddr *iap;
			union u_sr_data *res;
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link){
				iap = ifatoia(ifa);
				if(iap->ia_addr.sin_family == AF_INET){
/* check multiple FIB ? */
					res = (union u_sr_data *)(opt_sr + 1);
					res->sin_addr = iap->ia_addr.sin_addr;
					break;
				}
			}
		}
		IF_ADDR_UNLOCK(ifp);
#endif
	default:
		break;
	}
}

static void
sr_gather_data(struct ipopt_sr *opt_sr, struct SRSFEntry *srp)
{
	struct sr_hopdata *hopdata;
	struct sr_info *sr_info;
	union u_sr_data *resdata = (union u_sr_data *)(opt_sr + 1);
	u_int reslen = IPOPTLENTORESLEN(opt_sr->len);
	struct timeval now;
	int i, j;

#if defined(__linux__)
	do_gettimeofday(&now);
#elif defined (__FreeBSD__)
	microtime(&now);
#endif /* defined(__linux__) defined(__FreeBSD__) */

	for (i = 0; i < srp->sr_nmax; i++) {
		sr_info = &(srp->inp_sr[i]);
		if (sr_info->mode != opt_sr->req_mode ||
				sr_info->probe != opt_sr->req_probe)
			continue;

		hopdata = &(sr_info->sr_qdata[opt_sr->req_ttl]);
		hopdata->tv.tv_sec = now.tv_sec;
		hopdata->tv.tv_usec = now.tv_usec;
		hopdata->val = opt_sr->req_data;
#ifdef SR_DEBUG
		if (hopdata->val.set == -1)
			break;
		printk(KERN_DEBUG "%s: qdata: mode=%d probe=0x%x ttl=%d "
			"val=%u\n", __FUNCTION__, inp->mode, inp->probe,
			opt_sr->req_ttl, ntohl(hopdata->val.set));
#endif /* SR_DEBUG */
		break;
	}

	if (reslen == 0)
		return;

	for (j = 0; j < srp->sr_nmax; j++) {
		sr_info = &(srp->inp_sr[j]);
		if (sr_info->mode != opt_sr->res_mode ||
				sr_info->probe != opt_sr->res_probe)
			continue;

		for (i = 0; i < reslen; i++) {
			if (opt_sr->res_ttl + i > IPSIRENS_HOPMAX)
				break;

			hopdata = &(sr_info->sr_sdata[opt_sr->res_ttl + i]);
			hopdata->tv.tv_sec = now.tv_sec;
			hopdata->tv.tv_usec = now.tv_usec;
			hopdata->val = resdata[i];
#ifdef SR_DEBUG
			if (hopdata->val.set == -1)
				continue;
			printk(KERN_DEBUG "%s: sdata: mode=%d probe=0x%x "
				"ttl=%d val=%u\n", __FUNCTION__, sr_info->mode,
				sr_info->probe, opt_sr->res_ttl+i,
				ntohl(hopdata->val.set));
#endif /* SR_DEBUG */
		}
		break;
	}
}

static void
sr_init_reqdata(struct ipopt_sr *opt_sr, struct SRSFEntry *srp)
{
	struct sr_info *inp;
	u_int qttl = srp->sr_qttl + 1;

	inp = &(srp->inp_sr[srp->sr_qnext]);
	if (qttl > (u_int) inp->qmax_ttl || qttl > IPSIRENS_HOPMAX) {
		/* over MAX TTL, goto next probe */
		srp->sr_qnext++;
		srp->sr_qnext %= srp->sr_nmax;
		inp = &(srp->inp_sr[srp->sr_qnext]);
		qttl = inp->qmin_ttl;
	}
	if (qttl < (u_int) inp->qmin_ttl) {
		/* under MIN TTL, correct start position */
		qttl = inp->qmin_ttl;
	}

	opt_sr->req_mode = inp->mode;
	opt_sr->req_probe = inp->probe;
	opt_sr->req_ttl = qttl;
	opt_sr->req_data.set = -1;
	/*
	 * if !SIRENS_DIR_IN, request data is updated at
	 * ip_sirens_post_routing().
	 */

	srp->sr_qttl = qttl;		/* update last TTL */
}

static void
sr_update_resdata(struct ipopt_sr *opt_sr, struct SRSFEntry *srp)
{
	struct sr_info *inp;
	struct sr_hopdata *hopdata;
	union u_sr_data *resdata = (union u_sr_data *)(opt_sr + 1);
	struct timeval now; 
	struct sr_timeval expire;
	u_int sttl;
	int i, reslen;

	sttl = srp->sr_sttl;
	inp = &(srp->inp_sr[srp->sr_snext]);
	if (sttl > (u_int) inp->smax_ttl || sttl > IPSIRENS_HOPMAX) {
		/* over MAX TTL, goto next probe */
		srp->sr_snext++;
		srp->sr_snext %= srp->sr_nmax;
		inp = &(srp->inp_sr[srp->sr_snext]);
		sttl = inp->smin_ttl;
	}
	if (sttl < (u_int) inp->smin_ttl) {
		/* under MIN TTL, correct start position */
		sttl = inp->smin_ttl;
	}

	opt_sr->res_mode = inp->mode;
	opt_sr->res_probe = inp->probe;
	opt_sr->res_ttl = sttl;

#if defined(__linux__)
	do_gettimeofday(&now);
#elif defined (__FreeBSD__)
	microtime(&now);
#endif /* defined(__linux__) defined(__FreeBSD__) */
	expire.tv_sec = now.tv_sec - IPSIRENS_TIMEOUT;
	expire.tv_usec = now.tv_usec;

	/* stack onto responce data */
	hopdata = &(inp->sr_qdata[sttl]);
	reslen = IPOPTLENTORESLEN(opt_sr->len);
	for (i = 0; i < reslen; i++) {
		if (i + sttl > inp->smax_ttl || i + sttl > IPSIRENS_HOPMAX) {
			resdata[i].set = -1;
		}
		else if (sr_timeval_compare(&expire,  &(hopdata[i].tv)) < 0)
			resdata[i] = hopdata[i].val;
		else
			resdata[i].set = -1;	/* invalid */
	}

	srp->sr_sttl = sttl + srp->sr_smax;	/* update last TTL */
}

static int
sr_setsockopt_srvar(
#if defined(__linux__)
	struct sock *sk, void __user *user, unsigned int len
#elif defined(__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) desined(__FreeBSD__) */
	) {
	struct if_srvarreq srreq;
	struct SRIFEntry *srp;
	struct sr_var *srvar;
	int idx, error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int len = sopt->sopt_valsize;
#endif

	if (len != sizeof(srreq))
		return -EINVAL;
#if defined(__linux__)
	if (copy_from_user(&srreq, user, (unsigned long)len))
		return -EFAULT;
#elif defined(__FreeBSD__)
	error = sooptcopyin(sopt, &srreq, len, len);
	if(error)
		return error;
#endif /* __linux__, __FreeBSD__ */

	srp = name_to_SRIFEntry(srreq.ifrname);
	if (srp == NULL)
		return -EINVAL;

	LOCK(&sr_lock, flags);

	idx = srreq.sr_probe & 0xFF;
	srvar = &(srp->storage.array[idx]);
	switch (srreq.sr_var.flag) {
	case IPSR_VAR_VALID:
		/*
		 * save value to interface storage.
		 */
		srvar->data = srreq.sr_var.data;
		srvar->flag = IPSR_VAR_VALID;
#ifdef SR_DEBUG
		DPRINT("%s: dev=[%s] arrayidx=%d (probe=0x%x) "
			"flag=%u data=%u\n", __FUNCTION__, srp->dev->name,
			idx, idx, srvar->flag, srvar->data);
#endif /* SR_DEBUG */
		error = 0;
		break;

	case IPSR_VAR_INVAL:
		srvar->flag = IPSR_VAR_INVAL;
		error = 0;
		break;

	default:
		error = -EINVAL;
		break;
	}

	UNLOCK(&sr_lock, flags);

	return error;
}

static int
sr_setsockopt_sdatax(
#if defined(__linux__)
	struct sock *sk, void __user *user, unsigned int len
#elif defined(__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) desined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	struct sr_dreq dreq;
	int error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int len = sopt->sopt_valsize;
#endif

	if (IPSIRENS_DREQSIZE(0) != len)
		return -EINVAL;
#if defined(__linux__)
	if (copy_from_user(&dreq, user, (unsigned long)len))
		return -EFAULT;
#elif defined(__FreeBSD__)
	error = sooptcopyin(sopt, &dreq, len, len);
	if(error)
		return error;
#endif /* __linux__, __FreeBSD__ */

	LOCK(&sr_lock, flags);

#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif
	if (srp == NULL || srp->sr_nmax == 0)
		error = -EINVAL;
	else {
		/*
		 * copy dreq value for later use.
		 * see getsockopt(IPSIRENS_SDATAX).
		 */
		srp->sr_dreq = dreq;
		error = 0;
	}

	UNLOCK(&sr_lock, flags);

	return error;
}

#if defined(__linux__)
/*
 * this function is deliverd from Linux kernel source.
 * see: net/ipv4/ip_sockglue.c:do_ip_setsockopt()
 */
static void
sr_set_ipoption(struct sock *sk, struct ip_options *opt)
{
	struct inet_sock *inet = inet_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (inet->is_icsk) {
		icsk = inet_csk(sk);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (sk->sk_family == PF_INET ||
			(!((1 << sk->sk_state) & (TCPF_LISTEN | TCPF_CLOSE)) &&
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
			inet->daddr != LOOPBACK4_IPV6)) {
#else
			inet->inet_daddr != LOOPBACK4_IPV6)) {
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34) */
#endif /* defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE) */
			if (inet->opt)
				icsk->icsk_ext_hdr_len -= inet->opt->optlen;
			if (opt)
				icsk->icsk_ext_hdr_len += opt->optlen;
			icsk->icsk_sync_mss(sk, icsk->icsk_pmtu_cookie);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		}
#endif
	}

	opt = xchg(&inet->opt, opt);
	kfree(opt);
}
#endif /* defined(__linux__) */
static int
sr_setsockopt_idx(
#if defined(__linux__)
struct sock *sk, void __user *user, unsigned int len
#elif defined(__FreeBSD__)
struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__), defined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	struct sr_ireq *srireq;
	struct srreq_index *sri;
	struct sr_info *sr_info;
	struct ipopt_sr *opt_sr;
	int i, optlen, alloc, error;
	unsigned long flags;
#if defined(__linux__)
	struct ip_options *opt;
#elif defined(__FreeBSD__)
	struct  inpcb *inp = sotoinpcb(so);
	struct mbuf *m;
	int len = sopt->sopt_valsize;
#endif

	if (len > IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX))
		return -EINVAL;

#if defined(__linux__)
	srireq = kmalloc(len, GFP_KERNEL);
#elif defined(__FreeBSD__)
	srireq = malloc(sizeof(struct sr_ireq), M_TEMP,M_NOWAIT);
#endif
	if (srireq == NULL)
		return -ENOMEM;

#if defined(__linux__)
	error = copy_from_user(srireq, user, (unsigned long)len);
	if (error)
		goto end;
#elif defined(__FreeBSD__)
	error = sooptcopyin(sopt, srireq, len, len);
	if(error)
		goto end;
#endif /* __linux__, __FreeBSD__ */

	if (len != IPSIRENS_IREQSIZE(srireq->sr_nindex) ||
			srireq->sr_nindex > IPSIRENS_IREQMAX || 
			srireq->sr_smax > SIRENSRESLEN) {
		error = -EINVAL;
		goto end;
	}

	sri = (struct srreq_index *)(srireq + 1);
	for (i = 0; i < srireq->sr_nindex; i++) {
		if (sri[i].qttl_min > sri[i].qttl_max ||
				sri[i].sttl_min > sri[i].sttl_max) {
			error = -EINVAL;
			goto end;
		}
	}

	optlen = IPOPTSIRENSLEN(srireq->sr_smax);
#if defined(__linux__)
	opt = kzalloc(sizeof(struct ip_options) + optlen, GFP_ATOMIC);

	if (opt == NULL) {
		error = -ENOMEM;
		goto end;
	}

	opt->optlen = optlen;
	opt_sr = (struct ipopt_sr *) opt->__data;
#elif defined(__FreeBSD__)
	if(IPOPTSIRENSLEN(srireq->sr_smax) > MLEN){
		return(EINVAL);
        }
        MGET(m, sopt->sopt_td ? M_TRYWAIT : M_DONTWAIT, MT_DATA);

	if(m == NULL){
		return(ENOMEM);
	}
	m->m_len = IPOPTSIRENSLEN(srireq->sr_smax);
	opt_sr = mtod(m, struct ipopt_sr *);
#endif
	opt_sr->type = IPOPT_SIRENS;
	opt_sr->len = optlen;

	LOCK(&sr_lock, flags);

	alloc = 0;
#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif
	if (srp == NULL) {
		if (list_empty(&sr_spool)) {
#ifdef SR_DEBUG
			printk(KERN_DEBUG "%s: no memory for socket\n",
				__FUNCTION__);
#endif /* SR_DEBUG */
			error = -ENOMEM;
#if defined(__linux__)
			kfree(opt);
#elif defined(__FreeBSD__)
			m_free(m);
#endif
			goto unlock;
		}
#if defined(__linux__)
		srp = list_first_entry(&sr_spool, struct SRSFEntry, list);
		list_del(&(srp->list));
#elif defined(__FreeBSD__)
		srp = LIST_FIRST(&sr_spool);
		LIST_REMOVE(srp, list);
#endif
		alloc = 1;
	}

	srp->sr_nmax = srireq->sr_nindex;
	srp->sr_smax = srireq->sr_smax;
	srp->sr_qnext = 0;
	srp->sr_snext = 0;
	srp->sr_qttl = 0;
	srp->sr_sttl = 0;
	for (i = 0; i < srireq->sr_nindex; i++) {
		sr_info = &(srp->inp_sr[i]);
		sr_info->mode = sri[i].mode;
		sr_info->probe = sri[i].probe;
		sr_info->qmin_ttl = sri[i].qttl_min;
		sr_info->qmax_ttl = sri[i].qttl_max;
		sr_info->smin_ttl = sri[i].sttl_min;
		sr_info->smax_ttl = sri[i].sttl_max;
	}

	if (alloc) {
#if defined(__linux__)
		srp->sk = sk;
		srp->sk_destruct = sk->sk_destruct;
		sk->sk_destruct = &sr_sk_destruct_hook;
#elif defined(__FreeBSD__)
		srp->sk = so;
#endif
#if defined(__linux__)
		list_add(&(srp->list), &sr_sactive);
#elif defined(__FreeBSD__)
		LIST_INSERT_HEAD(&sr_sactive, srp, list);
#endif
	}

	/*
	 * set SIRENS header template to socket object.
	 */
#if defined(__linux__)
	sr_set_ipoption(sk, opt);
	error = 0;
#elif defined(__FreeBSD__)
	INP_WLOCK(inp);
	error = ip_pcbopts(inp, sopt->sopt_name, m);
        INP_WUNLOCK(inp);
#endif

unlock:
	UNLOCK(&sr_lock, flags);

 end:
#if defined(__linux__)
	kfree(srireq);
#elif defined(__FreeBSD__)
	free(srireq, M_TEMP);
#endif
	return error;
}
static int
sr_getsockopt_srvar(
#if defined(__linux__)
	struct sock *sk, void __user *user, int *len
#elif defined(__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	struct SRIFEntry *srp;
	struct if_srvarreq srreq;
	struct sr_var *srvar;
	unsigned long flags;
#if defined(__FreeBSD__)
	int *len, solen;
	len = &solen;
	solen = sopt->sopt_valsize;
#endif /* defined(__FreeBSD__) */

	if (*len != sizeof(srreq))
		return -EINVAL;
#if defined (__linux__)
	if (copy_from_user(&srreq, user, (unsigned long)*len))
		return -EFAULT;
#elif defined (__FreeBSD__)
	if(sooptcopyin(sopt, &srreq, (unsigned long)*len, (unsigned long)*len))
		return -EFAULT;
#endif /* defined(__linux__) defined(__FreeBSD__) */

	srp = name_to_SRIFEntry(srreq.ifrname);
	if (srp == NULL)
		return -EINVAL;

	LOCK(&sr_lock, flags);

	/*
	 * load value from interface storage.
	 */
	srvar = &(srp->storage.array[srreq.sr_probe & 0xff]);
	srreq.sr_var.data = srvar->data;
	srreq.sr_var.flag = srvar->flag;

	UNLOCK(&sr_lock, flags);
#if defined (__linux__)
	return copy_to_user(user, &srreq, (unsigned long)*len);
#elif defined (__FreeBSD__)
	return sooptcopyout(sopt, &srreq, (unsigned long)*len);
#endif /* defined(__linux__) defined(__FreeBSD__) */
}

static int
sr_getsockopt_sdata0(struct SRSFEntry *srp, struct sr_dreq *dreq,
	union u_sr_data *sr_data)
{
	struct sr_hopdata *hopdata;
	struct sr_info *sr_info;
	struct timeval now;
	struct sr_timeval expire;
	int i, j;

	for (i = 0; i < srp->sr_nmax; i++) {
		sr_info = &(srp->inp_sr[i]);
		if (sr_info->mode != dreq->mode || sr_info->probe != dreq->probe)
			continue;
#if defined(__linux__)
		do_gettimeofday(&now);
#elif defined (__FreeBSD__)
		microtime(&now);
#endif /* defined(__linux__) defined(__FreeBSD__) */
		expire.tv_sec = now.tv_sec - IPSIRENS_TIMEOUT;
		expire.tv_usec = now.tv_usec;

		switch (dreq->dir) {
		case 1:
			hopdata = sr_info->sr_qdata;	/* use request data */
			break;
		case 2:
		default:
			hopdata = sr_info->sr_sdata;	/* use response data */
			break;
		}
		for (j = 0; j < IPSIRENS_HOPNUM; j++) {
			if (sr_timeval_compare(&expire, &(hopdata[j].tv)) < 0)
				sr_data[j] = hopdata[j].val;
			else
				sr_data[j].set = -1;	/* invalid */
		}

		return 0;
	}
	return -EINVAL;
}

static int
sr_getsockopt_stdata0(struct SRSFEntry *srp, struct sr_dreq *dreq,
	struct sr_hopdata *sr_datat)
{
	struct sr_hopdata *hopdata;
	struct sr_info *sr_info;
	int i;

	for (i = 0; i < srp->sr_nmax; i++) {
		sr_info = &(srp->inp_sr[i]);
		if (sr_info->mode != dreq->mode || sr_info->probe != dreq->probe)
			continue;

		switch (dreq->dir) {
		case 1:
			hopdata = sr_info->sr_qdata;	/* use request data */
			break;
		case 2:
		default:
			hopdata = sr_info->sr_sdata;	/* use response data */
			break;
		}
		memcpy(sr_datat, hopdata, IPSIRENS_HOPNUM * sizeof(struct sr_hopdata));
/*
		for (j = 0; j < IPSIRENS_HOPNUM; j++) {
			sr_datat[j].val = hopdata[j].val;
			sr_datat[j].tv = hopdata[j].tv;
		}
*/
		return 0;
	}
	return -EINVAL;
}

static int
sr_getsockopt_stdatax(
#if defined(__linux__)
	struct sock *sk, void __user *user, int *len
#elif defined (__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	struct sr_hopdata *hopdata;
	int error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int *len, lenc = sopt->sopt_valsize;
	len = &lenc;
#endif

	if (*len != IPSIRENS_HOPNUM * sizeof (struct sr_hopdata))
		return -EINVAL;

#if defined(__linux__)
	hopdata = kmalloc(*len, GFP_KERNEL);
#elif defined(__FreeBSD__)
	hopdata = malloc(*len, M_TEMP,M_NOWAIT);
#endif
	if (hopdata == NULL)
		return -ENOMEM;

	LOCK(&sr_lock, flags);

#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif
	if (srp == NULL)
		error = -EINVAL;
	else
		error = sr_getsockopt_stdata0(srp, &(srp->sr_dreq), hopdata);

	UNLOCK(&sr_lock, flags);

	if (error == 0)
#if defined (__linux__)
		error = copy_to_user(user, hopdata, (unsigned long)*len);
#elif defined (__FreeBSD__)
		error = sooptcopyout(sopt, hopdata, *len);
#endif /* defined(__linux__) defined(__FreeBSD__) */

#if defined(__linux__)
	kfree(hopdata);
#elif defined(__FreeBSD__)
	free(hopdata, M_TEMP);
#endif
	return error;
}

static int
sr_getsockopt_sdatax(
#if defined(__linux__)
	struct sock *sk, void __user *user, int *len
#elif defined (__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	union u_sr_data *sr_data;
	int error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int *len, lenc = sopt->sopt_valsize;
	len = &lenc;
#endif

	if (*len != IPSIRENS_HOPNUM * sizeof (union u_sr_data))
		return -EINVAL;

#if defined(__linux__)
	sr_data = kmalloc(*len, GFP_KERNEL);
#elif defined(__FreeBSD__)
	sr_data = malloc(*len, M_TEMP,M_NOWAIT);
#endif

	if (sr_data == NULL)
		return -ENOMEM;

	LOCK(&sr_lock, flags);

#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif

	if (srp == NULL)
		error = -EINVAL;
	else
		error = sr_getsockopt_sdata0(srp, &(srp->sr_dreq), sr_data);

	UNLOCK(&sr_lock, flags);

	if (error == 0)
#if defined (__linux__)
		error = copy_to_user(user, sr_data, (unsigned long)*len);
#elif defined (__FreeBSD__)
		error = sooptcopyout(sopt, sr_data, *len);
#endif /* defined(__linux__) defined(__FreeBSD__) */

#if defined(__linux__)
	kfree(sr_data);
#elif defined(__FreeBSD__)
	free(sr_data, M_TEMP);
#endif
	return error;
}

static int
sr_getsockopt_stdata(
#if defined(__linux__)
	struct sock *sk, void __user *user, int *len
#elif defined (__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	struct sr_dreq *dreqp;
	struct sr_hopdata *hopdata;
	int error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int *len, lenc = sopt->sopt_valsize;
	len = &lenc;
#endif

	if (*len != IPSIRENS_DTREQSIZE(IPSIRENS_HOPNUM))
		return -EINVAL;

#if defined(__linux__)
	dreqp = kmalloc(*len, GFP_KERNEL);
#elif defined(__FreeBSD__)
	dreqp = malloc(*len, M_TEMP,M_NOWAIT);
#endif
	if (dreqp == NULL)
		return -ENOMEM;

#if defined(__linux__)
	error = copy_from_user(dreqp, user, (unsigned long)*len);
#elif defined(__FreeBSD__)
	error = sooptcopyin(sopt, dreqp, *len, *len);
#endif /* __linux__, __FreeBSD__ */
	if (error)
		goto end;

	LOCK(&sr_lock, flags);

#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif
	if (srp == NULL) {
		/*
		 * this socket seems to be not tracked.
		 */
		dreqp->dir = 255;
		dreqp->mode = 255;
		dreqp->probe = 255;
		dreqp->dummy = 0;
		*len = IPSIRENS_DREQSIZE(0);
		error = 0;
	}
	else {
		hopdata = (struct sr_hopdata *)(dreqp + 1);
		error = sr_getsockopt_stdata0(srp, dreqp, hopdata);
	}

	UNLOCK(&sr_lock, flags);

	if (error == 0)
#if defined (__linux__)
		error = copy_to_user(user, dreqp, (unsigned long)*len);
#elif defined (__FreeBSD__)
		error = sooptcopyout(sopt, dreqp, *len);
#endif /* defined(__linux__) defined(__FreeBSD__) */

 end:
#if defined(__linux__)
	kfree(dreqp);
#elif defined(__FreeBSD__)
	free(dreqp, M_TEMP);
#endif
	return error;
}

static int
sr_getsockopt_sdata(
#if defined(__linux__)
	struct sock *sk, void __user *user, int *len
#elif defined (__FreeBSD__)
	struct socket *so, struct sockopt *sopt
#endif /* defined(__linux__) defined(__FreeBSD__) */
)
{
	struct SRSFEntry *srp;
	struct sr_dreq *dreqp;
	union u_sr_data *sr_data;
	int error;
	unsigned long flags;
#if defined(__FreeBSD__)
	int *len, lenc = sopt->sopt_valsize;
	len = &lenc;
#endif

	if (*len != IPSIRENS_DREQSIZE(IPSIRENS_HOPNUM))
		return -EINVAL;

#if defined(__linux__)
	dreqp = kmalloc(*len, GFP_KERNEL);
#elif defined(__FreeBSD__)
	dreqp = malloc(*len, M_TEMP,M_NOWAIT);
#endif
	if (dreqp == NULL)
		return -ENOMEM;

#if defined(__linux__)
	error = copy_from_user(dreqp, user, (unsigned long)*len);
#elif defined(__FreeBSD__)
	error = sooptcopyin(sopt, dreqp, *len, *len);
#endif /* __linux__, __FreeBSD__ */
	if (error)
		goto end;

	LOCK(&sr_lock, flags);

#if defined(__linux__)
	srp = sock_to_SRSFEntry(sk);
#elif defined(__FreeBSD__)
	srp = sock_to_SRSFEntry(so);
#endif
	if (srp == NULL) {
		/*
		 * this socket seems to be not tracked.
		 */
		dreqp->dir = 255;
		dreqp->mode = 255;
		dreqp->probe = 255;
		dreqp->dummy = 0;
		*len = IPSIRENS_DREQSIZE(0);
		error = 0;
	}
	else {
		sr_data = (union u_sr_data *)(dreqp + 1);
		error = sr_getsockopt_sdata0(srp, dreqp, sr_data);
	}

	UNLOCK(&sr_lock, flags);

	if (error == 0)
#if defined (__linux__)
		error = copy_to_user(user, dreqp, (unsigned long)*len);
#elif defined (__FreeBSD__)
		error = sooptcopyout(sopt, dreqp, *len);
#endif /* defined(__linux__) defined(__FreeBSD__) */

 end:
#if defined(__linux__)
	kfree(dreqp);
#elif defined(__FreeBSD__)
	free(dreqp, M_TEMP);
#endif
	return error;
}

#if defined(__linux__)
static unsigned int
ip_sirens_pre_routing(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	struct ipopt_sr *opt_sr;
	int len, save_header = 0;

	if (ip_hdrlen(skb) == sizeof (struct iphdr))
		return NF_ACCEPT;

	opt_sr = sr_find_sirens(skb);
	if (opt_sr == NULL)
		return NF_ACCEPT;

	len = ip_hdrlen(skb) + sizeof (struct icmphdr);
	if (iph->protocol == IPPROTO_ICMP && pskb_may_pull(skb, len)) {
		struct icmphdr *icmph = (struct icmphdr *)
				(skb_network_header(skb) + ip_hdrlen(skb));
		if (icmph->type == ICMP_ECHO)
			save_header = 1;
	}

	if((opt_sr->req_probe & SIRENS_DIR_IN) != 0){
		switch(opt_sr->req_mode){
			case SIRENS_TTL:
				if(ip->ip_ttl != opt_sr->req_ttl) break;
			case SIRENS_MAX:
			case SIRENS_MIN:
			case SIRENS_LE:
			case SIRENS_EQ:
			case SIRENS_GE:
			default:
				sr_update_reqdata(opt_sr, (struct net_device *)in);
				iph->check = 0;
				iph->check = ip_fast_csum(iph, iph->ihl);
				break;
		}
	}

	if (save_header) {
		/*
		 * remember SIRENS header for later use.
		 * see: ip_sirens_post_routing().
		 */
		sr_push_sirens(iph, opt_sr, (struct net_device *)in);
	}

	return NF_ACCEPT;
}
#endif /* defined(__linux__) */
#if defined(__FreeBSD__)
#define NF_ACCEPT 0
#endif

static unsigned int
ip_sirens_local_in(
#if defined(__linux__)
	unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *)
#elif defined(__FreeBSD__)
	void *arg, struct mbuf **m, struct ifnet *ifp, int dir, struct inpcb *inp
#endif
)
{
#if defined(__linux__)
	struct iphdr *iph;
	struct sock *sk, *lsk;
	struct ip_options *opt;
	int i;
	struct SRSFEntry *lsrp;
	struct sr_info *sr_info, *lsr_info;
	unsigned long flags;
#elif defined(__FreeBSD__)
	struct ip *ip;
	struct socket *sk, *lsk;
	struct tcpcb *tp;
	struct inpcb *sinp;
	int icmp = 0;
	struct m_tag *mtag;
	struct ipopt_sr *tag_sr;
#endif
	struct SRSFEntry *srp = NULL;
	struct ipopt_sr *opt_sr;
	struct tcphdr *th;
	int len;

#if defined(__linux__)
	iph = ip_hdr(skb);
	if (ip_hdrlen(skb) == sizeof (struct iphdr))
		return NF_ACCEPT;
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	opt_sr = sr_find_sirens(skb);
#elif defined(__FreeBSD__)
	ip = mtod(*m, struct ip*);
	if(ip->ip_hl == sizeof(struct ip))
		return NF_ACCEPT;

	switch(ip->ip_p) {
	case IPPROTO_ICMP:
		icmp = 1;
		break;
	case IPPROTO_TCP:
		break;
	default:
		return NF_ACCEPT;
	}

	opt_sr = sr_find_sirens(*m);
#endif
	if (opt_sr == NULL)
		return NF_ACCEPT;

#if defined(__linux__)
	len = ip_hdrlen(skb) + sizeof (struct tcphdr);
	if (! pskb_may_pull(skb, len))
		return NF_ACCEPT;
#elif defined(__FreeBSD__)
	len = ip->ip_hl * 4 + sizeof (struct tcphdr);
	*m = m_pullup(*m, len);
	ip = mtod(*m, struct ip*);
#endif

#if defined(__FreeBSD__)
	if(icmp){
		union u_sr_data *res_data;
		mtag = m_tag_locate(*m, MTAG_SIRENS, MTAG_SIRENS_OPTION, NULL);
		if(mtag != NULL)
			return NF_ACCEPT;
		mtag = m_tag_alloc(MTAG_SIRENS, MTAG_SIRENS_OPTION, opt_sr->len, M_NOWAIT);
		if(mtag == NULL)
			return NF_ACCEPT;
		tag_sr = (struct ipopt_sr *)(mtag + 1);
		res_data = (union u_sr_data *)(tag_sr + 1);

		bcopy(opt_sr, tag_sr, opt_sr->len);

		tag_sr->len = IPOPTSIRENSLEN(1);
		switch(tag_sr->req_mode){
			case SIRENS_TTL:
			case SIRENS_MAX:
			case SIRENS_MIN:
				tag_sr->res_ttl = tag_sr->req_ttl;
				tag_sr->res_probe = tag_sr->req_probe;
				tag_sr->res_mode = tag_sr->req_mode;
				res_data->set = tag_sr->req_data.set;
				tag_sr->req_data.set = 0xffffffff;
				break;
			default:
				break;
		}

		m_tag_prepend(*m, mtag);
		return NF_ACCEPT;
	}
#endif

	sk = lsk = NULL;
	/*
	 * lookup socket object from TCP source and destination port.
	 */
#if defined(__linux__)
	th = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
#elif defined(__FreeBSD__)
	th = (struct tcphdr *)((caddr_t)ip + ip->ip_hl * 4);
#endif
#if defined(__linux__)
	sk = inet_lookup(dev_net(in), &tcp_hashinfo, iph->saddr,
			th->source, iph->daddr, th->dest, inet_iif(skb));
	if (sk == NULL) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: socket not found\n", __FUNCTION__);
#endif /* SR_DEBUG */
		return NF_ACCEPT;
	}
	if (sk->sk_state != TCP_ESTABLISHED)
		goto end;
#elif defined(__FreeBSD__)
#if 0
	{
		struct inpcbhead *head;
		register struct inpcb *inp;
		head = &(&V_tcbinfo)->ipi_hashbase[INP_PCBHASH(ip->ip_src.s_addr, th->th_dport, th->th_sport, (&V_tcbinfo)->ipi_hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			DPRINT("local_in %02x %08x %08x %08x %08x: ",
				ip->ip_p, ntohl(ip->ip_src.s_addr), ntohl(ip->ip_dst.s_addr),
				ntohl(inp->inp_faddr.s_addr), ntohl(inp->inp_laddr.s_addr));
			DPRINT("local_in %d %d %d %d\n", ntohs(th->th_sport), ntohs(th->th_dport),
				ntohs(inp->inp_fport), ntohs(inp->inp_lport));
		}
	}
#endif
#if __FreeBSD_version < 900000
        sinp = in_pcblookup_hash(&V_tcbinfo,
                        ip->ip_src, th->th_sport,
                        ip->ip_dst, th->th_dport,
                        0,
                        NULL);
#else
        sinp = in_pcblookup(&V_tcbinfo,
                        ip->ip_src, th->th_sport,
                        ip->ip_dst, th->th_dport,
                        INPLOOKUP_RLOCKPCB,
                        NULL);
#endif
	if(sinp != NULL){
		tp = intotcpcb(sinp);
		sk = sinp->inp_socket;
#if !(__FreeBSD_version < 900000)
        	INP_RLOCK_ASSERT(sinp);
        	INP_RUNLOCK(sinp);
#endif
	}
#endif /* __FreeBSD__ */

	/*
	 * lookup server socket object from TCP destination port.
	 */
#if defined(__linux__)
	local_bh_disable();
	lsk = inet_lookup_listener(dev_net(in), &tcp_hashinfo, iph->daddr,
			th->dest, inet_iif(skb));
	local_bh_enable();

	LOCK(&sr_lock, flags);
#endif

	/*
	 * if we have tracking data refer to this connection,
	 * gather SIRENS data.
	 */
	if(sk){
		srp = sock_to_SRSFEntry(sk);
		if (srp) {
			if (srp->sr_nmax > 0)
				sr_gather_data(opt_sr, srp);
			goto unlock;
		}
	}

#if defined(__linux__)
	/*
	 * else this seems to be newly established connection,
	 * prepare tracking data for this connection.
	 */
	if (lsk) {
		lsrp = sock_to_SRSFEntry(lsk);
		if (lsrp == NULL)
			goto unlock;
	}
	else {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: server socket not found\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		goto unlock;
	}

	len = IPOPTSIRENSLEN(lsrp->sr_smax);
	opt = kzalloc(sizeof(struct ip_options) + len, GFP_ATOMIC);
	opt->optlen = len;
	opt_sr = (struct ipopt_sr *) opt->__data;
	if (opt == NULL) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: no memory for connected socket\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		goto unlock;
	}

	opt_sr->type = IPOPT_SIRENS;
	opt_sr->len = len;

	if (list_empty(&sr_spool)) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: no memory for connected socket\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		kfree(opt);
		goto unlock;
	}
	srp = list_first_entry(&sr_spool, struct SRSFEntry, list);
	list_del(&(srp->list));

	srp->sr_nmax = lsrp->sr_nmax;
	srp->sr_smax = lsrp->sr_smax;
	srp->sr_qnext = 0;
	srp->sr_snext = 0;
	srp->sr_qttl = 0;
	for (i = 0 ; i < srp->sr_nmax ; i++) {
		sr_info = &(srp->inp_sr[i]);
		lsr_info = &(lsrp->inp_sr[i]);
		sr_info->mode = lsr_info->mode;
		sr_info->probe = lsr_info->probe;
		sr_info->qmin_ttl = lsr_info->qmin_ttl;
		sr_info->qmax_ttl = lsr_info->qmax_ttl;
		sr_info->smin_ttl = lsr_info->smin_ttl;
		sr_info->smax_ttl = lsr_info->smax_ttl;
	}

	/*
	 * sk_destruct of connected socket is copy of that of
	 * server socket. so this may be sr_sk_destruct_hook.
	 * instead, we use backup in server's SRSFEntry
	 */
	srp->sk = sk;
	if (sk->sk_destruct == &sr_sk_destruct_hook)
		srp->sk_destruct = lsrp->sk_destruct;
	else
		srp->sk_destruct = sk->sk_destruct;
	sk->sk_destruct = &sr_sk_destruct_hook;
	list_add(&(srp->list), &sr_sactive);

	/*
	 * set SIRENS header template to socket object.
	 */
	sr_set_ipoption(sk, opt);
#endif /* defined(__linux__) */
 unlock:
#if defined(__linux__)
	UNLOCK(&sr_lock, flags);
	if (lsk)
		__sock_put(lsk);
#endif

#if defined(__linux__)
 end:
	__sock_put(sk);
#endif
	return NF_ACCEPT;
}

#if defined(__linux__)
static unsigned int
ip_sirens_local_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct SRSFEntry *srp;
	struct iphdr *iph = ip_hdr(skb);
	struct ipopt_sr *opt_sr;
	struct sock *sk = skb->sk;
	unsigned long flags;

	if (ip_hdrlen(skb) == sizeof (struct iphdr))
		return NF_ACCEPT;
	if (iph->protocol != IPPROTO_TCP ||
			sk == NULL || sk->sk_state != TCP_ESTABLISHED)
		return NF_ACCEPT;

	opt_sr = sr_find_sirens(skb);
	if (opt_sr == NULL)
		return NF_ACCEPT;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
	if (srp == NULL || srp->sr_nmax == 0)
		goto unlock;

	/*
	 * init SIRENS request data and update SIRENS response data
	 * if !SIRENS_DIR_IN, request data is updated at
	 * ip_sirens_post_routing().
	 */
	sr_init_reqdata(opt_sr, srp);
	sr_update_resdata(opt_sr, srp);

	iph->check = 0;
	iph->check = ip_fast_csum(iph, iph->ihl);

 unlock:
	spin_unlock_irqrestore(&sr_lock, flags);

	return NF_ACCEPT;
}

static unsigned int
ip_sirens_post_routing(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	struct ipopt_sr *opt_sr;
	int len;

	opt_sr = sr_find_sirens(skb);
	if (opt_sr == NULL) {
		/*
		 * ICMP echo reply support.
		 * Linux seems to drop unknown IP options from ICMP echo
		 * request, so we insert SIRENS header manually.
		 */
		struct icmphdr *icmph;

		if (iph->protocol != IPPROTO_ICMP)
			return NF_ACCEPT;
		len = ip_hdrlen(skb) + sizeof (struct icmphdr);
		if (! pskb_may_pull(skb, len))
			return NF_ACCEPT;

		icmph = (struct icmphdr *)
				(skb_network_header(skb) + ip_hdrlen(skb));
		if (icmph->type != ICMP_ECHOREPLY)
			return NF_ACCEPT;

		opt_sr = sr_pop_sirens(iph, skb, (struct net_device *)out);
		if (opt_sr == NULL)
			return NF_ACCEPT;

		iph = ip_hdr(skb);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);

		/*
		 * SIRENS header is already completed in sr_push_sirens,
		 * so we simply return.
		 */
		return NF_ACCEPT;
	}
	/* opt_sr != NULL */

	if((opt_sr->req_probe & SIRENS_DIR_IN) == 0){
		switch(opt_sr->req_mode){
			case SIRENS_TTL:
				if(ip->ip_ttl != opt_sr->req_ttl) break;
			case SIRENS_MAX:
			case SIRENS_MIN:
			case SIRENS_LE:
			case SIRENS_EQ:
			case SIRENS_GE:
			default:
				sr_update_reqdata(opt_sr, (struct net_device *)out);
				iph->check = 0;
				iph->check = ip_fast_csum(iph, iph->ihl);
				break;
		}
	}

	return NF_ACCEPT;
}
#endif /* defined(__linux__) */

static int
ip_sirens_setsockopt(
#if defined(__linux__)
struct sock *sk, int cmd, void __user *user, unsigned int len
#elif defined(__FreeBSD__)
struct socket *so, struct sockopt *sopt
#endif
)
{
	int ret;
#if defined(__FreeBSD__)
	int cmd = sopt->sopt_name;
#endif

#if 0		/* FIX ME: do we need capability check ? */
	if (! capable(CAP_NET_ADMIN))
		return -EPERM;
#endif

	switch (cmd) {
	case IPSIRENS_SRVAR:
#if defined(__linux__)
		ret = sr_setsockopt_srvar(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_setsockopt_srvar(so, sopt);
#endif
		break;
	case IPSIRENS_SDATAX:
	case IPSIRENS_STDATAX:
#if defined(__linux__)
		ret = sr_setsockopt_sdatax(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_setsockopt_sdatax(so, sopt);
#endif
		break;
	case IPSIRENS_IDX:
#if defined(__linux__)
		ret = sr_setsockopt_idx(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_setsockopt_idx(so, sopt);
#endif
		break;
	case IPSIRENS_SDATA:
	case IPSIRENS_STDATA:
		ret = -EINVAL;
		break;
	case IPSIRENS_ADATA:		/* fall down */
	default:
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: unknown request: %d\n", __FUNCTION__,
			cmd);
#endif /* SR_DEBUG */
		ret = -EINVAL;
		break;
	}
	return ret;
}

static int
ip_sirens_getsockopt(
#if defined(__linux__)
struct sock *sk, int cmd, void __user *user, int *len
#elif defined(__FreeBSD__)
struct socket *so, struct sockopt *sopt
#endif
)
{
	int ret;
#if defined(__FreeBSD__)
	int cmd = sopt->sopt_name;
#endif

#if 0		/* FIX ME: do we need capability check ? */
	if (! capable(CAP_NET_ADMIN))
		return -EPERM;
#endif

	switch (cmd) {
	case IPSIRENS_SRVAR:
#if defined(__linux__)
		ret = sr_getsockopt_srvar(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_getsockopt_srvar(so, sopt);
#endif
		break;
	case IPSIRENS_SDATAX:
#if defined(__linux__)
		ret = sr_getsockopt_sdatax(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_getsockopt_sdatax(so, sopt);
#endif
		break;
	case IPSIRENS_STDATAX:
#if defined(__linux__)
		ret = sr_getsockopt_stdatax(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_getsockopt_stdatax(so, sopt);
#endif
		break;
	case IPSIRENS_IDX:
		ret = -EINVAL;
		break;
	case IPSIRENS_SDATA:
#if defined(__linux__)
		ret = sr_getsockopt_sdata(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_getsockopt_sdata(so, sopt);
#endif
		break;
	case IPSIRENS_STDATA:
#if defined(__linux__)
		ret = sr_getsockopt_stdata(sk, user, len);
#elif defined(__FreeBSD__)
		ret = sr_getsockopt_stdata(so, sopt);
#endif
		break;
	case IPSIRENS_ADATA:	/* fall down */
	default:
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: unknown request: %d\n", __FUNCTION__,
			cmd);
#endif /* SR_DEBUG */
		ret = -EINVAL;
		break;
	}

	return ret;
}
#if defined(__linux__)

static struct nf_hook_ops ip_sirens_hooks[] __read_mostly = {
	{
		.hook = &ip_sirens_pre_routing,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = &ip_sirens_local_in,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = &ip_sirens_local_out,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FILTER,
	},
	{
		.hook = &ip_sirens_post_routing,
		.owner = THIS_MODULE,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_FILTER,
	},
};

static struct nf_sockopt_ops ip_sirens_sockopt __read_mostly = {
	.pf = PF_INET,
	.set_optmin = IPSIRENS_OPTMIN,
	.set_optmax = IPSIRENS_OPTMAX,
	.set = &ip_sirens_setsockopt,
	.get_optmin = IPSIRENS_OPTMIN,
	.get_optmax = IPSIRENS_OPTMAX,
	.get = &ip_sirens_getsockopt,
	.owner = THIS_MODULE,
};

static int __init
ip_sirens_init(void)
{
	struct net_device *dev;
	struct SRSFEntry *srsp;
	struct SRIFEntry *srip;
	struct ICMPEntry *icmp;
	int nhooks = sizeof(ip_sirens_hooks) / sizeof(ip_sirens_hooks[0]);
	int i, error = 0;

	/* allocate TCP socket tracking storage */
	for (i = 0; i < sr_max_sk; i++) {
		srsp = kzalloc(sizeof (struct SRSFEntry), GFP_KERNEL);
		if (srsp == NULL) {
			error = -ENOMEM;
			goto err0;
		}
		list_add(&(srsp->list), &sr_spool);
	}
	/* allocate ICMP echo tracking storage */
	for (i = 0; i < sr_max_icmp; i++) {
		icmp = kzalloc(sizeof (struct ICMPEntry), GFP_KERNEL);
		if (icmp == NULL) {
			error = -ENOMEM;
			goto err0;
		}
		list_add(&(icmp->list), &sr_icmppool);
	}

	/* allocate network interface tracking storage */
	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, dev) {
		srip = kzalloc(sizeof (struct SRIFEntry), GFP_KERNEL);
		if (srip == NULL) {
			error = -ENOMEM;
			break;
		}
		dev_hold(dev);
		srip->dev = dev;
		INIT_LIST_HEAD(&(srip->icmp));
		list_add(&(srip->list), &sr_iflist);
	}
	read_unlock(&dev_base_lock);
	if (error)
		goto err0;

	error = nf_register_hooks(ip_sirens_hooks, nhooks);
	if (error)
		goto err0;

	error = nf_register_sockopt(&ip_sirens_sockopt);
	if (error)
		goto err1;

	printk(KERN_INFO "ip_sirens: (C) 2010 National Institute of "
		"Advanced Industrial Science and Technology (AIST)\n");
	printk(KERN_INFO "ip_sirens: version: %s\n", SIRENS_VERSION);
	printk(KERN_INFO "ip_sirens: Maximum number of tracking TCP sockets: "
		"%d\n", sr_max_sk);
	printk(KERN_INFO "ip_sirens: Maximum number of tracking ICMP echo: "
		"%d\n", sr_max_icmp);
	printk(KERN_INFO "ip_sirens: SIRENS backword probe on ICMP: %s\n",
		(sr_icmp_sirens_res ? "enabled" : "disabled"));
	return 0;

 err1:
	nf_unregister_hooks(ip_sirens_hooks, nhooks);
 err0:
	while (! list_empty(&sr_iflist)) {
		srip = list_first_entry(&sr_iflist, struct SRIFEntry, list);
		list_del(&(srip->list));
		dev_put(srip->dev);
		kfree(srip);
	}
	while (! list_empty(&sr_spool)) {
		srsp = list_first_entry(&sr_spool, struct SRSFEntry, list);
		list_del(&(srsp->list));
		kfree(srsp);
	}
	while (! list_empty(&sr_icmppool)) {
		icmp = list_first_entry(&sr_icmppool, struct ICMPEntry, list);
		list_del(&(icmp->list));
		kfree(icmp);
	}
	return error;
}

static void __exit
ip_sirens_exit(void)
{
	struct SRSFEntry *srsp;
	struct SRIFEntry *srip;
	struct ICMPEntry *icmp;
	int nhooks = sizeof(ip_sirens_hooks) / sizeof(ip_sirens_hooks[0]);

	nf_unregister_sockopt(&ip_sirens_sockopt);
	nf_unregister_hooks(ip_sirens_hooks, nhooks);

	/* Now, nonody refered spool, sactive, iflist. */

	while (! list_empty(&sr_iflist)) {
		srip = list_first_entry(&sr_iflist, struct SRIFEntry, list);
		list_del(&(srip->list));
		dev_put(srip->dev);

		while (! list_empty(&(srip->icmp))) {
			icmp = list_first_entry(&(srip->icmp),
						struct ICMPEntry, list);
			list_del(&(icmp->list));
			kfree(icmp);
		}
		kfree(srip);
	}
	while (! list_empty(&sr_sactive)) {
		srsp = list_first_entry(&sr_sactive, struct SRSFEntry, list);
		list_del(&(srsp->list));

		if (srsp->sk)
			srsp->sk->sk_destruct = srsp->sk_destruct;
		kfree(srsp);
	}
	while (! list_empty(&sr_spool)) {
		srsp = list_first_entry(&sr_spool, struct SRSFEntry, list);
		list_del(&(srsp->list));
		kfree(srsp);
	}
	while (! list_empty(&sr_icmppool)) {
		icmp = list_first_entry(&sr_icmppool, struct ICMPEntry, list);
		list_del(&(icmp->list));
		kfree(icmp);
	}
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SIRENS for Linux. http://i-path.goto.info.waseda.ac.jp/trac/i-Path");
MODULE_VERSION(SIRENS_VERSION);

module_param(sr_max_sk, int, 0444);
MODULE_PARM_DESC(sr_max_sk, "Maximum number of tracking TCP socket");

module_param(sr_max_icmp, int, 0444);
MODULE_PARM_DESC(sr_max_icmp, "Maximum number of tracking ICMP echo");

module_param(sr_icmp_sirens_res, int, 0444);
MODULE_PARM_DESC(sr_icmp_sirens_res, "Enable SIRENS backword probe on ICMP");

module_init(ip_sirens_init);
module_exit(ip_sirens_exit);
#endif /* defined(__linux__) */

#if defined(__FreeBSD__)

static volatile int ip_sirens_hooked = 0;

extern  struct protosw inetsw[];
static struct protosw ip_sw[IPPROTO_MAX];

static struct pr_usrreqs o_tcp_usrreqs[IPPROTO_MAX];

static int ip_sirens_init(void *);
static int ip_sirens_deinit(void *);

static int rip_ctlout_hook(struct socket *, struct sockopt *);
static int tcp_ctlout_hook(struct socket *, struct sockopt *);
static int udp_ctlout_hook(struct socket *, struct sockopt *);
static void tcp_usr_detach_hook(struct socket *);
static int tcp_usr_connect_hook(struct socket *, struct sockaddr *, struct thread *);
static int tcp_usr_accept_hook(struct socket *, struct sockaddr **);
static int tcp_usr_listen_hook(struct socket *, int, struct thread *);

static int pf_sirens_input(void *, struct mbuf **, struct ifnet *, int, struct inpcb *);
static int pf_sirens_output(void *, struct mbuf **, struct ifnet *, int, struct inpcb *);

#define EPFDROP 1

static int pf_sirens_input(void *arg, struct mbuf **m, struct ifnet *ifp, int dir, struct inpcb *inp)
{
	struct ip *ip;
	struct ipopt_sr *opt_sr = NULL;

	M_ASSERTVALID(*m);
	M_ASSERTPKTHDR(*m);

	if((*m)->m_pkthdr.len < sizeof(struct ip))
		return 0;

	if((*m)->m_len < sizeof(struct ip) &&
	   (*m = m_pullup(*m, sizeof(struct ip) + sizeof(struct ipopt_sr))) == NULL)
		return 0;

	ip = mtod(*m, struct ip *);

/* find SIRENS option. */
	if((opt_sr = sr_find_sirens( *m)) == NULL)
		return 0;

/* Update SIRENS option, if needed */
	if((opt_sr->req_probe & SIRENS_DIR_IN) != 0){
		switch(opt_sr->req_mode){
			case SIRENS_TTL:
				if(ip->ip_ttl != opt_sr->req_ttl) break;
			case SIRENS_MAX:
			case SIRENS_MIN:
			case SIRENS_LE:
			case SIRENS_EQ:
			case SIRENS_GE:
			default:
				sr_update_reqdata(opt_sr, ifp);
				break;
		}
	}

/* check local destination. */
	if (in_localip(ip->ip_dst)) {
		ip_sirens_local_in(arg, m, ifp, dir, inp);
	}
	return 0;
}
static int pf_sirens_output(void *arg, struct mbuf **m, struct ifnet *ifp, int dir, struct inpcb *inp)
{
	struct ip *iph;
	struct ipopt_sr *opt_sr = NULL;
	struct ipopt_sr *tag_sr = NULL;
	struct SRSFEntry *srp = NULL;
	struct m_tag *mtag = NULL;

	M_ASSERTVALID(*m);
	M_ASSERTPKTHDR(*m);

	if((*m)->m_pkthdr.len < sizeof(struct ip))
		return 0;

	if((*m)->m_len < sizeof(struct ip) &&
	   (*m = m_pullup(*m, sizeof(struct ip) + sizeof(struct ipopt_sr))) == NULL){
		return 0;
	}
	iph = mtod(*m, struct ip *);
	if(iph->ip_p == IPPROTO_ICMP)
		mtag = m_tag_locate(*m, MTAG_SIRENS, MTAG_SIRENS_OPTION, NULL);

	if((opt_sr = sr_find_sirens( *m)) == NULL
		&& mtag == NULL)
		return 0;

	if(mtag && opt_sr == NULL && (iph->ip_hl << 2) == sizeof(struct ip)){
		char buffer [sizeof(struct ip) + MAXIPOPTSIRENSLEN];
		m_tag_unlink(*m, mtag);
		tag_sr = (struct ipopt_sr *)(mtag + 1);
		m_copydata(*m, 0, iph->ip_hl << 2, buffer);
		iph = (struct ip*)buffer;
		bcopy(tag_sr, buffer + (iph->ip_hl << 2), tag_sr->len);

		M_PREPEND(*m, tag_sr->len, M_DONTWAIT);
		if(*m == NULL){
			m_tag_free(mtag);
			return ENOMEM;
		}
/* fail-safe */
	   	if((*m = m_pullup(*m, sizeof(struct ip) + tag_sr->len)) == NULL){
			m_tag_free(mtag);
			return ENOMEM;
		}

		m_copyback(*m, 0, (iph->ip_hl << 2) + tag_sr->len, buffer);

		iph = mtod(*m, struct ip *);
		iph->ip_sum = 0;
#if 0
		{
			int i;
			uint16_t *sd;
			sd = mtod(*m, uint16_t*);
			for(i = 0 ; i < 32 ; i++){
				printf("%04x ", ntohs(sd[i]));
				if( i %8 == 7) printf("\n");
			}
			printf("\n");
		}
#endif

		iph->ip_hl = iph->ip_hl + (tag_sr->len >> 2);
		iph->ip_len = iph->ip_len + tag_sr->len;

		iph->ip_len = htons(iph->ip_len);
	        iph->ip_off = htons(iph->ip_off);

		iph->ip_sum = in_cksum(*m, iph->ip_hl << 2);

		iph->ip_len = ntohs(iph->ip_len);
	        iph->ip_off = ntohs(iph->ip_off);

		m_tag_free(mtag);
		opt_sr = sr_find_sirens( *m);
		if(opt_sr == NULL)
			return EINVAL;
	}

/* Update SIRENS option, if needed */
	if(inp){
		srp = sock_to_SRSFEntry(inp->inp_socket);
	}

	if(srp){
		sr_init_reqdata(opt_sr, srp);
		sr_update_resdata(opt_sr, srp);
	}

/* Update SIRENS option, if needed */
	if((opt_sr->req_probe & SIRENS_DIR_IN) == 0){
		switch(opt_sr->req_mode){
			case SIRENS_TTL:
				if(iph->ip_ttl != opt_sr->req_ttl) break;
			case SIRENS_MAX:
			case SIRENS_MIN:
			case SIRENS_LE:
			case SIRENS_EQ:
			case SIRENS_GE:
			default:
				sr_update_reqdata(opt_sr, ifp);
				break;
		}
	}
	return 0;
}

static int ip_sirens_handler(struct module *module, int event, void *arg) {
	int error = 0; /* Error, 0 for normal return status */
	switch (event) {
	case MOD_LOAD:
		error = ip_sirens_init( arg);
		break;
	case MOD_UNLOAD:
		error = ip_sirens_deinit( arg);
		break;
	default:
		error = EOPNOTSUPP; /* Error, Operation Not Supported */
		break;
	}
	return error;
}

int rip_ctlout_hook(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
#ifdef SR_DEBUG
	DPRINT(" rip_ctlout_hook");
#endif
	switch(sopt->sopt_name){
	case IPSIRENS_SRVAR:
	case IPSIRENS_SDATAX:
	case IPSIRENS_STDATAX:
	case IPSIRENS_IDX:
	case IPSIRENS_SDATA:
	case IPSIRENS_STDATA:
	case IPSIRENS_ADATA:
		switch (sopt->sopt_dir) {
		case SOPT_SET:
#ifdef SR_DEBUG
//			DPRINT(" SET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_setsockopt(so, sopt);
			return error;
		case SOPT_GET:
#ifdef SR_DEBUG
//			DPRINT(" GET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_getsockopt(so, sopt);
			return error;
		default:
			return EOPNOTSUPP;
		}
	default:
		break;
	}
	error = rip_ctloutput(so, sopt);
	return error;
}

int tcp_ctlout_hook(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
#ifdef SR_DEBUG
	DPRINT(" tcp_ctlout_hook %d\n", sopt->sopt_name);
#endif
	switch(sopt->sopt_name){
	case IPSIRENS_SRVAR:
	case IPSIRENS_SDATAX:
	case IPSIRENS_STDATAX:
	case IPSIRENS_IDX:
	case IPSIRENS_SDATA:
	case IPSIRENS_STDATA:
	case IPSIRENS_ADATA:
		switch (sopt->sopt_dir) {
		case SOPT_SET:
#ifdef SR_DEBUG
			DPRINT(" SET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_setsockopt(so, sopt);
			return error;
		case SOPT_GET:
#ifdef SR_DEBUG
		   	DPRINT(" GET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_getsockopt(so, sopt);
			return error;
		default:
			return EOPNOTSUPP;
		}
	default:
		break;
	}
	error = tcp_ctloutput(so, sopt);
	return error;
}

int udp_ctlout_hook(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	printf(" udp_ctlout_hook");
	switch(sopt->sopt_name){
	case IPSIRENS_SRVAR:
	case IPSIRENS_SDATAX:
	case IPSIRENS_STDATAX:
	case IPSIRENS_IDX:
	case IPSIRENS_SDATA:
	case IPSIRENS_STDATA:
	case IPSIRENS_ADATA:
		switch (sopt->sopt_dir) {
		case SOPT_SET:
#ifdef SR_DEBUG
			DPRINT(" SET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_setsockopt(so, sopt);
			return error;
		case SOPT_GET:
#ifdef SR_DEBUG
			DPRINT(" GET %d\n", sopt->sopt_name);
#endif
			error = ip_sirens_getsockopt(so, sopt);
			return error;
		default:
			return EOPNOTSUPP;
		}
	default:
		break;
	}
	error = udp_ctloutput(so, sopt);
	return error;
}

static void tcp_usr_detach_hook(struct socket *so)
{
#ifdef SR_DEBUG
	DPRINT("SIRENS TCP detach hook\n");
#endif
	o_tcp_usrreqs->pru_detach(so);
}

static int tcp_usr_connect_hook(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int error = 0;
#ifdef SR_DEBUG
	DPRINT("SIRENS TCP connect hook\n");
#endif
	error = o_tcp_usrreqs->pru_connect(so, nam, td);
	return error;
}

static int tcp_usr_accept_hook(struct socket *so, struct sockaddr **nam)
{
	int error = 0;
	struct  inpcb *inp = sotoinpcb(so);
	struct  inpcb *linp = NULL;
	struct SRSFEntry *srp = NULL;
	struct SRSFEntry *lsrp = NULL;
	struct mbuf *m = NULL;
	struct ipopt_sr *opt_sr;
	struct sr_info *sr_info;
	unsigned long flags;
	int i;

#ifdef SR_DEBUG
	DPRINT("SIRENS TCP accept hook inp %08x\n", (uint32_t)inp);
#endif
	error = o_tcp_usrreqs->pru_accept(so, nam);
/* to find listen socket */
#if __FreeBSD_version < 900000
		linp = in_pcblookup_hash(&V_tcbinfo,
			inp->inp_faddr, 0,
			inp->inp_laddr, inp->inp_lport,
			INPLOOKUP_WILDCARD,
			NULL);
#else
		linp = in_pcblookup(&V_tcbinfo,
			inp->inp_faddr, 0,
			inp->inp_laddr, inp->inp_lport,
			INPLOOKUP_WILDCARD | INPLOOKUP_RLOCKPCB,
			NULL);
#endif
	if(linp){
#ifdef SR_DEBUG
		DPRINT("lookup with wild card %08x\n", (uint32_t)linp);
#endif
		lsrp = sock_to_SRSFEntry(linp->inp_socket);
#if !(__FreeBSD_version < 900000)
        	INP_RLOCK_ASSERT(linp);
        	INP_RUNLOCK(linp);
#endif
	}
	if(!lsrp)
		goto end;

	if(IPOPTSIRENSLEN(lsrp->sr_smax) > MLEN){
		return 0;
		}
		MGET(m, M_DONTWAIT, MT_DATA);

	if(m == NULL){
		return 0;
	}
	m->m_len = IPOPTSIRENSLEN(lsrp->sr_smax);
	opt_sr = mtod(m, struct ipopt_sr *);
	opt_sr->type = IPOPT_SIRENS;
	opt_sr->len = IPOPTSIRENSLEN(lsrp->sr_smax);

	LOCK(&sr_lock, flags);
	if(LIST_EMPTY(&sr_spool)){
		m_free(m);
		m = NULL;
		goto unlock;
	}

	srp = LIST_FIRST(&sr_spool);
	LIST_REMOVE(srp, list);
	if(srp == NULL){
		m_free(m);
		m = NULL;
		goto unlock;
	}

	srp->sk = so;
	srp->sr_nmax = lsrp->sr_nmax;
	srp->sr_smax = lsrp->sr_smax;
	srp->sr_qnext = 0;
	srp->sr_snext = 0;
	srp->sr_qttl = 0;
	srp->sr_sttl = 0;
	for (i = 0; i < lsrp->sr_nmax; i++) {
		sr_info = &(srp->inp_sr[i]);
		sr_info->mode = lsrp->inp_sr[i].mode;
		sr_info->probe = lsrp->inp_sr[i].probe;
		sr_info->qmin_ttl = lsrp->inp_sr[i].qmin_ttl;
		sr_info->qmax_ttl = lsrp->inp_sr[i].qmax_ttl;
		sr_info->smin_ttl = lsrp->inp_sr[i].smin_ttl;
		sr_info->smax_ttl = lsrp->inp_sr[i].smax_ttl;
	}
	LIST_INSERT_HEAD(&sr_sactive, srp, list);

unlock:
	UNLOCK(&sr_lock, flags);
	if(m){
		INP_WLOCK(inp);
		error = ip_pcbopts(inp, 0, m);
		INP_WUNLOCK(inp);
	}
end:
	return error;
}
static int tcp_usr_listen_hook(struct socket *so, int backlog, struct thread *td)
{
	int error = 0;
#ifdef SR_DEBUG
	DPRINT("SIRENS TCP listen hook %08x %08x\n", (uint32_t)so, (uint32_t)sotoinpcb(so));
#endif
	error = o_tcp_usrreqs->pru_listen(so, backlog, td);
	return error;
}

static int ip_sirens_init(void *arg)
{
	int error = 0;
	int i, flags;
	struct pfil_head *pfh_inet = NULL;
	struct ifnet *ifp;
	struct SRSFEntry *srp;
	struct SRIFEntry *srip;

	uprintf("sirens_init\n");

	mtx_init(&sr_lock, "ip_sirens ", NULL, MTX_DEF);

	LIST_INIT(&sr_iflist);
	LIST_INIT(&sr_sactive);
	LIST_INIT(&sr_spool);

/* allocate network interface tracking storage */
	IFNET_WLOCK();
	for(ifp = TAILQ_FIRST(&V_ifnet); ifp != NULL ; ifp = TAILQ_NEXT(ifp, if_link)){
	srip = malloc(sizeof(struct SRIFEntry), M_TEMP,M_NOWAIT);
#ifdef SR_DEBUG
		DPRINT("%s attached \n", if_name(ifp));
#endif
		if(srip == NULL){
			IFNET_WUNLOCK();
			error = ENOMEM;
			goto err0;
		}
		bzero(srip, sizeof(struct SRIFEntry));
		srip->ifp = ifp;
		LIST_INSERT_HEAD(&sr_iflist, srip, list);
	}
	IFNET_WUNLOCK();

	LOCK(&sr_lock, flags);
	for( i = 0 ; i < sr_max_so ; i++){
	srp = malloc(sizeof(struct SRSFEntry), M_TEMP,M_NOWAIT);
		if(srp == NULL){
			UNLOCK(&sr_lock, flags);
			error = ENOMEM;
			goto err0;
		}
		bzero(srp, sizeof(struct SRSFEntry));
		LIST_INSERT_HEAD(&sr_spool, srp, list);
	}
	UNLOCK(&sr_lock, flags);

/* Hook protocol swtch */
	bcopy(inetsw, ip_sw, sizeof(struct protosw) * IPPROTO_MAX);

/* RAW IP */
	for( i = 0 ; i < IPPROTO_MAX ; i++ ){
		if(inetsw[i].pr_protocol == IPPROTO_RAW &&
		   inetsw[i].pr_type == SOCK_RAW) break;
	}
	if( i == IPPROTO_MAX) goto err;
	inetsw[i].pr_ctloutput = rip_ctlout_hook;

/* TCP */
	for( i = 0 ; i < IPPROTO_MAX ; i++ ){
		if(inetsw[i].pr_protocol == IPPROTO_TCP &&
		   inetsw[i].pr_type == SOCK_STREAM) break;
	}
	if( i == IPPROTO_MAX) goto err;
	inetsw[i].pr_ctloutput = tcp_ctlout_hook;
	bcopy(inetsw[i].pr_usrreqs, o_tcp_usrreqs, sizeof(struct pr_usrreqs));
	INP_INFO_WLOCK(&V_tcbinfo);
	inetsw[i].pr_usrreqs->pru_detach = tcp_usr_detach_hook;
	inetsw[i].pr_usrreqs->pru_connect = tcp_usr_connect_hook;
	inetsw[i].pr_usrreqs->pru_accept = tcp_usr_accept_hook;
	inetsw[i].pr_usrreqs->pru_listen = tcp_usr_listen_hook;
	INP_INFO_WUNLOCK(&V_tcbinfo);

/* UDP */
	for( i = 0 ; i < IPPROTO_MAX ; i++ ){
		if(inetsw[i].pr_protocol == IPPROTO_UDP &&
		   inetsw[i].pr_type == SOCK_DGRAM) break;
	}
	if( i == IPPROTO_MAX) goto err;
	inetsw[i].pr_ctloutput = udp_ctlout_hook;

/* attach filter */
	pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	if(pfh_inet == NULL) {
		goto err;
		error = EOPNOTSUPP;
	}
	pfil_add_hook(pf_sirens_input, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet);
	pfil_add_hook(pf_sirens_output, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet);

	ip_sirens_hooked = 1;

	return error;

err:
	ip_sirens_hooked = 0;
	if(pfh_inet != NULL){
		pfil_remove_hook(pf_sirens_input, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet);
		pfil_remove_hook(pf_sirens_output, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet);
	}
	bcopy(ip_sw, inetsw, sizeof(struct protosw) * IPPROTO_MAX);
err0:
	while(!LIST_EMPTY(&sr_iflist)){
		srip = LIST_FIRST(&sr_iflist);
		LIST_REMOVE(srip, list);
		free(srip, M_TEMP);
	}
	while(!LIST_EMPTY(&sr_spool)){
		srp = LIST_FIRST(&sr_spool);
		LIST_REMOVE(srp, list);
		free(srp, M_TEMP);
	}
	return error;
}

static int ip_sirens_deinit(void *arg)
{
	int error = 0;
	int flags;
	int i;
	struct pfil_head *pfh_inet = NULL;
	struct SRIFEntry *srip;
	struct SRSFEntry *srp;

	if(!ip_sirens_hooked) return error;

/* detach filter */
	pfh_inet = pfil_head_get(PFIL_TYPE_AF, AF_INET);
	if(pfh_inet != NULL){
		pfil_remove_hook(pf_sirens_input, NULL, PFIL_IN | PFIL_WAITOK, pfh_inet);
		pfil_remove_hook(pf_sirens_output, NULL, PFIL_OUT | PFIL_WAITOK, pfh_inet);
	}
/* XXX: Lock to avoid interfere with packet processing  ? */
	bcopy(ip_sw, inetsw, sizeof(struct protosw) * IPPROTO_MAX);

/* TCP */
	for( i = 0 ; i < IPPROTO_MAX ; i++ ){
		if(inetsw[i].pr_protocol == IPPROTO_TCP &&
		   inetsw[i].pr_type == SOCK_STREAM) break;
	}
	if( i != IPPROTO_MAX){
		INP_INFO_WLOCK(&V_tcbinfo);
		bcopy(o_tcp_usrreqs, inetsw[i].pr_usrreqs, sizeof(struct pr_usrreqs));
		INP_INFO_WUNLOCK(&V_tcbinfo);
	}

/* deallocate network interface tracking storage */
	IFNET_WLOCK();
	while(!LIST_EMPTY(&sr_iflist)){
		srip = LIST_FIRST(&sr_iflist);
		LIST_REMOVE(srip, list);
		free(srip, M_TEMP);
	}
	IFNET_WUNLOCK();
	LOCK(&sr_lock, flags);
	while(!LIST_EMPTY(&sr_spool)){
		srp = LIST_FIRST(&sr_spool);
		LIST_REMOVE(srp, list);
		free(srp, M_TEMP);
	}
	while(!LIST_EMPTY(&sr_sactive)){
		srp = LIST_FIRST(&sr_sactive);
		LIST_REMOVE(srp, list);
		free(srp, M_TEMP);
	}
	UNLOCK(&sr_lock, flags);
	uprintf("deinit module !\n");
	ip_sirens_hooked = 0;
	return error;
}

/* The second argument of DECLARE_MODULE.*/
static moduledata_t ip_sirens_conf = {
	"ip_sirens",	/* module name */
	ip_sirens_handler,  /* event handler */
	NULL			/* extra data */
};
DECLARE_MODULE(ip_sirens, ip_sirens_conf, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
#endif /* defined(__FreeBSD__) */
