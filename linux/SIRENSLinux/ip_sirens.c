/*
 * Copyright (c) 2010
 * National Institute of Advanced Industrial Science and Technology (AIST).
 * All rights reserved.
 *
 */

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

#include "ip_sirens.h"

#define SIRENS_VERSION		"1.0.0"

#define IPSIRENS_OPTMIN		IPSIRENS_SRVAR
#define IPSIRENS_OPTMAX		IPSIRENS_STDATAX
#define IPSIRENS_HOPNUM		256
#define IPSIRENS_HOPMAX		(IPSIRENS_HOPNUM - 1)
#define IPSIRENS_TIMEOUT	100	/* sec */

#ifndef IPSIRENS_MAX_SK
#define IPSIRENS_MAX_SK		50
#endif

#ifndef IPSIRENS_MAX_ICMP
#define IPSIRENS_MAX_ICMP	50
#endif


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


struct SRIFEntry {
	struct list_head list;
	struct net_device *dev;		/* pointer to the interface */

	struct list_head icmp;		/* pushed ICMP echo request */
	struct sr_storage storage;	/* external data of the interface */
};

struct SRSFEntry {
	struct list_head list;
	struct sock *sk;			/* pointer to the socket */
	void (*sk_destruct)(struct sock *);	/* socket destructor hook */

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

struct ICMPEntry {
	struct list_head list;

	uint32_t saddr;			/* source address */
	int reslen;
	char buf[IPOPTSIRENSLEN(1)];	/* SIRENS header cache */
};


/* global lock */
static DEFINE_SPINLOCK(sr_lock);

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


static inline struct SRIFEntry *
netdev_to_SRIFEntry(struct net_device *ndev)
{
	struct SRIFEntry *srp;

	list_for_each_entry(srp, &sr_iflist, list) {
		if (srp->dev == ndev)
			return srp;
	}

	return NULL;
}

static inline struct SRIFEntry *
name_to_SRIFEntry(const char *name)
{
	struct SRIFEntry *srp;

	list_for_each_entry(srp, &sr_iflist, list) {
		if (strncmp(srp->dev->name, name, IFNAMSIZ) == 0)
			return srp;
	}

	return NULL;
}

static inline struct SRSFEntry *
sock_to_SRSFEntry(struct sock *sk)
{
	struct SRSFEntry *srp;

	list_for_each_entry(srp, &sr_sactive, list) {
		if (srp->sk == sk)
			return srp;
	}

	return NULL;
}

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

static struct ipopt_sr *
sr_find_sirens(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct ipopt_sr *opt_sr;
	u_char *cp;
	int opt, optlen, cnt, code;

	if (! pskb_may_pull(skb, ip_hdrlen(skb))) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: pskb_may_pull() failed\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		return NULL;
	}

	cp = (u_char *)(iph + 1);
	cnt = (iph->ihl << 2) - sizeof (struct iphdr);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_END)
			break;
		if (opt == IPOPT_NOOP)
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
		opt_sr->res_probe = opt_sr->req_probe;
		opt_sr->res_ttl = opt_sr->req_ttl;
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

static void
sr_update_reqdata(struct ipopt_sr *opt_sr, struct net_device *ndev)
{
	uint32_t data = ~0;
	struct SRIFEntry *srp;
	struct sr_var *srvar;
	struct ethtool_cmd ethcmd;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	const struct net_device_stats *stats;
#else
	struct rtnl_link_stats64 *stats;
	struct rtnl_link_stats64 temp;
#endif
	uint32_t flag;
	unsigned long flags;

	/* getting interface information */
	if (ndev == NULL)
		goto update;

	srp = netdev_to_SRIFEntry(ndev);
	if (srp) {
		spin_lock_irqsave(&sr_lock, flags);

		srvar = &(srp->storage.array[opt_sr->req_probe]);
		flag = srvar->flag;
		data = (uint32_t) srvar->data;

		spin_unlock_irqrestore(&sr_lock, flags);

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
	stats = dev_get_stats(ndev);
#else
	stats = dev_get_stats(ndev, &temp);
#endif
	switch (opt_sr->req_probe & ~SIRENS_DIR_IN) {
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
	default:
		break;
	}
#ifdef SR_DEBUG
	printk(KERN_DEBUG "%s: internal data: dev=[%.*s] probe=0x%x data=%u "
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
	default:
		break;
	}
}

static void
sr_gather_data(struct ipopt_sr *opt_sr, struct SRSFEntry *srp)
{
	struct sr_hopdata *hopdata;
	struct sr_info *inp;
	union u_sr_data *resdata = (union u_sr_data *)(opt_sr + 1);
	u_int reslen = IPOPTLENTORESLEN(opt_sr->len);
	struct timeval now;
	int i, j;

	do_gettimeofday(&now);

	for (i = 0; i < srp->sr_nmax; i++) {
		inp = &(srp->inp_sr[i]);
		if (inp->mode != opt_sr->req_mode ||
				inp->probe != opt_sr->req_probe)
			continue;

		hopdata = &(inp->sr_qdata[opt_sr->req_ttl]);
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
		inp = &(srp->inp_sr[j]);
		if (inp->mode != opt_sr->res_mode ||
				inp->probe != opt_sr->res_probe)
			continue;

		for (i = 0; i < reslen; i++) {
			if (opt_sr->res_ttl + i > IPSIRENS_HOPMAX)
				break;

			hopdata = &(inp->sr_sdata[opt_sr->res_ttl + i]);
			hopdata->tv.tv_sec = now.tv_sec;
			hopdata->tv.tv_usec = now.tv_usec;
			hopdata->val = resdata[i];
#ifdef SR_DEBUG
			if (hopdata->val.set == -1)
				continue;
			printk(KERN_DEBUG "%s: sdata: mode=%d probe=0x%x "
				"ttl=%d val=%u\n", __FUNCTION__, inp->mode,
				inp->probe, opt_sr->res_ttl+i,
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

	do_gettimeofday(&now);
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
sr_setsockopt_srvar(struct sock *sk, void __user *user, unsigned int len)
{
	struct if_srvarreq srreq;
	struct SRIFEntry *srp;
	struct sr_var *srvar;
	int idx, error;
	unsigned long flags;

	if (len != sizeof(srreq))
		return -EINVAL;
	if (copy_from_user(&srreq, user, (unsigned long)len))
		return -EFAULT;

	srp = name_to_SRIFEntry(srreq.ifrname);
	if (srp == NULL)
		return -EINVAL;

	spin_lock_irqsave(&sr_lock, flags);

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
		printk(KERN_DEBUG "%s: dev=[%s] array_idx=%d (probe=0x%x) "
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

	spin_unlock_irqrestore(&sr_lock, flags);

	return error;
}

static int
sr_setsockopt_sdatax(struct sock *sk, void __user *user, unsigned int len)
{
	struct SRSFEntry *srp;
	struct sr_dreq dreq;
	int error;
	unsigned long flags;

	if (IPSIRENS_DREQSIZE(0) != len)
		return -EINVAL;
	if (copy_from_user(&dreq, user, (unsigned long)len))
		return -EFAULT;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
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

	spin_unlock_irqrestore(&sr_lock, flags);

	return error;
}

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

static int
sr_setsockopt_idx(struct sock *sk, void __user *user, unsigned int len)
{
	struct SRSFEntry *srp;
	struct sr_ireq *srireq;
	struct srreq_index *sri;
	struct sr_info *inp;
	struct ip_options *opt;
	struct ipopt_sr *opt_sr;
	int i, optlen, alloc, error;
	unsigned long flags;

	if (len > IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX))
		return -EINVAL;
	
	srireq = kmalloc(len, GFP_KERNEL);
	if (srireq == NULL)
		return -ENOMEM;

	error = copy_from_user(srireq, user, (unsigned long)len);
	if (error)
		goto end;

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
	opt = kzalloc(sizeof(struct ip_options) + optlen, GFP_ATOMIC);
	if (opt == NULL) {
		error = -ENOMEM;
		goto end;
	}

	opt->optlen = optlen;
	opt_sr = (struct ipopt_sr *) opt->__data;
	opt_sr->type = IPOPT_SIRENS;
	opt_sr->len = optlen;

	spin_lock_irqsave(&sr_lock, flags);

	alloc = 0;
	srp = sock_to_SRSFEntry(sk);
	if (srp == NULL) {
		if (list_empty(&sr_spool)) {
#ifdef SR_DEBUG
			printk(KERN_DEBUG "%s: no memory for socket\n",
				__FUNCTION__);
#endif /* SR_DEBUG */
			error = -ENOMEM;
			kfree(opt);
			goto unlock;
		}
		srp = list_first_entry(&sr_spool, struct SRSFEntry, list);
		list_del(&(srp->list));
		alloc = 1;
	}

	srp->sr_nmax = srireq->sr_nindex;
	srp->sr_smax = srireq->sr_smax;
	srp->sr_qnext = 0;
	srp->sr_snext = 0;
	srp->sr_qttl = 0;
	srp->sr_sttl = 0;
	for (i = 0; i < srireq->sr_nindex; i++) {
		inp = &(srp->inp_sr[i]);
		inp->mode = sri[i].mode;
		inp->probe = sri[i].probe;
		inp->qmin_ttl = sri[i].qttl_min;
		inp->qmax_ttl = sri[i].qttl_max;
		inp->smin_ttl = sri[i].sttl_min;
		inp->smax_ttl = sri[i].sttl_max;
	}

	if (alloc) {
		srp->sk = sk;
		srp->sk_destruct = sk->sk_destruct;
		sk->sk_destruct = &sr_sk_destruct_hook;
		list_add(&(srp->list), &sr_sactive);
	}

	/*
	 * set SIRENS header template to socket object.
	 */
	sr_set_ipoption(sk, opt);
	error = 0;

 unlock:
	spin_unlock_irqrestore(&sr_lock, flags);

 end:
	kfree(srireq);
	return error;
}

static int
sr_getsockopt_srvar(struct sock *sk, void __user *user, int *len)
{
	struct SRIFEntry *srp;
	struct if_srvarreq srreq;
	struct sr_var *srvar;
	unsigned long flags;

	if (*len != sizeof(srreq))
		return -EINVAL;

	if (copy_from_user(&srreq, user, (unsigned long)*len))
		return -EFAULT;

	srp = name_to_SRIFEntry(srreq.ifrname);
	if (srp == NULL)
		return -EINVAL;

	spin_lock_irqsave(&sr_lock, flags);

	/*
	 * load value from interface storage.
	 */
	srvar = &(srp->storage.array[srreq.sr_probe & 0xff]);
	srreq.sr_var.data = srvar->data;
	srreq.sr_var.flag = srvar->flag;

	spin_unlock_irqrestore(&sr_lock, flags);

	return copy_to_user(user, &srreq, (unsigned long)*len);
}

static int
sr_getsockopt_sdata0(struct SRSFEntry *srp, struct sr_dreq *dreq,
	union u_sr_data *sr_data)
{
	struct sr_hopdata *hopdata;
	struct sr_info *inp;
	struct timeval now;
	struct sr_timeval expire;
	int i, j;

	for (i = 0; i < srp->sr_nmax; i++) {
		inp = &(srp->inp_sr[i]);
		if (inp->mode != dreq->mode || inp->probe != dreq->probe)
			continue;

		do_gettimeofday(&now);
		expire.tv_sec = now.tv_sec - IPSIRENS_TIMEOUT;
		expire.tv_usec = now.tv_usec;

		switch (dreq->dir) {
		case 1:
			hopdata = inp->sr_qdata;	/* use request data */
			break;
		case 2:
		default:
			hopdata = inp->sr_sdata;	/* use response data */
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
	struct sr_info *inp;
	int i;

	for (i = 0; i < srp->sr_nmax; i++) {
		inp = &(srp->inp_sr[i]);
		if (inp->mode != dreq->mode || inp->probe != dreq->probe)
			continue;

		switch (dreq->dir) {
		case 1:
			hopdata = inp->sr_qdata;	/* use request data */
			break;
		case 2:
		default:
			hopdata = inp->sr_sdata;	/* use response data */
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
sr_getsockopt_stdatax(struct sock *sk, void __user *user, int *len)
{
	struct SRSFEntry *srp;
	struct sr_hopdata *hopdata;
	int error;
	unsigned long flags;

	if (*len != IPSIRENS_HOPNUM * sizeof (struct sr_hopdata))
		return -EINVAL;

	hopdata = kmalloc(*len, GFP_KERNEL);
	if (hopdata == NULL)
		return -ENOMEM;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
	if (srp == NULL)
		error = -EINVAL;
	else
		error = sr_getsockopt_stdata0(srp, &(srp->sr_dreq), hopdata);

	spin_unlock_irqrestore(&sr_lock, flags);

	if (error == 0)
		error = copy_to_user(user, hopdata, (unsigned long)*len);

	kfree(hopdata);
	return error;
}

static int
sr_getsockopt_sdatax(struct sock *sk, void __user *user, int *len)
{
	struct SRSFEntry *srp;
	union u_sr_data *sr_data;
	int error;
	unsigned long flags;

	if (*len != IPSIRENS_HOPNUM * sizeof (union u_sr_data))
		return -EINVAL;

	sr_data = kmalloc(*len, GFP_KERNEL);
	if (sr_data == NULL)
		return -ENOMEM;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
	if (srp == NULL)
		error = -EINVAL;
	else
		error = sr_getsockopt_sdata0(srp, &(srp->sr_dreq), sr_data);

	spin_unlock_irqrestore(&sr_lock, flags);

	if (error == 0)
		error = copy_to_user(user, sr_data, (unsigned long)*len);

	kfree(sr_data);
	return error;
}

static int
sr_getsockopt_stdata(struct sock *sk, void __user *user, int *len)
{
	struct SRSFEntry *srp;
	struct sr_dreq *dreqp;
	struct sr_hopdata *hopdata;
	int error;
	unsigned long flags;

	if (*len != IPSIRENS_DTREQSIZE(IPSIRENS_HOPNUM))
		return -EINVAL;

	dreqp = kmalloc(*len, GFP_KERNEL);
	if (dreqp == NULL)
		return -ENOMEM;

	error = copy_from_user(dreqp, user, (unsigned long)*len);
	if (error)
		goto end;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
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

	spin_unlock_irqrestore(&sr_lock, flags);

	if (error == 0)
		error = copy_to_user(user, dreqp, (unsigned long)*len);

 end:
	kfree(dreqp);
	return error;
}

static int
sr_getsockopt_sdata(struct sock *sk, void __user *user, int *len)
{
	struct SRSFEntry *srp;
	struct sr_dreq *dreqp;
	union u_sr_data *sr_data;
	int error;
	unsigned long flags;

	if (*len != IPSIRENS_DREQSIZE(IPSIRENS_HOPNUM))
		return -EINVAL;

	dreqp = kmalloc(*len, GFP_KERNEL);
	if (dreqp == NULL)
		return -ENOMEM;

	error = copy_from_user(dreqp, user, (unsigned long)*len);
	if (error)
		goto end;

	spin_lock_irqsave(&sr_lock, flags);

	srp = sock_to_SRSFEntry(sk);
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

	spin_unlock_irqrestore(&sr_lock, flags);

	if (error == 0)
		error = copy_to_user(user, dreqp, (unsigned long)*len);

 end:
	kfree(dreqp);
	return error;
}

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

	if (opt_sr->req_mode == SIRENS_TTL && iph->ttl == opt_sr->req_ttl &&
			(opt_sr->req_probe & SIRENS_DIR_IN) != 0) {
		/*
		 * updata request data in in-coming packet.
		 */
		sr_update_reqdata(opt_sr, (struct net_device *)in);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
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

static unsigned int
ip_sirens_local_in(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct SRSFEntry *srp, *lsrp;
	struct sr_info *inp, *linp;
	struct iphdr *iph = ip_hdr(skb);
	struct ip_options *opt;
	struct ipopt_sr *opt_sr;
	struct tcphdr *th;
	struct sock *sk, *lsk;
	int len, i;
	unsigned long flags;

	if (ip_hdrlen(skb) == sizeof (struct iphdr))
		return NF_ACCEPT;
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	opt_sr = sr_find_sirens(skb);
	if (opt_sr == NULL)
		return NF_ACCEPT;

	len = ip_hdrlen(skb) + sizeof (struct tcphdr);
	if (! pskb_may_pull(skb, len))
		return NF_ACCEPT;

	sk = lsk = NULL;
	/*
	 * lookup socket object from TCP source and destination port.
	 */
	th = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
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

	/*
	 * lookup server socket object from TCP destination port.
	 */
	local_bh_disable();
	lsk = inet_lookup_listener(dev_net(in), &tcp_hashinfo, iph->daddr,
			th->dest, inet_iif(skb));
	local_bh_enable();

	spin_lock_irqsave(&sr_lock, flags);

	/*
	 * if we have tracking data refer to this connection,
	 * gather SIRENS data.
	 */
	srp = sock_to_SRSFEntry(sk);
	if (srp) {
		if (srp->sr_nmax > 0)
			sr_gather_data(opt_sr, srp);
		goto unlock;
	}
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
	if (opt == NULL) {
#ifdef SR_DEBUG
		printk(KERN_DEBUG "%s: no memory for connected socket\n",
			__FUNCTION__);
#endif /* SR_DEBUG */
		goto unlock;
	}

	opt->optlen = len;
	opt_sr = (struct ipopt_sr *) opt->__data;
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
		inp = &(srp->inp_sr[i]);
		linp = &(lsrp->inp_sr[i]);
		inp->mode = linp->mode;
		inp->probe = linp->probe;
		inp->qmin_ttl = linp->qmin_ttl;
		inp->qmax_ttl = linp->qmax_ttl;
		inp->smin_ttl = linp->smin_ttl;
		inp->smax_ttl = linp->smax_ttl;
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

 unlock:
	spin_unlock_irqrestore(&sr_lock, flags);
	if (lsk)
		__sock_put(lsk);

 end:
	__sock_put(sk);

	return NF_ACCEPT;
}

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

	if (opt_sr->req_mode == SIRENS_TTL && iph->ttl == opt_sr->req_ttl &&
			(opt_sr->req_probe & SIRENS_DIR_IN) == 0) {
		/*
		 * updata request data in out-going packet.
		 */
		sr_update_reqdata(opt_sr, (struct net_device *)out);
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
	}

	return NF_ACCEPT;
}

static int
ip_sirens_setsockopt(struct sock *sk, int cmd, void __user *user,
		unsigned int len)
{
	int ret;

#if 0		/* FIX ME: do we need capability check ? */
	if (! capable(CAP_NET_ADMIN))
		return -EPERM;
#endif

	switch (cmd) {
	case IPSIRENS_SRVAR:
		ret = sr_setsockopt_srvar(sk, user, len);
		break;
	case IPSIRENS_SDATAX:
	case IPSIRENS_STDATAX:
		ret = sr_setsockopt_sdatax(sk, user, len);
		break;
	case IPSIRENS_IDX:
		ret = sr_setsockopt_idx(sk, user, len);
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
ip_sirens_getsockopt(struct sock *sk, int cmd, void __user *user, int *len)
{
	int ret;

#if 0		/* FIX ME: do we need capability check ? */
	if (! capable(CAP_NET_ADMIN))
		return -EPERM;
#endif

	switch (cmd) {
	case IPSIRENS_SRVAR:
		ret = sr_getsockopt_srvar(sk, user, len);
		break;
	case IPSIRENS_SDATAX:
		ret = sr_getsockopt_sdatax(sk, user, len);
		break;
	case IPSIRENS_STDATAX:
		ret = sr_getsockopt_stdatax(sk, user, len);
		break;
	case IPSIRENS_IDX:
		ret = -EINVAL;
		break;
	case IPSIRENS_SDATA:
		ret = sr_getsockopt_sdata(sk, user, len);
		break;
	case IPSIRENS_STDATA:
		ret = sr_getsockopt_stdata(sk, user, len);
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
