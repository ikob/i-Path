/*
 * Copyright (c) 2009, 2010 National Institute of Advanced Industrial
 * Science and Technology (AIST).
 * Copyright (c) 2011 RIKEN.
 * 
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
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/kernel_types.h>
#include <net/kpi_interfacefilter.h>

#include <sys/systm.h>
#include <sys/select.h>
#include <sys/proc.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>

#include "sirensnke.h"

#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <libkern/OSKextLib.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <stdarg.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>

#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/kpi_ipfilter.h>

#include <net/if_types.h>

#include <net/ethernet.h>
#include <net/if_var.h>
#include <netinet/ip_sirens.h>


struct ipopt_sr *ip_sirens_dooptions_d(mbuf_t, size_t);


#define DEBUG	1

/*
 * 
 */
#if DEBUG > 0
static void
debug_printf(const char *fmt, ...)
{

	va_list listp;
	char log_buffer[92];
	
	va_start(listp, fmt);
	
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("%s", log_buffer);
	
	va_end(listp);
}
#else
inline debug_printf(char *fmt, ...)
{
	/* do nothing */
}
#endif

#define SR_TIMEOUT 100

#define SIRENS_HANDLE4TCP 0x696b6f62		/* Temp hack to identify this filter */
#define SIRENS_HANDLE4UDP 0x696b6f63
#define SIRENS_HANDLE6TCP 0x696b6f64
#define SIRENS_HANDLE6UDP 0x696b6f65
/*
 Used a registered creator type here - to register for one - go to the
 Apple Developer Connection Datatype Registration page
 <http://developer.apple.com/datatype/>
 */
#define MYBUNDLEID		"jp.hpcc.ikob.kext.sirensnke"

static boolean_t sirens_initted = FALSE;

static	int sr_enable = 0;
static	int sr_count = 0;


/* SIRENS Tag type */
#define SR_TAG_TYPE		1

static OSMallocTag		gOSMallocTag;	// tag for use with OSMalloc calls which is used to associate memory
// allocations made with this kext. Preferred to using MALLOC and FREE

static boolean_t	gFReged_ip4_tcp = FALSE;
static boolean_t	gUnreg_started_ip4_tcp = FALSE;
static boolean_t	gUnreg_complete_ip4_tcp = FALSE;

static boolean_t	gFReged_ip4_udp = FALSE;
static boolean_t	gUnreg_started_ip4_udp = FALSE;
static boolean_t	gUnreg_complete_ip4_udp = FALSE;

static boolean_t	gFReged_ip6_tcp = FALSE;
static boolean_t	gUnreg_started_ip6_tcp = FALSE;
static boolean_t	gUnreg_complete_ip6_tcp = FALSE;

static boolean_t	gFReged_ip6_udp = FALSE;
static boolean_t	gUnreg_started_ip6_udp = FALSE;
static boolean_t	gUnreg_complete_ip6_udp = FALSE;

static boolean_t	gipFilterRegistered = FALSE;

static interface_filter_t	gsr_if_filter[256];
static int	gifFilterRegistered = 0;

static u_int16_t
in_update_csum(u_int16_t, u_int16_t, u_int16_t);

struct SRIFEntry {
	TAILQ_ENTRY(SRIFEntry)	srif_list;
	struct iff_filter		srif_filter;
	struct sr_storage		srif_storage;
};
static struct sr_iflist sr_iflist;

/* List of sockets */
static struct sr_sflist sr_list;				// protected by gmutex
static struct sr_sflist sr_active;

/* Protect consistency of our data at entry points */
static lck_mtx_t		*gmutex = NULL;				// used to protect the sr_list queues
static lck_grp_t		*gmutex_grp = NULL;

/* Tag to assign jp.hpcc.ikob.kext.sirens */
static mbuf_tag_id_t	gsr_idtag;

struct sr_mbuf_tag {
	short len;
	short offset;
	struct ipopt_sr opt_sr;
};

struct SRSFEntry {
	TAILQ_ENTRY(SRSFEntry)		sre_list;
	uint32_t					sre_flag;
	socket_t					sre_so;		/* Pointer to owning socket */
	uint32_t					magic;		/* magic value to ensure that system is passing me my buffer */
	/* SIRENS options */
#define INPSIRENSMAX 8
 	u_char sr_qnext, sr_snext, sr_nmax, sr_qttl, sr_sttl;
	struct {
		u_char dir;
		u_char mode;
		u_char probe;
	} sr_dreq;
	struct {
		u_char mode, probe;
		u_char qmin_ttl, qmax_ttl, smin_ttl, smax_ttl;
		struct sr_hopdata *sr_qdata, *sr_sdata;
	} inp_sr[INPSIRENSMAX];
	struct in_addr faddr;
	struct in_addr group;
};
#define SRE_FL_NONE		0
#define	SRE_FL_ACTIVE	1
#define	SRE_FL_ARMED	2

typedef struct SRSFEntry  SRSFEntry;
typedef struct SRIFEntry  SRIFEntry;

#define kSRSFEntryMagic		0xAABBCCDD

TAILQ_HEAD(sr_sflist, SRSFEntry);
TAILQ_HEAD(sr_iflist, SRIFEntry);

#define kInvalidUnit	0xFFFFFFFF

static ipfilter_t sr_ipf_ref = NULL;

static void  sr_remove(struct SRSFEntry *srp);
//static void	 debug_printf(const char *fmt, ...);
static errno_t alloc_locks(void);
static void free_locks(void);
static errno_t sr_fl_arm(struct SRSFEntry *srp);

/* =================================== */


static struct SRSFEntry * SRSFEntryFromCookie(void *cookie)
{
	struct SRSFEntry * result;
	result = (struct SRSFEntry *) cookie;
	assert(result != NULL);
	assert(result->magic == kSRSFEntryMagic);
	return result;
}

/*
 */
static	void
sr_unregistered_fn(sflt_handle handle)
{
	debug_printf("sr_unregistered_func entered\n");
	switch (handle) {
		case SIRENS_HANDLE4TCP:
			gUnreg_complete_ip4_tcp = TRUE;
			gFReged_ip4_tcp = FALSE;
			break;
		case SIRENS_HANDLE4UDP:
			gUnreg_complete_ip4_udp = TRUE;
			gFReged_ip4_udp = FALSE;
			break;			
		case SIRENS_HANDLE6TCP:
			gUnreg_complete_ip6_tcp = TRUE;
			gFReged_ip6_tcp = FALSE;
			break;
		case SIRENS_HANDLE6UDP:
			gUnreg_complete_ip6_tcp = TRUE;
			gFReged_ip6_udp = FALSE;
			break;
		default:
			break;
	}
}

/*
 */
static	void
sr_attach_fn_locked(socket_t so, struct SRSFEntry *srp)
{ 		
	// set the magic cookie for debugging purposes only to verify that the system 
	// only returns memory that I allocated.
	srp->magic = kSRSFEntryMagic;

	TAILQ_INSERT_TAIL(&sr_list, srp, sre_list);
}

/*
 */

static	errno_t
sr_attach_fn(void **cookie, socket_t so)
{ 
	struct SRSFEntry *srp;
	errno_t	result = 0;
	
    debug_printf("sr_attach_fn  - so: 0x%X\n", so);	
	
	if (sr_enable != 0) {
		srp = (struct SRSFEntry *)OSMalloc(sizeof (struct SRSFEntry), gOSMallocTag);
		sr_count++;

		bzero(srp, sizeof(struct SRSFEntry));
		if (srp == NULL) {
			return ENOBUFS;
		}

		*(struct SRSFEntry**)cookie = srp;

		srp->sre_flag = SRE_FL_NONE;
		srp->sre_so = so;
		lck_mtx_lock(gmutex);	// take the lock so that we can protect against the srp structure access
		sr_attach_fn_locked(so, srp);
		lck_mtx_unlock(gmutex);
	} else {
		*cookie = NULL;
		result = ENXIO;
	}
	return result;
}

/*
 */
static void	
sr_detach_fn(void *cookie, socket_t so)
{
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	int ret = 0;
	
	debug_printf("sr_detach_fn - so: 0x%X sr_count: %d %d 0x%X\n", so, sr_enable, sr_count, srp);
	if (srp == NULL)
		goto err;
	
	sr_remove(srp);
	
	if(sr_enable == 0 && sr_count == 0){
		OSKextLoadTag OStag;
		printf("sirensnke: all descriptor is free'ed, unload again\n");
		OStag = OSKextGetCurrentLoadTag();
		printf("tag: %x\n", OStag);
		ret = jp_hpcc_ikob_kext_sirensnke_flush();
		if(ret == KERN_SUCCESS){
			OSReturn OSret;
			OSret = OSKextRetainKextWithLoadTag(OStag);
			if(OSret != kOSReturnSuccess){
				printf("sirensnke: failed to retain err: %d\n", OSret);
				return;
			}
			OSret = OSKextReleaseKextWithLoadTag(OStag);
			if(OSret != kOSReturnSuccess){
				printf("sirensnke: failed to release err: %d\n", OSret);
				return;
			}
			printf("sirensnke: success to releasee\n", OSret);
			return;			
		}
	}
err:
	return;
}
/*
 */
static	errno_t	
sr_connect_out_fn(void *cookie, socket_t so, const struct sockaddr *to)
{
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	debug_printf("sr_connect_out_fn        - so: 0x%X 0x%X\n", so, srp);
	if(srp->sre_flag & SRE_FL_ACTIVE && !(srp->sre_flag & SRE_FL_ARMED)){
		sr_fl_arm(srp);
	}
	return 0;
}
/*
 */
static	errno_t	
sr_connect_in_fn(void *cookie, socket_t so, const struct sockaddr *to)
{
	/* Connect in called before accepting connection, so cookie and socket is
	 listening socket one, not the new connection */
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	debug_printf("sr_connect_in_fn        - so: 0x%X 0x%X\n", so, srp);
	return 0;
}
/*
 */
static errno_t
sr_bind_fn(void *cookie, socket_t so, const struct sockaddr *to){
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	debug_printf("sr_bind_fn        - so: 0x%X 0x%X\n", so, srp);
	if(srp->sre_flag & SRE_FL_ARMED){
		debug_printf("sr_bind_fn        - so: 0x%X already armed.\n");
	}
	if(srp->sre_flag & SRE_FL_ACTIVE && !(srp->sre_flag & SRE_FL_ARMED)){
		sr_fl_arm(srp);
	}
}
/*
 */
static void
sr_add_active_locked(struct SRSFEntry *srp)
{
	debug_printf("sr_add_active        - srp:0x%X\n", srp);

	if (sr_enable == 0)
		goto err;
	if (srp == NULL)
		goto err;
	if (srp->sre_flag & SRE_FL_ACTIVE)
		goto err;
	TAILQ_REMOVE(&sr_list, srp, sre_list);
	srp->sre_flag |= SRE_FL_ACTIVE;
	TAILQ_INSERT_TAIL(&sr_active, srp, sre_list);
err:
	return;

}

static	errno_t
sr_fl_arm(struct SRSFEntry *srp)
{
	int i, j;
	debug_printf("sr_fl_arm        - so:0X%08x srp:0X%08x\n", srp->sre_so, srp);
	if (sr_enable == 0)
		return 0;
	if(srp->sre_flag & SRE_FL_ARMED)
		return EINVAL;
	for(i = 0; i < INPSIRENSMAX ; i++){
		srp->inp_sr[i].sr_qdata = (struct sr_hopdata *)
			OSMalloc(sizeof(struct sr_hopdata) * 256, gOSMallocTag);
		bzero(srp->inp_sr[i].sr_qdata, sizeof(struct sr_hopdata) * 256);
		for(j = 0 ; j < 256 ; j++){
			srp->inp_sr[i].sr_qdata[j].val.set = 0xffffffff;
		}
		srp->inp_sr[i].sr_sdata = (struct sr_hopdata *)
			OSMalloc(sizeof(struct sr_hopdata) * 256, gOSMallocTag);
		bzero(srp->inp_sr[i].sr_sdata, sizeof(struct sr_hopdata) * 256);
		for(j = 0 ; j < 256 ; j++){
			srp->inp_sr[i].sr_sdata[j].val.set = 0xffffffff;
		}		
	}
	srp->sre_flag |= SRE_FL_ARMED;
	return 0;
}


/*
 */
static	errno_t	
sr_setoption_fn(void *cookie, socket_t so, sockopt_t opt)
{
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	debug_printf("sr_setoption_fn   - so: 0x%X, 0x%X %d %d\n", so, srp, sockopt_name(opt), sockopt_valsize(opt));
	int error = 0;
	int tcp = 0;
	int so_domain, so_type, so_protocol;
	if(sock_gettype(so, &so_domain, &so_type, &so_protocol) != 0){
		return EPROTO;
	}
	if(so_domain == AF_INET && so_type == SOCK_STREAM){
		tcp = 1;
	}
	switch(sockopt_name(opt)){
		case IP_ADD_MEMBERSHIP:
		{
			struct ip_mreq mreq;
			debug_printf("Catch add membership");
			error = sockopt_copyin(opt, &mreq, sockopt_valsize(opt));
			if(error) return error;
			if(srp->group.s_addr == INADDR_ANY){
				srp->group.s_addr = mreq.imr_multiaddr.s_addr;
				srp->faddr.s_addr = INADDR_ANY;
			}
			break;
		}
		case IP_DROP_MEMBERSHIP:
		{
			struct ip_mreq mreq;
			debug_printf("Catch drop membership");
			error = sockopt_copyin(opt, &mreq, sockopt_valsize(opt));
			if(error) return error;
			if(srp->group.s_addr == mreq.imr_multiaddr.s_addr){
				srp->group.s_addr = INADDR_ANY;
				srp->faddr.s_addr = INADDR_ANY;
			}
		}	
		case IPSIRENS_IDX:
			/*
			 * Set probe information and areas
			 * opt->val : {sr_ireq, srreq_index[0]..srreq_index[N]}
			 * N: srireq.sr_nindex
			 */
			{
				struct sr_ireq *srireq;
				struct inpcb *inp;
				srireq = (struct sr_ireq *)OSMalloc(IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX), gOSMallocTag);
			
				struct srreq_index *sri = (struct srreq_index *)(srireq + 1);
				mbuf_t data;
				struct ipopt_sr *opt_sr; 
				if(srireq == NULL){
					return(EINVAL);
				}
				if(sockopt_valsize(opt) > IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX)){
					return(EINVAL);
				}
				error = sockopt_copyin(opt, srireq, sockopt_valsize(opt));
				if(sockopt_valsize(opt) != IPSIRENS_IREQSIZE(srireq->sr_nindex)){
					return(EINVAL);
				}
				if(srireq->sr_smax > SIRENSRESLEN){
					return(EINVAL);
				}
				/* set SIRENS flag, and initialize storage in tcpcb */
				/* if connection destination is determined, call ip layer */
				/*
				 if(IPOPTSIRENSLEN(srireq->sr_smax) > MLEN){
				 return(EMSGSIZE);
				 }
				 */

				if (srireq->sr_nindex > 0){
					int i;
					for( i = 0 ; i < srireq->sr_nindex ; i++){
						if(sri[i].qttl_min > sri[i].qttl_max ||
						   sri[i].sttl_min > sri[i].sttl_max ){
							OSFree(srireq, IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX), gOSMallocTag);
							return(EINVAL);
						}
					}
				}
#if 1
				if (mbuf_get(MBUF_DONTWAIT, MBUF_TYPE_DATA, &data) != 0) {
					return(EMSGSIZE);
				}
				opt_sr = (struct ipopt_sr *)mbuf_data(data);
				opt_sr->type = IPOPT_SIRENS;
				opt_sr->len = IPOPTSIRENSLEN(srireq->sr_smax);
				mbuf_setlen(data, IPOPTSIRENSLEN(srireq->sr_smax));
				inp = (struct inpcb *)(((struct socket *)so)->so_pcb);
				debug_printf("sr_setoption_fn   - so: 0x%X, 0x%X 0x%X 0x%X\n", so, inp, &inp->inp_options, (struct mbuf *)data);
#if 0
				debug_printf("From:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}
#endif
				
				error = ip_pcbopts(sockopt_name(opt), (caddr_t)(&inp->inp_options) + 4, (struct mbuf *)data);
#else
#if 0
				debug_printf("From:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}
#endif
				{
					int sodomain, sotype, soprotocol;
					
					sock_gettype(so, &sodomain, &sotype, &soprotocol);
					
					debug_printf("domain: type: %d protocol: %d level:%d\n", sodomain, sotype, soprotocol, sockopt_level(opt));
					
					if((opt_sr =(struct ipopt_sr *) _MALLOC(IPOPTSIRENSLEN(srireq->sr_smax), MT_DATA, M_NOWAIT)) == NULL)
						return(ENOMEM);
					opt_sr->type = IPOPT_SIRENS;
					opt_sr->len = IPOPTSIRENSLEN(srireq->sr_smax);

//					error = sock_setsockopt(so, IPPROTO_IP, IP_OPTIONS, opt_sr, IPOPTSIRENSLEN(srireq->sr_smax));
					error = sock_setsockopt(so, sockopt_level(opt), IP_OPTIONS, opt_sr, IPOPTSIRENSLEN(srireq->sr_smax));

					if(error){
						debug_printf("sr_setoption_fn ipoption header setting ERR: %d \n", error);
					}
				}
#endif
#if 0

				debug_printf("To:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}
#endif
				if (srireq->sr_nindex > 0 && srp->sr_nmax == 0){
					int i;
					srp->sr_qnext = 0;
					srp->sr_snext = 0;
					srp->sr_qttl = 0;
					for( i = 0 ; i < INPSIRENSMAX ; i++){
						srp->inp_sr[i].mode = sri[i].mode;
						srp->inp_sr[i].probe = sri[i].probe;
						srp->inp_sr[i].qmin_ttl = sri[i].qttl_min;
						srp->inp_sr[i].qmax_ttl = sri[i].qttl_max;
						srp->inp_sr[i].smin_ttl = sri[i].sttl_min;
						srp->inp_sr[i].smax_ttl = sri[i].sttl_max;
						srp->inp_sr[i].sr_qdata = NULL;
						srp->inp_sr[i].sr_sdata = NULL;
					}
				/* if sock is connected, to attach SIRENS storage */
					/* && sock_gettype(so, AF_INET, SOCK_STREAM, NULL)*/
					if(sock_isconnected(so)){
						sr_fl_arm(srp);
					}
				/* if sock is binded (UDP), to attach SIRENS storage */
					if(tcp != 1 && (inp->inp_lport || inp->inp_laddr.s_addr != INADDR_ANY)){
						debug_printf("sr_setoption_fn UDP\n");
						sr_fl_arm(srp);
					}
					
				}
				srp->sr_nmax = srireq->sr_nindex;

				lck_mtx_lock(gmutex);	// take the lock so that we can protect against the srp structure access
				sr_add_active_locked(srp);
				lck_mtx_unlock(gmutex);
				
				OSFree(srireq, IPSIRENS_IREQSIZE(IPSIRENS_IREQMAX), gOSMallocTag);
				error = EJUSTRETURN;
			}
			break;
		case IPSIRENS_SDATAX:
		case IPSIRENS_STDATAX:
			/*
			 * Specify dataset to retrieve next getsockopt(s, IPSIRENS_SDATAX) call.
			 * Python's getsockopt()  does not allows to give a paremater set, unlike UNIX.
			 * So, we split getsockopt(s, IPSIRENS_STADA) into two phases,
			 * i.e., to set dataset, and to get dataset. 
			 * opt->val : {sr_dreq}
			 */			
			{
				struct sr_dreq *dreq;

				if(IPSIRENS_DREQSIZE(0) != sockopt_valsize(opt)){
					return(EINVAL);
				}
				if(srp->sr_nmax == 0 || !(srp->sre_flag & SRE_FL_ARMED)){
					return(EINVAL);
				}
				dreq = (struct sr_dreq *)OSMalloc(IPSIRENS_DREQSIZE(0), gOSMallocTag);
				if(dreq == NULL)
					return(ENOMEM);
				error = sockopt_copyin(opt, dreq, IPSIRENS_DREQSIZE(0));
				srp->sr_dreq.dir = dreq->dir;
				srp->sr_dreq.probe = dreq->probe;
				srp->sr_dreq.mode = dreq->mode;
				OSFree(dreq, IPSIRENS_DREQSIZE(0), gOSMallocTag);
				error = EJUSTRETURN;
				break;
			}
			break;
			
		default:
			break;
	}

	return error;
}
/*
 */
static	errno_t
sr_getoption_fn(void *cookie, socket_t so, sockopt_t opt)
{
	int error = 0;
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);

	debug_printf("sr_getoption_fn   - so: 0x%X, 0x%X %d\n", so, srp, sockopt_name(opt));

	switch(sockopt_name(opt)){
		case IPSIRENS_IDX:
			error = EINVAL;
			break;
		case IPSIRENS_SDATAX:
		case IPSIRENS_STDATAX:
			/*
			 * Retrieve dataset specified previous setsockopt(s, IPSIRENS_SDATAX) call.
			 * opt->val : {u_sr_dreq[256]}
			 * opt->val : {sr_hopdata[256]}
			 */
		{
			char *dreq;
			int i, j;        
			struct timeval now;
			struct sr_timeval expire;
			struct sr_hopdata *thopdata;
			union u_sr_data *sr_data;
			struct sr_hopdata *hopdata;
			int dreqsize;

			switch(sockopt_name(opt)){
				case IPSIRENS_SDATAX:
					dreqsize = 256 * sizeof(union u_sr_data);
					break;
				case IPSIRENS_STDATAX:
					dreqsize = 256 * sizeof(struct sr_hopdata);
					break;
				default:
					return(EINVAL);
			}
			
			if(dreqsize != sockopt_valsize(opt)){
				return(EINVAL);
			}
			if(srp->sr_nmax == 0 || !(srp->sre_flag & SRE_FL_ARMED)){
				return(EINVAL);
			}
			dreq = (char *)OSMalloc(dreqsize, gOSMallocTag);
			sr_data = (union u_sr_data*)dreq;
			hopdata = (struct sr_hopdata*)dreq;
			if(sr_data == NULL)
				return(ENOMEM);
			for(i = 0 ; i < srp->sr_nmax ; i++){
				if(srp->inp_sr[i].mode == srp->sr_dreq.mode
				   && srp->inp_sr[i].probe == srp->sr_dreq.probe) break;
			}
			if( i == srp->sr_nmax){
				OSFree(dreq, dreqsize, gOSMallocTag);
				return(EINVAL);
			}
			switch(srp->sr_dreq.dir){
				case 1:
					thopdata = srp->inp_sr[i].sr_qdata;
					break;
				case 2:
				default:
					thopdata = srp->inp_sr[i].sr_sdata;
					break;
			}			
			switch(sockopt_name(opt)){
				case IPSIRENS_SDATAX:
					microtime(&now);
					expire.tv_sec = now.tv_sec - SR_TIMEOUT;
					expire.tv_usec = now.tv_usec;
			/* omit old data */
					for(j = 0 ; j < 256 ; j++){
						if(sr_timeval_compare(&expire, &thopdata[j].tv) < 0){
							sr_data[j] = thopdata[j].val;
						} else {
							sr_data[j].set = -1;
						}
					}
					break;
				case IPSIRENS_STDATAX:
					memcpy(hopdata, thopdata, sizeof(struct sr_hopdata) * 256);
					break;
				default:
					OSFree(dreq, dreqsize, gOSMallocTag);
					return(EINVAL);
					break;
			}
			error = sockopt_copyout(opt, sr_data, dreqsize);
			OSFree(dreq, dreqsize, gOSMallocTag);
			if (error)
				return(error);
			error = EJUSTRETURN;
		}
			break;
		case IPSIRENS_SDATA:
		case IPSIRENS_STDATA:
			/*
			 * Retrieve dataset specified in given parameters.
			 * given: opt->val : {sr_dreq}
			 * return: opt->cal : {sr_dreq, u_sr_data[256]} when SDATA
			 * return: opt->cal : {sr_dreq, sr_hopdata[256]} when STDATA
			 */	
		{
			struct sr_dreq *dreq;
			int i, j;
			struct timeval now;
			struct sr_timeval expire;
			struct sr_hopdata *thopdata;
			union u_sr_data *sr_data;
			struct sr_hopdata *hopdata;
			int dreqsize = 0;

			if(IPSIRENS_DREQSIZE(0) > sockopt_valsize(opt)){
				return(EINVAL);
			}
			switch(sockopt_name(opt)){
				case IPSIRENS_SDATA:
					dreqsize = IPSIRENS_DREQSIZE(256);
					break;
				case IPSIRENS_STDATA:
					dreqsize = IPSIRENS_DTREQSIZE(256);
					break;
				default:
					return(EINVAL);
			}

			dreq = (struct sr_dreq *)OSMalloc(dreqsize, gOSMallocTag);
			if(dreq == NULL)
				return(ENOMEM);
			sr_data = (union u_sr_data*)((char *)dreq + sizeof(struct sr_dreq));
			hopdata = (struct sr_hopdata*)((char *)dreq + sizeof(struct sr_dreq));
			if(srp->sr_nmax == 0 || !(srp->sre_flag & SRE_FL_ARMED)){
				dreq->dir = 255;
				dreq->mode = 255;
				dreq->probe = 255;
				error = sockopt_copyout(opt, dreq, IPSIRENS_DREQSIZE(0));
				OSFree(dreq, dreqsize, gOSMallocTag);
				return(error);
			}
			error = sockopt_copyin(opt, dreq, sockopt_valsize(opt));
			for(i = 0 ; i < srp->sr_nmax ; i++){
				if(srp->inp_sr[i].mode == dreq->mode
					&& srp->inp_sr[i].probe == dreq->probe) break;
			}
			if( i == srp->sr_nmax){
				OSFree(dreq, dreqsize, gOSMallocTag);
				return(EINVAL);
			}
			switch(dreq->dir){
				case 1:
					thopdata = srp->inp_sr[i].sr_qdata;
					break;
				case 2:
				default:
					thopdata = srp->inp_sr[i].sr_sdata;
					break;
			}
			switch(sockopt_name(opt)){
				case IPSIRENS_SDATA:
					microtime(&now);
					expire.tv_sec = now.tv_sec - SR_TIMEOUT;
					expire.tv_usec = now.tv_usec;
			/* omit old data */
					for(j = 0 ; j < 256 ; j++){
						if(sr_timeval_compare(&expire, &thopdata[j].tv) < 0){
							sr_data[j] = thopdata[j].val;
						} else {
							sr_data[j].set = -1; /* invalid */
						}
					}
					break;
				case IPSIRENS_STDATA:
					memcpy(hopdata, thopdata, sizeof(struct sr_hopdata) * 256);
//					for(j = 0 ; j < 256 ; j++){
//						hopdata[j].val = thopdata[j].val;
//						hopdata[j].tv = thopdata[j].tv;
//					}
					break;
				default:
					OSFree(dreq, dreqsize, gOSMallocTag);
					return(EINVAL);
					break;
			}
			error = sockopt_copyout(opt, dreq, sockopt_valsize(opt));
			OSFree(dreq, dreqsize, gOSMallocTag);
			if (error)
				return(error);
			error = EJUSTRETURN;
		}
			break;
		default:
			break;
	}
	return error;
}

/*
 */
static	errno_t
sr_accept_fn(void *cookie, socket_t so_listen, socket_t so, struct sockaddr *local, struct sockaddr *remote)
{
	struct SRSFEntry *srp = SRSFEntryFromCookie(cookie);
	struct SRSFEntry *lsrp, *nsrp = NULL;
	int i;

	debug_printf("sr_accept_fn   - so_listen: 0x%X, srp: 0x%X so: 0x%X ", so_listen, srp, so);
	/* search active lsit */
	for( lsrp = TAILQ_FIRST(&sr_active); lsrp; lsrp = nsrp){
		if(lsrp->sre_so == so_listen)
			break;
		nsrp = TAILQ_NEXT(lsrp, sre_list);
	}
	
	if(lsrp == NULL || !(lsrp->sre_flag & SRE_FL_ACTIVE) || lsrp->sr_nmax == 0)
		return 0;

	srp->sr_nmax = lsrp->sr_nmax;
	srp->sr_qnext = 0;
	srp->sr_snext = 0;
	srp->sr_qttl = 0;
	for( i = 0 ; i < INPSIRENSMAX ; i++){
		srp->inp_sr[i].mode = lsrp->inp_sr[i].mode;
		srp->inp_sr[i].probe = lsrp->inp_sr[i].probe;
		srp->inp_sr[i].qmin_ttl = lsrp->inp_sr[i].qmin_ttl;
		srp->inp_sr[i].qmax_ttl = lsrp->inp_sr[i].qmax_ttl;
		srp->inp_sr[i].smin_ttl = lsrp->inp_sr[i].smin_ttl;
		srp->inp_sr[i].smax_ttl = lsrp->inp_sr[i].smax_ttl;
		srp->inp_sr[i].sr_qdata = NULL;
		srp->inp_sr[i].sr_sdata = NULL;
	}
	sr_fl_arm(srp);
	lck_mtx_lock(gmutex);	// take the lock so that we can protect against the srp structure access
	sr_add_active_locked(srp);
	lck_mtx_unlock(gmutex);	
	return 0;
}

/* =================================== */
#pragma mark SIRENS Filter Definition

/* Dispatch vector for SIRENS socket functions */
static struct sflt_filter sr_sflt_ip4_tcp = {
	SIRENS_HANDLE4TCP,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL | SFLT_EXTENDED,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	sr_unregistered_fn,		/* sf_unregistered_func */
	sr_attach_fn,			/* sf_attach_func - cannot be nil else param err results */			
	sr_detach_fn,			/* sf_detach_func - cannot be nil else param err results */
	NULL,					/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	NULL,					/* sf_data_in_func */
	NULL,					/* sf_data_out_func */
	sr_connect_in_fn,		/* sf_connect_in_func */
	sr_connect_out_fn,		/* sf_connect_out_func */
	NULL,					/* sf_bind_func */
	sr_setoption_fn,		/* sf_setoption_func */
	sr_getoption_fn,		/* sf_getoption_func */
	NULL,					/* sf_listen_func */
	NULL					/* sf_iocsr_func */
/*	sr_accept_fn			is in extension part in filter */
};
static struct sflt_filter sr_sflt_ip4_udp = {
	SIRENS_HANDLE4UDP,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	sr_unregistered_fn,		/* sf_unregistered_func */
	sr_attach_fn,			/* sf_attach_func - cannot be nil else param err results */			
	sr_detach_fn,			/* sf_detach_func - cannot be nil else param err results */
	NULL,					/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	NULL,					/* sf_data_in_func */
	NULL,					/* sf_data_out_func */
	sr_connect_in_fn,		/* sf_connect_in_func */
	sr_connect_out_fn,		/* sf_connect_out_func */
	sr_bind_fn,				/* sf_bind_func */
	sr_setoption_fn,		/* sf_setoption_func */
	sr_getoption_fn,		/* sf_getoption_func */
	NULL,					/* sf_listen_func */
	NULL					/* sf_iocsr_func */
	/*	sr_accept_fn			is in extension part in filter */
};


/* Dispatch vector for SIRENS socket functions */
static struct sflt_filter sr_sflt_ip6_tcp = {
	SIRENS_HANDLE6TCP,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	sr_unregistered_fn,		/* sf_unregistered_func */
	sr_attach_fn,			/* sf_attach_func - cannot be nil else param err results */			
	sr_detach_fn,			/* sf_detach_func - cannot be nil else param err results */
	NULL,					/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	NULL,					/* sf_data_in_func */
	NULL,					/* sf_data_out_func */
	sr_connect_in_fn,		/* sf_connect_in_func */
	sr_connect_out_fn,		/* sf_connect_out_func */
	NULL,					/* sf_bind_func */
	sr_setoption_fn,		/* sf_setoption_func */
	sr_getoption_fn,		/* sf_getoption_func */
	NULL,					/* sf_listen_func */
	NULL					/* sf_iocsr_func */
	/*	sr_accept_fn			is in extension part in filter */
};
static struct sflt_filter sr_sflt_ip6_udp = {
	SIRENS_HANDLE6UDP,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	sr_unregistered_fn,		/* sf_unregistered_func */
	sr_attach_fn,			/* sf_attach_func - cannot be nil else param err results */			
	sr_detach_fn,			/* sf_detach_func - cannot be nil else param err results */
	NULL,					/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	NULL,					/* sf_data_in_func */
	NULL,					/* sf_data_out_func */
	sr_connect_in_fn,		/* sf_connect_in_func */
	sr_connect_out_fn,		/* sf_connect_out_func */
	NULL,					/* sf_bind_func */
	sr_setoption_fn,		/* sf_setoption_func */
	sr_getoption_fn,		/* sf_getoption_func */
	NULL,					/* sf_listen_func */
	NULL					/* sf_iocsr_func */
	/*	sr_accept_fn			is in extension part in filter */
};

static	errno_t
sr_ipf_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	errno_t	ret = 0;
	errno_t status;
	struct sr_mbuf_tag *tag_ref;
	size_t	len;
	struct ipopt_sr *opt_sr = NULL;
	struct ip *iph;
	struct inpcb *inp;
	struct SRSFEntry *srp = NULL, *nsrp = NULL;
	boolean_t local = FALSE;
	
	iph = (struct ip*) mbuf_data(*data);
	
	if(mbuf_pkthdr_rcvif(*data) == NULL
	   || mbuf_pkthdr_rcvif(*data) == ifunit("lo0")){
		local = TRUE;
	}

	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status == KERN_SUCCESS){
		debug_printf("sr_ipf_output: found a tag len %x: %x %x %x : pktlen = %x, local = %x\n",
						 len, tag_ref->len, tag_ref->offset, tag_ref->opt_sr.req_data.set, mbuf_pkthdr_len(*data), local);
	}
	opt_sr = ip_sirens_dooptions_d(*data, 0);
#if 1
	/*
	 * not a forwarding packet
	 * Have a tag
	 * ICMP protocol
	 * not have SIRENS option
	 */
	if(local == TRUE && status == 0 && iph->ip_p == IPPROTO_ICMP && opt_sr == NULL){
		char buffer[sizeof(struct ip) + MAXIPOPTSIRENSLEN];
		mbuf_copydata(*data, 0, iph->ip_hl << 2, buffer);
		if(mbuf_prepend(data, tag_ref->opt_sr.len, MBUF_DONTWAIT) != 0){
			return EJUSTRETURN;
		}
		iph = (struct ip*)buffer;
		bcopy(&tag_ref->opt_sr, buffer + (iph->ip_hl << 2), tag_ref->opt_sr.len);
		
		iph->ip_hl = iph->ip_hl + (tag_ref->opt_sr.len >> 2);
		iph->ip_len = htons(ntohs(iph->ip_len) + tag_ref->opt_sr.len);
		if(mbuf_copyback(*data, 0, (iph->ip_hl << 2), buffer, MBUF_DONTWAIT)){
			return EJUSTRETURN;
		}
		return;
	}
#endif
	if(opt_sr == NULL)
		goto out;

//	debug_printf("ipf_output proto %d\n", iph->ip_p, IPPROTO_UDP);
	
	switch (iph->ip_p) {
		case IPPROTO_UDP:
		{
			struct udphdr *up, uh;
			up = &uh;
			mbuf_copydata(*data, iph->ip_hl << 2, sizeof(uh), up);
			/**/
			for(srp = TAILQ_FIRST(&sr_active); srp ; srp = nsrp){
				nsrp = TAILQ_NEXT(srp, sre_list);
				inp = (struct inpcb *)(((struct socket *)(srp->sre_so))->so_pcb);
								debug_printf("pkt: %2x %08x %08x %04x %04x\n",
											 iph->ip_p, iph->ip_dst, iph->ip_src, up->uh_sport, up->uh_dport);				
								debug_printf("flt: %2x %08x %08x %04x %04x\n",
											 inp->inp_ip_p, inp->inp_laddr, inp->inp_faddr, inp->inp_lport, inp->inp_fport);
//				if(IN_MULTICAST(ntohl(iph->ip_dst.s_addr))){
					if((inp->inp_vflag == INP_IPV4)
					   && local
					   && (inp->inp_faddr.s_addr == INADDR_ANY)
					   && (inp->inp_lport == up->uh_sport))
						break;
//				}else {
					if((inp->inp_vflag == INP_IPV4)
					   && (inp->inp_laddr.s_addr == iph->ip_src.s_addr)
					   && (inp->inp_faddr.s_addr == iph->ip_dst.s_addr)
					   && (inp->inp_lport == up->uh_sport)
					   && (inp->inp_fport == up->uh_dport))
						break;
//				}
			}
		}
			break;
		case IPPROTO_TCP:
			{
				struct tcphdr *tp, th;
				tp = &th;
				mbuf_copydata(*data, iph->ip_hl << 2, sizeof(th), tp);
			/**/
				for(srp = TAILQ_FIRST(&sr_active); srp ; srp = nsrp){
					nsrp = TAILQ_NEXT(srp, sre_list);
					inp = (struct inpcb *)(((struct socket *)(srp->sre_so))->so_pcb);
				
//				debug_printf("%2x %08x %08x %04x %04x\n",
//							 iph->ip_p, iph->ip_dst, iph->ip_src, tp->th_dport, tp->th_sport);				
//				debug_printf("%2x %08x %08x %04x %04x\n",
//							 inp->inp_ip_p, inp->inp_laddr, inp->inp_faddr, inp->inp_lport, inp->inp_fport);
					if((inp->inp_vflag == INP_IPV4)
					   && (inp->inp_laddr.s_addr == iph->ip_src.s_addr)
					   && (inp->inp_faddr.s_addr == iph->ip_dst.s_addr)
					   && (inp->inp_lport == tp->th_sport)
					   && (inp->inp_fport == tp->th_dport))
						break;
				}
			}
			break;
		default:
			break;
	}
	
	if(srp != NULL){
		debug_printf("found outgoing flow so:0x%08x %d %d\n", srp->sre_so, srp->sr_nmax, srp->sre_flag);
	}
	
	if(srp != NULL && srp->sr_nmax > 0 && srp->sre_flag & SRE_FL_ARMED){
		int reslen, j;
		union u_sr_data *resdata;
		u_int qttl, sttl;
		srp->sr_qnext %= srp->sr_nmax;
		qttl = srp->sr_qttl;
		qttl++;
		if(qttl > (u_int)srp->inp_sr[srp->sr_qnext].qmax_ttl || qttl > 255){
			srp->sr_qnext++;
			srp->sr_qnext %= srp->sr_nmax;
			qttl = srp->inp_sr[srp->sr_qnext].qmin_ttl;
		}
		if(qttl < (u_int)srp->inp_sr[srp->sr_qnext].qmin_ttl) {
			qttl = srp->inp_sr[srp->sr_qnext].qmin_ttl;
		}
		srp->sr_qttl = qttl;
		opt_sr->req_mode = srp->inp_sr[srp->sr_qnext].mode;
		opt_sr->req_probe = srp->inp_sr[srp->sr_qnext].probe;
		opt_sr->req_ttl = qttl;
		opt_sr->req_data.set = -1;
		
		reslen = IPOPTLENTORESLEN(opt_sr->len);
		
		srp->sr_snext %= srp->sr_nmax;
		sttl = srp->sr_sttl;
		if(sttl > srp->inp_sr[srp->sr_snext].smax_ttl || sttl > 255){
			srp->sr_snext++;
			srp->sr_snext %= srp->sr_nmax;
			sttl = srp->inp_sr[srp->sr_snext].smin_ttl;
		}
		if(sttl < srp->inp_sr[srp->sr_snext].smin_ttl) {
			sttl = srp->inp_sr[srp->sr_snext].smin_ttl;
		}
		opt_sr->res_mode = srp->inp_sr[srp->sr_snext].mode;
		opt_sr->res_probe = srp->inp_sr[srp->sr_snext].probe;
		opt_sr->res_ttl = sttl;
		resdata = (union u_sr_data *)(opt_sr + 1);
		
		//				debug_printf("output: start lock\n");
		
		lck_mtx_lock(gmutex); 
		for(j = 0 ; j < reslen ; j++){
			struct timeval now;
			struct sr_timeval expire;
			/* stack onto responce data */
			microtime(&now);
			expire.tv_sec = now.tv_sec - SR_TIMEOUT;
			expire.tv_usec = now.tv_usec;
			if( sr_timeval_compare(&expire, &srp->inp_sr[srp->sr_snext].sr_qdata[sttl + j].tv) < 0 &&
			   j + sttl <= srp->inp_sr[srp->sr_snext].smax_ttl &&
			   (sttl + j) < 255){
				resdata[j] = srp->inp_sr[srp->sr_snext].sr_qdata[sttl + j].val;
			}else{
				resdata[j].set = -1;
			}
		}
		lck_mtx_unlock(gmutex);
		srp->sr_sttl = sttl + j;
	}
	
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(!status){
		goto out;
	}
	if(opt_sr->req_mode == SIRENS_TTL
	   && !(opt_sr->req_probe & SIRENS_DIR_IN)
	   && iph->ip_ttl == opt_sr->req_ttl){
		printf("sr_ipf_output: allocate tag for post-processing on outgoing if\n");
		status = mbuf_tag_allocate(*data, gsr_idtag, SR_TAG_TYPE, 4 * sizeof(int), MBUF_WAITOK, (void**)&tag_ref);
		if(status == 0){
			tag_ref->len = ntohs(iph->ip_len);
			tag_ref->offset = (caddr_t)opt_sr - (caddr_t)iph;
			bcopy(opt_sr, &tag_ref->opt_sr, sizeof(struct ipopt_sr));
		}
	}
out:
	return ret;
}

static errno_t
sr_ipf_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol){
	errno_t	ret = 0;
	errno_t status;
	struct sr_mbuf_tag *tag_ref;
	size_t	len;
	struct ipopt_sr *opt_sr = NULL;
	struct ip *iph;
	struct inpcb *inp;
	struct SRSFEntry *srp = NULL, *nsrp = NULL;

	/* Take fast path, if there is no IP option */
	if(offset == sizeof(struct ip)){
		goto out;
	}

	iph = (struct ip*) mbuf_data(*data);
	opt_sr = ip_sirens_dooptions_d(*data, 0);
	if(opt_sr == NULL)
			goto out;

	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status == 0) {
		debug_printf("sr_ipf_input: found tag!\n");
		goto in;
	}
	
	if((opt_sr->req_mode == SIRENS_TTL)
	   && (iph->ip_ttl == opt_sr->req_ttl)){
		ifnet_t interface;
		debug_printf("sr_ipf_input: match TTL update hdr data and re-compute IP checksum TTL:%x:%x probe:%x\n",
					 iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_probe);
		
		interface = mbuf_pkthdr_rcvif(*data);
		if(interface == NULL) goto in;
		if(opt_sr->req_probe & SIRENS_DIR_IN){
			sr_setparam(opt_sr, interface, &(((struct SRIFEntry *)cookie)->srif_storage));
		}
	}
	status = mbuf_tag_allocate(*data, gsr_idtag, SR_TAG_TYPE, sizeof(struct ipopt_sr), MBUF_WAITOK, (void**)&tag_ref);
	if(status == 0){
		debug_printf("sr_ipf_input: allocate tag!\n");
		tag_ref->len = ntohs(iph->ip_len);
		tag_ref->offset = (caddr_t)opt_sr - (caddr_t)iph;
		bcopy(opt_sr, &tag_ref->opt_sr, sizeof(struct ipopt_sr));
	}
in:
	switch (iph->ip_p) {
		case IPPROTO_ICMP:
		{
			debug_printf("sr_ipf_input: ICMP and SIRENS!\n");
			srp = NULL;
		}
			break;
		case IPPROTO_UDP:
		{
			struct ip_moptions      *imo;
			struct udphdr *up, uh;
			up = &uh;
			mbuf_copydata(*data, iph->ip_hl << 2, sizeof(uh), up);
			/**/
			for(srp = TAILQ_FIRST(&sr_active); srp ; srp = nsrp){
				nsrp = TAILQ_NEXT(srp, sre_list);
				inp = (struct inpcb *)(((struct socket *)(srp->sre_so))->so_pcb);
#if 1
				debug_printf("pkt: %2x %08x %08x %04x %04x\n",
							 iph->ip_p, iph->ip_src, iph->ip_dst, up->uh_sport, up->uh_dport);				
				debug_printf("flt: %2x %08x %08x %04x %04x\n",
							 inp->inp_ip_p, inp->inp_faddr, inp->inp_laddr, inp->inp_fport, inp->inp_lport);	
				debug_printf("srp:     %08x %08x %08x\n",
							 srp->faddr.s_addr, srp->group.s_addr, srp->sre_flag);		
#endif				
				if((inp->inp_vflag == INP_IPV4)
//				   && (inp->inp_ip_p == iph->ip_p)
				   && (inp->inp_laddr.s_addr == iph->ip_dst.s_addr)
				   && (inp->inp_faddr.s_addr == iph->ip_src.s_addr)
				   && (inp->inp_lport == up->uh_dport)
				   && (inp->inp_fport == up->uh_sport))
					break;
				if((inp->inp_vflag == INP_IPV4)
				   && (srp->group.s_addr == iph->ip_dst.s_addr)
				   && (srp->faddr.s_addr == iph->ip_src.s_addr)
				   && (inp->inp_lport == up->uh_dport)){				   
					break;
				}
				if((inp->inp_vflag == INP_IPV4)
				   && (srp->group.s_addr == iph->ip_dst.s_addr)
				   && (inp->inp_lport == up->uh_dport)){
					srp->faddr.s_addr = iph->ip_src.s_addr;
					break;
				}
			}
			if(srp != NULL)
				debug_printf("sr_ipf_input: match SRF and UDP PCB!\n");
		}
			break;
		case IPPROTO_TCP:
			{
				struct tcphdr *tp, th;
				tp = &th;
				mbuf_copydata(*data, iph->ip_hl << 2, sizeof(th), tp);
/**/
				for(srp = TAILQ_FIRST(&sr_active); srp ; srp = nsrp){
					nsrp = TAILQ_NEXT(srp, sre_list);
					inp = (struct inpcb *)(((struct socket *)(srp->sre_so))->so_pcb);
					if((inp->inp_vflag == INP_IPV4)
//					   && (inp->inp_ip_p == iph->ip_p)
					   && (inp->inp_laddr.s_addr == iph->ip_dst.s_addr)
					   && (inp->inp_faddr.s_addr == iph->ip_src.s_addr)
					   && (inp->inp_lport == tp->th_dport)
					   && (inp->inp_fport == tp->th_sport))
						break;
				}
			}
			break;
		default:
			srp = NULL;
			break;
	}
	if(srp != NULL && srp->sr_nmax > 0 && srp->sre_flag & SRE_FL_ARMED){
		int j, i, n;
		struct timeval now;
		union u_sr_data *sr_data;
		
		getmicrotime(&now);
		for( j = 0 ; j < srp->sr_nmax ; j++){
			debug_printf("ipf_input %08x:%08x %08x:%08x\n", srp->inp_sr[j].mode, opt_sr->req_mode, srp->inp_sr[j].probe, opt_sr->req_probe);
			if(srp->inp_sr[j].mode == opt_sr->req_mode
			   && srp->inp_sr[j].probe == opt_sr->req_probe)
				break;
		}
		lck_mtx_lock(gmutex);
		if( j == srp->sr_nmax ) goto skip_req;
		srp->inp_sr[j].sr_qdata[opt_sr->req_ttl].tv.tv_sec = now.tv_sec;
		srp->inp_sr[j].sr_qdata[opt_sr->req_ttl].tv.tv_usec = now.tv_usec;
		srp->inp_sr[j].sr_qdata[opt_sr->req_ttl].val = opt_sr->req_data;
skip_req:
		if((n = IPOPTLENTORESLEN(opt_sr->len)) == 0 )
			goto skip_res;
		for( j = 0 ; j < srp->sr_nmax ; j++){
			if(srp->inp_sr[j].mode == opt_sr->res_mode
			   && srp->inp_sr[j].probe == opt_sr->res_probe)
				break;
		}
		if( j == srp->sr_nmax ) goto skip_res;
		sr_data = (union u_sr_data *)(opt_sr + 1);
		for( i = 0 ; i < n ; i++){
			if(opt_sr->res_ttl + i > 255) break;
			srp->inp_sr[j].sr_sdata[opt_sr->res_ttl + i].tv.tv_sec = now.tv_sec;
			srp->inp_sr[j].sr_sdata[opt_sr->res_ttl + i].tv.tv_usec = now.tv_usec;
			srp->inp_sr[j].sr_sdata[opt_sr->res_ttl + i].val = sr_data[i];
		}
skip_res:
		lck_mtx_unlock(gmutex);		
	}
out:
	return ret;
}

static void
sr_ipf_detach_func(cookie)
{
	return;
}

/* Dispatch vector for SIRENS IP functions */
static struct ipf_filter sr_ipf_filter = {
	&sr_enable,				/* cookie */
	MYBUNDLEID,				/* name		*/
	sr_ipf_input,			/* ipf_input_func	*/
	sr_ipf_output,			/* ipf_output_func	*/
	sr_ipf_detach_func		/* ipf_detach_func	*/
};

static void
sr_remove_locked(struct SRSFEntry *srp)
{
	if (srp == NULL)
		goto err;

	if(srp->sre_flag & SRE_FL_ACTIVE){
		TAILQ_REMOVE(&sr_active, srp, sre_list);
		srp->sre_flag &= ~SRE_FL_ACTIVE;
	}else {
		TAILQ_REMOVE(&sr_list, srp, sre_list);
	}
	if(srp->sre_flag & SRE_FL_ARMED){
		int i;
		for( i = 0; i < INPSIRENSMAX ; i++){
			OSFree(srp->inp_sr[i].sr_qdata, 
				   sizeof(struct sr_hopdata) * 256, gOSMallocTag);
			OSFree(srp->inp_sr[i].sr_sdata, 
				   sizeof(struct sr_hopdata) * 256, gOSMallocTag);
		}
	}
	OSFree(srp, sizeof(struct SRSFEntry), gOSMallocTag);
	sr_count--;	
err:
	return;
}

static void
sr_remove(struct SRSFEntry *srp)
{
	debug_printf("sr_remove       - so: 0x%X\n", srp->sre_so);
	
	lck_mtx_lock(gmutex);    
    sr_remove_locked(srp);
	lck_mtx_unlock(gmutex);
		
	return;
}

#define SIRENS_DSIZE 32

int sr_setparam (struct ipopt_sr *opt_sr, ifnet_t interface, struct sr_storage *srp) {
	int error = 0;
//	struct sr_storage *srp;
#if SIRENS_DSIZE > 16
	uint32_t data = 0;
#else
	u_int16_t e1 = 0, e2 = 0;
#endif
	switch(opt_sr->req_probe){
		default:
			break;
	}
	/* getting if info */
	if(interface == NULL){
		data = ~0;
		goto update;
	}
#ifdef __APPLE__
	{
		struct ifnet_stats_param stats;
		if(srp->array[opt_sr->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[opt_sr->req_probe].data;
		} else {
			ifnet_stat(interface, &stats);
			switch ((opt_sr->req_probe) & ~SIRENS_DIR_IN){
				case SIRENS_LINK:
					data = (u_int32_t) (ifnet_baudrate(interface)/ 1000000);
					break;
				case SIRENS_OBYTES:
					data = (u_int32_t) (stats.bytes_out);
					break;
				case SIRENS_IBYTES:
					data = (u_int32_t) (stats.bytes_in);
				break;
				case SIRENS_DROPS:
					data = (u_int32_t) (stats.dropped);
					break;
				case SIRENS_ERRORS:
					data = (u_int32_t) (stats.dropped);
					break;
//				case SIRENS_QMAX:
//					data = (u_int32_t) (ifp->if_snd.ifq_maxlen);
//					break;
//				case SIRENS_QLEN:
//					data = (u_int32_t) (ifp->if_snd.ifq_len);
//					break;
				case SIRENS_MTU:
					data = (u_int32_t) (ifnet_mtu(interface));
					break;
				default:
					data = ~0;
					break;
			}
		}
	}
#else
	srs_update ++;
	IF_AFDATA_LOCK(ifp);
	srp = (struct sr_storage *)(ifp->if_sr);
#ifdef SR_DEBUG
	printf("probe%d %d %d\n", opt_sr->req_probe, srp->array[srh->req_probe].flag, srp->array[srh->req_probe].data);
#endif
	if(srp->array[opt_sr->req_probe].flag == IPSR_VAR_VALID){
		data = (u_int32_t) srp->array[opt_sr->req_probe].data;
	} else {
		switch ((opt_sr->req_probe) & ~SIRENS_DIR_IN){
			case SIRENS_LINK:
				data = (u_int32_t) (ifp->if_baudrate / 1000000);
				break;
			case SIRENS_OBYTES:
				data = (u_int32_t) (ifp->if_obytes);
				break;
			case SIRENS_IBYTES:
				data = (u_int32_t) (ifp->if_ibytes);
				break;
			case SIRENS_DROPS:
				data = (u_int32_t) (ifp->if_snd.ifq_drops);
				break;
			case SIRENS_ERRORS:
				data = (u_int32_t) (ifp->if_oerrors);
				break;
			case SIRENS_QMAX:
				data = (u_int32_t) (ifp->if_snd.ifq_maxlen);
				break;
			case SIRENS_QLEN:
				data = (u_int32_t) (ifp->if_snd.ifq_len);
				break;
			case SIRENS_MTU:
				data = (u_int32_t) (ifp->if_mtu);
				break;
			default:
				data = ~0;
				break;
		}
	}
	IF_AFDATA_UNLOCK(ifp);
#endif
update:
	switch(opt_sr->req_mode){
		case SIRENS_TTL:
			opt_sr->req_data.set = htonl(data);
			break;
		case SIRENS_MIN:
			opt_sr->req_ttl = opt_sr->req_ttl == 0 ? 0xff : opt_sr->req_ttl - 1;
			if(data == ~0) return error;
			if( data < opt_sr->req_data.set ){
				opt_sr->req_data.set = htonl(data);
			}
			break;
		case SIRENS_MAX:
			opt_sr->req_ttl = opt_sr->req_ttl == 0 ? 0xff : opt_sr->req_ttl - 1;
			if(data == ~0) return error;
			if( data >  opt_sr->req_data.set ){
				opt_sr->req_data.set = htonl(data);
			}
			break;
		default:
			break;
	}
	return error;
}
static u_int16_t
in_update_csum(u_int16_t original, u_int16_t old, u_int16_t new){
	u_int32_t tmp;
//	debug_printf("%4x %4x %4x\n", ~original, ~old, new);
	tmp = ((~original)& 0xffff) + ((~old) & 0xffff) + new;
	tmp = (tmp & 0xffff) + (tmp >> 16);
	return((u_int16_t)((~tmp) & 0xffff));
}
static errno_t
sr_iff_ioctl_fn(void *cookie,
				ifnet_t interface, 
				protocol_family_t protocol,
				unsigned long ioctl_cmd,
				void *ioctl_arg){
	int error = ENOTSUP;/* continue to normal process */
//	debug_printf("SIRENSNKE:ioctl_fn: called iff_ioctl_fn %d\n", ioctl_cmd);
	switch(ioctl_cmd){
	case SIOCSSRVAR:
        {
			struct if_srvarreq *ifsrr = (struct if_srvarreq *)ioctl_arg;
			struct sr_storage *srp;
			int idx = ifsrr->sr_probe &0xFF;
			srp = &(((struct SRIFEntry *)cookie)->srif_storage);
			switch(ifsrr->sr_var.flag){
                case IPSR_VAR_VALID:
					srp->array[idx].data = ifsrr->sr_var.data;
					srp->array[idx].flag = ifsrr->sr_var.flag;
//					 debug_printf("SIOCSSRVAR %d %d %d %d\n", ifsrr->sr_probe, idx, srp->array[idx].data, srp->array[idx].flag);
					break;
                case IPSR_VAR_INVAL:
					srp->array[idx].flag = ifsrr->sr_var.flag;
					break;
                default:
					return(EINVAL);
			}
			error = 0;
			break;
        }
	case SIOCGSRVAR:
        {
			struct if_srvarreq *ifsrr = (struct if_srvarreq *)ioctl_arg;
			struct sr_storage *srp;
			int idx = ifsrr->sr_probe & 0xFF;
			srp = &(((struct SRIFEntry *)cookie)->srif_storage);
//			debug_printf("SIOCGSRVAR %d %d %d %d\n", ifsrr->sr_probe, idx, srp->array[idx].data, srp->array[idx].flag);
			ifsrr->sr_var.data = srp->array[idx].data;
			ifsrr->sr_var.flag = srp->array[idx].flag;
			error = 0;
			break;
        }
		
	}
	return error; 
}
/* 
 * XXX: ad-hoc SIRENS header traversal is problematic.
 * XXX: Preserving input interface info. using mbuf_tag
 * XXX: enables post-update on iff_out() phase.
 */
static errno_t
sr_iff_in_fn( void *cookie,
			 ifnet_t interface, 
			 protocol_family_t protocol,
			 mbuf_t *data,
			 char **frame_ptr)
{
	size_t len;
	struct ether_header *eh = (struct ether_header *)*frame_ptr;
	int error = 0;
	int status;
	struct sr_mbuf_tag *tag_ref;
	struct ip *iph = NULL;
	struct ipopt_sr *opt_sr = NULL;
	if(sr_enable == 0 ) return error;
	if(protocol != AF_INET)
		return error;
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status == 0){
		return error;
		/* XXX: or remove */
	}	
	switch(ifnet_type(interface)){
		case IFT_ETHER:
		{
			/* seek 0x800 */
			/* seek VLAN tag */
			/* seek LLC/SNAP */			
			/* Strip ARP and non-IP packets out of the list */
			switch (htons(eh->ether_type)) {
				case ETHERTYPE_IP:
					iph = (struct ip*)(eh + 1);
					if((iph->ip_hl << 2) < sizeof(struct ip) + sizeof(struct ipopt_sr)){
						return error;
					}
					//				debug_printf("Longer IP header %d %d %d\n", iph->ip_hl << 2, sizeof(struct ip), sizeof(struct ipopt_sr));
#if 0
					mbuf_pkthdr_setheader(*data, *frame_ptr);
					error = mbuf_pullup(data, sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ipopt_sr));
					if(error) return error;
					*frame_ptr = mbuf_pkthdr_header(*data);
					mbuf_pkthdr_setheader(*data, NULL);
					eh = (struct ether_header *)*frame_ptr;
					iph = (struct ip*)(eh + 1);
#else
					if(mbuf_len(*data) < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct ipopt_sr)){
						printf("sirens input: should mbuf_pullup hear!!\n");
						return;
					}
#endif
					/*
					opt_sr = (struct ipopt_sr*)(iph + 1);
					if(opt_sr->type != IPOPT_SIRENS || opt_sr->len < sizeof(struct ipopt_sr)){
						return;
					}
					 */
					opt_sr = ip_sirens_dooptions_d(*data, 0);
					if(opt_sr == NULL)
						return;
					//				debug_printf("%08x %08x %d %d\n", iph, opt_sr, iph->ip_ttl, mbuf_len(*data));					
					break;
				default:
					return error;
					break;
			}
			if(eh->ether_type == htons(ETHERTYPE_IP)){
			}
		}
			break;
		default:
			return error;
			break;
	}
//	opt_sr = ip_sirens_dooptions_d(iph);
	if(opt_sr == NULL || iph == NULL)
		return error;
//	debug_printf("inspect:%08x %08x %d %d %d\n", iph, opt_sr, iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_mode);
	if(opt_sr->req_mode != SIRENS_TTL
	   || iph->ip_ttl != opt_sr->req_ttl){
		return error;
	}
	/* Prevent duplicate tag */
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status == 0) {
		debug_printf("sirens if-filter input: found tag!\n");
		goto in;
	}
	
	if(interface == NULL) goto in;
	if(opt_sr->req_probe & SIRENS_DIR_IN){
		u_int32_t tmp, tcksum;
		debug_printf("sirens if-input: match TTL update TTL:%x:%x probe:%x from: %x\n",
					 iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_probe, ntohl(opt_sr->req_data.set));
		tcksum = ntohl(opt_sr->req_data.set);
		if(!sr_setparam(opt_sr, interface, &(((struct SRIFEntry *)cookie)->srif_storage))){
#if 0
			debug_printf("re-compute checksum from %04x\n", ntohs(iph->ip_sum));
			tmp = ((~ntohs(iph->ip_sum) & 0xffff)
				   + ((~tcksum) & 0xffff)
				   + ((~(tcksum >> 16)) & 0xffff)
				   + (ntohl(opt_sr->req_data.set) & 0xffff)
				   + (ntohl(opt_sr->req_data.set) >> 16));
			debug_printf("%08x %08x %08x %08x %08x %08x\n",
						 (~ntohs(iph->ip_sum)) & 0xffff,
						 (~tcksum) & 0xffff,
						 (~(tcksum) >> 16) & 0xffff,
						 ntohl(opt_sr->req_data.set) & 0xffff,
						 ntohl(opt_sr->req_data.set) >> 16,
						 tmp);
			tmp = (tmp & 0xffff) + (tmp >> 16);

			iph->ip_sum = htons((~tmp) & 0xffff);
#else
			tmp = in_update_csum(ntohs(iph->ip_sum), (u_int16_t)(tcksum & 0xffff), (u_int16_t)(ntohl(opt_sr->req_data.set) & 0xffff));

//			debug_printf("1: %04x %04x\n",tmp, (~tmp)& 0xffff);
			
			tmp = in_update_csum((u_int16_t)tmp, (u_int16_t)(tcksum >> 16), (u_int16_t)(ntohl(opt_sr->req_data.set) >> 16));
//			debug_printf("2: %04x %04x\n",tmp, (~tmp)& 0xffff);
			iph->ip_sum = htons(tmp);
//			debug_printf("re-compute checksum to %04x\n", ntohs(iph->ip_sum));
#endif

		}
		debug_printf("sirens if-input: to: %08x\n", ntohl(opt_sr->req_data.set));
	}else{
		debug_printf("sirens if-input: unchange data:%08x\n", opt_sr->req_data.set);
	}
	status = mbuf_tag_allocate(*data, gsr_idtag, SR_TAG_TYPE, sizeof(struct ipopt_sr), MBUF_WAITOK, (void**)&tag_ref);
	if(status == 0){
		tag_ref->len = ntohs(iph->ip_len);
//		tag_ref[1] = sizeof(struct ip);
//		tag_ref->offset = iph->ip_hl << 2;
		tag_ref->offset = (caddr_t)opt_sr - (caddr_t)iph;
		bcopy(opt_sr, &tag_ref->opt_sr, sizeof(struct ipopt_sr));
	}else{
		return status;
	}
in:
	return error;
}
/*
 * iff_input() and ipf_output() give a tag in case header modification is required on outgoing if.
 */
static errno_t
sr_iff_out_fn (void *cookie,
			   ifnet_t interface,
			   protocol_family_t protocol,
			   mbuf_t *data)
{
	size_t	len;
	int status;
	int pktlen;
	int error = 0;
	struct sr_mbuf_tag *tag_ref;
	struct ip *iph;
	struct ipopt_sr *opt_sr = NULL;
	u_int32_t *qp;
//	int i;
	
	if(sr_enable == 0 ) return error;
	if(protocol != AF_INET)
		return error;
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status != 0){
		return error;
	}
	pktlen = mbuf_pkthdr_len(*data);
	if(pktlen < tag_ref->len){
		debug_printf("iff_out_fn: found tag but error %x < %x\n", pktlen, tag_ref->len);
		return error;
	}
	error = mbuf_pullup(data, pktlen - tag_ref->len + sizeof (struct ip) + sizeof(struct ipopt_sr));
	if(error){
		debug_printf("found tag but pullup %x %x\n", pktlen, tag_ref->len);
		return error;
	}
	qp = (u_int32_t *)(mbuf_data(*data));
	iph = (struct ip *)((caddr_t)qp + pktlen - tag_ref->len);
//	for( i = 0 ; i < (pktlen - *tag_ref + sizeof (struct ip) + sizeof(struct ipopt_sr))/4  + 2 ; i ++){
//		printf("%08x ", ntohl(qp[i]));
//	}
//	printf("\n");

	opt_sr = (struct ipopt_sr*)((caddr_t)iph + tag_ref->offset);
#if 1
	if(iph->ip_p == IPPROTO_ICMP){
		{
			int hlen;
			u_int16_t csum;
			hlen = iph->ip_hl << 2;
			iph->ip_sum = 0;
			mbuf_inet_cksum(*data, 0, pktlen - tag_ref->len, hlen, &csum);
			iph->ip_sum = csum;
		}
		error = mbuf_pullup(data, pktlen - tag_ref->len + sizeof (struct ip) + sizeof(struct ipopt_sr));
		if(error){
			debug_printf("iff_out_fn: pullup error %x %x\n", pktlen, tag_ref->len);
			return error;
		}		
		qp = (u_int32_t *)(mbuf_data(*data));
		iph = (struct ip *)((caddr_t)qp + pktlen - tag_ref->len);
		opt_sr = (struct ipopt_sr*)((caddr_t)iph + tag_ref->offset);
	}
#endif
//	if(opt_sr->req_data.set == tag_ref->opt_sr.req_data.set){
	if( (opt_sr->req_mode == SIRENS_TTL)
	   && (iph->ip_ttl == opt_sr->req_ttl)){
		debug_printf("sirens output: match TTL update TTL:%x:%x probe:%x from: %x\n",
					 iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_probe, ntohl(opt_sr->req_data.set));
		debug_printf("re-compute checksum from %04x\n", ntohs(iph->ip_sum));
		{
			u_int32_t tmp, tcksum;
			tcksum = ntohl(opt_sr->req_data.set);
			if(!sr_setparam(opt_sr, interface, &(((struct SRIFEntry *)cookie)->srif_storage) )){
				tmp = in_update_csum(ntohs(iph->ip_sum), (u_int16_t)(tcksum & 0xffff), (u_int16_t)(ntohl(opt_sr->req_data.set) & 0xffff));
				tmp = in_update_csum((u_int16_t)tmp, (u_int16_t)(tcksum >> 16), (u_int16_t)(ntohl(opt_sr->req_data.set) >> 16));
				iph->ip_sum = htons(tmp);
			}
		}
		debug_printf("sirens output: to: %08x\n", ntohl(opt_sr->req_data.set));
	}else{
		printf("sirens output : data %08x -> %08x\n", tag_ref->opt_sr.req_data.set, opt_sr->req_data.set);
	}
	return error;
}

static void
sr_iff_detached_fn( void *cookie, ifnet_t interface)
{
	return;
}
#if 0
static struct iff_filter sr_iff_filter = { 
    &sr_enable,
    MYBUNDLEID,
	0,
	sr_iff_in_fn,
	sr_iff_out_fn,
	NULL,
	NULL,
	sr_iff_detached_fn
};
#endif
/* =================================== */
extern int
jp_hpcc_ikob_kext_sirensnke_start(kmod_info_t *ki, void *data)
{	
	int				ret = 0;
	ifnet_t			*ifnetp;
	u_int32_t ifcount;
	SRIFEntry *srifp;
	int i;
	
	printf("SIRENS_start\n");
	
	if (sirens_initted)
		return 0;

	ret = alloc_locks();
	if (ret)
		goto err;

	sr_enable = 1;
	
	// initialize the queues which we are going to use.
	TAILQ_INIT(&sr_list);
	TAILQ_INIT(&sr_active);
	TAILQ_INIT(&sr_iflist);
	
	gOSMallocTag = OSMalloc_Tagalloc(MYBUNDLEID, OSMT_DEFAULT);
	// don't want the flag set to OSMT_PAGEABLE since
	// it would indicate that the memory was pageable.
	if (gOSMallocTag == NULL)
		goto err;	
	
	// set up the tag value associated with this NKE in preparation for swallowing packets and re-injecting them
	ret = mbuf_tag_id_find(MYBUNDLEID , &gsr_idtag);
	if (ret != 0)
	{
		printf("mbuf_tag_id_find returned error %d\n", ret);
		goto err;
	}
		
	/* Later extension part of filter */
	sr_sflt_ip4_tcp.sf_len = sizeof(struct sflt_filter_ext);
	sr_sflt_ip4_tcp.sf_accept = (sf_accept_func) sr_accept_fn;
	
	bzero(&sr_sflt_ip4_udp.sf_ext, sizeof(sr_sflt_ip4_udp.sf_ext));
	bzero(&sr_sflt_ip6_tcp.sf_ext, sizeof(sr_sflt_ip6_tcp.sf_ext));
	bzero(&sr_sflt_ip6_udp.sf_ext, sizeof(sr_sflt_ip6_udp.sf_ext));

	// register the filter with AF_INET domain, SOCK_STREAM type, TCP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_ip4_tcp, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	debug_printf("sflt_register returned result %d for ip4 TCP filter.\n", ret);
	if (ret == 0)
		gFReged_ip4_tcp = TRUE;
	else
		goto err;

	// register the filter with AF_INET domain, SOCKDGRAM type, UDP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_ip4_udp, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	debug_printf("sflt_register returned result %d for ip4 UDP filter.\n", ret);
	if (ret == 0)
		gFReged_ip4_udp = TRUE;
	else
		goto err;

	// register the filter with AF_INET6 domain, SOCK_STREAM type, TCP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_ip6_tcp, PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	debug_printf("sflt_register returned result %d for ip6 TCP filter.\n", ret);
	if (ret == 0)
		gFReged_ip6_tcp = TRUE;
	else
		goto err;

	// register the filter with AF_INET6 domain, SOCK_DGRAM type, TCP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_ip6_udp, PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	debug_printf("sflt_register returned result %d for ip6 UDP filter.\n", ret);
	if (ret == 0)
		gFReged_ip6_udp = TRUE;
	else
		goto err;
	
	ret = ipf_addv4(&sr_ipf_filter, &sr_ipf_ref);
	if (ret == 0)
		gipFilterRegistered = TRUE;
	else
		goto err;
	
	ret = ifnet_list_get(IFNET_FAMILY_ANY, &ifnetp, &ifcount);
	if(ret != 0 ) goto err;

	for(i = 0; i < ifcount; i++){
		if(strncmp(ifnet_name(ifnetp[i]), "lo", 2) == 0)
			continue;
		srifp = (struct SRIFEntry *)OSMalloc(sizeof (struct SRIFEntry), gOSMallocTag);
		if(srifp == NULL){
			ifnet_list_free(ifnetp);
			goto err;
		}
		bzero(srifp, sizeof(struct SRIFEntry));
		srifp->srif_filter.iff_cookie = (void *)srifp;
		srifp->srif_filter.iff_name = MYBUNDLEID;
		srifp->srif_filter.iff_protocol = 0;
		srifp->srif_filter.iff_input = sr_iff_in_fn;
		srifp->srif_filter.iff_output = sr_iff_out_fn;
		srifp->srif_filter.iff_event = NULL;
		srifp->srif_filter.iff_ioctl = sr_iff_ioctl_fn;
		srifp->srif_filter.iff_detached = sr_iff_detached_fn;
		TAILQ_INSERT_TAIL(&sr_iflist, srifp, srif_list);
		ret = iflt_attach(ifnetp[i], &(srifp->srif_filter), &(gsr_if_filter[i]));
//		ret = iflt_attach(ifnetp[i], &sr_iff_filter, &(gsr_if_filter[i]));
		if(ret == 0){
			gifFilterRegistered++;
			debug_printf("SIRENS filter is registered on \"%s%d\"\n", ifnet_name(ifnetp[i]), ifnet_unit(ifnetp[i]));
		}
	}
	ifnet_list_free(ifnetp);

	sirens_initted = TRUE;
	
	return KERN_SUCCESS;
	
err:
	if (gFReged_ip4_tcp){
		sflt_unregister(SIRENS_HANDLE4TCP);
	}
	if (gFReged_ip4_udp){
		sflt_unregister(SIRENS_HANDLE4UDP);
	}	
	if(gFReged_ip6_tcp){
		sflt_unregister(SIRENS_HANDLE6TCP);
	}
	if(gFReged_ip6_udp){
		sflt_unregister(SIRENS_HANDLE6UDP);
	}	
	if (gipFilterRegistered){
		ipf_remove(sr_ipf_ref);
	}
	if (gifFilterRegistered){
		for(i = 0 ; i < gifFilterRegistered ; i++){
			iflt_detach(gsr_if_filter[i]);
		}
		for(srifp = TAILQ_FIRST(&sr_iflist) ; srifp ; srifp = TAILQ_FIRST(&sr_iflist)){
			TAILQ_REMOVE(&sr_iflist, srifp, srif_list);
			OSFree(srifp, sizeof(struct SRIFEntry), gOSMallocTag);
		}		
	}
	free_locks();
	return KERN_FAILURE;
}

/*
 */

extern int
jp_hpcc_ikob_kext_sirensnke_flush()
{
	int ret = 0;
	SRIFEntry *srifp;
	if ((!gFReged_ip4_tcp
		 && !gFReged_ip4_udp
		 && !gFReged_ip6_tcp
		 && !gFReged_ip6_udp
		 && !gipFilterRegistered
		 && gifFilterRegistered == 0))
		return KERN_SUCCESS;
	
	if (!sirens_initted)
		return KERN_SUCCESS;
	lck_mtx_lock(gmutex);
	if(sr_enable) {
		lck_mtx_unlock(gmutex);
		return EBUSY;
	}
	lck_mtx_unlock(gmutex);
	lck_mtx_lock(gmutex);
	if (sr_count > 0) {
		debug_printf("sirensnke_flush busy, sr_count: %d\n", sr_count);
		ret = EBUSY;
		lck_mtx_unlock(gmutex);
		goto err;
	}
	lck_mtx_unlock(gmutex);
	
	if (gUnreg_started_ip4_tcp == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE4TCP);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip4 TCP %d\n", ret);
		else {
			gUnreg_started_ip4_tcp = TRUE;	// indicate that we've started the unreg process.
		}
	}
	if (gUnreg_started_ip4_udp == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE4UDP);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip4 UDP %d\n", ret);
		else {
			gUnreg_started_ip4_udp = TRUE;	// indicate that we've started the unreg process.
		}
	}	
	if (gUnreg_started_ip6_tcp == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE6TCP);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip6 TCP %d\n", ret);
		else {
			gUnreg_started_ip6_tcp = TRUE;	// indicate that we've started the unreg process.
		}
	}
	if (gUnreg_started_ip6_udp == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE6UDP);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip6 %d\n", ret);
		else {
			gUnreg_started_ip6_udp = TRUE;	// indicate that we've started the unreg process.
		}
	}	
	if (gipFilterRegistered == TRUE) {
		ret = ipf_remove(sr_ipf_ref);
		if (ret != 0)
			debug_printf( "sirensnke_flush: ipflt_unregister failed for ip4 %d\n", ret);
		else {
			gipFilterRegistered = FALSE;	// indicate that we've started the unreg process.
		}			
	}
	
	if (gifFilterRegistered){
		int i;
		for(i = 0 ; i < gifFilterRegistered ; i++){
			iflt_detach(gsr_if_filter[i]);
		}
		for(srifp = TAILQ_FIRST(&sr_iflist) ; srifp ; srifp = TAILQ_FIRST(&sr_iflist)){
			TAILQ_REMOVE(&sr_iflist, srifp, srif_list);
			OSFree(srifp, sizeof(struct SRIFEntry), gOSMallocTag);
		}
	}
	
	if ((gUnreg_complete_ip4_tcp &&
		 gUnreg_complete_ip4_udp &&
		 gUnreg_complete_ip6_tcp &&
		 gUnreg_complete_ip6_udp &&
		 !(gipFilterRegistered &&
		 (gifFilterRegistered == 0)))){
		ret = KERN_SUCCESS;
	} else {
		printf( "sirensnke: sirensnke_flush: failed unload again\n");
		ret = KERN_FAILURE;
	}
	
	if (ret == KERN_SUCCESS) {
		free_locks();
		if (gOSMallocTag) {
			OSMalloc_Tagfree(gOSMallocTag);
			gOSMallocTag = NULL;
		}
	}
err:
	printf("jp_hpcc_ikob_sirens_kext_stop end %d\n", ret);
	return ret;
	
}
extern int
jp_hpcc_ikob_kext_sirensnke_stop(kmod_info_t *ki, void *data)
{	
	int	ret = 0;

#if 0
	struct SRSFEntry *srp, *srpnext = NULL;
#endif
	
	if ((!gFReged_ip4_tcp 
		 && !gFReged_ip4_udp
		 && !gFReged_ip6_tcp
		 && !gFReged_ip6_udp 
		 && !gipFilterRegistered))
		return KERN_SUCCESS;
	
	if (!sirens_initted)
		return KERN_SUCCESS;

	lck_mtx_lock(gmutex);
	sr_enable = 0;
	lck_mtx_unlock(gmutex);
	
	debug_printf("sirensnke_stop - \n");
	
	lck_mtx_lock(gmutex);
#if 0
	for (srp = TAILQ_FIRST(&sr_list); srp; srp = srpnext) {
		srpnext = TAILQ_NEXT(srp, sre_list);
		sr_remove_locked(srp);
	}
	for (srp = TAILQ_FIRST(&sr_active); srp; srp = srpnext) {
		srpnext = TAILQ_NEXT(srp, sre_list);
		sr_remove_locked(srp);
	}
#endif
	lck_mtx_unlock(gmutex);
	
	ret = jp_hpcc_ikob_kext_sirensnke_flush();
	
	printf("jp_hpcc_ikob_sirens_kext_stop end %d\n", ret);
	return ret;
}

static errno_t alloc_locks(void)
{
	errno_t			result = 0;
	gmutex_grp = lck_grp_alloc_init(MYBUNDLEID, LCK_GRP_ATTR_NULL);
	if (gmutex_grp == NULL)
	{
		debug_printf("error calling lck_grp_alloc_init\n");
		result = ENOMEM;
	}
	
	if (result == 0)
	{
		gmutex = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
		if (gmutex == NULL)
		{
			debug_printf("error calling lck_mtx_alloc_init\n");
			result = ENOMEM;
		}
	}
	
	return result;	// if we make it here, return success
}

struct ipopt_sr *
ip_sirens_dooptions_d(mbuf_t data, size_t offset)
{
	struct ip *ip;
	u_char *cp;
	int opt, optlen, cnt, code;
/* XXX: unsafe, need mbuf_pulup */
	ip = (struct ip*) (mbuf_data(data) + offset);
	
	cp = (u_char *)(ip + 1);
	cnt = (ip->ip_hl << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
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
			{
				struct ipopt_sr *opt_sr = (struct ipopt_sr *)cp;
				
				if(cp[IPOPT_OLEN] < sizeof(struct ipopt_sr)
				   || MAXIPOPTSIRENSLEN < cp[IPOPT_OLEN]){
					code = &cp[IPOPT_OLEN] - (u_char *)ip;
					goto bad;
				}
				return(opt_sr);
			}
				break;
		}
	}
	return (NULL);
bad:
//	icmp_error(m, type, code, 0, 0);
//	ipstat.ips_badoptions++;
	return (NULL);
}

#define MAX_IPOPTLEN    40
struct ipoption {
	struct  in_addr ipopt_dst;      /* first-hop dst if source routed */
	char    ipopt_list[MAX_IPOPTLEN];       /* options proper */
};


static void free_locks(void)
{
	if (gmutex)
	{
		lck_mtx_free(gmutex, gmutex_grp);
		gmutex = NULL;
	}
	if (gmutex_grp)
	{
		lck_grp_free(gmutex_grp);
		gmutex_grp = NULL;
	}
}


