/*
 * Copyright (c) 2009 Katsushi Kobayashi
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
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/kpi_ipfilter.h>

#include <net/if_var.h>
#include <netinet/ip_sirens.h>


struct ipopt_sr *ip_sirens_dooptions_d(mbuf_t);


#define DEBUG	1

#define SIRENS_HANDLE4 0x696b6f62		/* Temp hack to identify this filter */
#define SIRENS_HANDLE6 0x696b6f64
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

static boolean_t	gFilterRegistered = FALSE;
static boolean_t	gUnregisterProc_started = FALSE;
static boolean_t	gUnregisterProc_complete = FALSE;

static boolean_t	gFilterRegistered_ip6 = FALSE;
static boolean_t	gUnregisterProc_started_ip6 = FALSE;
static boolean_t	gUnregisterProc_complete_ip6 = FALSE;

static boolean_t	gipFilterRegistered = FALSE;

static interface_filter_t	gsr_if_filter[256];
static int	gifFilterRegistered = 0;


/* List of sockets */
static struct sr_sflist sr_list;				// protected by gmutex
static struct sr_sflist sr_active;

/* Protect consistency of our data at entry points */
static lck_mtx_t		*gmutex = NULL;				// used to protect the sr_list queues
static lck_grp_t		*gmutex_grp = NULL;

/* Tag to assign jp.hpcc.ikob.kext.sirens */
static mbuf_tag_id_t	gsr_idtag;

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
};
#define SRE_FL_NONE		0
#define	SRE_FL_ACTIVE	1
#define	SRE_FL_ARMED	2

typedef struct SRSFEntry  SRSFEntry;

#define kSRSFEntryMagic		0xAABBCCDD

TAILQ_HEAD(sr_sflist, SRSFEntry);

#define kInvalidUnit	0xFFFFFFFF

static ipfilter_t sr_ipf_ref = NULL;

static void  sr_remove(struct SRSFEntry *srp);
static void	 debug_printf(const char *fmt, ...);
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
		case SIRENS_HANDLE4:
			gUnregisterProc_complete = TRUE;
			gFilterRegistered = FALSE;
			break;
		case SIRENS_HANDLE6:
			gUnregisterProc_complete_ip6 = TRUE;
			gFilterRegistered_ip6 = FALSE;
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
	int i;
	debug_printf("sr_fl_arm        - so:0X%08x srp:0X%08x\n", srp->sre_so, srp);
	if (sr_enable == 0)
		return 0;
	if(srp->sre_flag & SRE_FL_ARMED)
		return EINVAL;
	for(i = 0; i < INPSIRENSMAX ; i++){
		srp->inp_sr[i].sr_qdata = (struct sr_hopdata *)
			OSMalloc(sizeof(struct sr_hopdata) * 256, gOSMallocTag);
		bzero(srp->inp_sr[i].sr_qdata, sizeof(struct sr_hopdata) * 256);
		srp->inp_sr[i].sr_sdata = (struct sr_hopdata *)
			OSMalloc(sizeof(struct sr_hopdata) * 256, gOSMallocTag);
		bzero(srp->inp_sr[i].sr_sdata, sizeof(struct sr_hopdata) * 256);		
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
	switch(sockopt_name(opt)){			
		case IPSIRENS_IDX:
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

				debug_printf("From:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}

				error = ip_pcbopts(sockopt_name(opt), (caddr_t)(&inp->inp_options) + 4, (struct mbuf *)data);
#else
				debug_printf("From:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}
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

				debug_printf("To:\n");
				{
					int i;
					u_int32_t *dp = (u_int32_t *)inp;
					for(i = 0 ; i < 64 ; i++){
						debug_printf("%08x ", dp[i]);
					}
					debug_printf("\n");
				}
/* if sock is connected, to provide SIRENS state */
				
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
					if(sock_isconnected(so)){
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
		{
			int i, j;        
			struct timeval tv;
			struct sr_hopdata *thopdata;
			union u_sr_data *sr_data;

			if(256 * sizeof(union u_sr_data) != sockopt_valsize(opt)){
				return(EINVAL);
			}
			if(srp->sr_nmax == 0 || !(srp->sre_flag & SRE_FL_ARMED)){
				return(EINVAL);
			}
			sr_data = (union u_sr_data*) OSMalloc(256 * sizeof(union u_sr_data), gOSMallocTag);			
			if(sr_data == NULL)
				return(ENOMEM);
			for(i = 0 ; i < srp->sr_nmax ; i++){
				if(srp->inp_sr[i].mode == srp->sr_dreq.mode
				   && srp->inp_sr[i].probe == srp->sr_dreq.probe) break;
			}
			if( i == srp->sr_nmax){
				OSFree(sr_data, 256 * sizeof(union u_sr_data), gOSMallocTag);
				return(EINVAL);
			}
			microtime(&tv);
			tv.tv_sec -= 2;
			switch(srp->sr_dreq.dir){
				case 1:
					thopdata = srp->inp_sr[i].sr_qdata;
					break;
				case 2:
				default:
					thopdata = srp->inp_sr[i].sr_sdata;
					break;
			}
			for(j = 0 ; j < 256 ; j++){
				if(timevalcmp(&tv, &thopdata[j].tv, <)){
					sr_data[j] = thopdata[j].val;
				} else {
					sr_data[j].set = -1;
				}
			}
			error = sockopt_copyout(opt, sr_data, 256 * sizeof(union u_sr_data));
			OSFree(sr_data, 256 * sizeof(union u_sr_data), gOSMallocTag);
			if (error)
				return(error);
			error = EJUSTRETURN;
		}
			break;
		case IPSIRENS_SDATA:
		{
			struct sr_dreq *dreq;
			int i, j;
			struct timeval tv;
			struct sr_hopdata *thopdata;
			union u_sr_data *sr_data;
			if(IPSIRENS_DREQSIZE(0) > sockopt_valsize(opt)){
				return(EINVAL);
			}
			dreq = (struct sr_dreq *)OSMalloc(IPSIRENS_DREQSIZE(256), gOSMallocTag);
			if(dreq == NULL)
				return(ENOMEM);
			sr_data = (union u_sr_data*)((char *)dreq + sizeof(struct sr_dreq));
			if(srp->sr_nmax == 0 || !(srp->sre_flag & SRE_FL_ARMED)){
				dreq->dir = 255;
				dreq->mode = 255;
				dreq->probe = 255;
				error = sockopt_copyout(opt, dreq, IPSIRENS_DREQSIZE(0));
				OSFree(dreq, IPSIRENS_DREQSIZE(256), gOSMallocTag);
				return(error);
			}
			error = sockopt_copyin(opt, dreq, IPSIRENS_DREQSIZE(256));
			for(i = 0 ; i < srp->sr_nmax ; i++){
				if(srp->inp_sr[i].mode == dreq->mode
					&& srp->inp_sr[i].probe == dreq->probe) break;
			}
			if( i == srp->sr_nmax){
				OSFree(dreq, IPSIRENS_DREQSIZE(256), gOSMallocTag);
				return(EINVAL);
			}
			microtime(&tv);
			tv.tv_sec -= 2;
			switch(dreq->dir){
				case 1:
					thopdata = srp->inp_sr[i].sr_qdata;
					break;
				case 2:
				default:
					thopdata = srp->inp_sr[i].sr_sdata;
					break;
			}
			for(j = 0 ; j < 256 ; j++){
				if(timevalcmp(&tv, &thopdata[j].tv, <)){
					sr_data[j] = thopdata[j].val;
				} else {
					sr_data[j].set = -1;
				}
			}
			error = sockopt_copyout(opt, dreq, IPSIRENS_DREQSIZE(256));
			OSFree(dreq, IPSIRENS_DREQSIZE(256), gOSMallocTag);
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
static struct sflt_filter sr_sflt_filter = {
	SIRENS_HANDLE4,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
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

/* Dispatch vector for SIRENS socket functions */
static struct sflt_filter sr_sflt_filter_ip6 = {
	SIRENS_HANDLE6,			/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
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

static	errno_t
sr_ipf_output(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
	errno_t	ret = 0;
	errno_t status;
	int *tag_ref;
	size_t	len;
	struct ipopt_sr *opt_sr = NULL;
	struct tcphdr *tp, th;
	struct ip *iph;
	struct inpcb *inp;
	struct SRSFEntry *srp, *nsrp = NULL;	
	
	opt_sr = ip_sirens_dooptions_d(*data);
	if(opt_sr == NULL)
			goto out;

//	debug_printf("ipf_output found SIRENS\n");
	iph = (struct ip*) mbuf_data(*data);

	switch (iph->ip_p) {
		case IPPROTO_TCP:
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
				/* how to determine upper layer protocol from inpcb ???? */
				if((inp->inp_vflag == INP_IPV4)
				   &&(inp->inp_laddr.s_addr == iph->ip_src.s_addr)
				   && (inp->inp_faddr.s_addr == iph->ip_dst.s_addr)
				   && (inp->inp_lport == tp->th_sport)
				   && (inp->inp_fport == tp->th_dport))
					break;
			}
			if(srp == NULL)
				break;
//			debug_printf("found outgoing flow so:0x%08x %d %d\n", srp->sre_so, srp->sr_nmax, srp->sre_flag);
			
			if(srp->sr_nmax > 0 && srp->sre_flag & SRE_FL_ARMED){
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
				for(j = 0 ; j < reslen; j++){
					struct timeval tv;
					/* stack onto responce data */
					microtime(&tv);
					timevalsub(&tv, &srp->inp_sr[srp->sr_snext].sr_qdata[sttl].tv);
					if(tv.tv_sec < 2 &&
						   j + sttl <= srp->inp_sr[srp->sr_snext].smax_ttl &&
						   sttl < 255){
						resdata[j] = srp->inp_sr[srp->sr_snext].sr_qdata[sttl].val;
					}else{
						resdata[j].set = -1;
					}
				}
				lck_mtx_unlock(gmutex);
				srp->sr_sttl = sttl + j;
			}
			break;
		default:
			break;
	}
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(!status){
		goto out;
	}
	if(opt_sr->req_mode == SIRENS_TTL
	   && !(opt_sr->req_probe & SIRENS_DIR_IN)
	   && iph->ip_ttl == opt_sr->req_ttl){
		status = mbuf_tag_allocate(*data, gsr_idtag, SR_TAG_TYPE, 4 * sizeof(int), MBUF_WAITOK, (void**)&tag_ref);
		if(status == 0){
			tag_ref[0] = mbuf_pkthdr_len(*data);
			tag_ref[1] = (caddr_t)opt_sr - (caddr_t)iph;
			tag_ref[2] = opt_sr->req_data.set;
		}
	}
out:
	return ret;
}

static errno_t
sr_ipf_input(void *cookie, mbuf_t *data, int offset, u_int8_t protocol){
	errno_t	ret = 0;
	errno_t status;
	int *tag_ref;
	size_t	len;
	struct ipopt_sr *opt_sr = NULL;
	struct tcphdr *tp, th;
	struct ip *iph;
	struct inpcb *inp;
	struct SRSFEntry *srp, *nsrp = NULL;

	/* Take fast path, if there is no IP option */
	if(offset == sizeof(struct ip)){
		goto in; 
	}

	opt_sr = ip_sirens_dooptions_d(*data);
	if(opt_sr == NULL)
			goto in;

//	debug_printf("ipf_input found SIRENS\n");
	iph = (struct ip*) mbuf_data(*data);
	switch (iph->ip_p) {
		case IPPROTO_TCP:
			tp = &th;
			mbuf_copydata(*data, iph->ip_hl << 2, sizeof(th), tp);
/**/
			for(srp = TAILQ_FIRST(&sr_active); srp ; srp = nsrp){
				nsrp = TAILQ_NEXT(srp, sre_list);
				inp = (struct inpcb *)(((struct socket *)(srp->sre_so))->so_pcb);
				if((inp->inp_vflag == INP_IPV4)
				   && (inp->inp_laddr.s_addr == iph->ip_dst.s_addr)
				   && (inp->inp_faddr.s_addr == iph->ip_src.s_addr)
				   && (inp->inp_lport == tp->th_dport)
				   && (inp->inp_fport == tp->th_sport))
					break;
			}
			if(srp == NULL)
				break;
			if(srp->sr_nmax > 0 && srp->sre_flag & SRE_FL_ARMED){
				int j, i, n;
				struct timeval tv;
				union u_sr_data *sr_data;
				
				getmicrotime(&tv);
				for( j = 0 ; j < srp->sr_nmax ; j++){
					if(srp->inp_sr[j].mode == opt_sr->req_mode
					   && srp->inp_sr[j].probe == opt_sr->req_probe)
						break;
                }
				lck_mtx_lock(gmutex);
                if( j == srp->sr_nmax ) goto skip_req;
                srp->inp_sr[j].sr_qdata[opt_sr->req_ttl].tv = tv;
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
					srp->inp_sr[j].sr_sdata[opt_sr->res_ttl + i].tv = tv;
					srp->inp_sr[j].sr_sdata[opt_sr->res_ttl + i].val = sr_data[i];
                }
skip_res:
				lck_mtx_unlock(gmutex);
/* allocate tag for later process */
			}
			break;
		default:
			break;
	}
	
	/* Prevent duplicate tag */
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status == 0) {
		debug_printf("ipf_input: found tag!\n");
		goto in;
	}
	if(opt_sr->req_mode == SIRENS_TTL
	   && iph->ip_ttl == opt_sr->req_ttl){
		ifnet_t interface;
//		debug_printf("sirens input: match TTL update hdr data and re-compute IP checksum TTL:%x:%x probe:%x\n",
//					 iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_probe);
		interface = mbuf_pkthdr_rcvif(*data);
		if(opt_sr->req_probe & SIRENS_DIR_IN && interface){
			if(!sr_setparam(opt_sr, interface)){
				u_int32_t tmp;
				tmp = (~ntohs(iph->ip_sum) & 0xffff
					   + ~tag_ref[2] & 0xffff 
					   + ~(tag_ref[2] >> 16) & 0xffff
					   + opt_sr->req_data.set & 0xffff
					   + opt_sr->req_data.set >> 16);
				tmp = tmp & 0xffff + tmp >> 16;
				tmp = ~tmp;
				iph->ip_sum = htons((u_int16_t)tmp);
			}
		}else{
/* tag for later use */
			status = mbuf_tag_allocate(*data, gsr_idtag, SR_TAG_TYPE, 4 * sizeof(int), MBUF_WAITOK, (void**)&tag_ref);
			if(status == 0){
				if(status == 0){
					tag_ref[0] = mbuf_pkthdr_len(*data);
					tag_ref[1] = (caddr_t)opt_sr - (caddr_t)iph;
					tag_ref[2] = opt_sr->req_data.set;
				}
			}
		}
	}
	goto in;
in:
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

int sr_setparam (struct ipopt_sr *opt_sr, ifnet_t interface) {
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
//			case SIRENS_QMAX:
//				data = (u_int32_t) (ifp->if_snd.ifq_maxlen);
//				break;
//			case SIRENS_QLEN:
//				data = (u_int32_t) (ifp->if_snd.ifq_len);
//				break;
			case SIRENS_MTU:
				data = (u_int32_t) (ifnet_mtu(interface));
				break;
			default:
				data = ~0;
				break;
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

static errno_t
sr_iff_out_fn (void *cookie, ifnet_t interface, protocol_family_t protocol, mbuf_t *data)
{
	size_t	len;
	int status;
	int pktlen;
	int error = 0;
	int *tag_ref;
	struct ip *iph;
	struct ipopt_sr *opt_sr = NULL;
	u_int32_t *qp;
	int i;
	
	status = mbuf_tag_find(*data, gsr_idtag, SR_TAG_TYPE, &len, (void**)&tag_ref);
	if(status != 0){
		return error;
	}
	pktlen = mbuf_pkthdr_len(*data);
	if(pktlen < tag_ref[0]){
		debug_printf("found tag but error %x < %x\n", pktlen, *tag_ref);
		return error;
	}
	error = mbuf_pullup(data, pktlen - *tag_ref + sizeof (struct ip) + sizeof(struct ipopt_sr));
	if(error){
		debug_printf("found tag but pullup %x %x\n", pktlen, *tag_ref);
		return error;
	}
	qp = (u_int32_t *)(mbuf_data(*data));
	iph = (struct ip *)((caddr_t)qp + pktlen - *tag_ref);
//	for( i = 0 ; i < (pktlen - *tag_ref + sizeof (struct ip) + sizeof(struct ipopt_sr))/4  + 2 ; i ++){
//		printf("%08x ", ntohl(qp[i]));
//	}
//	printf("\n");

	opt_sr = (struct ipopt_sr*)((caddr_t)iph + tag_ref[1]);
	
	if(opt_sr->req_data.set == tag_ref[2]){
//	debug_printf("sirens output: match TTL update hdr data and re-compute IP checksum TTL:%x:%x probe:%x\n",
//					 iph->ip_ttl, opt_sr->req_ttl, opt_sr->req_probe);
		if(!sr_setparam(opt_sr, interface)){
			u_int32_t tmp;
			tmp = (~ntohs(iph->ip_sum) & 0xffff
				   + ~tag_ref[2] & 0xffff 
				   + ~(tag_ref[2] >> 16) & 0xffff
				   + opt_sr->req_data.set & 0xffff
				   + opt_sr->req_data.set >> 16);
			tmp = tmp & 0xffff + tmp >> 16;
			tmp = ~tmp;
			iph->ip_sum = htons((u_int16_t)tmp);
		}
	}else{
		printf("sirens output: found tag, data value is not changed : data %08x -> %08x\n", tag_ref[2], opt_sr->req_data.set);
	}
	return error;
}

static errno_t
sr_iff_detached_fn( void *cookie, ifnet_t interface)
{
	int error = 0;
	return error;
}

static struct iff_filter sr_iff_filter = { 
    &sr_enable,
    MYBUNDLEID,
	0,
	NULL,
	sr_iff_out_fn,
	NULL,
	NULL,
	sr_iff_detached_fn
};

/* =================================== */
extern int
jp_hpcc_ikob_kext_sirensnke_start(kmod_info_t *ki, void *data)
{	
	int				ret = 0;
	ifnet_t			*ifnetp;
	u_int32_t ifcount;
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
	sr_sflt_filter.sf_len = sizeof(struct sflt_filter_ext);
	sr_sflt_filter.sf_accept = (sf_accept_func) sr_accept_fn;

	// register the filter with AF_INET domain, SOCK_STREAM type, TCP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	debug_printf("sflt_register returned result %d for ip4 filter.\n", ret);
	if (ret == 0)
		gFilterRegistered = TRUE;
	else
		goto err;

	// register the filter with AF_INET6 domain, SOCK_STREAM type, TCP protocol and set the global flag	
	ret = sflt_register(&sr_sflt_filter_ip6, PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	debug_printf("sflt_register returned result %d for ip6 filter.\n", ret);
	if (ret == 0)
		gFilterRegistered_ip6 = TRUE;
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
		ret = iflt_attach(ifnetp[i], &sr_iff_filter, &(gsr_if_filter[i]));
		if(ret == 0){
			gifFilterRegistered++;
			debug_printf("SIRENS filter is registered on \"%s%d\"\n", ifnet_name(ifnetp[i]), ifnet_unit(ifnetp[i]));
		}
	}
	ifnet_list_free(ifnetp);

	sirens_initted = TRUE;
	
	return KERN_SUCCESS;
	
err:
	if (gFilterRegistered){
		sflt_unregister(SIRENS_HANDLE4);
	}
	if(gFilterRegistered_ip6){
		sflt_unregister(SIRENS_HANDLE6);
	}
	if (gipFilterRegistered){
		ipf_remove(sr_ipf_ref);
	}
	if (gifFilterRegistered){
		for(i = 0 ; i < gifFilterRegistered ; i++){
			iflt_detach(gsr_if_filter[i]);
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
	if ((!gFilterRegistered && !gFilterRegistered_ip6 && !gipFilterRegistered && gifFilterRegistered == 0))
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
	
	if (gUnregisterProc_started == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE4);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip4 %d\n", ret);
		else {
			gUnregisterProc_started = TRUE;	// indicate that we've started the unreg process.
		}
	}
	if (gUnregisterProc_started_ip6 == FALSE) {
		ret = sflt_unregister(SIRENS_HANDLE6);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip6 %d\n", ret);
		else {
			gUnregisterProc_started_ip6 = TRUE;	// indicate that we've started the unreg process.
		}
	}
	if (gipFilterRegistered == TRUE) {
		ret = ipf_remove(sr_ipf_ref);
		if (ret != 0)
			debug_printf( "sirensnke_flush: sflt_unregister failed for ip4 %d\n", ret);
		else {
			gipFilterRegistered = FALSE;	// indicate that we've started the unreg process.
		}			
	}
	
	if (gifFilterRegistered){
		int i;
		for(i = 0 ; i < gifFilterRegistered ; i++){
			iflt_detach(gsr_if_filter[i]);
		}
	}
	
	if ((gUnregisterProc_complete &&
		 gUnregisterProc_complete_ip6 &&
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
	
	if ((!gFilterRegistered && !gFilterRegistered_ip6 && !gipFilterRegistered))
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

/*
 * 
 */

static void
debug_printf(const char *fmt, ...)
{
#if DEBUG
	va_list listp;
	char log_buffer[92];
	
	va_start(listp, fmt);
	
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
	printf("%s", log_buffer);
	
	va_end(listp);
#endif
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
ip_sirens_dooptions_d(mbuf_t data)
{
	struct ip *ip = (struct ip*) mbuf_data(data);
	u_char *cp;
	int opt, optlen, cnt, code;
		
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


