/*
 *	@(#)ip_sirens.c
 * $$
 */

#include "opt_ipsec.h"
#if (defined (__FreeBSD__))
# include "opt_inet6.h"
#endif

#include "opt_ipsirens.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/time.h>

#if 0
#if (defined (__FreeBSD__))
# include <vm/vm_zone.h>
#endif
#endif

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if (defined (__FreeBSD__))
# include <netinet/ipprotosw.h>
# else
#  if (defined (__NetBSD__))
#  include <sys/protosw.h>
# endif
#endif
#ifdef INET6
#include <netinet6/ip6_var.h>
#endif
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/ip_sirens.h>
#include <netinet/ip_sirens_var.h>

#ifdef FAST_IPSEC
#include <netipsec/ipsec.h>
#endif /*FAST_IPSEC*/

#ifdef IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if (defined (__FreeBSD__))
# include <machine/in_cksum.h>
#endif        

MALLOC_DEFINE(M_SROPTS, "sroption", "opaqueue option storage");
#if (defined (__FreeBSD__))
extern  struct ipprotosw inetsw[];
#endif
#if (defined (__NetBSD__))
extern  struct protosw inetsw[];
#endif

struct	inpcbhead srb;
#if (defined(__FreeBSD__))
struct	inpcbinfo srdbinfo;
#endif

#include <machine/stdarg.h>

#ifdef SR_DEBUG
#undef SR_DEBUG
#endif
/*
#define SR_DEBUG 1
*/

char sr_str [][25] = {"link bw, util", "loss drop, error", "queue limit, delay", ""};

int	srs_ipackets = 0;
int	srs_hdrops = 0;
int	srs_update = 0;
int	srs_through = 0;

static struct	sockaddr_in sr_in = { sizeof(sr_in), AF_INET };
#ifdef INET6
struct sr_in6 {
	struct sockaddr_in6	oin6_sin;
	u_char			oin6_init_done : 1;
} sr_in6 = {
	{ sizeof(sr_in6.oin6_sin), AF_INET6 },
	0
};
struct sr_ip6 {
	struct ip6_hdr		oip6_ip6;
	u_char			oip6_init_done : 1;
} udp_ip6;
#endif /* INET6 */
int sr_setparam (struct srhdr *srh, struct ifnet *rifp, struct ifnet *sifp) {
	struct ifnet *tifp;
	int error = 0;
	struct sr_storage *srp;
#if SIRENS_DSIZE > 16
	uint32_t data = 0;
#else
	u_int16_t e1 = 0, e2 = 0;
#endif
	switch(srh->req_probe){
	default:
		break;
	}
/* getting if info */
	if((srh->req_probe & SIRENS_DIR_IN) == 0){
		tifp = sifp;
	}else{
		tifp = rifp;
	}
	if(tifp == NULL){
		data = ~0;
		goto update;
	}
	srs_update ++;
	IF_AFDATA_LOCK(tifp);
	if(srh->req_probe & SIRENS_DIR_IN){
		srp = (struct sr_storage *)(tifp->if_sr_in);
	}else{
		srp = (struct sr_storage *)(tifp->if_sr_out);
	}
#ifdef SR_DEBUG
printf("probe%d %d %d\n", srh->req_probe, srp->array[srh->req_probe].flag, srp->array[srh->req_probe].data);
#endif
	switch ((srh->req_probe) & ~SIRENS_DIR_IN){
	case SIRENS_LINK:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_baudrate);
		}
		break;
	case SIRENS_OBYTES:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_obytes);
		}
		break;
	case SIRENS_IBYTES:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_ibytes);
		}
		break;
	case SIRENS_DROPS:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_snd.ifq_drops);
		}
		break;
	case SIRENS_ERRORS:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_oerrors);
		}
		break;
	case SIRENS_QMAX:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_snd.ifq_maxlen);
		}
		break;
	case SIRENS_QLEN:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_snd.ifq_len);
		}
		break;
	case SIRENS_MTU:
		if(srp->array[srh->req_probe].flag == IPSR_VAR_VALID){
			data = (u_int32_t) srp->array[srh->req_probe].data;
		}else{
			data = (u_int32_t) (tifp->if_mtu);
		}
		break;
	default:
		data = ~0;
		break;
	}
	IF_AFDATA_UNLOCK(tifp);
update:
	switch(srh->req_mode){
	case SIRENS_TTL:
		srh->req.data.set = htonl(data);
		break;
	case SIRENS_MIN:
		srh->req_ttl = srh->req_ttl == 0 ? 0xff : srh->req_ttl - 1;
		if(data == ~0) return error;
		if( data < srh->req.data.set ){
			srh->req.data.set = htonl(data);
		}
		break;
	case SIRENS_MAX:
		srh->req_ttl = srh->req_ttl == 0 ? 0xff : srh->req_ttl - 1;
		if(data == ~0) return error;
		if( data >  srh->req.data.set ){
			srh->req.data.set = htonl(data);
		}
		break;
	default:
		break;
	}
	return error;
}
#if 0
void sr_tick(struct inpcb *inp){
	struct sr_lst *srl = &inp->sro->sr_lst;
	u_char i, j;
	u_char min_ttl = 0, max_ttl = 0;
	u_int16_t max1, max2;
	u_int16_t min1, min2;
	u_int16_t sum1, sum2;
	u_int valid;

#if (defined (__NetBSD__))
	struct timeval time;
	time_t time_second;
	microtime(&time);
	time_second = time.tv_sec;
#endif

	for(i = 0 ; i < SIRENS_PMAX ; i++){
#ifdef SR_DEBUG
		printf("sr_tick:RX[%d:%s] TTL min:max=%d,%d\n", i, sr_str[i], srl->rx[i].min_ttl, srl->rx[i].max_ttl);
#endif /* SR_DEBUG */
		max1 = 0;
		max2 = 0;
		min1 = 0xffff;
		min2 = 0xffff;
		sum1 = 0;
		sum2 = 0;
		valid = 0;
		for( j = srl->rx[i].min_ttl, min_ttl = 0; j <= srl->rx[i].max_ttl && min_ttl == 0; j++){
			if((time_second - srl->rx[i].sample[j].time) < 10) {
#ifdef SR_DEBUG
		printf("sr_tick min:RX[%d:%s] TTL:%d, e1:%d, e2:%d\n",
				i, sr_str[i], j, srl->rx[i].sample[j].data.set.e1, srl->rx[i].sample[j].data.set.e2);
#endif /* SR_DEBUG */
				min_ttl = j;
				sum1 += srl->rx[i].sample[j].data.set.e1;
				sum2 += srl->rx[i].sample[j].data.set.e2;
				valid++;
				if( max1 < srl->rx[i].sample[j].data.set.e1){
					max1 = srl->rx[i].sample[j].data.set.e1;
				}
				if( max2 < srl->rx[i].sample[j].data.set.e2){
					max2 = srl->rx[i].sample[j].data.set.e2;
				}
				if( min1 > srl->rx[i].sample[j].data.set.e1){
					min1 = srl->rx[i].sample[j].data.set.e1;
				}
				if( min2 > srl->rx[i].sample[j].data.set.e2){
					min2 = srl->rx[i].sample[j].data.set.e2;
				}
			}else{
				srl->rx[i].sample[j].time = 0;
			}
		}
		for( max_ttl = min_ttl; j <= srl->rx[i].max_ttl ; j++){
			if((time_second - srl->rx[i].sample[j].time) < 10) {
#ifdef SR_DEBUG
		printf("sr_tick max:RX[%d:%s] TTL:%d, e1:%d, e2:%d\n",
				i, sr_str[i], j, srl->rx[i].sample[j].data.set.e1, srl->rx[i].sample[j].data.set.e2);
#endif /* SR_DEBUG */
				max_ttl = j;
				sum1 += srl->rx[i].sample[j].data.set.e1;
				sum2 += srl->rx[i].sample[j].data.set.e2;
				valid++;
				if( max1 < srl->rx[i].sample[j].data.set.e1){
					max1 = srl->rx[i].sample[j].data.set.e1;
				}
				if( max2 < srl->rx[i].sample[j].data.set.e2){
					max2 = srl->rx[i].sample[j].data.set.e2;
				}
				if( min1 > srl->rx[i].sample[j].data.set.e1){
					min1 = srl->rx[i].sample[j].data.set.e1;
				}
				if( min2 > srl->rx[i].sample[j].data.set.e2){
					min2 = srl->rx[i].sample[j].data.set.e2;
				}
			}else{
				srl->rx[i].sample[j].time = 0;
			}
		}
		if(min_ttl != 0) srl->rx[i].min_ttl = min_ttl;
		if(max_ttl != 0) srl->rx[i].max_ttl = max_ttl;
		if(valid != 0) srl->rx[i].valid = valid;
		if(max1 != 0) srl->rx[i].max.set.e1 = (max1);
		if(max2 != 0) srl->rx[i].max.set.e2 = (max2);
		if(min1 != 0xffff) srl->rx[i].min.set.e1 = (min1);
		if(min2 != 0xffff) srl->rx[i].min.set.e2 = (min2);
		if(sum1 != 0) srl->rx[i].sum.set.e1 = (sum1);
		if(sum2 != 0) srl->rx[i].sum.set.e2 = (sum2);
#ifdef SR_DEBUG
		printf("sr_tick:RX[%d:%s] TTL min:max=%d,%d\n", i, sr_str[i], min_ttl, max_ttl);
#endif /* SR_DEBUG */

		max1 = 0;
		max2 = 0;
		min1 = 0xffff;
		min2 = 0xffff;
		sum1 = 0;
		sum2 = 0;
		valid = 0;
		for( j = srl->tx[i].min_ttl, min_ttl = 0; j <= srl->tx[i].max_ttl && min_ttl == 0; j++){
#ifdef SR_DEBUG
			printf("sr_tick:TX[%d] TTL min:max=%d,%d\n", i, srl->tx[i].min_ttl, srl->tx[i].max_ttl);
#endif /* SR_DEBUG */
			if((time_second - srl->tx[i].sample[j].time) < 2) {
#ifdef SR_DEBUG
		printf("sr_tick min:TX[%d] TTL:%d, e1:%d, e2:%d\n",
				i, j, erl->tx[i].sample[j].data.set.e1, srl->tx[i].sample[j].data.set.e2);
#endif /* SR_DEBUG */
				min_ttl = j;
				sum1 += (srl->tx[i].sample[j].data.set.e1);
				sum2 += (srl->tx[i].sample[j].data.set.e2);
				valid++;
				if( max1 < (srl->tx[i].sample[j].data.set.e1)){
					max1 = (srl->tx[i].sample[j].data.set.e1);
				}
				if( max2 < (srl->tx[i].sample[j].data.set.e2)){
					max2 = (srl->tx[i].sample[j].data.set.e2);
				}
				if( min1 > (srl->tx[i].sample[j].data.set.e1)){
					min1 = (srl->tx[i].sample[j].data.set.e1);
				}
				if( min2 > (srl->tx[i].sample[j].data.set.e2)){
					min2 = (srl->tx[i].sample[j].data.set.e2);
				}
			}else{
				srl->tx[i].sample[j].time = 0;
			}
		}
		for( max_ttl = min_ttl; j <= srl->tx[i].max_ttl ; j++){
			if((time_second - srl->tx[i].sample[j].time) < 2) {
#ifdef SR_DEBUG
		printf("sr_tick max:TX[%d] TTL:%d, e1:%d, e2:%d\n",
				i, j, srl->tx[i].sample[j].data.set.e1, srl->tx[i].sample[j].data.set.e2);
#endif /* SR_DEBUG */
				max_ttl = j;
				sum1 += (srl->tx[i].sample[j].data.set.e1);
				sum2 += (srl->tx[i].sample[j].data.set.e2);
				valid++;
				if( max1 < (srl->tx[i].sample[j].data.set.e1)){
					max1 = (srl->tx[i].sample[j].data.set.e1);
				}
				if( max2 < (srl->tx[i].sample[j].data.set.e2)){
					max2 = (srl->tx[i].sample[j].data.set.e2);
				}
				if( min1 > (srl->tx[i].sample[j].data.set.e1)){
					min1 = (srl->tx[i].sample[j].data.set.e1);
				}
				if( min2 > (srl->tx[i].sample[j].data.set.e2)){
					min2 = (srl->tx[i].sample[j].data.set.e2);
				}
			}else{
				srl->tx[i].sample[j].time = 0;
			}
		}
		if(min_ttl != 0) srl->tx[i].min_ttl = min_ttl;
		if(max_ttl != 0) srl->tx[i].max_ttl = max_ttl;
		if(valid != 0) srl->tx[i].valid = valid;
		if(max1 != 0) srl->tx[i].max.set.e1 = (max1);
		if(max2 != 0) srl->tx[i].max.set.e2 = (max2);
		if(min1 != 0xffff) srl->tx[i].min.set.e1 = (min1);
		if(min2 != 0xffff) srl->tx[i].min.set.e2 = (min2);
		if(sum1 != 0) srl->tx[i].sum.set.e1 = (sum1);
		if(sum2 != 0) srl->tx[i].sum.set.e2 = (sum2);
#ifdef SR_DEBUG
		printf("sr_tick:TX[%d] TTL min:max=%d,%d\n", i, min_ttl, max_ttl);
#endif /* SR_DEBUG */
	}
}
#endif 
#if 0
void sirens_update( struct sr_options *sro, struct srhdr *srh)
{
	struct sr_lst *srl = &sro->sr_lst;
	u_int i, j;

#if (defined (__NetBSD__))
	struct timeval time;
	time_t time_second;
	microtime(&time);
	time_second = time.tv_sec;
#endif

	for(i = 0 , j = srh->res_ttl ; i < srh->res_len && i < SIRENSRESLEN ; i++, j++){
		if(j >= MAXTTL) break;
		if( srh->res[i].data.set.e1 != 0 || srh->res[i].data.set.e2 != 0){
			if(srl->tx[srh->res_probe].sample[j].time == 0){
				srl->tx[srh->res_probe].valid += 1;
#ifdef SR_DEBUG
printf("sirens_update 0:TX[%d:%s] valid tx probe %d/%d TTL=%d v=%d max:min=%d:%d %d %d\n", srh->res_probe, sr_str[srh->res_probe], i, srh->res_len, j, srl->tx[srh->res_probe].valid, srl->tx[srh->res_probe].max_ttl, srl->tx[srh->res_probe].min_ttl, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			srl->tx[srh->res_probe].sample[j].time = time_second;
			srl->tx[srh->res_probe].sum.set.e1
				= srl->tx[srh->res_probe].sum.set.e1 + ntohs(srh->res[i].data.set.e1)
					- srl->tx[srh->res_probe].sample[j].data.set.e1;
			srl->tx[srh->res_probe].sum.set.e2
				 = srl->tx[srh->res_probe].sum.set.e2 + ntohs(srh->res[i].data.set.e2)
					- srl->tx[srh->res_probe].sample[j].data.set.e2;
			if(ntohs(srh->res[i].data.set.e1) != srl->tx[srh->res_probe].sample[j].data.set.e1){
#ifdef SR_DEBUG
printf("sirens_update 1:TX[%d] SR sum.e1 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			if(ntohs(srh->res[i].data.set.e2) != srl->tx[srh->res_probe].sample[j].data.set.e2){
#ifdef SR_DEBUG
printf("sirens_update 2:TX[%d] SR sum.e2 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			srl->tx[srh->res_probe].sample[j].data.set.e1 = ntohs(srh->res[i].data.set.e1);
			srl->tx[srh->res_probe].sample[j].data.set.e2 = ntohs(srh->res[i].data.set.e2);


			if(srl->tx[srh->res_probe].min.set.e1 > ntohs(srh->res[i].data.set.e1)){
				srl->tx[srh->res_probe].min.set.e1 = ntohs(srh->res[i].data.set.e1);
#ifdef SR_DEBUG
printf("sirens_update 3:TX[%d] SR min.e1 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			if(srl->tx[srh->res_probe].min.set.e2 > ntohs(srh->res[i].data.set.e2)){
				srl->tx[srh->res_probe].min.set.e2 = ntohs(srh->res[i].data.set.e2);
#ifdef SR_DEBUG
printf("sirens_update 4:TX[%d] min.e2 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			if(srl->tx[srh->res_probe].max.set.e1 < ntohs(srh->res[i].data.set.e1)){
				srl->tx[srh->res_probe].max.set.e1 = ntohs(srh->res[i].data.set.e1);
#ifdef SR_DEBUG
printf("sirens_update 5:TX[%d] max.e1 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			if(srl->tx[srh->res_probe].max.set.e2 < ntohs(srh->res[i].data.set.e2)){
				srl->tx[srh->res_probe].max.set.e2 = ntohs(srh->res[i].data.set.e2);
#ifdef SR_DEBUG
printf("sirens_update 6:TX[%d] max.e2 %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif
			}
			if(srl->tx[srh->res_probe].min_ttl > j){
				srl->tx[srh->res_probe].min_ttl = j;
#ifdef SR_DEBUG
				printf("sirens_update 7:TX[%d] min %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].min_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif /* SR_DEBUG */
			}
			if(srl->tx[srh->res_probe].max_ttl < j){
				srl->tx[srh->res_probe].max_ttl = j;
#ifdef SR_DEBUG
				printf("sirens_update 8:TX[%d] max %d/%d %d %d %08x e1 %d, e2 %d\n", srh->res_probe, i, srh->res_len, srh->res_ttl, srl->tx[srh->res_probe].max_ttl, (int)time_second, ntohs(srh->res[i].data.set.e1), ntohs(srh->res[i].data.set.e2));
#endif /* SR_DEBUG */
			}
#if defined(SR_DEBUG) && SR_DEBUG > 4
			if(srl->tx[srh->res_probe].max_ttl - srl->tx[srh->res_probe].min_ttl == (srl->tx[srh->res_probe].valid - 1)){
				printf("sirens_update 9:TX[%d] complete TX path TTL %d:%d\n", srh->res_probe, srl->tx[srh->res_probe].max_ttl, srl->tx[srh->res_probe].min_ttl);
			}
#endif /* SR_DEBUG */
		}
	}

#ifdef SR_DEBUG
printf("sirens_update 9.2:RX[%d:%s] %d %d %d\n", srh->req_probe, sirens_str[srh->req_probe], srh->req_ttl, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
	if(srh->req.data.set.e1 == 0 && srh->req.data.set.e2 == 0){
		return;
	}

#ifdef SR_DEBUG
printf("sirens_update 9.5:RX[%d:%s] %d\n", srh->req_probe, sr_str[srh->req_probe], srh->req_ttl);
#endif
	if(srl->rx[srh->req_probe].min_ttl > srh->req_ttl){
		srl->rx[srh->req_probe].min_ttl = srh->req_ttl;
		if(srl->rx[srh->req_probe].min.set.e1 > ntohs(srh->req.data.set.e1)){
			srl->rx[srh->req_probe].min.set.e1 = ntohs(srh->req.data.set.e1);
#ifdef SR_DEBUG
printf("sirens_update 10:RX[%d:%s] min.e1 %d %d %08x e1 %d, e2 %d\n", srh->req_probe, sr_str[srh->req_probe], srh->req_ttl, srl->rx[srh->req_probe].min_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
		}
		if(srl->rx[srh->req_probe].min.set.e2 > ntohs(srh->req.data.set.e2)){
			srl->rx[srh->req_probe].min.set.e2 = ntohs(srh->req.data.set.e2);
#ifdef SR_DEBUG
printf("sirens_update 11:RX[%d] min.e2 %d %d %08x e1 %d, e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].min_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
		}
		if(srl->rx[srh->req_probe].max.set.e1 < ntohs(srh->req.data.set.e1)){
			srl->rx[srh->req_probe].max.set.e1 = ntohs(srh->req.data.set.e1);
#ifdef SR_DEBUG
printf("sirens_update 12:RX[%d] max.e1 %d %d %08x e1 %d, e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].min_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
		}
		if(srl->rx[srh->req_probe].max.set.e2 < ntohs(srh->req.data.set.e2)){
			srl->rx[srh->req_probe].max.set.e2 = ntohs(srh->req.data.set.e2);
#ifdef SR_DEBUG
printf("sirens_update 13:RX[%d] max.e2 %d %d %08x e1 %d, e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].min_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
		}
#ifdef SR_DEBUG
		printf("sirens_update 14:RX[%d] min %d %d %08x e1 %d, e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].min_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif /* SR_DEBUG */
	}
	if(srl->rx[srh->req_probe].max_ttl < srh->req_ttl){
		srl->rx[srh->req_probe].max_ttl = srh->req_ttl;
#ifdef SR_DEBUG
		printf("sirens_update 15:RX[%d] max %d %d %08x e1 %d, e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].max_ttl, (int)time_second, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif /* SR_DEBUG */
	}

	if( srh->req.data.set.e1 != 0 || srh->req.data.set.e2 != 0) {
		if(srl->rx[srh->req_probe].sample[srh->req_ttl].time == 0){
			srl->rx[srh->req_probe].valid ++;
#ifdef SR_DEBUG
printf("sirens_update 16:RX[%d] valid rx probe TTL:%d v=%d max:min=%d:%d e1 %d e2 %d\n", srh->req_probe, srh->req_ttl, srl->rx[srh->req_probe].valid, srl->rx[srh->req_probe].max_ttl, srl->rx[srh->req_probe].min_ttl, ntohs(srh->req.data.set.e1), ntohs(srh->req.data.set.e2));
#endif
		}
		srl->rx[srh->req_probe].sample[srh->req_ttl].time = (int)time_second;
		srl->rx[srh->req_probe].sum.set.e1
			= srl->rx[srh->req_probe].sum.set.e1 + ntohs(srh->req.data.set.e1)
				- srl->rx[srh->req_probe].sample[srh->req_ttl].data.set.e1;
		srl->rx[srh->req_probe].sum.set.e2 = srl->rx[srh->req_probe].sum.set.e2 + ntohs(srh->req.data.set.e2)
				- srl->rx[srh->req_probe].sample[srh->req_ttl].data.set.e2;
		srl->rx[srh->req_probe].sample[srh->req_ttl].data.set.e1 = ntohs(srh->req.data.set.e1);
		srl->rx[srh->req_probe].sample[srh->req_ttl].data.set.e2 = ntohs(srh->req.data.set.e2);
#if defined(SR_DEBUG) && SR_DEBUG > 4
		if(srl->rx[srh->req_probe].max_ttl - srl->rx[srh->req_probe].min_ttl == (srl->rx[srh->req_probe].valid - 1)){
			printf("sirens_update 17:RX[%d] complete RX path %d:%d\n", srh->req_probe, srl->rx[srh->req_probe].max_ttl, srl->rx[srh->req_probe].min_ttl);
		}
#endif
	}
}

void sirens_freeoptions (struct sr_options *sro)
{
	if(sro != NULL)
		free(sro, M_SROPTS);
}
struct sr_options *sirens_allocoptions()
{
	struct sr_options *sro;
	struct sr_lst *srl;
	int i, j;

	sro = malloc(sizeof(struct sr_options), M_SROPTS, M_NOWAIT);
	if(sro == NULL) return NULL;

	bzero(sro, sizeof(struct sr_options));
	srl = &sro->sr_lst;

	srl->txbw = 0;
	srl->rx_ttl = 0;
	srl->tx_ttl = 0;
	for(i = 0 ; i < SIRENS_PMAX ; i++){
		srl->rx[i].min_ttl = MAXTTL;
		srl->rx[i].max_ttl = 0;
		srl->rx[i].next_ttl = 0;
		srl->rx[i].valid = 0;

		srl->rx[i].min.set.e1 = 0x7fffffff;
		srl->rx[i].min.set.e2 = 0x7fffffff;
		srl->rx[i].max.set.e1 = 0;
		srl->rx[i].max.set.e2 = 0;
		srl->rx[i].sum.set.e1 = 0;
		srl->rx[i].sum.set.e2 = 0;

		srl->tx[i].min_ttl = MAXTTL;
		srl->tx[i].max_ttl = 0;
		srl->tx[i].next_ttl = 0;
		srl->tx[i].valid = 0;

		srl->tx[i].min.set.e1 = 0x7fffffff;
		srl->tx[i].min.set.e2 = 0x7fffffff;
		srl->tx[i].max.set.e1 = 0;
		srl->tx[i].max.set.e2 = 0;
		srl->tx[i].sum.set.e1 = 0;
		srl->tx[i].sum.set.e2 = 0;

		for(j = 0 ; j < MAXTTL ; j++){
			srl->rx[i].sample[j].time = 0;
			srl->tx[i].sample[j].time = 0;
		}
	}
	return sro;
}
#endif
void
sirens_init()
{
	return;
}
void
sirens_input(struct mbuf *m, int off)
{
	register struct ip* ip;
	register struct srhdr* srh;

	int iphlen = off;

        /*
         * Get IP and SR header together in first mbuf.
         */
       	srs_ipackets++;
        ip = mtod(m, struct ip *);
        if (m->m_len < iphlen + sizeof(struct srhdr)) {
                if ((m = m_pullup(m, iphlen + sizeof(struct srhdr))) == 0) {
                        srs_hdrops++;
                        return;
                }
                ip = mtod(m, struct ip *);
        }
        srh = (struct srhdr *)((caddr_t)ip + iphlen);
	if( srh->sr_p != IPPROTO_TCP && srh->sr_p != IPPROTO_UDP) {
/* XXX: bad protocol */
		printf("SR bad protocol %d %d %d\n", srh->sr_p, IPPROTO_TCP, IPPROTO_UDP);
		srs_hdrops++;
		return;
	}
#if 0
	m->m_pkthdr.csum_flags |= M_CSUM_BORROW_SR;
#endif
	off +=  sizeof(struct srhdr);
       	(*inetsw[ip_protox[srh->sr_p]].pr_input)((struct mbuf *)m, off, srh->sr_p);
        return;
}
/* 
* Sysctl for sr variables.
*/
int     sirens_enable = 0;
#if (defined(__FreeBSD__))
SYSCTL_NODE(_net_inet, IPPROTO_SIRENS, sirens, CTLFLAG_RW, 0, "sirens");
SYSCTL_INT(_net_inet_sirens, SIRENSCTL_ENABLE, enable, CTLFLAG_RW,
    &sirens_enable, 0, "Enable IP sirens");
SYSCTL_INT(_net_inet_sirens, SIRENSCTL_INPKTS, ipackets, CTLFLAG_RW,
    &srs_ipackets, 0, "SIRENS INPUTS");
SYSCTL_INT(_net_inet_sirens, SIRENSCTL_HDROP, hdrops, CTLFLAG_RW,
    &srs_hdrops, 0, "SIRENS drop count");
SYSCTL_INT(_net_inet_sirens, SIRENSCTL_UPDATE, update, CTLFLAG_RW,
    &srs_update, 0, "SIRENS header update");
SYSCTL_INT(_net_inet_sirens, SIRENSCTL_THROUGH, through, CTLFLAG_RW,
    &srs_through, 0, "SIRENS header through");
#endif
#if (defined(__NetBSD__))
SYSCTL_SETUP(sysctl_net_inet_sr_setup, "sysctl net.inet.sr subtree setup")
{  
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "net", NULL,
		NULL, 0, NULL, 0,
		CTL_NET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "inet", NULL,
		NULL, 0, NULL, 0,
		CTL_NET, PF_INET, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "sr",
		SYSCTL_DESCR("OpaQueue settings"),
		NULL, 0, NULL, 0,
		CTL_NET, PF_INET, IPPROTO_SR, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "stat",
		SYSCTL_DESCR("SR statistic"),
		NULL, 0, &srstat, 0,
		CTL_NET, PF_INET, IPPROTO_SR, SRCTL_STATS, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT|CTLFLAG_READONLY,
		CTLTYPE_INT, "ipackets",
		SYSCTL_DESCR("SR Inputs"),
		NULL, 0, &srstat.srs_ipackets, 0,
		CTL_NET, PF_INET, IPPROTO_SR, SRCTL_STATS, SRSCTL_IPACKETS,  
		CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT|CTLFLAG_READONLY,
		CTLTYPE_INT, "hdrops",
		SYSCTL_DESCR("SR Drops"),
		NULL, 0, &srstat.srs_hdrops, 0,
		CTL_NET, PF_INET, IPPROTO_SR, SRCTL_STATS, SRSCTL_HDROP,  
		CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT|CTLFLAG_READONLY,
		CTLTYPE_INT, "opackets",
		SYSCTL_DESCR("SR Drop"),
		NULL, 0, &srstat.srs_opackets, 0,
		CTL_NET, PF_INET, IPPROTO_SR, SRCTL_STATS, SRCTL_OPACKETS,  
		CTL_EOL);
}
#endif
