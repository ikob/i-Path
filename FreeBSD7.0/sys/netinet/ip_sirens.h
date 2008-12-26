/*
 *	@(#)ip_sirens.h
 * $$
 */

#ifndef _NETINET_SIRENS_H_
#define _NETINET_SIRENS_H_

/*
 * SIRENS protocol header.
 */

enum SIRENS_MODE { SIRENS_DISABLE, SIRENS_MIN, SIRENS_MAX, SIRENS_TTL};
char *sirens_mode_s[] = {
	"disable",
	"minimal",
	"maximum",
	"ttl",
};
enum SIRENS_PROBE {
	SIRENS_LINK,
	SIRENS_OBYTES,
	SIRENS_IBYTES,
	SIRENS_DROPS,
	SIRENS_ERRORS,
	SIRENS_QMAX,
	SIRENS_QLEN,
	SIRENS_MTU,
	SIRENS_PMAX
};
char *sirens_probe_s[] = {
	"link",
	"obytes",
	"ibytes",
	"drops",
	"errors",
	"qmax",
	"qlen",
	"qmtu",
	"dummy",
};
#define SIRENS_DIR_IN	0x80
#define SIRENS_DIR_OUT	0x00
#define SIRENS_DSIZE	32
#if SIRENS_DSIZE > 16
union u_sr_data {
	uint32_t link;
	uint32_t loss;
	uint32_t queue;
	uint32_t mtu;
	uint32_t set;
};
#else
union u_sr_data {
	struct {
		u_int16_t bw;
		u_int16_t util;
	} link;
	struct {
		u_int16_t drop;
		u_int16_t error;
	} loss;
	struct {
		u_int16_t limit;
		u_int16_t delay;
	} queue;
	struct {
		u_int16_t mtu;
		u_int16_t mtu2;
	} mtu;
	struct {
		int e1;
		int e2;
	} set;
};
#endif
struct srhdr {
	u_char req_mode;
	u_char req_probe;
	u_char req_flag;
	u_char req_ttl;

	u_char res_probe;
	u_char res_len;
	u_char res_ttl;
	u_char sr_p;

	struct {
		union u_sr_data data;
#define SIRENSRESLEN 8
	} req, res[SIRENSRESLEN];
};
/* must change according rt socket */
struct sr_options {
	struct sr_lst {
		u_char rx_probe, tx_probe;
		u_char rx_ttl, tx_ttl;
		int txbw;
		struct {
			union u_sr_data min, max, sum;
			int min_ttl, max_ttl, next_ttl;
			int valid;
			struct {
				time_t time;
				union u_sr_data data;
			} sample[256];
		} rx[SIRENS_PMAX], tx[SIRENS_PMAX];
	} sr_lst;
};

struct sr_options * sr_allocoptions __P((void));
void sr_freeoptions __P((struct sr_options *));
void sr_update __P((struct sr_options *, struct srhdr*));
void sr_tick __P((struct inpcb *));
int sr_setparam __P((struct srhdr *, struct ifnet *, struct ifnet *));
#endif
