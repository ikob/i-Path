#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <libconfig.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/session_api.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/if.h>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <netinet/in_pcb.h>
#endif /* defined(__APPLE__) || defined(__FreeBSD__) */
#include <netinet/ip_sirens.h>

#define CONFIG_FILE "sample.cfg"
#define MAX_IF 32
int vid_get(struct snmp_session *, char *, int *);
struct qtbl_e qtblloc_set(config_setting_t *);
int fd;
int vifsetdebug = 1;
struct qtbl_e{
	int flag; /* XXX: should be changed to type ? */
#define QDISABLE 0
#define QSNMPOID 1
#define QSTATIC 2
        union{
		struct {
			char community[128];
			char host[128];
			char oid[MAX_OID_LEN];
		} snmp;
		u_int32_t val;
	}data;
};
struct qtbl_e gsnmpoid;
struct qtbl_e glocation;
int interval = 4;
struct qtbl_t{
	struct qtbl_e in[SIRENS_PMAX], out[SIRENS_PMAX];
	char ifname[IFNAMSIZ];
};
int qtbl_init(char *, struct qtbl_t *);
int vid_query(struct qtbl_t *, int);
int qtbl_if_set(config_setting_t *, struct qtbl_t *, struct qtbl_e, struct qtbl_e);
int qtbl_if_io_set(config_setting_t *, struct qtbl_e *, struct qtbl_e, struct qtbl_e);
int qtbl32_set(config_setting_t *, struct qtbl_e *, struct qtbl_e);
int vid_if_static(struct qtbl_e *, char *, int);
int vid_if_snmpoid(struct qtbl_e *, char *, int);

void usage(){
	fprintf(stderr, "usage: vifset [-c config_file]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int ch;
	extern char *optarg;
	extern int optind, opterr;

	struct qtbl_t qtbl[MAX_IF];

	char config_file[64] = CONFIG_FILE;
	int nif;

	while((ch = getopt(argc, argv, "c:")) != -1){
		switch(ch){
		case 'c':
			strncpy(config_file, optarg, 64);
			break;
		default:
			usage();
			break;
		}
	}

	fd = socket(PF_INET, SOCK_DGRAM, 0);
	nif = qtbl_init(config_file, qtbl);
	if(nif == 0){
		printf("No valid interface is founded\n");
		exit(1);
	}

	init_snmp("vifset");
	while(1){
		vid_query(qtbl, nif);
		sleep(interval);
	}
/*
*/

	return (0);
}
int qtbl_init(char *file, struct qtbl_t *qtbl)
{
	int i, j;
	long t_long;
	char *t_str;
	int iif, nif = 0;
	config_t cf;
	config_setting_t *ifsp, *tcfsp;
	FILE *FP;
	struct if_srvarreq ifsrr;

	glocation.flag = QDISABLE;

	gsnmpoid.flag = QDISABLE;
	strcpy(gsnmpoid.data.snmp.community, "public");

	for (i = 0 ; i < MAX_IF ; i++){
		for( j = 0 ; j < SIRENS_PMAX ; j++){ 
			qtbl[i].in[j].flag = QDISABLE;
			qtbl[i].out[j].flag = QDISABLE;
		}
	}

	if((FP = fopen(file, "r")) == NULL){
		printf("file read error \"%s\"\n", file);
		exit(1);
	}

	config_init(&cf);
	
	if(CONFIG_TRUE != config_read(&cf, FP) ){
		printf("config error line:%d %s\n", config_error_line(&cf), config_error_text(&cf));
		return(1);
	}

	fclose(FP);

/* Check global parameters, query interval ... */

	if(config_lookup_int(&cf, "default.polling", &t_long) == CONFIG_TRUE){
		interval = t_long;
	}
	if(t_long < 0 ){
		printf("config error : invalid update interval %ld\n", t_long);
		return(1);
	}

/* Check default parameters, query interval ... */
	if(config_lookup_string(&cf, "default.community", (const char **)&t_str) == CONFIG_TRUE){
		if(t_str != NULL){
			strcpy(gsnmpoid.data.snmp.community, t_str);
		}
	}
	if(vifsetdebug)
		printf("vifset default community: %s\n", gsnmpoid.data.snmp.community);

	if(config_lookup_string(&cf, "default.host", (const char **)&t_str) == CONFIG_TRUE){
		if(t_str != NULL){
			strcpy(gsnmpoid.data.snmp.host, t_str);
		}
	}
	if(vifsetdebug)
		printf("vifset default host: %s\n", gsnmpoid.data.snmp.host);
	gsnmpoid.flag = QSNMPOID;

	if((tcfsp = config_lookup(&cf, "default.location")) != NULL){
		glocation = qtblloc_set(tcfsp);
	}
	if(vifsetdebug && glocation.flag == QSTATIC)
		printf("vifset default location: %08x\n", glocation.data.val);

/* check if's */
	if((ifsp = config_lookup(&cf, "interface")) == NULL){
		printf("config error not defined any interface\n");
		exit(1);
	}
	for( iif = 0 , nif = 0; nif < MAX_IF ; iif++){
		char *iftok;
		tcfsp = config_setting_get_elem(ifsp, iif);
		if(tcfsp == NULL) break;

/* replace '_' with '.', due to libconfig restrictuon */
		strncpy(qtbl[nif].ifname, config_setting_name(tcfsp), IFNAMSIZ);
		if((iftok = strchr(qtbl[nif].ifname, '_')) != NULL){
			*iftok ='.';
		}

/* checking actual i/f or not */
		bzero(&ifsrr, sizeof(struct if_srvarreq));
#if defined(__FreeBSD__) || defined(__APPLE__)
		strncpy(ifsrr.ifr_name, qtbl[nif].ifname, IFNAMSIZ);
		if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
			printf("failed in %s\n", qtbl[nif].ifname);
			continue;
		};
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */
#if defined(__linux__)
		strncpy(ifsrr.ifrname, qtbl[nif].ifname, IFNAMSIZ);
	{
		socklen_t slen = sizeof(ifsrr);
		if(getsockopt(fd, IPPROTO_IP, IPSIRENS_SRVAR, &ifsrr, &slen)
				< 0){
			printf("failed in %s\n", qtbl[nif].ifname);
			continue;
		};
	}
#endif /* defined(__linux__) */
		if(qtbl_if_set(tcfsp, &(qtbl[nif]), gsnmpoid, glocation) == 0)
			continue;
		nif++;
	}
	if(nif == MAX_IF){
		printf("vifset Too much if's %d >  %d\n", nif, MAX_IF);
		exit(1);
	}
	return nif;
}
int qtbl_if_set(config_setting_t *icsp, struct qtbl_t *qip, struct qtbl_e ifsnmpoid, struct qtbl_e iflocation) {
	config_setting_t *tcsp;
	int ret = 0;
/* to determine default value for each if*/
	if((tcsp = config_setting_get_member(icsp, "host")) != NULL){
		if(strlen(config_setting_get_string(tcsp)) == 0){
			printf("vifset Wrong hostname \n");
		}else{
			strncpy(ifsnmpoid.data.snmp.host, config_setting_get_string(tcsp), 128);
		}
	}
	if((tcsp = config_setting_get_member(icsp, "community")) != NULL){
		if(strlen(config_setting_get_string(tcsp)) == 0){
			printf("vifset Wrong community \n");
		}else{
			strncpy(ifsnmpoid.data.snmp.community, config_setting_get_string(tcsp), 128);
		}
	}
	if(strlen(ifsnmpoid.data.snmp.host) > 0 && strlen(ifsnmpoid.data.snmp.community) > 0)
		ifsnmpoid.flag = QSNMPOID;

	if((tcsp = config_setting_get_member(icsp, "location")) != NULL){
		iflocation = qtblloc_set(tcsp);
		if(vifsetdebug && iflocation.flag == QSTATIC)
			printf("vifset if location: %08x\n", iflocation.data.val);
	}
/* getting in/out configuration*/
	if((tcsp = config_setting_get_member(icsp, "in")) != NULL){
		ret += qtbl_if_io_set(tcsp, qip->in, ifsnmpoid, iflocation);
	}
	if((tcsp = config_setting_get_member(icsp, "out")) != NULL){
		ret += qtbl_if_io_set(tcsp, qip->out, ifsnmpoid, iflocation);
	}
	return ret;
}
int qtbl_if_io_set(config_setting_t *iocsp, struct qtbl_e *qiop, struct qtbl_e ifsnmpoid, struct qtbl_e iflocation) {
	int ret = 0;
	config_setting_t *tcsp;
	if((tcsp = config_setting_get_member(iocsp, "bw")) != NULL){
		ret += qtbl32_set(tcsp, &qiop[SIRENS_LINK], ifsnmpoid);
	}
	if((tcsp = config_setting_get_member(iocsp, "octets")) != NULL){
		ret += qtbl32_set(tcsp, &qiop[SIRENS_OBYTES], ifsnmpoid);
	}
	if((tcsp = config_setting_get_member(iocsp, "queue")) != NULL){
		ret += qtbl32_set(tcsp, &qiop[SIRENS_QLEN], ifsnmpoid);
	}
	if((tcsp = config_setting_get_member(iocsp, "location")) != NULL){
		qiop[SIRENS_LOCATION] = qtblloc_set(tcsp);
		ret += 1;
	}else if(iflocation.flag == QSTATIC) {
		qiop[SIRENS_LOCATION] = iflocation;
		ret += 1;
	}
	return ret;
}
int qtbl32_set(config_setting_t *cfsp, struct qtbl_e *qep, struct qtbl_e ifsnmpoid) {
	config_setting_t *tcfsp;
	if((tcfsp = config_setting_get_member(cfsp, "static")) != NULL){
		qep->data.val = config_setting_get_int(tcfsp);
		qep->flag = QSTATIC;
		return 1;
/* SNMP is default. if SNMP option is not found, to assume SNMP MIB */
	}else if((tcfsp = config_setting_get_member(cfsp, "snmp")) == NULL){
		tcfsp = cfsp;
	}
	if(ifsnmpoid.flag != QSNMPOID){
		printf("Not defined SNMP data\n");
		return 0;
	}
	if(strlen(config_setting_get_string(tcfsp)) == 0){
		printf("wrong OID data\n");
		return 0;
	}
	*qep = ifsnmpoid;
	strncpy(qep->data.snmp.oid, config_setting_get_string(tcfsp), MAX_OID_LEN);
	return 1;
}
struct qtbl_e qtblloc_set(config_setting_t *cfsp) {
	struct qtbl_e qe;
	config_setting_t *tcfsp;
	double longitude = 9999, latitude = 9999;
	short ilo, ila;
	qe.flag = QDISABLE; 
/* skip static */
	if((tcfsp = config_setting_get_member(cfsp, "static")) == NULL){
		tcfsp = cfsp;
	}
	latitude = config_setting_get_float_elem(tcfsp, 0);
	longitude = config_setting_get_float_elem(tcfsp, 1);
	if(longitude < -180 || longitude > 180){
		return qe;
	}
	if(latitude < -90 || latitude > 90){
		return qe;
	}
	ilo = (short)(longitude * 128);
	ila = (short)(latitude * 128);
	qe.data.val = (((ila << 16) & 0xffff0000) | (ilo & 0xffff));
	qe.flag = QSTATIC;
	return qe;
}
int vid_query( struct qtbl_t *qtbl, int nif){
	int i, j;
	for( i = 0 ; i < nif ; i++ ){
		for( j = 0 ; j < SIRENS_PMAX ; j++){
			switch(qtbl[i].in[j].flag) {
			case QSNMPOID:
				printf("snmp in:%d %d\n", i, j);
				vid_if_snmpoid(&qtbl[i].in[j], qtbl[i].ifname, j | SIRENS_DIR_IN);
				break;
			case QSTATIC:
				printf("static in:%d %d\n", i, j);
				vid_if_static(&qtbl[i].in[j], qtbl[i].ifname, j | SIRENS_DIR_IN);
				break;
			case QDISABLE:
			default:
				break;
			}
			switch(qtbl[i].out[j].flag) {
			case QSNMPOID:
				printf("snmp out:%d %d\n", i, j);
				vid_if_snmpoid(&qtbl[i].out[j], qtbl[i].ifname, j | SIRENS_DIR_OUT);
				break;
			case QSTATIC:
				printf("static out:%d %d\n", i, j);
				vid_if_static(&qtbl[i].out[j], qtbl[i].ifname, j | SIRENS_DIR_OUT);
				break;
			case QDISABLE:
			default:
				break;
			}
		}
	}
	return 0;
}
int vid_if_static(struct qtbl_e *qe, char *ifname, int sindex)
{
	struct if_srvarreq ifsrr;
	bzero(&ifsrr, sizeof(struct if_srvarreq));
#if defined(__FreeBSD__) || defined(__APPLE__)
	strncpy(ifsrr.ifr_name, ifname, IFNAMSIZ);
#endif
#if defined(__linux__)
	strncpy(ifsrr.ifrname, ifname, IFNAMSIZ);
#endif
	ifsrr.sr_probe = sindex; 
	ifsrr.sr_var.flag = 1;
	ifsrr.sr_var.data = qe->data.val;
	if(vifsetdebug)
		printf("request in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
#if defined(__FreeBSD__) || defined(__APPLE__)
	if(ioctl(fd, SIOCSSRVAR, &ifsrr) < 0){
		printf("failed in %s\n", ifname);
	}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */
#if defined(__linux__)
{
	socklen_t slen = sizeof(ifsrr);
	if(setsockopt(fd, IPPROTO_IP, IPSIRENS_SRVAR, &ifsrr, slen) < 0){
		printf("failed in %s\n", ifname);
	}
}
#endif /* defined(__linux__) */
	bzero(&ifsrr, sizeof(struct if_srvarreq));
#if defined(__FreeBSD__) || defined(__APPLE__)
	strncpy(ifsrr.ifr_name, ifname, IFNAMSIZ);
#endif
#if defined(__linux__)
	strncpy(ifsrr.ifrname, ifname, IFNAMSIZ);
#endif
	ifsrr.sr_probe = sindex;
#if defined(__FreeBSD__) || defined(__APPLE__)
	if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
		printf("failed in %s\n", ifname);
	}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */
#if defined(__linux__)
{
	socklen_t slen = sizeof(ifsrr);
	if(getsockopt(fd, IPPROTO_IP, IPSIRENS_SRVAR, &ifsrr, &slen) < 0){
		printf("failed in %s\n", ifname);
	}
}
#endif /* defined(__linux__) */
	if(vifsetdebug)
		printf("result in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
	return 0;
}
int vid_if_snmpoid(struct qtbl_e *qe, char *ifname, int sindex)
{
	netsnmp_session session, *sp;
	char *oid;
	int val;
	struct if_srvarreq ifsrr;
	if(strcmp(qe->data.snmp.host , "") == 0 ){
		printf("Wrong hostname\n");
		return -1;
	}
	snmp_sess_init( &session);
	session.version = SNMP_VERSION_2c;
	session.peername = strdup(qe->data.snmp.host);
	session.community = (u_char *)strdup(qe->data.snmp.community);
	session.community_len = strlen((const char *)session.community);
	SOCK_STARTUP;
	sp = snmp_open(&session);
	if (!sp) {
		snmp_sess_perror("ack", &session);
		SOCK_CLEANUP;
		exit(1);
	}
	oid = strdup(qe->data.snmp.oid);

	vid_get(sp, oid, &val);

	if(vifsetdebug)
		printf("SNMP val = %08x\n", val);
	bzero(&ifsrr, sizeof(struct if_srvarreq));
#if defined(__FreeBSD__) || defined(__APPLE__)
	strncpy(ifsrr.ifr_name, ifname, IFNAMSIZ);
#endif
#if defined(__linux__)
	strncpy(ifsrr.ifrname, ifname, IFNAMSIZ);
#endif
	ifsrr.sr_probe = sindex; 
	ifsrr.sr_var.flag = 1;
	ifsrr.sr_var.data = val;
	if(vifsetdebug)
		printf("request in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
#if defined(__FreeBSD__) || defined(__APPLE__)
	if(ioctl(fd, SIOCSSRVAR, &ifsrr) < 0){
		printf("failed in %s\n", ifname);
	}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */
#if defined(__linux__)
{
	socklen_t slen = sizeof(ifsrr);
	if(setsockopt(fd, IPPROTO_IP, IPSIRENS_SRVAR, &ifsrr, slen) < 0){
		printf("failed in %s\n", ifname);
	}
}
#endif /* defined(__linux__) */
	bzero(&ifsrr, sizeof(struct if_srvarreq));
#if defined(__FreeBSD__) || defined(__APPLE__)
	strncpy(ifsrr.ifr_name, ifname, IFNAMSIZ);
#endif
#if defined(__linux__)
	strncpy(ifsrr.ifrname, ifname, IFNAMSIZ);
#endif
	ifsrr.sr_probe = sindex;
#if defined(__FreeBSD__) || defined(__APPLE__)
	if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
		printf("failed in %s\n", ifname);
	}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */
#if defined(__linux__)
{
	socklen_t slen = sizeof(ifsrr);
	if(getsockopt(fd, IPPROTO_IP, IPSIRENS_SRVAR, &ifsrr, &slen) < 0){
		printf("failed in %s\n", ifname);
	}
}
#endif /* defined(__linux__) */
	if(vifsetdebug)
		printf("result in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
	snmp_close(sp);
	SOCK_CLEANUP;
	return 1;
}
int
vid_get(struct snmp_session *ss, char *oid, int *val)
{
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;
	size_t anOID_len;
	u_long anOID[MAX_OID_LEN];
	int status;
	netsnmp_variable_list *vars;
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	anOID_len = MAX_OID_LEN;
	int err = 0;
	*val = 0;
	if (!snmp_parse_oid(oid, anOID, &anOID_len)) {
		snmp_perror(oid);
		SOCK_CLEANUP;
		exit (1);
	}
	snmp_add_null_var(pdu, anOID, anOID_len);
	status = snmp_synch_response(ss, pdu, &response);
	if (status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR) {
      /*
       * FAILURE: print what went wrong!
       */
		if (status == STAT_SUCCESS)
			fprintf(stderr, "Error in packet\nReason: %s\n",
				snmp_errstring(response->errstat));
		else if (status == STAT_TIMEOUT)
			fprintf(stderr, "Timeout: No response from %s.\n",
				ss->peername);
		else
			snmp_sess_perror("viftest", ss);
		err = -1;
		if (response)
			snmp_free_pdu(response);
		return err;
	}
      /*
       * SUCCESS: Print the result variables
       */
	if(vifsetdebug)
		for(vars = response->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);

	/* manipuate the information ourselves */
	for(vars = response->variables; vars; vars = vars->next_variable) {
		switch(vars->type){
		case ASN_GAUGE:
			{
				u_int gauge;
				gauge = *vars->val.integer;
//				printf("gauge %10d\n", gauge);
				*val = gauge;
			}
			break;
		case ASN_COUNTER64:
			{
				struct counter64 data64;
				memcpy(&data64, vars->val.counter64, vars->val_len);
//				printf("counter64 %08x%08x\n", data64.high, data64.low);
				*val = data64.low;
			}
			break;
		case ASN_OCTET_STR:
			{
 				char *sp = (char *)malloc(1 + vars->val_len);
				memcpy(sp, vars->val.string, vars->val_len);
				sp[vars->val_len] = '\0';
//     					printf("value #%d is a string: %s\n", count++, sp);
				free(sp);
			}
			break;
		default:
//     			printf("%x value #%d is NOT support Ack!\n", vars->type, count++);
			break;
		}
      	}
	if (response)
		snmp_free_pdu(response);
	return err;
}
