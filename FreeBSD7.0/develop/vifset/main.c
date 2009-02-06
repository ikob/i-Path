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

#include <netinet/in_pcb.h>
#include <netinet/ip_sirens.h>


#define CONFIG_FILE "sample.cfg"
#define MAX_IF 32

void usage(){
	fprintf(stderr, "Usage .....\n");
	exit(1);
}

main(int argc, char *argv[])
{
	int ch;
	extern char *optarg;
	extern int optind, opterr;

	char config_file[64] = CONFIG_FILE;
	config_t cf;
	config_setting_t *ifsp, *tcfsp, *ttcfsp;
	FILE *FP;
	char *oid;
	char elem[256];
	int nif, noid;
	struct {
		struct {
			int flag;
			char oid[MAX_OID_LEN];
		}in[SIRENS_PMAX], out[SIRENS_PMAX];
		char community[128];
		char host[128];
		char ifname[IFNAMSIZ];
	} qtbl[MAX_IF];
	char dcomm[256] = "public";

	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;

	long anOID[MAX_OID_LEN];
	size_t anOID_len;

	netsnmp_variable_list *vars;
	int status;
	int count=1;

	int fd;
	struct if_srvarreq ifsrr;

	int i, j;

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

	for (i = 0 ; i < MAX_IF ; i++){
		for( j = 0 ; j < SIRENS_PMAX ; j++){ 
			qtbl[i].in[j].flag = 0;
			qtbl[i].out[j].flag = 0;
		}
		strcpy(qtbl[i].community, "");
	}

	if((FP = fopen(config_file, "r")) == NULL){
		printf("file read error \"%s\"\n", config_file);
		exit(1);
	}

	config_init(&cf);
	
	if(CONFIG_TRUE != config_read(&cf, FP) ){
		printf("config error line:%d %s\n", config_error_line(&cf), config_error_text(&cf));
		return(1);
	}
	if((ifsp = config_lookup(&cf, "default")) != NULL){
		if((tcfsp = config_setting_get_member(ifsp, "community")) != NULL){
			strncpy(dcomm, config_setting_get_string(tcfsp), 128);
		}
	}

	if((ifsp = config_lookup(&cf, "interface")) == NULL){
		printf("config error not defined any interface\n");
		exit(1);
	}

	for( nif = 0, noid = 0 ; nif < MAX_IF ; nif ++){
		config_setting_t *oidcfsp;
		char tstr[256], *iftok;

		tcfsp = config_setting_get_elem(ifsp, nif);
		if(tcfsp == NULL) break;

/* replace '_' with '.', due to libconfig restrictuon */
		strncpy(qtbl[nif].ifname, config_setting_name(tcfsp), IFNAMSIZ);
		if((iftok = strchr(qtbl[nif].ifname, '_')) != NULL){
			*iftok ='.';
		}

		fd = socket(PF_INET, SOCK_DGRAM, 0);

		bzero(&ifsrr, sizeof(struct if_srvarreq));
		strncpy(ifsrr.ifr_name, qtbl[nif].ifname, IFNAMSIZ);
		if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
			printf("failed in %s\n", qtbl[nif].ifname);
		}

		if((ttcfsp = config_setting_get_member(tcfsp, "host")) == NULL){
			printf("not found community in %s\n", qtbl[nif].ifname);
			exit(1);
		}
		strncpy(qtbl[nif].host, config_setting_get_string(ttcfsp), 128);
		if((ttcfsp = config_setting_get_member(tcfsp, "community")) == NULL){
			strncpy(qtbl[nif].community, dcomm, 128);
		}else{
			strncpy(qtbl[nif].community, config_setting_get_string(ttcfsp), 128);
		}
		if((ttcfsp = config_setting_get_member(tcfsp, "in")) != NULL){
			if((oidcfsp = config_setting_get_member(ttcfsp, "bw")) != NULL){
				noid ++;
				qtbl[nif].in[SIRENS_LINK].flag = 1;
				strncpy(qtbl[nif].in[SIRENS_LINK].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
			if((oidcfsp = config_setting_get_member(ttcfsp, "octets")) != NULL){
				noid ++;
				qtbl[nif].in[SIRENS_OBYTES].flag = 1;
				strncpy(qtbl[nif].in[SIRENS_OBYTES].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
			if((oidcfsp = config_setting_get_member(ttcfsp, "queue")) != NULL){
				noid ++;
				qtbl[nif].in[SIRENS_QLEN].flag = 1;
				strncpy(qtbl[nif].in[SIRENS_QLEN].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
		}
		if((ttcfsp = config_setting_get_member(tcfsp, "out")) != NULL){
			if((oidcfsp = config_setting_get_member(ttcfsp, "bw")) != NULL){
				noid ++;
				qtbl[nif].out[SIRENS_LINK].flag = 1;
				strncpy(qtbl[nif].out[SIRENS_LINK].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
			if((oidcfsp = config_setting_get_member(ttcfsp, "octets")) != NULL){
				noid ++;
				qtbl[nif].out[SIRENS_OBYTES].flag = 1;
				strncpy(qtbl[nif].out[SIRENS_OBYTES].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
			if((oidcfsp = config_setting_get_member(ttcfsp, "queue")) != NULL){
				noid ++;
				qtbl[nif].out[SIRENS_QLEN].flag = 1;
				strncpy(qtbl[nif].out[SIRENS_QLEN].oid, config_setting_get_string(oidcfsp), MAX_OID_LEN);
			}
		}
	}
	if(nif == MAX_IF){
		fprintf(stderr, "Too much if's %d >  %d\n", nif, MAX_IF);
		exit(1);
	}
	printf("total if %d oid %d\n", nif, noid);
	if(nif == 0){
		printf("no if is defined\n");
		exit(0);
	}
	if(noid == 0){
		printf("no oid is defined\n");
		exit(0);
	}

	init_snmp("vifset");

	for( i = 0 ; i < nif ; i++ ){
		snmp_sess_init( &session);
		session.version = SNMP_VERSION_2c;
		session.peername = strdup(qtbl[i].host);
		session.community = strdup(qtbl[i].community);
		session.community_len = strlen(session.community);
		SOCK_STARTUP;
		ss = snmp_open(&session);
		if (!ss) {
			snmp_sess_perror("ack", &session);
			SOCK_CLEANUP;
			exit(1);
		}
		for( j = 0 ; j < SIRENS_PMAX ; j++){
			if(qtbl[i].in[j].flag != 0) {
				int val;
				oid = strdup(qtbl[i].in[j].oid);
				vid_get(ss, oid, &val);
				printf("val = %08x\n", val);
				bzero(&ifsrr, sizeof(struct if_srvarreq));
				strncpy(ifsrr.ifr_name, qtbl[i].ifname, IFNAMSIZ);
				ifsrr.sr_probe = j | SIRENS_DIR_IN;
				ifsrr.sr_var.flag = 1;
				ifsrr.sr_var.data = val;
				printf("request in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
				if(ioctl(fd, SIOCSSRVAR, &ifsrr) < 0){
					printf("failed in %s\n", qtbl[i].ifname);
				}
				bzero(&ifsrr, sizeof(struct if_srvarreq));
				strncpy(ifsrr.ifr_name, qtbl[i].ifname, IFNAMSIZ);
				ifsrr.sr_probe = j | SIRENS_DIR_IN;
				if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
					printf("failed in %s\n", qtbl[i].ifname);
				}
				printf("result in : P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
			}
		}
		for( j = 0 ; j < SIRENS_PMAX ; j++){
			if(qtbl[i].out[j].flag != 0){
				int val;
				oid = strdup(qtbl[i].out[j].oid);
				vid_get(ss, oid, &val);
				printf("val = %08x\n", val);
				bzero(&ifsrr, sizeof(struct if_srvarreq));
				strncpy(ifsrr.ifr_name, qtbl[i].ifname, IFNAMSIZ);
				ifsrr.sr_probe = j | SIRENS_DIR_OUT;
				ifsrr.sr_var.flag = 1;
				ifsrr.sr_var.data = val;
				printf("request out: P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
				if(ioctl(fd, SIOCSSRVAR, &ifsrr) < 0){
					printf("failed in %s\n", qtbl[i].ifname);
				}
				bzero(&ifsrr, sizeof(struct if_srvarreq));
				strncpy(ifsrr.ifr_name, qtbl[i].ifname, IFNAMSIZ);
				if(ioctl(fd, SIOCSSRVAR, &ifsrr) < 0){
					printf("failed in %s\n", qtbl[i].ifname);
				}
				bzero(&ifsrr, sizeof(struct if_srvarreq));
				strncpy(ifsrr.ifr_name, qtbl[i].ifname, IFNAMSIZ);
				ifsrr.sr_probe = j | SIRENS_DIR_OUT;
				if(ioctl(fd, SIOCGSRVAR, &ifsrr) < 0){
					printf("failed in %s\n", qtbl[i].ifname);
				}
				printf("result out: P:%d V:%d D:%d\n", ifsrr.sr_probe, ifsrr.sr_var.flag, ifsrr.sr_var.data);
			}
		}
		snmp_close(ss);
		SOCK_CLEANUP;
	}

	return (0);
}
int
vid_get(struct snmp_session *ss, char *oid, int *val)
{
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;
	size_t anOID_len;
	long anOID[MAX_OID_LEN];
	int status;
	int count=1;
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
	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
      /*
       * SUCCESS: Print the result variables
       */
/*
		for(vars = response->variables; vars; vars = vars->next_variable)
			print_variable(vars->name, vars->name_length, vars);
*/

	/* manipuate the information ourselves */
		for(vars = response->variables; vars; vars = vars->next_variable) {
			switch(vars->type){
			case ASN_GAUGE:
				{
					u_int gauge;
					gauge = *vars->val.integer;
//					printf("gauge %10d\n", gauge);
					*val = gauge;
				}
				break;
			case ASN_COUNTER64:
				{
					struct counter64 data64;
					memcpy(&data64, vars->val.counter64, vars->val_len);
//					printf("counter64 %08x%08x\n", data64.high, data64.low);
					*val = data64.low;
				}
				break;
			case ASN_OCTET_STR:
				{
 					char *sp = (char *)malloc(1 + vars->val_len);
					memcpy(sp, vars->val.string, vars->val_len);
					sp[vars->val_len] = '\0';
//      					printf("value #%d is a string: %s\n", count++, sp);
					free(sp);
				}
				break;
			default:
//     				printf("%x value #%d is NOT support Ack!\n", vars->type, count++);
				break;
			}
      		}
	} else {
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
    	}

    /*
     * Clean up:
     *  1) free the response.
     *  2) close the session.
     */
	if (response)
		snmp_free_pdu(response);
	return err;
}
