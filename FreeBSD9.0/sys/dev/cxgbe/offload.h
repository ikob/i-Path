/*-
 * Copyright (c) 2010 Chelsio Communications, Inc.
 * All rights reserved.
 * Written by: Navdeep Parhar <np@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/9.0.0/sys/dev/cxgbe/offload.h 222509 2011-05-30 21:07:26Z np $
 *
 */

#ifndef __T4_OFFLOAD_H__
#define __T4_OFFLOAD_H__

/* CPL message priority levels */
enum {
	CPL_PRIORITY_DATA     = 0,  /* data messages */
	CPL_PRIORITY_SETUP    = 1,  /* connection setup messages */
	CPL_PRIORITY_TEARDOWN = 0,  /* connection teardown messages */
	CPL_PRIORITY_LISTEN   = 1,  /* listen start/stop messages */
	CPL_PRIORITY_ACK      = 1,  /* RX ACK messages */
	CPL_PRIORITY_CONTROL  = 1   /* control messages */
};

#define INIT_TP_WR(w, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_TP_WR) | \
                              V_FW_WR_IMMDLEN(sizeof(*w) - sizeof(w->wr))); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof(*w), 16)) | \
                               V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

/*
 * Max # of ATIDs.  The absolute HW max is 16K but we keep it lower.
 */
#define MAX_ATIDS 8192U

struct serv_entry {
	void *data;
};

union aopen_entry {
	void *data;
	union aopen_entry *next;
};

/*
 * Holds the size, base address, free list start, etc of the TID, server TID,
 * and active-open TID tables.  The tables themselves are allocated dynamically.
 */
struct tid_info {
	void **tid_tab;
	unsigned int ntids;

	struct serv_entry *stid_tab;
	unsigned long *stid_bmap;
	unsigned int nstids;
	unsigned int stid_base;

	union aopen_entry *atid_tab;
	unsigned int natids;

	struct filter_entry *ftid_tab;
	unsigned int nftids;
	unsigned int ftid_base;
	unsigned int ftids_in_use;

	union aopen_entry *afree;
	unsigned int atids_in_use;

	unsigned int stids_in_use;
};

struct t4_range {
	unsigned int start;
	unsigned int size;
};

struct t4_virt_res {                      /* virtualized HW resources */
	struct t4_range ddp;
	struct t4_range iscsi;
	struct t4_range stag;
	struct t4_range rq;
	struct t4_range pbl;
};

#endif
