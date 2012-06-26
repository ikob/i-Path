/**************************************************************************

Copyright (c) 2007, Chelsio Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Neither the name of the Chelsio Corporation nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

***************************************************************************/
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.0.0/sys/dev/cxgb/ulp/iw_cxgb/iw_cxgb_mem.c 183292 2008-09-23 03:16:54Z kmacy $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/pciio.h>
#include <sys/conf.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/bus_dma.h>
#include <sys/rman.h>
#include <sys/ioccom.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/linker.h>
#include <sys/firmware.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/libkern.h>

#include <netinet/in.h>

#include <contrib/rdma/ib_verbs.h>
#include <contrib/rdma/ib_umem.h>
#include <contrib/rdma/ib_user_verbs.h>

#include <cxgb_include.h>
#include <ulp/iw_cxgb/iw_cxgb_wr.h>
#include <ulp/iw_cxgb/iw_cxgb_hal.h>
#include <ulp/iw_cxgb/iw_cxgb_provider.h>
#include <ulp/iw_cxgb/iw_cxgb_cm.h>
#include <ulp/iw_cxgb/iw_cxgb.h>
#include <ulp/iw_cxgb/iw_cxgb_resource.h>
#include <ulp/iw_cxgb/iw_cxgb_user.h>

int iwch_register_mem(struct iwch_dev *rhp, struct iwch_pd *php,
					struct iwch_mr *mhp,
					int shift,
					__be64 *page_list)
{
	u32 stag;
	u32 mmid;


	if (cxio_register_phys_mem(&rhp->rdev,
				   &stag, mhp->attr.pdid,
				   mhp->attr.perms,
				   mhp->attr.zbva,
				   mhp->attr.va_fbo,
				   mhp->attr.len,
				   shift-12,
				   page_list,
				   &mhp->attr.pbl_size, &mhp->attr.pbl_addr))
		return (-ENOMEM);
	mhp->attr.state = 1;
	mhp->attr.stag = stag;
	mmid = stag >> 8;
	mhp->ibmr.rkey = mhp->ibmr.lkey = stag;
	insert_handle(rhp, &rhp->mmidr, mhp, mmid);
	CTR3(KTR_IW_CXGB, "%s mmid 0x%x mhp %p", __FUNCTION__, mmid, mhp);
	return 0;
}

int iwch_reregister_mem(struct iwch_dev *rhp, struct iwch_pd *php,
					struct iwch_mr *mhp,
					int shift,
					__be64 *page_list,
					int npages)
{
	u32 stag;
	u32 mmid;


	/* We could support this... */
	if (npages > mhp->attr.pbl_size)
		return (-ENOMEM);

	stag = mhp->attr.stag;
	if (cxio_reregister_phys_mem(&rhp->rdev,
				   &stag, mhp->attr.pdid,
				   mhp->attr.perms,
				   mhp->attr.zbva,
				   mhp->attr.va_fbo,
				   mhp->attr.len,
				   shift-12,
				   page_list,
				   &mhp->attr.pbl_size, &mhp->attr.pbl_addr))
		return (-ENOMEM);
	mhp->attr.state = 1;
	mhp->attr.stag = stag;
	mmid = stag >> 8;
	mhp->ibmr.rkey = mhp->ibmr.lkey = stag;
	insert_handle(rhp, &rhp->mmidr, mhp, mmid);
	CTR3(KTR_IW_CXGB, "%s mmid 0x%x mhp %p", __FUNCTION__, mmid, mhp);
	return 0;
}

int build_phys_page_list(struct ib_phys_buf *buffer_list,
					int num_phys_buf,
					u64 *iova_start,
					u64 *total_size,
					int *npages,
					int *shift,
					__be64 **page_list)
{
	u64 mask;
	int i, j, n;

	mask = 0;
	*total_size = 0;
	for (i = 0; i < num_phys_buf; ++i) {
		if (i != 0 && buffer_list[i].addr & ~PAGE_MASK)
			return (-EINVAL);
		if (i != 0 && i != num_phys_buf - 1 &&
		    (buffer_list[i].size & ~PAGE_MASK))
			return (-EINVAL);
		*total_size += buffer_list[i].size;
		if (i > 0)
			mask |= buffer_list[i].addr;
		else
			mask |= buffer_list[i].addr & PAGE_MASK;
		if (i != num_phys_buf - 1)
			mask |= buffer_list[i].addr + buffer_list[i].size;
		else
			mask |= (buffer_list[i].addr + buffer_list[i].size +
				PAGE_SIZE - 1) & PAGE_MASK;
	}

	if (*total_size > 0xFFFFFFFFULL)
		return (-ENOMEM);

	/* Find largest page shift we can use to cover buffers */
	for (*shift = PAGE_SHIFT; *shift < 27; ++(*shift))
		if ((1ULL << *shift) & mask)
			break;

	buffer_list[0].size += buffer_list[0].addr & ((1ULL << *shift) - 1);
	buffer_list[0].addr &= ~0ull << *shift;

	*npages = 0;
	for (i = 0; i < num_phys_buf; ++i)
		*npages += (buffer_list[i].size +
			(1ULL << *shift) - 1) >> *shift;

	if (!*npages)
		return (-EINVAL);

	*page_list = kmalloc(sizeof(u64) * *npages, M_NOWAIT);
	if (!*page_list)
		return (-ENOMEM);

	n = 0;
	for (i = 0; i < num_phys_buf; ++i)
		for (j = 0;
		     j < (buffer_list[i].size + (1ULL << *shift) - 1) >> *shift;
		     ++j)
			(*page_list)[n++] = htobe64(buffer_list[i].addr +
			    ((u64) j << *shift));

	CTR6(KTR_IW_CXGB, "%s va 0x%llx mask 0x%llx shift %d len %lld pbl_size %d",
	     __FUNCTION__, (unsigned long long) *iova_start,
	     (unsigned long long) mask, *shift, (unsigned long long) *total_size,
	     *npages);

	return 0;

}
