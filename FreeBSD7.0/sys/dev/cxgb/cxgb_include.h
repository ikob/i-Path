/*
 *  $FreeBSD: src/sys/dev/cxgb/cxgb_include.h,v 1.2.2.1.2.1 2008/11/25 02:59:29 kensmith Exp $ 
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <machine/bus.h>
#ifdef CONFIG_DEFINED
#include <cxgb_osdep.h>
#include <common/cxgb_common.h>
#include <cxgb_ioctl.h>
#include <cxgb_offload.h>
#include <common/cxgb_regs.h>
#include <common/cxgb_t3_cpl.h>
#include <common/cxgb_ctl_defs.h>
#include <common/cxgb_sge_defs.h>
#include <common/cxgb_firmware_exports.h>
#include <common/jhash.h>
#include <ulp/toecore/cxgb_toedev.h>
#else
#include <dev/cxgb/cxgb_osdep.h>
#include <dev/cxgb/common/cxgb_common.h>
#include <dev/cxgb/cxgb_ioctl.h>
#include <dev/cxgb/cxgb_offload.h>
#include <dev/cxgb/common/cxgb_regs.h>
#include <dev/cxgb/common/cxgb_t3_cpl.h>
#include <dev/cxgb/common/cxgb_ctl_defs.h>
#include <dev/cxgb/common/cxgb_sge_defs.h>
#include <dev/cxgb/common/cxgb_firmware_exports.h>
#include <dev/cxgb/common/jhash.h>
#include <dev/cxgb/ulp/toecore/cxgb_toedev.h>
#endif


