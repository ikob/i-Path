/*-
 * Copyright (c) 2008 Weongyo Jeong <weongyo@freebsd.org>
 * Copyright (c) 2007 Marvell Semiconductor, Inc.
 * Copyright (c) 2007 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 */

#include <sys/cdefs.h>
#ifdef __FreeBSD__
__FBSDID("$FreeBSD: src/sys/dev/malo/if_malo.c,v 1.3.2.1.2.1 2008/11/25 02:59:29 kensmith Exp $");
#endif

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>
#include <sys/bus.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/ethernet.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>

#include <net/bpf.h>

#include <dev/malo/if_malo.h>

SYSCTL_NODE(_hw, OID_AUTO, malo, CTLFLAG_RD, 0,
    "Marvell 88w8335 driver parameters");

static	int malo_txcoalesce = 8;	/* # tx pkts to q before poking f/w*/
SYSCTL_INT(_hw_malo, OID_AUTO, txcoalesce, CTLFLAG_RW, &malo_txcoalesce,
	    0, "tx buffers to send at once");
TUNABLE_INT("hw.malo.txcoalesce", &malo_txcoalesce);
static	int malo_rxbuf = MALO_RXBUF;		/* # rx buffers to allocate */
SYSCTL_INT(_hw_malo, OID_AUTO, rxbuf, CTLFLAG_RW, &malo_rxbuf,
	    0, "rx buffers allocated");
TUNABLE_INT("hw.malo.rxbuf", &malo_rxbuf);
static	int malo_rxquota = MALO_RXBUF;		/* # max buffers to process */
SYSCTL_INT(_hw_malo, OID_AUTO, rxquota, CTLFLAG_RW, &malo_rxquota,
	    0, "max rx buffers to process per interrupt");
TUNABLE_INT("hw.malo.rxquota", &malo_rxquota);
static	int malo_txbuf = MALO_TXBUF;		/* # tx buffers to allocate */
SYSCTL_INT(_hw_malo, OID_AUTO, txbuf, CTLFLAG_RW, &malo_txbuf,
	    0, "tx buffers allocated");
TUNABLE_INT("hw.malo.txbuf", &malo_txbuf);

#ifdef MALO_DEBUG
static	int malo_debug = 0;
SYSCTL_INT(_hw_malo, OID_AUTO, debug, CTLFLAG_RW, &malo_debug,
	    0, "control debugging printfs");
TUNABLE_INT("hw.malo.debug", &malo_debug);
enum {
	MALO_DEBUG_XMIT		= 0x00000001,	/* basic xmit operation */
	MALO_DEBUG_XMIT_DESC	= 0x00000002,	/* xmit descriptors */
	MALO_DEBUG_RECV		= 0x00000004,	/* basic recv operation */
	MALO_DEBUG_RECV_DESC	= 0x00000008,	/* recv descriptors */
	MALO_DEBUG_RESET	= 0x00000010,	/* reset processing */
	MALO_DEBUG_INTR		= 0x00000040,	/* ISR */
	MALO_DEBUG_TX_PROC	= 0x00000080,	/* tx ISR proc */
	MALO_DEBUG_RX_PROC	= 0x00000100,	/* rx ISR proc */
	MALO_DEBUG_STATE	= 0x00000400,	/* 802.11 state transitions */
	MALO_DEBUG_NODE		= 0x00000800,	/* node management */
	MALO_DEBUG_RECV_ALL	= 0x00001000,	/* trace all frames (beacons) */
	MALO_DEBUG_FW		= 0x00008000,	/* firmware */
	MALO_DEBUG_ANY		= 0xffffffff
};
#define	IS_BEACON(wh)							\
	((wh->i_fc[0] & (IEEE80211_FC0_TYPE_MASK |			\
		IEEE80211_FC0_SUBTYPE_MASK)) ==				\
	 (IEEE80211_FC0_TYPE_MGT|IEEE80211_FC0_SUBTYPE_BEACON))
#define	IFF_DUMPPKTS_RECV(sc, wh)					\
	(((sc->malo_debug & MALO_DEBUG_RECV) &&				\
	  ((sc->malo_debug & MALO_DEBUG_RECV_ALL) || !IS_BEACON(wh))) || \
	 (sc->malo_ifp->if_flags & (IFF_DEBUG|IFF_LINK2)) ==		\
	  (IFF_DEBUG|IFF_LINK2))
#define	IFF_DUMPPKTS_XMIT(sc)						\
	((sc->malo_debug & MALO_DEBUG_XMIT) ||				\
	 (sc->malo_ifp->if_flags & (IFF_DEBUG | IFF_LINK2)) ==		\
	     (IFF_DEBUG | IFF_LINK2))
#define	DPRINTF(sc, m, fmt, ...) do {				\
	if (sc->malo_debug & (m))				\
		printf(fmt, __VA_ARGS__);			\
} while (0)
#else
#define	DPRINTF(sc, m, fmt, ...) do {				\
	(void) sc;						\
} while (0)
#endif

MALLOC_DEFINE(M_MALODEV, "malodev", "malo driver dma buffers");

static	int	malo_dma_setup(struct malo_softc *);
static	int	malo_setup_hwdma(struct malo_softc *);
static	void	malo_txq_init(struct malo_softc *, struct malo_txq *, int);
static	void	malo_tx_cleanupq(struct malo_softc *, struct malo_txq *);
static	void	malo_start(struct ifnet *);
static	void	malo_watchdog(struct ifnet *);
static	int	malo_ioctl(struct ifnet *, u_long, caddr_t);
static	void	malo_updateslot(struct ifnet *);
static	int	malo_newstate(struct ieee80211com *, enum ieee80211_state, int);
static	void	malo_scan_start(struct ieee80211com *);
static	void	malo_scan_end(struct ieee80211com *);
static	void	malo_set_channel(struct ieee80211com *);
static	int	malo_raw_xmit(struct ieee80211_node *, struct mbuf *,
		    const struct ieee80211_bpf_params *);
static	int	malo_media_change(struct ifnet *);
static	void	malo_bpfattach(struct malo_softc *);
static	void	malo_sysctlattach(struct malo_softc *);
static	void	malo_announce(struct malo_softc *);
static	void	malo_dma_cleanup(struct malo_softc *);
static	void	malo_stop_locked(struct ifnet *, int);
static	int	malo_chan_set(struct malo_softc *, struct ieee80211_channel *);
static	int	malo_mode_init(struct malo_softc *);
static	void	malo_tx_proc(void *, int);
static	void	malo_rx_proc(void *, int);
static	void	malo_init(void *);

/*
 * Read/Write shorthands for accesses to BAR 0.  Note that all BAR 1
 * operations are done in the "hal" except getting H/W MAC address at
 * malo_attach and there should be no reference to them here.
 */
static uint32_t
malo_bar0_read4(struct malo_softc *sc, bus_size_t off)
{
	return bus_space_read_4(sc->malo_io0t, sc->malo_io0h, off);
}

static void
malo_bar0_write4(struct malo_softc *sc, bus_size_t off, uint32_t val)
{
	DPRINTF(sc, MALO_DEBUG_FW, "%s: off 0x%x val 0x%x\n",
	    __func__, off, val);

	bus_space_write_4(sc->malo_io0t, sc->malo_io0h, off, val);
}

static uint8_t
malo_bar1_read1(struct malo_softc *sc, bus_size_t off)
{
	return bus_space_read_1(sc->malo_io1t, sc->malo_io1h, off);
}

int
malo_attach(uint16_t devid, struct malo_softc *sc)
{
	int error, i;
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifnet *ifp;
	struct malo_hal *mh;
	uint8_t bands;

	ifp = sc->malo_ifp = if_alloc(IFT_ETHER);
	if (ifp == NULL) {
		device_printf(sc->malo_dev, "can not if_alloc()\n");
		return ENOSPC;
	}

	MALO_LOCK_INIT(sc);

	/* set these up early for if_printf use */
	if_initname(ifp, device_get_name(sc->malo_dev),
	    device_get_unit(sc->malo_dev));

	/*
	 * NB: get mac address from hardware directly here before we set DMAs
	 * for HAL because we don't want to disturb operations of HAL at BAR 1.
	 */
	for (i = 0; i < IEEE80211_ADDR_LEN; i++) {
		/* XXX remove a magic number but we don't have documents.  */
		ic->ic_myaddr[i] = malo_bar1_read1(sc, 0xa528 + i);
		DELAY(1000);
	}

	mh = malo_hal_attach(sc->malo_dev, devid,
	    sc->malo_io1h, sc->malo_io1t, sc->malo_dmat);
	if (mh == NULL) {
		if_printf(ifp, "unable to attach HAL\n");
		error = EIO;
		goto bad;
	}
	sc->malo_mh = mh;

	sc->malo_txantenna = 0x2;	/* h/w default */
	sc->malo_rxantenna = 0xffff;	/* h/w default */

	/*
	 * Allocate tx + rx descriptors and populate the lists.
	 * We immediately push the information to the firmware
	 * as otherwise it gets upset.
	 */
	error = malo_dma_setup(sc);
	if (error != 0) {
		if_printf(ifp, "failed to setup descriptors: %d\n", error);
		goto bad1;
	}

	sc->malo_tq = taskqueue_create_fast("malo_taskq", M_NOWAIT,
		taskqueue_thread_enqueue, &sc->malo_tq);
	taskqueue_start_threads(&sc->malo_tq, 1, PI_NET,
		"%s taskq", ifp->if_xname);

	TASK_INIT(&sc->malo_rxtask, 0, malo_rx_proc, sc);
	TASK_INIT(&sc->malo_txtask, 0, malo_tx_proc, sc);

	ifp->if_softc = sc;
	ifp->if_flags = IFF_SIMPLEX | IFF_BROADCAST | IFF_MULTICAST;
	ifp->if_start = malo_start;
	ifp->if_watchdog = malo_watchdog;
	ifp->if_ioctl = malo_ioctl;
	ifp->if_init = malo_init;
	IFQ_SET_MAXLEN(&ifp->if_snd, IFQ_MAXLEN);
	ifp->if_snd.ifq_drv_maxlen = IFQ_MAXLEN;
	IFQ_SET_READY(&ifp->if_snd);

	/* NB: firmware looks that it does not export regdomain info API.  */
	bands = 0;
	setbit(&bands, IEEE80211_MODE_11B);
	setbit(&bands, IEEE80211_MODE_11G);
	ieee80211_init_channels(ic, 0, CTRY_DEFAULT, bands, 0, 1);

	ic->ic_ifp = ifp;
	/* XXX not right but it's not used anywhere important */
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps =
	      IEEE80211_C_BGSCAN		/* capable of bg scanning */
	    | IEEE80211_C_MONITOR		/* monitor mode */
	    | IEEE80211_C_SHPREAMBLE		/* short preamble supported */
	    | IEEE80211_C_SHSLOT		/* short slot time supported */
	    | IEEE80211_C_TXPMGT		/* capable of txpow mgt */
	    | IEEE80211_C_WPA			/* capable of WPA1+WPA2 */
	    ;

	/*
	 * Transmit requires space in the packet for a special format transmit
	 * record and optional padding between this record and the payload.
	 * Ask the net80211 layer to arrange this when encapsulating
	 * packets so we can add it efficiently. 
	 */
	ic->ic_headroom = sizeof(struct malo_txrec) -
	    sizeof(struct ieee80211_frame);

	/* call MI attach routine. */
	ieee80211_ifattach(ic);
	/* override default methods */
	ic->ic_updateslot = malo_updateslot;
	ic->ic_raw_xmit = malo_raw_xmit;

	sc->malo_newstate = ic->ic_newstate;
	ic->ic_newstate = malo_newstate;

	ic->ic_scan_start = malo_scan_start;
	ic->ic_scan_end = malo_scan_end;
	ic->ic_set_channel = malo_set_channel;

	/* complete initialization */
	ieee80211_media_init(ic, malo_media_change, ieee80211_media_status);

	sc->malo_invalid = 0;		/* ready to go, enable int handling */

	malo_bpfattach(sc);

	/*
	 * Setup dynamic sysctl's.
	 */
	malo_sysctlattach(sc);

	if (bootverbose)
		ieee80211_announce(ic);

	return 0;
bad1:
	malo_hal_detach(mh);
bad:
	if_free(ifp);
	sc->malo_invalid = 1;

	return error;
}

int
malo_intr(void *arg)
{
	struct malo_softc *sc = arg;
	struct malo_hal *mh = sc->malo_mh;
	uint32_t status;

	if (sc->malo_invalid) {
		/*
		 * The hardware is not ready/present, don't touch anything.
		 * Note this can happen early on if the IRQ is shared.
		 */
		DPRINTF(sc, MALO_DEBUG_ANY, "%s: invalid; ignored\n", __func__);
		return (FILTER_STRAY);
	}

	/*
	 * Figure out the reason(s) for the interrupt.
	 */
	malo_hal_getisr(mh, &status);		/* NB: clears ISR too */
	if (status == 0)			/* must be a shared irq */
		return (FILTER_STRAY);

	DPRINTF(sc, MALO_DEBUG_INTR, "%s: status 0x%x imask 0x%x\n",
	    __func__, status, sc->malo_imask);

	if (status & MALO_A2HRIC_BIT_RX_RDY)
		taskqueue_enqueue_fast(sc->malo_tq, &sc->malo_rxtask);
	if (status & MALO_A2HRIC_BIT_TX_DONE)
		taskqueue_enqueue_fast(sc->malo_tq, &sc->malo_txtask);
	if (status & MALO_A2HRIC_BIT_OPC_DONE)
		malo_hal_cmddone(mh);
	if (status & MALO_A2HRIC_BIT_MAC_EVENT)
		;
	if (status & MALO_A2HRIC_BIT_RX_PROBLEM)
		;
	if (status & MALO_A2HRIC_BIT_ICV_ERROR) {
		/* TKIP ICV error */
		sc->malo_stats.mst_rx_badtkipicv++;
	}

#ifdef MALO_DEBUG
	if (((status | sc->malo_imask) ^ sc->malo_imask) != 0)
		DPRINTF(sc, MALO_DEBUG_INTR,
		    "%s: can't handle interrupt status 0x%x\n",
		    __func__, status);
#endif

	return (FILTER_HANDLED);
}

static void
malo_load_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	bus_addr_t *paddr = (bus_addr_t*) arg;

	KASSERT(error == 0, ("error %u on bus_dma callback", error));

	*paddr = segs->ds_addr;
}

static int
malo_desc_setup(struct malo_softc *sc, const char *name,
    struct malo_descdma *dd,
    int nbuf, size_t bufsize, int ndesc, size_t descsize)
{
	int error;
	struct ifnet *ifp = sc->malo_ifp;
	uint8_t *ds;

	DPRINTF(sc, MALO_DEBUG_RESET,
	    "%s: %s DMA: %u bufs (%ju) %u desc/buf (%ju)\n",
	    __func__, name, nbuf, (uintmax_t) bufsize,
	    ndesc, (uintmax_t) descsize);
	
	dd->dd_name = name;
	dd->dd_desc_len = nbuf * ndesc * descsize;

	/*
	 * Setup DMA descriptor area.
	 */
	error = bus_dma_tag_create(bus_get_dma_tag(sc->malo_dev),/* parent */
		       PAGE_SIZE, 0,		/* alignment, bounds */
		       BUS_SPACE_MAXADDR_32BIT,	/* lowaddr */
		       BUS_SPACE_MAXADDR,	/* highaddr */
		       NULL, NULL,		/* filter, filterarg */
		       dd->dd_desc_len,		/* maxsize */
		       1,			/* nsegments */
		       dd->dd_desc_len,		/* maxsegsize */
		       BUS_DMA_ALLOCNOW,	/* flags */
		       NULL,			/* lockfunc */
		       NULL,			/* lockarg */
		       &dd->dd_dmat);
	if (error != 0) {
		if_printf(ifp, "cannot allocate %s DMA tag\n", dd->dd_name);
		return error;
	}
	
	/* allocate descriptors */
	error = bus_dmamap_create(dd->dd_dmat, BUS_DMA_NOWAIT, &dd->dd_dmamap);
	if (error != 0) {
		if_printf(ifp, "unable to create dmamap for %s descriptors, "
		    "error %u\n", dd->dd_name, error);
		goto fail0;
	}
	
	error = bus_dmamem_alloc(dd->dd_dmat, (void**) &dd->dd_desc,
	    BUS_DMA_NOWAIT | BUS_DMA_COHERENT, &dd->dd_dmamap);
	if (error != 0) {
		if_printf(ifp, "unable to alloc memory for %u %s descriptors, "
		    "error %u\n", nbuf * ndesc, dd->dd_name, error);
		goto fail1;
	}

	error = bus_dmamap_load(dd->dd_dmat, dd->dd_dmamap,
	    dd->dd_desc, dd->dd_desc_len,
	    malo_load_cb, &dd->dd_desc_paddr, BUS_DMA_NOWAIT);
	if (error != 0) {
		if_printf(ifp, "unable to map %s descriptors, error %u\n",
		    dd->dd_name, error);
		goto fail2;
	}
	
	ds = dd->dd_desc;
	memset(ds, 0, dd->dd_desc_len);
	DPRINTF(sc, MALO_DEBUG_RESET, "%s: %s DMA map: %p (%lu) -> %p (%lu)\n",
	    __func__, dd->dd_name, ds, (u_long) dd->dd_desc_len,
	    (caddr_t) dd->dd_desc_paddr, /*XXX*/ (u_long) dd->dd_desc_len);

	return 0;
fail2:
	bus_dmamem_free(dd->dd_dmat, dd->dd_desc, dd->dd_dmamap);
fail1:
	bus_dmamap_destroy(dd->dd_dmat, dd->dd_dmamap);
fail0:
	bus_dma_tag_destroy(dd->dd_dmat);
	memset(dd, 0, sizeof(*dd));
	return error;
}

#define	DS2PHYS(_dd, _ds) \
	((_dd)->dd_desc_paddr + ((caddr_t)(_ds) - (caddr_t)(_dd)->dd_desc))

static int
malo_rxdma_setup(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;
	int error, bsize, i;
	struct malo_rxbuf *bf;
	struct malo_rxdesc *ds;

	error = malo_desc_setup(sc, "rx", &sc->malo_rxdma,
	    malo_rxbuf, sizeof(struct malo_rxbuf),
	    1, sizeof(struct malo_rxdesc));
	if (error != 0)
		return error;

	/*
	 * Allocate rx buffers and set them up.
	 */
	bsize = malo_rxbuf * sizeof(struct malo_rxbuf);
	bf = malloc(bsize, M_MALODEV, M_NOWAIT | M_ZERO);
	if (bf == NULL) {
		if_printf(ifp, "malloc of %u rx buffers failed\n", bsize);
		return error;
	}
	sc->malo_rxdma.dd_bufptr = bf;
	
	STAILQ_INIT(&sc->malo_rxbuf);
	ds = sc->malo_rxdma.dd_desc;
	for (i = 0; i < malo_rxbuf; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(&sc->malo_rxdma, ds);
		error = bus_dmamap_create(sc->malo_dmat, BUS_DMA_NOWAIT,
		    &bf->bf_dmamap);
		if (error != 0) {
			if_printf(ifp, "%s: unable to dmamap for rx buffer, "
			    "error %d\n", __func__, error);
			return error;
		}
		/* NB: tail is intentional to preserve descriptor order */
		STAILQ_INSERT_TAIL(&sc->malo_rxbuf, bf, bf_list);
	}
	return 0;
}

static int
malo_txdma_setup(struct malo_softc *sc, struct malo_txq *txq)
{
	struct ifnet *ifp = sc->malo_ifp;
	int error, bsize, i;
	struct malo_txbuf *bf;
	struct malo_txdesc *ds;

	error = malo_desc_setup(sc, "tx", &txq->dma,
	    malo_txbuf, sizeof(struct malo_txbuf),
	    MALO_TXDESC, sizeof(struct malo_txdesc));
	if (error != 0)
		return error;
	
	/* allocate and setup tx buffers */
	bsize = malo_txbuf * sizeof(struct malo_txbuf);
	bf = malloc(bsize, M_MALODEV, M_NOWAIT | M_ZERO);
	if (bf == NULL) {
		if_printf(ifp, "malloc of %u tx buffers failed\n",
		    malo_txbuf);
		return ENOMEM;
	}
	txq->dma.dd_bufptr = bf;
	
	STAILQ_INIT(&txq->free);
	txq->nfree = 0;
	ds = txq->dma.dd_desc;
	for (i = 0; i < malo_txbuf; i++, bf++, ds += MALO_TXDESC) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(&txq->dma, ds);
		error = bus_dmamap_create(sc->malo_dmat, BUS_DMA_NOWAIT,
		    &bf->bf_dmamap);
		if (error != 0) {
			if_printf(ifp, "unable to create dmamap for tx "
			    "buffer %u, error %u\n", i, error);
			return error;
		}
		STAILQ_INSERT_TAIL(&txq->free, bf, bf_list);
		txq->nfree++;
	}

	return 0;
}

static void
malo_desc_cleanup(struct malo_softc *sc, struct malo_descdma *dd)
{
	bus_dmamap_unload(dd->dd_dmat, dd->dd_dmamap);
	bus_dmamem_free(dd->dd_dmat, dd->dd_desc, dd->dd_dmamap);
	bus_dmamap_destroy(dd->dd_dmat, dd->dd_dmamap);
	bus_dma_tag_destroy(dd->dd_dmat);

	memset(dd, 0, sizeof(*dd));
}

static void
malo_rxdma_cleanup(struct malo_softc *sc)
{
	struct malo_rxbuf *bf;

	STAILQ_FOREACH(bf, &sc->malo_rxbuf, bf_list) {
		if (bf->bf_m != NULL) {
			m_freem(bf->bf_m);
			bf->bf_m = NULL;
		}
		if (bf->bf_dmamap != NULL) {
			bus_dmamap_destroy(sc->malo_dmat, bf->bf_dmamap);
			bf->bf_dmamap = NULL;
		}
	}
	STAILQ_INIT(&sc->malo_rxbuf);
	if (sc->malo_rxdma.dd_bufptr != NULL) {
		free(sc->malo_rxdma.dd_bufptr, M_MALODEV);
		sc->malo_rxdma.dd_bufptr = NULL;
	}
	if (sc->malo_rxdma.dd_desc_len != 0)
		malo_desc_cleanup(sc, &sc->malo_rxdma);
}

static void
malo_txdma_cleanup(struct malo_softc *sc, struct malo_txq *txq)
{
	struct malo_txbuf *bf;
	struct ieee80211_node *ni;

	STAILQ_FOREACH(bf, &txq->free, bf_list) {
		if (bf->bf_m != NULL) {
			m_freem(bf->bf_m);
			bf->bf_m = NULL;
		}
		ni = bf->bf_node;
		bf->bf_node = NULL;
		if (ni != NULL) {
			/*
			 * Reclaim node reference.
			 */
			ieee80211_free_node(ni);
		}
		if (bf->bf_dmamap != NULL) {
			bus_dmamap_destroy(sc->malo_dmat, bf->bf_dmamap);
			bf->bf_dmamap = NULL;
		}
	}
	STAILQ_INIT(&txq->free);
	txq->nfree = 0;
	if (txq->dma.dd_bufptr != NULL) {
		free(txq->dma.dd_bufptr, M_MALODEV);
		txq->dma.dd_bufptr = NULL;
	}
	if (txq->dma.dd_desc_len != 0)
		malo_desc_cleanup(sc, &txq->dma);
}

static void
malo_dma_cleanup(struct malo_softc *sc)
{
	int i;

	for (i = 0; i < MALO_NUM_TX_QUEUES; i++)
		malo_txdma_cleanup(sc, &sc->malo_txq[i]);

	malo_rxdma_cleanup(sc);
}

static int
malo_dma_setup(struct malo_softc *sc)
{
	int error, i;

	/* rxdma initializing.  */
	error = malo_rxdma_setup(sc);
	if (error != 0)
		return error;

	/* NB: we just have 1 tx queue now.  */
	for (i = 0; i < MALO_NUM_TX_QUEUES; i++) {
		error = malo_txdma_setup(sc, &sc->malo_txq[i]);
		if (error != 0) {
			malo_dma_cleanup(sc);

			return error;
		}

		malo_txq_init(sc, &sc->malo_txq[i], i);
	}

	return 0;
}

static void
malo_hal_set_rxtxdma(struct malo_softc *sc)
{
	int i;

	malo_bar0_write4(sc, sc->malo_hwspecs.rxdesc_read,
	    sc->malo_hwdma.rxdesc_read);
	malo_bar0_write4(sc, sc->malo_hwspecs.rxdesc_write,
	    sc->malo_hwdma.rxdesc_read);

	for (i = 0; i < MALO_NUM_TX_QUEUES; i++) {
		malo_bar0_write4(sc,
		    sc->malo_hwspecs.wcbbase[i], sc->malo_hwdma.wcbbase[i]);
	}
}

/*
 * Inform firmware of our tx/rx dma setup.  The BAR 0 writes below are
 * for compatibility with older firmware.  For current firmware we send
 * this information with a cmd block via malo_hal_sethwdma.
 */
static int
malo_setup_hwdma(struct malo_softc *sc)
{
	int i;
	struct malo_txq *txq;

	sc->malo_hwdma.rxdesc_read = sc->malo_rxdma.dd_desc_paddr;

	for (i = 0; i < MALO_NUM_TX_QUEUES; i++) {
		txq = &sc->malo_txq[i];
		sc->malo_hwdma.wcbbase[i] = txq->dma.dd_desc_paddr;
	}
	sc->malo_hwdma.maxnum_txwcb = malo_txbuf;
	sc->malo_hwdma.maxnum_wcb = MALO_NUM_TX_QUEUES;

	malo_hal_set_rxtxdma(sc);

	return 0;
}

static void
malo_txq_init(struct malo_softc *sc, struct malo_txq *txq, int qnum)
{
	struct malo_txbuf *bf, *bn;
	struct malo_txdesc *ds;

	MALO_TXQ_LOCK_INIT(sc, txq);
	txq->qnum = qnum;
	txq->txpri = 0;	/* XXX */

	STAILQ_FOREACH(bf, &txq->free, bf_list) {
		bf->bf_txq = txq;

		ds = bf->bf_desc;
		bn = STAILQ_NEXT(bf, bf_list);
		if (bn == NULL)
			bn = STAILQ_FIRST(&txq->free);
		ds->physnext = htole32(bn->bf_daddr);
	}
	STAILQ_INIT(&txq->active);
}

/*
 * Reclaim resources for a setup queue.
 */
static void
malo_tx_cleanupq(struct malo_softc *sc, struct malo_txq *txq)
{
	/* XXX hal work? */
	MALO_TXQ_LOCK_DESTROY(txq);
}

/*
 * Allocate a tx buffer for sending a frame.
 */
static struct malo_txbuf *
malo_getbuf(struct malo_softc *sc, struct malo_txq *txq)
{
	struct malo_txbuf *bf;

	MALO_TXQ_LOCK(txq);
	bf = STAILQ_FIRST(&txq->free);
	if (bf != NULL) {
		STAILQ_REMOVE_HEAD(&txq->free, bf_list);
		txq->nfree--;
	}
	MALO_TXQ_UNLOCK(txq);
	if (bf == NULL) {
		DPRINTF(sc, MALO_DEBUG_XMIT,
		    "%s: out of xmit buffers on q %d\n", __func__, txq->qnum);
		sc->malo_stats.mst_tx_qstop++;
	}
	return bf;
}

static int
malo_tx_dmasetup(struct malo_softc *sc, struct malo_txbuf *bf, struct mbuf *m0)
{
	struct mbuf *m;
	int error;

	/*
	 * Load the DMA map so any coalescing is done.  This also calculates
	 * the number of descriptors we need.
	 */
	error = bus_dmamap_load_mbuf_sg(sc->malo_dmat, bf->bf_dmamap, m0,
				     bf->bf_segs, &bf->bf_nseg,
				     BUS_DMA_NOWAIT);
	if (error == EFBIG) {
		/* XXX packet requires too many descriptors */
		bf->bf_nseg = MALO_TXDESC + 1;
	} else if (error != 0) {
		sc->malo_stats.mst_tx_busdma++;
		m_freem(m0);
		return error;
	}
	/*
	 * Discard null packets and check for packets that require too many
	 * TX descriptors.  We try to convert the latter to a cluster.
	 */
	if (error == EFBIG) {		/* too many desc's, linearize */
		sc->malo_stats.mst_tx_linear++;
		m = m_defrag(m0, M_DONTWAIT);
		if (m == NULL) {
			m_freem(m0);
			sc->malo_stats.mst_tx_nombuf++;
			return ENOMEM;
		}
		m0 = m;
		error = bus_dmamap_load_mbuf_sg(sc->malo_dmat, bf->bf_dmamap, m0,
					     bf->bf_segs, &bf->bf_nseg,
					     BUS_DMA_NOWAIT);
		if (error != 0) {
			sc->malo_stats.mst_tx_busdma++;
			m_freem(m0);
			return error;
		}
		KASSERT(bf->bf_nseg <= MALO_TXDESC,
		    ("too many segments after defrag; nseg %u", bf->bf_nseg));
	} else if (bf->bf_nseg == 0) {		/* null packet, discard */
		sc->malo_stats.mst_tx_nodata++;
		m_freem(m0);
		return EIO;
	}
	DPRINTF(sc, MALO_DEBUG_XMIT, "%s: m %p len %u\n",
		__func__, m0, m0->m_pkthdr.len);
	bus_dmamap_sync(sc->malo_dmat, bf->bf_dmamap, BUS_DMASYNC_PREWRITE);
	bf->bf_m = m0;

	return 0;
}

#ifdef MALO_DEBUG
static void
malo_printrxbuf(const struct malo_rxbuf *bf, u_int ix)
{
	const struct malo_rxdesc *ds = bf->bf_desc;
	uint32_t status = le32toh(ds->status);
	
	printf("R[%2u] (DS.V:%p DS.P:%p) NEXT:%08x DATA:%08x RC:%02x%s\n"
	    "      STAT:%02x LEN:%04x SNR:%02x NF:%02x CHAN:%02x"
	    " RATE:%02x QOS:%04x\n",
	    ix, ds, (const struct malo_desc *)bf->bf_daddr,
	    le32toh(ds->physnext), le32toh(ds->physbuffdata),
	    ds->rxcontrol, 
	    ds->rxcontrol != MALO_RXD_CTRL_DRIVER_OWN ?
	        "" : (status & MALO_RXD_STATUS_OK) ? " *" : " !",
	    ds->status, le16toh(ds->pktlen), ds->snr, ds->nf, ds->channel,
	    ds->rate, le16toh(ds->qosctrl));
}

static void
malo_printtxbuf(const struct malo_txbuf *bf, u_int qnum, u_int ix)
{
	const struct malo_txdesc *ds = bf->bf_desc;
	uint32_t status = le32toh(ds->status);
	
	printf("Q%u[%3u]", qnum, ix);
	printf(" (DS.V:%p DS.P:%p)\n",
	    ds, (const struct malo_txdesc *)bf->bf_daddr);
	printf("    NEXT:%08x DATA:%08x LEN:%04x STAT:%08x%s\n",
	    le32toh(ds->physnext),
	    le32toh(ds->pktptr), le16toh(ds->pktlen), status,
	    status & MALO_TXD_STATUS_USED ?
	    "" : (status & 3) != 0 ? " *" : " !");
	printf("    RATE:%02x PRI:%x QOS:%04x SAP:%08x FORMAT:%04x\n",
	    ds->datarate, ds->txpriority, le16toh(ds->qosctrl),
	    le32toh(ds->sap_pktinfo), le16toh(ds->format));
#if 0
	{
		const uint8_t *cp = (const uint8_t *) ds;
		int i;
		for (i = 0; i < sizeof(struct malo_txdesc); i++) {
			printf("%02x ", cp[i]);
			if (((i+1) % 16) == 0)
				printf("\n");
		}
		printf("\n");
	}
#endif
}
#endif /* MALO_DEBUG */

static __inline void
malo_updatetxrate(struct ieee80211_node *ni, int rix)
{
#define	N(x)	(sizeof(x)/sizeof(x[0]))
	static const int ieeerates[] =
	    { 2, 4, 11, 22, 44, 12, 18, 24, 36, 48, 96, 108 };
	if (rix < N(ieeerates))
		ni->ni_txrate = ieeerates[rix];
#undef N
}

static int
malo_fix2rate(int fix_rate)
{
#define	N(x)	(sizeof(x)/sizeof(x[0]))
	static const int rates[] =
	    { 2, 4, 11, 22, 12, 18, 24, 36, 48, 96, 108 };
	return (fix_rate < N(rates) ? rates[fix_rate] : 0);
#undef N
}

/* idiomatic shorthands: MS = mask+shift, SM = shift+mask */
#define	MS(v,x)			(((v) & x) >> x##_S)
#define	SM(v,x)			(((v) << x##_S) & x)

/*
 * Process completed xmit descriptors from the specified queue.
 */
static int
malo_tx_processq(struct malo_softc *sc, struct malo_txq *txq)
{
	struct malo_txbuf *bf;
	struct malo_txdesc *ds;
	struct ieee80211_node *ni;
	int nreaped;
	uint32_t status;

	DPRINTF(sc, MALO_DEBUG_TX_PROC, "%s: tx queue %u\n",
	    __func__, txq->qnum);
	for (nreaped = 0;; nreaped++) {
		MALO_TXQ_LOCK(txq);
		bf = STAILQ_FIRST(&txq->active);
		if (bf == NULL) {
			MALO_TXQ_UNLOCK(txq);
			break;
		}
		ds = bf->bf_desc;
		MALO_TXDESC_SYNC(txq, ds,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (ds->status & htole32(MALO_TXD_STATUS_FW_OWNED)) {
			MALO_TXQ_UNLOCK(txq);
			break;
		}
		STAILQ_REMOVE_HEAD(&txq->active, bf_list);
		MALO_TXQ_UNLOCK(txq);

#ifdef MALO_DEBUG
		if (sc->malo_debug & MALO_DEBUG_XMIT_DESC)
			malo_printtxbuf(bf, txq->qnum, nreaped);
#endif
		ni = bf->bf_node;
		if (ni != NULL) {
			status = le32toh(ds->status);
			if (status & MALO_TXD_STATUS_OK) {
				uint16_t format = le16toh(ds->format);
				uint8_t txant = MS(format, MALO_TXD_ANTENNA);

				sc->malo_stats.mst_ant_tx[txant]++;
				if (status & MALO_TXD_STATUS_OK_RETRY)
					sc->malo_stats.mst_tx_retries++;
				if (status & MALO_TXD_STATUS_OK_MORE_RETRY)
					sc->malo_stats.mst_tx_mretries++;
				malo_updatetxrate(ni, ds->datarate);
				sc->malo_stats.mst_tx_rate = ds->datarate;
			} else {
				if (status & MALO_TXD_STATUS_FAILED_LINK_ERROR)
					sc->malo_stats.mst_tx_linkerror++;
				if (status & MALO_TXD_STATUS_FAILED_XRETRY)
					sc->malo_stats.mst_tx_xretries++;
				if (status & MALO_TXD_STATUS_FAILED_AGING)
					sc->malo_stats.mst_tx_aging++;
			}
			/*
			 * Do any tx complete callback.  Note this must
			 * be done before releasing the node reference.
			 * XXX no way to figure out if frame was ACK'd
			 */
			if (bf->bf_m->m_flags & M_TXCB) {
				/* XXX strip fw len in case header inspected */
				m_adj(bf->bf_m, sizeof(uint16_t));
				ieee80211_process_callback(ni, bf->bf_m,
					(status & MALO_TXD_STATUS_OK) == 0);
			}
			/*
			 * Reclaim reference to node.
			 *
			 * NB: the node may be reclaimed here if, for example
			 *     this is a DEAUTH message that was sent and the
			 *     node was timed out due to inactivity.
			 */
			ieee80211_free_node(ni);
		}
		ds->status = htole32(MALO_TXD_STATUS_IDLE);
		ds->pktlen = htole32(0);

		bus_dmamap_sync(sc->malo_dmat, bf->bf_dmamap,
		    BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->malo_dmat, bf->bf_dmamap);
		m_freem(bf->bf_m);
		bf->bf_m = NULL;
		bf->bf_node = NULL;

		MALO_TXQ_LOCK(txq);
		STAILQ_INSERT_TAIL(&txq->free, bf, bf_list);
		txq->nfree++;
		MALO_TXQ_UNLOCK(txq);
	}
	return nreaped;
}

/*
 * Deferred processing of transmit interrupt.
 */
static void
malo_tx_proc(void *arg, int npending)
{
	struct malo_softc *sc = arg;
	struct ifnet *ifp = sc->malo_ifp;
	int i, nreaped;

	/*
	 * Process each active queue.
	 */
	nreaped = 0;
	for (i = 0; i < MALO_NUM_TX_QUEUES; i++) {
		if (!STAILQ_EMPTY(&sc->malo_txq[i].active))
			nreaped += malo_tx_processq(sc, &sc->malo_txq[i]);
	}

	if (nreaped != 0) {
		ifp->if_drv_flags &= ~IFF_DRV_OACTIVE;
		ifp->if_timer = 0;
		malo_start(ifp);
	}
}

static int
malo_tx_start(struct malo_softc *sc, struct ieee80211_node *ni,
    struct malo_txbuf *bf, struct mbuf *m0)
{
#define	IEEE80211_DIR_DSTODS(wh) \
	((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
#define	IS_DATA_FRAME(wh)						\
	((wh->i_fc[0] & (IEEE80211_FC0_TYPE_MASK)) == IEEE80211_FC0_TYPE_DATA)
	int error, ismcast, iswep;
	int copyhdrlen, hdrlen, pktlen;
	struct ieee80211_frame *wh;
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifnet *ifp = sc->malo_ifp;
	struct malo_txdesc *ds;
	struct malo_txrec *tr;
	struct malo_txq *txq;
	uint16_t qos;

	wh = mtod(m0, struct ieee80211_frame *);
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	ismcast = IEEE80211_IS_MULTICAST(wh->i_addr1);
	copyhdrlen = hdrlen = ieee80211_anyhdrsize(wh);
	pktlen = m0->m_pkthdr.len;
	if (IEEE80211_QOS_HAS_SEQ(wh)) {
		if (IEEE80211_DIR_DSTODS(wh)) {
			qos = *(uint16_t *)
			    (((struct ieee80211_qosframe_addr4 *) wh)->i_qos);
			copyhdrlen -= sizeof(qos);
		} else
			qos = *(uint16_t *)
			    (((struct ieee80211_qosframe *) wh)->i_qos);
	} else
		qos = 0;

	if (iswep) {
		struct ieee80211_key *k;

		/*
		 * Construct the 802.11 header+trailer for an encrypted
		 * frame. The only reason this can fail is because of an
		 * unknown or unsupported cipher/key type.
		 *
		 * NB: we do this even though the firmware will ignore
		 *     what we've done for WEP and TKIP as we need the
		 *     ExtIV filled in for CCMP and this also adjusts
		 *     the headers which simplifies our work below.
		 */
		k = ieee80211_crypto_encap(ic, ni, m0);
		if (k == NULL) {
			/*
			 * This can happen when the key is yanked after the
			 * frame was queued.  Just discard the frame; the
			 * 802.11 layer counts failures and provides
			 * debugging/diagnostics.
			 */
			m_freem(m0);
			return EIO;
		}

		/*
		 * Adjust the packet length for the crypto additions
		 * done during encap and any other bits that the f/w
		 * will add later on.
		 */
		pktlen = m0->m_pkthdr.len;

		/* packet header may have moved, reset our local pointer */
		wh = mtod(m0, struct ieee80211_frame *);
	}

	if (bpf_peers_present(sc->malo_drvbpf)) {
		sc->malo_tx_th.wt_flags = 0;	/* XXX */
		if (iswep)
			sc->malo_tx_th.wt_flags |= IEEE80211_RADIOTAP_F_WEP;
		sc->malo_tx_th.wt_txpower = ni->ni_txpower;
		sc->malo_tx_th.wt_antenna = sc->malo_txantenna;

		bpf_mtap2(sc->malo_drvbpf,
			&sc->malo_tx_th, sc->malo_tx_th_len, m0);
	}

	/*
	 * Copy up/down the 802.11 header; the firmware requires
	 * we present a 2-byte payload length followed by a
	 * 4-address header (w/o QoS), followed (optionally) by
	 * any WEP/ExtIV header (but only filled in for CCMP).
	 * We are assured the mbuf has sufficient headroom to
	 * prepend in-place by the setup of ic_headroom in
	 * malo_attach.
	 */
	if (hdrlen < sizeof(struct malo_txrec)) {
		const int space = sizeof(struct malo_txrec) - hdrlen;
		if (M_LEADINGSPACE(m0) < space) {
			/* NB: should never happen */
			device_printf(sc->malo_dev,
			    "not enough headroom, need %d found %zd, "
			    "m_flags 0x%x m_len %d\n",
			    space, M_LEADINGSPACE(m0), m0->m_flags, m0->m_len);
			ieee80211_dump_pkt(ic,
			    mtod(m0, const uint8_t *), m0->m_len, 0, -1);
			m_freem(m0);
			/* XXX stat */
			return EIO;
		}
		M_PREPEND(m0, space, M_NOWAIT);
	}
	tr = mtod(m0, struct malo_txrec *);
	if (wh != (struct ieee80211_frame *) &tr->wh)
		ovbcopy(wh, &tr->wh, hdrlen);
	/*
	 * Note: the "firmware length" is actually the length of the fully
	 * formed "802.11 payload".  That is, it's everything except for
	 * the 802.11 header.  In particular this includes all crypto
	 * material including the MIC!
	 */
	tr->fwlen = htole16(pktlen - hdrlen);

	/*
	 * Load the DMA map so any coalescing is done.  This
	 * also calculates the number of descriptors we need.
	 */
	error = malo_tx_dmasetup(sc, bf, m0);
	if (error != 0)
		return error;
	bf->bf_node = ni;			/* NB: held reference */
	m0 = bf->bf_m;				/* NB: may have changed */
	tr = mtod(m0, struct malo_txrec *);
	wh = (struct ieee80211_frame *)&tr->wh;

	/*
	 * Formulate tx descriptor.
	 */
	ds = bf->bf_desc;
	txq = bf->bf_txq;

	ds->qosctrl = qos;			/* NB: already little-endian */
	ds->pktptr = htole32(bf->bf_segs[0].ds_addr);
	ds->pktlen = htole16(bf->bf_segs[0].ds_len);
	/* NB: pPhysNext setup once, don't touch */
	ds->datarate = IS_DATA_FRAME(wh) ? 1 : 0;
	ds->sap_pktinfo = 0;
	ds->format = 0;

	/*
	 * Select transmit rate.
	 */
	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		sc->malo_stats.mst_tx_mgmt++;
		/* fall thru... */
	case IEEE80211_FC0_TYPE_CTL:
		ds->txpriority = 1;
		break;
	case IEEE80211_FC0_TYPE_DATA:
		ds->txpriority = txq->qnum;
		break;
	default:
		if_printf(ifp, "bogus frame type 0x%x (%s)\n",
			wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK, __func__);
		/* XXX statistic */
		m_freem(m0);
		return EIO;
	}

#ifdef MALO_DEBUG
	if (IFF_DUMPPKTS_XMIT(sc))
		ieee80211_dump_pkt(ic,
		    mtod(m0, const uint8_t *)+sizeof(uint16_t),
		    m0->m_len - sizeof(uint16_t), ds->datarate, -1);
#endif

	MALO_TXQ_LOCK(txq);
	if (!IS_DATA_FRAME(wh))
		ds->status |= htole32(1);
	ds->status |= htole32(MALO_TXD_STATUS_FW_OWNED);
	STAILQ_INSERT_TAIL(&txq->active, bf, bf_list);
	MALO_TXDESC_SYNC(txq, ds, BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	ifp->if_opackets++;
	ifp->if_timer = 5;
	MALO_TXQ_UNLOCK(txq);
	return 0;
#undef IEEE80211_DIR_DSTODS
}

static void
malo_start(struct ifnet *ifp)
{
	int nqueued = 0;
	struct ether_header *eh;
	struct malo_softc *sc = ifp->if_softc;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct ieee80211com *ic = &sc->malo_ic;
	struct malo_txbuf *bf = NULL;
	struct malo_txq *txq = NULL;
	struct mbuf *m;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0 || sc->malo_invalid)
		return;

	for (;;) {
		/*
		 * Poll the management queue for frames; they
		 * have priority over normal data frames.
		 */
		IF_DEQUEUE(&ic->ic_mgtq, m);
		if (m == NULL) {
			/*
			 * No data frames go out unless we're associated.
			 */
			if (ic->ic_state != IEEE80211_S_RUN) {
				DPRINTF(sc, MALO_DEBUG_XMIT,
				    "%s: discard data packet, state %s\n",
				    __func__,
				    ieee80211_state_name[ic->ic_state]);
				sc->malo_stats.mst_tx_discard++;
				break;
			}
			IFQ_DRV_DEQUEUE(&ifp->if_snd, m);
			if (m == NULL)
				break;
			/*
			 * Cancel any background scan.
			 */
			if (ic->ic_flags & IEEE80211_F_SCAN)
				ieee80211_cancel_scan(ic);

			/*
			 * Find the node for the destination so we can do
			 * things like power save and fast frames aggregation.
			 */
			if (m->m_len < sizeof(struct ether_header) &&
			   (m = m_pullup(m, sizeof(struct ether_header))) ==
			    NULL) {
				ic->ic_stats.is_tx_nobuf++;	/* XXX */
				ni = NULL;
				goto bad;
			}
			eh = mtod(m, struct ether_header *);
			ni = ieee80211_find_txnode(ic, eh->ether_dhost);
			if (ni == NULL) {
				/* NB: ieee80211_find_txnode does stat+msg */
				m_freem(m);
				goto bad;
			}
			/* calculate priority so we can find the tx queue */
			if (ieee80211_classify(ic, m, ni)) {
				DPRINTF(sc, MALO_DEBUG_XMIT,
					"%s: discard, classification failure\n",
					__func__);
				m_freem(m);
				goto bad;
			}

			txq = &sc->malo_txq[0];

			bf = malo_getbuf(sc, txq);
			if (bf == NULL) {
				IFQ_DRV_PREPEND(&ifp->if_snd, m);
				ieee80211_free_node(ni);

				/* XXX blocks other traffic */
				ifp->if_drv_flags |= IFF_DRV_OACTIVE;
				sc->malo_stats.mst_tx_qstop++;
				break;
			}
			ifp->if_opackets++;

			if (bpf_peers_present(ifp->if_bpf))
				bpf_mtap(ifp->if_bpf, m);

			/*
			 * Encapsulate the packet in prep for transmission.
			 */
			m = ieee80211_encap(ic, m, ni);
			if (m == NULL) {
				DPRINTF(sc, MALO_DEBUG_XMIT,
				    "%s: encapsulation failure\n", __func__);
				sc->malo_stats.mst_tx_encap++;
				goto bad;
			}
		} else {
			/*
			 * Grab a TX buffer and associated resources.
			 * Note that we depend on the classification
			 * by the 802.11 layer to get to the right h/w
			 * queue.  Management frames must ALWAYS go on
			 * queue 1 but we cannot just force that here
			 * because we may receive non-mgt frames through
			 * the ic_mgtq (e.g. null data frames).
			 */
			txq = &sc->malo_txq[0];
			bf = malo_getbuf(sc, txq);
			if (bf == NULL) {
				IF_PREPEND(&ic->ic_mgtq, m);
				/* XXX stat */
				break;
			}

			/*
			 * Hack!  The referenced node pointer is in the
			 * rcvif field of the packet header.  This is
			 * placed there by ieee80211_mgmt_output because
			 * we need to hold the reference with the frame
			 * and there's no other way (other than packet
			 * tags which we consider too expensive to use)
			 * to pass it along.
			 */
			ni = (struct ieee80211_node *) m->m_pkthdr.rcvif;
			m->m_pkthdr.rcvif = NULL;

			wh = mtod(m, struct ieee80211_frame *);
			sc->malo_stats.mst_tx_mgmt++;

			if (bpf_peers_present(ic->ic_rawbpf))
				bpf_mtap(ic->ic_rawbpf, m);
		}

		/*
		 * Pass the frame to the h/w for transmission.
		 */
		if (malo_tx_start(sc, ni, bf, m)) {
	bad:
			ifp->if_oerrors++;
			if (bf != NULL) {
				bf->bf_m = NULL;
				bf->bf_node = NULL;
				MALO_TXQ_LOCK(txq);
				STAILQ_INSERT_HEAD(&txq->free, bf, bf_list);
				MALO_TXQ_UNLOCK(txq);
			}
			ieee80211_free_node(ni);
			continue;
		}
		nqueued++;

		if (nqueued >= malo_txcoalesce) {
			/*
			 * Poke the firmware to process queued frames;
			 * see below about (lack of) locking.
			 */
			nqueued = 0;
			malo_hal_txstart(sc->malo_mh, 0/*XXX*/);
		}
	}

	if (nqueued) {
		/*
		 * NB: We don't need to lock against tx done because
		 * this just prods the firmware to check the transmit
		 * descriptors.  The firmware will also start fetching
		 * descriptors by itself if it notices new ones are
		 * present when it goes to deliver a tx done interrupt
		 * to the host. So if we race with tx done processing
		 * it's ok.  Delivering the kick here rather than in
		 * malo_tx_start is an optimization to avoid poking the
		 * firmware for each packet.
		 *
		 * NB: the queue id isn't used so 0 is ok.
		 */
		malo_hal_txstart(sc->malo_mh, 0/*XXX*/);
	}
}

static void
malo_watchdog(struct ifnet *ifp)
{
	struct malo_softc *sc = ifp->if_softc;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) && !sc->malo_invalid) {
		if_printf(ifp, "watchdog timeout\n");

		/* XXX no way to reset h/w. now  */

		ifp->if_oerrors++;
		sc->malo_stats.mst_watchdog++;
	}
}

static int
malo_hal_reset(struct malo_softc *sc)
{
	static int first = 0;
	struct ieee80211com *ic = &sc->malo_ic;
	struct malo_hal *mh = sc->malo_mh;

	if (first == 0) {
		/*
		 * NB: when the device firstly is initialized, sometimes
		 * firmware could override rx/tx dma registers so we re-set
		 * these values once.
		 */
		malo_hal_set_rxtxdma(sc);
		first = 1;
	}

	malo_hal_setantenna(mh, MHA_ANTENNATYPE_RX, sc->malo_rxantenna);
	malo_hal_setantenna(mh, MHA_ANTENNATYPE_TX, sc->malo_txantenna);
	malo_hal_setradio(mh, 1, MHP_AUTO_PREAMBLE);
	malo_chan_set(sc, ic->ic_curchan);

	/* XXX needs other stuffs?  */

	return 1;
}

static __inline struct mbuf *
malo_getrxmbuf(struct malo_softc *sc, struct malo_rxbuf *bf)
{
	struct mbuf *m;
	bus_addr_t paddr;
	int error;

	/* XXX don't need mbuf, just dma buffer */
	m = m_getjcl(M_DONTWAIT, MT_DATA, M_PKTHDR, MJUMPAGESIZE);
	if (m == NULL) {
		sc->malo_stats.mst_rx_nombuf++;	/* XXX */
		return NULL;
	}
	error = bus_dmamap_load(sc->malo_dmat, bf->bf_dmamap,
	    mtod(m, caddr_t), MJUMPAGESIZE,
	    malo_load_cb, &paddr, BUS_DMA_NOWAIT);
	if (error != 0) {
		if_printf(sc->malo_ifp,
		    "%s: bus_dmamap_load failed, error %d\n", __func__, error);
		m_freem(m);
		return NULL;
	}
	bf->bf_data = paddr;
	bus_dmamap_sync(sc->malo_dmat, bf->bf_dmamap, BUS_DMASYNC_PREWRITE);

	return m;
}

static int
malo_rxbuf_init(struct malo_softc *sc, struct malo_rxbuf *bf)
{
	struct malo_rxdesc *ds;

	ds = bf->bf_desc;
	if (bf->bf_m == NULL) {
		bf->bf_m = malo_getrxmbuf(sc, bf);
		if (bf->bf_m == NULL) {
			/* mark descriptor to be skipped */
			ds->rxcontrol = MALO_RXD_CTRL_OS_OWN;
			/* NB: don't need PREREAD */
			MALO_RXDESC_SYNC(sc, ds, BUS_DMASYNC_PREWRITE);
			return ENOMEM;
		}
	}

	/*
	 * Setup descriptor.
	 */
	ds->qosctrl = 0;
	ds->snr = 0;
	ds->status = MALO_RXD_STATUS_IDLE;
	ds->channel = 0;
	ds->pktlen = htole16(MALO_RXSIZE);
	ds->nf = 0;
	ds->physbuffdata = htole32(bf->bf_data);
	/* NB: don't touch pPhysNext, set once */
	ds->rxcontrol = MALO_RXD_CTRL_DRIVER_OWN;
	MALO_RXDESC_SYNC(sc, ds, BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	return 0;
}

/*
 * Setup the rx data structures.  This should only be done once or we may get
 * out of sync with the firmware.
 */
static int
malo_startrecv(struct malo_softc *sc)
{
	struct malo_rxbuf *bf, *prev;
	struct malo_rxdesc *ds;
	
	if (sc->malo_recvsetup == 1) {
		malo_mode_init(sc);		/* set filters, etc. */
		return 0;
	}
	
	prev = NULL;
	STAILQ_FOREACH(bf, &sc->malo_rxbuf, bf_list) {
		int error = malo_rxbuf_init(sc, bf);
		if (error != 0) {
			DPRINTF(sc, MALO_DEBUG_RECV,
			    "%s: malo_rxbuf_init failed %d\n",
			    __func__, error);
			return error;
		}
		if (prev != NULL) {
			ds = prev->bf_desc;
			ds->physnext = htole32(bf->bf_daddr);
		}
		prev = bf;
	}
	if (prev != NULL) {
		ds = prev->bf_desc;
		ds->physnext =
		    htole32(STAILQ_FIRST(&sc->malo_rxbuf)->bf_daddr);
	}

	sc->malo_recvsetup = 1;

	malo_mode_init(sc);		/* set filters, etc. */
	
	return 0;
}

static void
malo_init(void *arg)
{
	struct malo_softc *sc = (struct malo_softc *) arg;
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifnet *ifp = sc->malo_ifp;
	struct malo_hal *mh = sc->malo_mh;
	int error;
	
	DPRINTF(sc, MALO_DEBUG_ANY, "%s: if_flags 0x%x\n",
	    __func__, ifp->if_flags);

	if (!sc->malo_fw_loaded) {
		/*
		 * Load firmware so we can get setup.
		 */
		error = malo_hal_fwload(mh, "malo8335-h", "malo8335-m");
		if (error != 0) {
			if_printf(ifp, "unable to setup firmware\n");
			return;
		}
		/* XXX gethwspecs() extracts correct informations? not maybe! */
		error = malo_hal_gethwspecs(mh, &sc->malo_hwspecs);
		if (error != 0) {
			if_printf(ifp, "unable to fetch h/w specs\n");
			return;
		}

		DPRINTF(sc, MALO_DEBUG_FW,
		    "malo_hal_gethwspecs: hwversion 0x%x hostif 0x%x"
		    "maxnum_wcb 0x%x maxnum_mcaddr 0x%x maxnum_tx_wcb 0x%x"
		    "regioncode 0x%x num_antenna 0x%x fw_releasenum 0x%x"
		    "wcbbase0 0x%x rxdesc_read 0x%x rxdesc_write 0x%x"
		    "ul_fw_awakecookie 0x%x w[4] = %x %x %x %x",
		    sc->malo_hwspecs.hwversion,
		    sc->malo_hwspecs.hostinterface, sc->malo_hwspecs.maxnum_wcb,
		    sc->malo_hwspecs.maxnum_mcaddr,
		    sc->malo_hwspecs.maxnum_tx_wcb,
		    sc->malo_hwspecs.regioncode, sc->malo_hwspecs.num_antenna,
		    sc->malo_hwspecs.fw_releasenum, sc->malo_hwspecs.wcbbase0,
		    sc->malo_hwspecs.rxdesc_read, sc->malo_hwspecs.rxdesc_write,
		    sc->malo_hwspecs.ul_fw_awakecookie,
		    sc->malo_hwspecs.wcbbase[0], sc->malo_hwspecs.wcbbase[1],
		    sc->malo_hwspecs.wcbbase[2], sc->malo_hwspecs.wcbbase[3]);
		
		error = malo_setup_hwdma(sc);	/* push to firmware */
		/* NB: malo_setupdma prints msg */
		if (error != 0) {
			if_printf(ifp, "%s: failed to set up h/w dma\n",
			    __func__);
			return;
		}

		/* set reddomain.  */
		ic->ic_regdomain = sc->malo_hwspecs.regioncode;

		malo_announce(sc);

		sc->malo_fw_loaded = 1;
	}

	MALO_LOCK(sc);
	
	/*
	 * Stop anything previously setup.  This is safe whether this is
	 * the first time through or not.
	 */
	malo_stop_locked(ifp, 0);

	/*
	 * Push state to the firmware.
	 */
	if (!malo_hal_reset(sc)) {
		if_printf(ifp, "%s: unable to reset hardware\n", __func__);
		goto done;
	}

	/*
	 * Setup recv (once); transmit is already good to go.
	 */
	error = malo_startrecv(sc);
	if (error != 0) {
		if_printf(ifp, "%s: unable to start recv logic, error %d\n",
		    __func__, error);
		goto done;
	}

	/*
	 * Enable interrupts.
	 */
	sc->malo_imask = MALO_A2HRIC_BIT_RX_RDY
	    | MALO_A2HRIC_BIT_TX_DONE
	    | MALO_A2HRIC_BIT_OPC_DONE
	    | MALO_A2HRIC_BIT_MAC_EVENT
	    | MALO_A2HRIC_BIT_RX_PROBLEM
	    | MALO_A2HRIC_BIT_ICV_ERROR
	    | MALO_A2HRIC_BIT_RADAR_DETECT
	    | MALO_A2HRIC_BIT_CHAN_SWITCH;

	ifp->if_drv_flags |= IFF_DRV_RUNNING;
	ic->ic_state = IEEE80211_S_INIT;
	IEEE80211_ADDR_COPY(ic->ic_myaddr, IF_LLADDR(ifp));

	malo_hal_intrset(mh, sc->malo_imask);

	/*
	 * The hardware should be ready to go now so it's safe to kick
	 * the 802.11 state machine as it's likely to immediately call back
	 * to us to send mgmt frames.
	 */
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		if (ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
			ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
	} else
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);

done:
	if (error != 0)
		if_printf(ifp,
		    "error(%d) occurred during the initializing.\n", error);

	MALO_UNLOCK(sc);

	return;
}

/*
 * Set the multicast filter contents into the hardware.
 */
static void
malo_setmcastfilter(struct malo_softc *sc)
{
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifmultiaddr *ifma;
	struct ifnet *ifp = sc->malo_ifp;
	uint8_t macs[IEEE80211_ADDR_LEN * MALO_HAL_MCAST_MAX];
	uint8_t *mp;
	int nmc;

	mp = macs;
	nmc = 0;

	if (ic->ic_opmode == IEEE80211_M_MONITOR ||
	    (ifp->if_flags & (IFF_ALLMULTI | IFF_PROMISC)))
		goto all;
	
	IF_ADDR_LOCK(ifp);
	TAILQ_FOREACH(ifma, &ifp->if_multiaddrs, ifma_link) {
		if (ifma->ifma_addr->sa_family != AF_LINK)
			continue;

		if (nmc == MALO_HAL_MCAST_MAX) {
			ifp->if_flags |= IFF_ALLMULTI;
			IF_ADDR_UNLOCK(ifp);
			goto all;
		}
		IEEE80211_ADDR_COPY(mp,
		    LLADDR((struct sockaddr_dl *)ifma->ifma_addr));

		mp += IEEE80211_ADDR_LEN, nmc++;
	}
	IF_ADDR_UNLOCK(ifp);

	malo_hal_setmcast(sc->malo_mh, nmc, macs);

all:
	/*
	 * XXX we don't know how to set the f/w for supporting
	 * IFF_ALLMULTI | IFF_PROMISC cases
	 */
	return;
}

static int
malo_mode_init(struct malo_softc *sc)
{
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_hal *mh = sc->malo_mh;

	/*
	 * Handle any link-level address change.  Note that we only
	 * need to force ic_myaddr; any other addresses are handled
	 * as a byproduct of the ifnet code marking the interface
	 * down then up.
	 */
	IEEE80211_ADDR_COPY(ic->ic_myaddr, IF_LLADDR(ifp));

	/*
	 * NB: Ignore promisc in hostap mode; it's set by the
	 * bridge.  This is wrong but we have no way to
	 * identify internal requests (from the bridge)
	 * versus external requests such as for tcpdump.
	 */
	malo_hal_setpromisc(mh, (ifp->if_flags & IFF_PROMISC) &&
	    ic->ic_opmode != IEEE80211_M_HOSTAP);
	malo_setmcastfilter(sc);

	return ENXIO;
}

static void
malo_tx_draintxq(struct malo_softc *sc, struct malo_txq *txq)
{
	struct ieee80211_node *ni;
	struct malo_txbuf *bf;
	u_int ix;
	
	/*
	 * NB: this assumes output has been stopped and
	 *     we do not need to block malo_tx_tasklet
	 */
	for (ix = 0;; ix++) {
		MALO_TXQ_LOCK(txq);
		bf = STAILQ_FIRST(&txq->active);
		if (bf == NULL) {
			MALO_TXQ_UNLOCK(txq);
			break;
		}
		STAILQ_REMOVE_HEAD(&txq->active, bf_list);
		MALO_TXQ_UNLOCK(txq);
#ifdef MALO_DEBUG
		if (sc->malo_debug & MALO_DEBUG_RESET) {
			const struct malo_txrec *tr =
			    mtod(bf->bf_m, const struct malo_txrec *);
			malo_printtxbuf(bf, txq->qnum, ix);
			ieee80211_dump_pkt(&sc->malo_ic,
			    (const uint8_t *)&tr->wh,
			    bf->bf_m->m_len - sizeof(tr->fwlen), 0, -1);
		}
#endif /* MALO_DEBUG */
		bus_dmamap_unload(sc->malo_dmat, bf->bf_dmamap);
		ni = bf->bf_node;
		bf->bf_node = NULL;
		if (ni != NULL) {
			/*
			 * Reclaim node reference.
			 */
			ieee80211_free_node(ni);
		}
		m_freem(bf->bf_m);
		bf->bf_m = NULL;
		
		MALO_TXQ_LOCK(txq);
		STAILQ_INSERT_TAIL(&txq->free, bf, bf_list);
		txq->nfree++;
		MALO_TXQ_UNLOCK(txq);
	}
}

static void
malo_stop_locked(struct ifnet *ifp, int disable)
{
	int i;
	struct malo_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->malo_ic;
	struct malo_hal *mh = sc->malo_mh;

	DPRINTF(sc, MALO_DEBUG_ANY, "%s: invalid %u if_flags 0x%x\n",
	    __func__, sc->malo_invalid, ifp->if_flags);

	MALO_LOCK_ASSERT(sc);

	if (!(ifp->if_drv_flags & IFF_DRV_RUNNING))
		return;

	/*
	 * Shutdown the hardware and driver:
	 *    reset 802.11 state machine
	 *    turn off timers
	 *    disable interrupts
	 *    turn off the radio
	 *    clear transmit machinery
	 *    clear receive machinery
	 *    drain and release tx queues
	 *    reclaim beacon resources
	 *    power down hardware
	 *
	 * Note that some of this work is not possible if the hardware
	 * is gone (invalid).
	 */
	ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
	ifp->if_timer = 0;
	if (sc->malo_fw_loaded == 1) {
		/* diable interrupt.  */
		malo_hal_intrset(mh, 0);
		/* turn off the radio.  */
		malo_hal_setradio(mh, 0, MHP_AUTO_PREAMBLE);
	}

	/* drain and release tx queues.  */
	for (i = 0; i < MALO_NUM_TX_QUEUES; i++)
		malo_tx_draintxq(sc, &sc->malo_txq[i]);
}

static int
malo_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
#define	MALO_IS_RUNNING(ifp) \
	((ifp->if_flags & IFF_UP) && (ifp->if_drv_flags & IFF_DRV_RUNNING))
	struct malo_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->malo_ic;
	int error = 0;

	MALO_LOCK(sc);

	switch (cmd) {
	case SIOCSIFFLAGS:
		if (MALO_IS_RUNNING(ifp)) {
			/*
			 * To avoid rescanning another access point,
			 * do not call malo_init() here.  Instead,
			 * only reflect promisc mode settings.
			 */
			malo_mode_init(sc);
		} else if (ifp->if_flags & IFF_UP) {
			/*
			 * Beware of being called during attach/detach
			 * to reset promiscuous mode.  In that case we
			 * will still be marked UP but not RUNNING.
			 * However trying to re-init the interface
			 * is the wrong thing to do as we've already
			 * torn down much of our state.  There's
			 * probably a better way to deal with this.
			 */
			if (!sc->malo_invalid)
				malo_init(sc);
		} else
			malo_stop_locked(ifp, 1);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/*
		 * The upper layer has already installed/removed
		 * the multicast address(es), just recalculate the
		 * multicast filter for the card.
		 */
		if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			malo_mode_init(sc);
		break;
	default:
		error = ieee80211_ioctl(ic, cmd, data);
		if (error == ENETRESET) {
			if (MALO_IS_RUNNING(ifp) &&
			    ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
				malo_init(sc);
			error = 0;
		}
		if (error == ERESTART) {
			/* XXX we need to reset the device here.  */
			error = 0;
		}
		break;
	}

	MALO_UNLOCK(sc);

	return error;
#undef MALO_IS_RUNNING
}

/*
 * Callback from the 802.11 layer to update the slot time
 * based on the current setting.  We use it to notify the
 * firmware of ERP changes and the f/w takes care of things
 * like slot time and preamble.
 */
static void
malo_updateslot(struct ifnet *ifp)
{
	struct malo_softc *sc = ifp->if_softc;
	struct ieee80211com *ic = &sc->malo_ic;
	struct malo_hal *mh = sc->malo_mh;
	int error;
	
	/* NB: can be called early; suppress needless cmds */
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0)
		return;

	DPRINTF(sc, MALO_DEBUG_RESET,
	    "%s: chan %u MHz/flags 0x%x %s slot, (ic_flags 0x%x)\n",
	    __func__, ic->ic_curchan->ic_freq, ic->ic_curchan->ic_flags,
	    ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long", ic->ic_flags);

	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		error = malo_hal_set_slot(mh, 1);
	else
		error = malo_hal_set_slot(mh, 0);

	if (error != 0)
		device_printf(sc->malo_dev, "setting %s slot failed\n",
			ic->ic_flags & IEEE80211_F_SHSLOT ? "short" : "long");
}

static int
malo_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct ieee80211_node *ni = ic->ic_bss;
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_softc *sc = ifp->if_softc;
	struct malo_hal *mh = sc->malo_mh;
	int error;

	DPRINTF(sc, MALO_DEBUG_STATE, "%s: %s -> %s\n", __func__,
	    ieee80211_state_name[ic->ic_state],
	    ieee80211_state_name[nstate]);

	/*
	 * Carry out firmware actions per-state.
	 */
	switch (nstate) {
	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
	case IEEE80211_S_AUTH:
		/* NB: do nothing.  */
		break;
	case IEEE80211_S_ASSOC:
		malo_hal_setradio(mh, 1,
		    (ic->ic_flags & IEEE80211_F_SHPREAMBLE) ?
		    MHP_SHORT_PREAMBLE : MHP_LONG_PREAMBLE);
		break;
	case IEEE80211_S_RUN:
		DPRINTF(sc, MALO_DEBUG_STATE,
		    "%s: %s(RUN): ic_flags 0x%08x bintvl %d bssid %s "
		    "capinfo 0x%04x chan %d\n",
		    ifp->if_xname, __func__, ic->ic_flags,
		    ni->ni_intval, ether_sprintf(ni->ni_bssid), ni->ni_capinfo,
		    ieee80211_chan2ieee(ic, ic->ic_curchan));

		switch (ic->ic_opmode) {
		case IEEE80211_M_STA:
			DPRINTF(sc, MALO_DEBUG_STATE, "%s: %s: aid 0x%x\n",
			    ic->ic_ifp->if_xname, __func__, ni->ni_associd);
			malo_hal_setassocid(sc->malo_mh,
			    ni->ni_bssid, ni->ni_associd);

			if (ic->ic_fixed_rate == IEEE80211_FIXED_RATE_NONE)
				/* automatic rate adaption */
				malo_hal_set_rate(mh, ic->ic_curmode, 0);
			else
				/* fixed rate */
				malo_hal_set_rate(mh, ic->ic_curmode, 
				    malo_fix2rate(ic->ic_fixed_rate));
			break;
		default:
			break;
		}

		break;
	default:
		if_printf(ifp, "%s: can't handle state %s -> %s\n",
		    __func__, ieee80211_state_name[ic->ic_state],
		    ieee80211_state_name[nstate]);
	}

	/*
	 * Invoke the parent method to complete the work.
	 */
	error = sc->malo_newstate(ic, nstate, arg);

	return error;
}

static int
malo_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
	const struct ieee80211_bpf_params *params)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_softc *sc = ifp->if_softc;
	struct malo_txbuf *bf;
	struct malo_txq *txq;

	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0 || sc->malo_invalid) {
		ieee80211_free_node(ni);
		m_freem(m);
		return ENETDOWN;
	}

	/*
	 * Grab a TX buffer and associated resources.  Note that we depend
	 * on the classification by the 802.11 layer to get to the right h/w
	 * queue.  Management frames must ALWAYS go on queue 1 but we
	 * cannot just force that here because we may receive non-mgt frames.
	 */
	txq = &sc->malo_txq[0];
	bf = malo_getbuf(sc, txq);
	if (bf == NULL) {
		/* XXX blocks other traffic */
		ifp->if_drv_flags |= IFF_DRV_OACTIVE;
		ieee80211_free_node(ni);
		m_freem(m);
		return ENOBUFS;
	}

	/*
	 * Pass the frame to the h/w for transmission.
	 */
	if (malo_tx_start(sc, ni, bf, m) != 0) {
		ifp->if_oerrors++;
		bf->bf_m = NULL;
		bf->bf_node = NULL;
		MALO_TXQ_LOCK(txq);
		STAILQ_INSERT_HEAD(&txq->free, bf, bf_list);
		txq->nfree++;
		MALO_TXQ_UNLOCK(txq);

		ieee80211_free_node(ni);
		return EIO;		/* XXX */
	}

	/*
	 * NB: We don't need to lock against tx done because this just
	 * prods the firmware to check the transmit descriptors.  The firmware
	 * will also start fetching descriptors by itself if it notices
	 * new ones are present when it goes to deliver a tx done interrupt
	 * to the host. So if we race with tx done processing it's ok.
	 * Delivering the kick here rather than in malo_tx_start is
	 * an optimization to avoid poking the firmware for each packet.
	 *
	 * NB: the queue id isn't used so 0 is ok.
	 */
	malo_hal_txstart(sc->malo_mh, 0/*XXX*/);

	return 0;
}

static int
malo_media_change(struct ifnet *ifp)
{
#define	IS_UP(ifp) \
	((ifp->if_flags & IFF_UP) && (ifp->if_drv_flags & IFF_DRV_RUNNING))
	int error;

	error = ieee80211_media_change(ifp);
	if (error == ENETRESET) {
		struct malo_softc *sc = ifp->if_softc;

		if (IS_UP(ifp))
			malo_init(sc);
		error = 0;
	}
	return error;
#undef IS_UP
}

static void
malo_bpfattach(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;

	bpfattach2(ifp, DLT_IEEE802_11_RADIO,
	    sizeof(struct ieee80211_frame) + sizeof(sc->malo_tx_th),
	    &sc->malo_drvbpf);

	/*
	 * Initialize constant fields.
	 * XXX make header lengths a multiple of 32-bits so subsequent
	 *     headers are properly aligned; this is a kludge to keep
	 *     certain applications happy.
	 *
	 * NB: the channel is setup each time we transition to the
	 *     RUN state to avoid filling it in for each frame.
	 */
	sc->malo_tx_th_len = roundup(sizeof(sc->malo_tx_th), sizeof(uint32_t));
	sc->malo_tx_th.wt_ihdr.it_len = htole16(sc->malo_tx_th_len);
	sc->malo_tx_th.wt_ihdr.it_present = htole32(MALO_TX_RADIOTAP_PRESENT);

	sc->malo_rx_th_len = roundup(sizeof(sc->malo_rx_th), sizeof(uint32_t));
	sc->malo_rx_th.wr_ihdr.it_len = htole16(sc->malo_rx_th_len);
	sc->malo_rx_th.wr_ihdr.it_present = htole32(MALO_RX_RADIOTAP_PRESENT);
}

static void
malo_sysctlattach(struct malo_softc *sc)
{
#ifdef	MALO_DEBUG
	struct sysctl_ctx_list *ctx = device_get_sysctl_ctx(sc->malo_dev);
	struct sysctl_oid *tree = device_get_sysctl_tree(sc->malo_dev);

	sc->malo_debug = malo_debug;
	SYSCTL_ADD_INT(ctx, SYSCTL_CHILDREN(tree), OID_AUTO,
		"debug", CTLFLAG_RW, &sc->malo_debug, 0,
		"control debugging printfs");
#endif
}

static void
malo_announce(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;

	if_printf(ifp, "versions [hw %d fw %d.%d.%d.%d] (regioncode %d)\n",
		sc->malo_hwspecs.hwversion,
		(sc->malo_hwspecs.fw_releasenum >> 24) & 0xff,
		(sc->malo_hwspecs.fw_releasenum >> 16) & 0xff,
		(sc->malo_hwspecs.fw_releasenum >> 8) & 0xff,
		(sc->malo_hwspecs.fw_releasenum >> 0) & 0xff,
		sc->malo_hwspecs.regioncode);

	if (bootverbose || malo_rxbuf != MALO_RXBUF)
		if_printf(ifp, "using %u rx buffers\n", malo_rxbuf);
	if (bootverbose || malo_txbuf != MALO_TXBUF)
		if_printf(ifp, "using %u tx buffers\n", malo_txbuf);
}

/*
 * Convert net80211 channel to a HAL channel.
 */
static void
malo_mapchan(struct malo_hal_channel *hc, const struct ieee80211_channel *chan)
{
	hc->channel = chan->ic_ieee;

	*(uint32_t *)&hc->flags = 0;
	if (IEEE80211_IS_CHAN_2GHZ(chan))
		hc->flags.freqband = MALO_FREQ_BAND_2DOT4GHZ;
}

/*
 * Set/change channels.  If the channel is really being changed,
 * it's done by reseting the chip.  To accomplish this we must
 * first cleanup any pending DMA, then restart stuff after a la
 * malo_init.
 */
static int
malo_chan_set(struct malo_softc *sc, struct ieee80211_channel *chan)
{
	struct malo_hal *mh = sc->malo_mh;
	struct malo_hal_channel hchan;

	DPRINTF(sc, MALO_DEBUG_RESET, "%s: chan %u MHz/flags 0x%x\n",
	    __func__, chan->ic_freq, chan->ic_flags);

	/*
	 * Convert to a HAL channel description with the flags constrained
	 * to reflect the current operating mode.
	 */
	malo_mapchan(&hchan, chan);
	malo_hal_intrset(mh, 0);		/* disable interrupts */
	malo_hal_setchannel(mh, &hchan);
	malo_hal_settxpower(mh, &hchan);

	/*
	 * Update internal state.
	 */
	sc->malo_tx_th.wt_chan_freq = htole16(chan->ic_freq);
	sc->malo_rx_th.wr_chan_freq = htole16(chan->ic_freq);
	if (IEEE80211_IS_CHAN_ANYG(chan)) {
		sc->malo_tx_th.wt_chan_flags = htole16(IEEE80211_CHAN_G);
		sc->malo_rx_th.wr_chan_flags = htole16(IEEE80211_CHAN_G);
	} else {
		sc->malo_tx_th.wt_chan_flags = htole16(IEEE80211_CHAN_B);
		sc->malo_rx_th.wr_chan_flags = htole16(IEEE80211_CHAN_B);
	}
	sc->malo_curchan = hchan;
	malo_hal_intrset(mh, sc->malo_imask);

	return 0;
}

static void
malo_scan_start(struct ieee80211com *ic)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_softc *sc = ifp->if_softc;

	DPRINTF(sc, MALO_DEBUG_STATE, "%s\n", __func__);
}

static void
malo_scan_end(struct ieee80211com *ic)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_softc *sc = ifp->if_softc;

	DPRINTF(sc, MALO_DEBUG_STATE, "%s\n", __func__);
}

static void
malo_set_channel(struct ieee80211com *ic)
{
	struct ifnet *ifp = ic->ic_ifp;
	struct malo_softc *sc = ifp->if_softc;

	(void) malo_chan_set(sc, ic->ic_curchan);
}

static void
malo_rx_proc(void *arg, int npending)
{
#define	IEEE80211_DIR_DSTODS(wh)					\
	((((const struct ieee80211_frame *)wh)->i_fc[1] &		\
	    IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
	struct malo_softc *sc = arg;
	struct malo_rxbuf *bf;
	struct ieee80211com *ic = &sc->malo_ic;
	struct ifnet *ifp = sc->malo_ifp;
	struct malo_rxdesc *ds;
	struct mbuf *m, *mnew;
	struct ieee80211_qosframe *wh;
	struct ieee80211_qosframe_addr4 *wh4;
	struct ieee80211_node *ni;
	int off, len, hdrlen, pktlen, rssi, ntodo;
	uint8_t *data, status;
	uint32_t readptr, writeptr;

	DPRINTF(sc, MALO_DEBUG_RX_PROC,
	    "%s: pending %u rdptr(0x%x) 0x%x wrptr(0x%x) 0x%x\n",
	    __func__, npending,
	    sc->malo_hwspecs.rxdesc_read,
	    malo_bar0_read4(sc, sc->malo_hwspecs.rxdesc_read),
	    sc->malo_hwspecs.rxdesc_write,
	    malo_bar0_read4(sc, sc->malo_hwspecs.rxdesc_write));

	readptr = malo_bar0_read4(sc, sc->malo_hwspecs.rxdesc_read);
	writeptr = malo_bar0_read4(sc, sc->malo_hwspecs.rxdesc_write);
	if (readptr == writeptr)
		return;

	bf = sc->malo_rxnext;
	for (ntodo = malo_rxquota; ntodo > 0 && (readptr != writeptr);
	     ntodo--) {
		if (bf == NULL) {
			bf = STAILQ_FIRST(&sc->malo_rxbuf);
			break;
		}
		ds = bf->bf_desc;
		if (bf->bf_m == NULL) {
			/*
			 * If data allocation failed previously there
			 * will be no buffer; try again to re-populate it.
			 * Note the firmware will not advance to the next
			 * descriptor with a dma buffer so we must mimic
			 * this or we'll get out of sync.
			 */ 
			DPRINTF(sc, MALO_DEBUG_ANY,
			    "%s: rx buf w/o dma memory\n", __func__);
			(void)malo_rxbuf_init(sc, bf);
			break;
		}
		MALO_RXDESC_SYNC(sc, ds,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		if (ds->rxcontrol != MALO_RXD_CTRL_DMA_OWN)
			break;

		readptr = le32toh(ds->physnext);

#ifdef MALO_DEBUG
		if (sc->malo_debug & MALO_DEBUG_RECV_DESC)
			malo_printrxbuf(bf, 0);
#endif
		status = ds->status;
		if (status & MALO_RXD_STATUS_DECRYPT_ERR_MASK) {
			ifp->if_ierrors++;
			goto rx_next;
		}
		/*
		 * Sync the data buffer.
		 */
		len = le16toh(ds->pktlen);
		bus_dmamap_sync(sc->malo_dmat, bf->bf_dmamap,
		    BUS_DMASYNC_POSTREAD);
		/*
		 * The 802.11 header is provided all or in part at the front;
		 * use it to calculate the true size of the header that we'll
		 * construct below.  We use this to figure out where to copy
		 * payload prior to constructing the header.
		 */
		m = bf->bf_m;
		data = mtod(m, uint8_t *);
		hdrlen = ieee80211_anyhdrsize(data + sizeof(uint16_t));
		off = sizeof(uint16_t) + sizeof(struct ieee80211_frame_addr4);

		/*
		 * Calculate RSSI.  XXX wrong
		 */
		rssi = 2 * ((int) ds->snr - ds->nf);	/* NB: .5 dBm  */
		if (rssi > 100)
			rssi = 100;

		pktlen = hdrlen + (len - off);
		/*
		 * NB: we know our frame is at least as large as
		 * IEEE80211_MIN_LEN because there is a 4-address frame at
		 * the front.  Hence there's no need to vet the packet length.
		 * If the frame in fact is too small it should be discarded
		 * at the net80211 layer.
		 */

		/* XXX don't need mbuf, just dma buffer */
		mnew = malo_getrxmbuf(sc, bf);
		if (mnew == NULL) {
			ifp->if_ierrors++;
			goto rx_next;
		}
		
		/*
		 * Attach the dma buffer to the mbuf; malo_rxbuf_init will
		 * re-setup the rx descriptor using the replacement dma
		 * buffer we just installed above.
		 */
		bf->bf_m = mnew;
		m->m_data += off - hdrlen;
		m->m_pkthdr.len = m->m_len = pktlen;
		m->m_pkthdr.rcvif = ifp;

		/*
		 * Piece 802.11 header together.
		 */
		wh = mtod(m, struct ieee80211_qosframe *);
		/* NB: don't need to do this sometimes but ... */
		/* XXX special case so we can memcpy after m_devget? */
		ovbcopy(data + sizeof(uint16_t), wh, hdrlen);
		if (IEEE80211_QOS_HAS_SEQ(wh)) {
			if (IEEE80211_DIR_DSTODS(wh)) {
				wh4 = mtod(m,
				    struct ieee80211_qosframe_addr4*);
				*(uint16_t *)wh4->i_qos = ds->qosctrl;
			} else {
				*(uint16_t *)wh->i_qos = ds->qosctrl;
			}
		}
		if (sc->malo_drvbpf != NULL) {
			sc->malo_rx_th.wr_flags = 0;
			sc->malo_rx_th.wr_rate = ds->rate;
			sc->malo_rx_th.wr_antsignal = rssi;
			sc->malo_rx_th.wr_antnoise = ds->nf;

			bpf_mtap2(sc->malo_drvbpf,
			    &sc->malo_rx_th, sc->malo_rx_th_len, m);
		}
#ifdef MALO_DEBUG
		if (IFF_DUMPPKTS_RECV(sc, wh)) {
			ieee80211_dump_pkt(ic, mtod(m, caddr_t),
			    len, ds->rate, rssi);
		}
#endif
		ifp->if_ipackets++;
		
		/* dispatch */
		ni = ieee80211_find_rxnode(ic,
		    (const struct ieee80211_frame_min *) wh);
		(void) ieee80211_input(ic, m, ni, rssi, ds->nf, 0/*XXX*/);
		ieee80211_free_node(ni);

rx_next:
		/* NB: ignore ENOMEM so we process more descriptors */
		(void) malo_rxbuf_init(sc, bf);
		bf = STAILQ_NEXT(bf, bf_list);
	}
	
	malo_bar0_write4(sc, sc->malo_hwspecs.rxdesc_read, readptr);
	sc->malo_rxnext = bf;

	if ((ifp->if_drv_flags & IFF_DRV_OACTIVE) == 0 &&
	    !IFQ_IS_EMPTY(&ifp->if_snd))
		malo_start(ifp);
#undef IEEE80211_DIR_DSTODS
}

static void
malo_stop(struct ifnet *ifp, int disable)
{
	struct malo_softc *sc = ifp->if_softc;

	MALO_LOCK(sc);

	malo_stop_locked(ifp, disable);

	MALO_UNLOCK(sc);
}

/*
 * Reclaim all tx queue resources.
 */
static void
malo_tx_cleanup(struct malo_softc *sc)
{
	int i;

	for (i = 0; i < MALO_NUM_TX_QUEUES; i++)
		malo_tx_cleanupq(sc, &sc->malo_txq[i]);
}

int
malo_detach(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;

	DPRINTF(sc, MALO_DEBUG_ANY, "%s: if_flags %x\n",
		__func__, ifp->if_flags);

	malo_stop(ifp, 1);

	if (sc->malo_tq != NULL) {
		taskqueue_drain(sc->malo_tq, &sc->malo_rxtask);
		taskqueue_drain(sc->malo_tq, &sc->malo_txtask);
		taskqueue_free(sc->malo_tq);
		sc->malo_tq = NULL;
	}

	bpfdetach(ifp);

	/*
	 * NB: the order of these is important:
	 * o call the 802.11 layer before detaching the hal to
	 *   insure callbacks into the driver to delete global
	 *   key cache entries can be handled
	 * o reclaim the tx queue data structures after calling
	 *   the 802.11 layer as we'll get called back to reclaim
	 *   node state and potentially want to use them
	 * o to cleanup the tx queues the hal is called, so detach
	 *   it last
	 * Other than that, it's straightforward...
	 */
	ieee80211_ifdetach(&sc->malo_ic);
	malo_dma_cleanup(sc);
	malo_tx_cleanup(sc);
	malo_hal_detach(sc->malo_mh);
	if_free(ifp);

	MALO_LOCK_DESTROY(sc);

	return 0;
}

void
malo_shutdown(struct malo_softc *sc)
{

	malo_stop(sc->malo_ifp, 1);
}

void
malo_suspend(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;

	DPRINTF(sc, MALO_DEBUG_ANY, "%s: if_flags %x\n",
		__func__, ifp->if_flags);

	malo_stop(ifp, 1);
}

void
malo_resume(struct malo_softc *sc)
{
	struct ifnet *ifp = sc->malo_ifp;

	DPRINTF(sc, MALO_DEBUG_ANY, "%s: if_flags %x\n",
		__func__, ifp->if_flags);

	if (ifp->if_flags & IFF_UP) {
		malo_init(sc);
		if (ifp->if_drv_flags & IFF_DRV_RUNNING)
			malo_start(ifp);
	}
}
