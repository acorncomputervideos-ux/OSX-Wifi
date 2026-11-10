/*
 * Mac OS X kernel driver for Realtek RTL8187L USB wireless adapters.
 *
 * This file is the glue between three things: Apple's USB family (bulk
 * pipes and control requests), Apple's networking family (an Ethernet
 * controller with one interface), and the portable driver core in
 * src/core (the chip register code and the 802.11 station logic).
 *
 * Threading.  All driver core state is protected by the gate of the
 * driver's own work loop:
 *   - commands from user space, enable/disable and transmit arrive on
 *     other threads and enter through the command gate (transmit via
 *     the IOGatedOutputQueue);
 *   - the timer and the receive event source run on the work loop;
 *   - USB completions run on the USB family's work loop and never touch
 *     core state: they only copy data into the receive ring or release
 *     a transmit buffer.
 * Register access is a synchronous USB control request and therefore
 * sleeps; that is fine under our own gate, never in a USB completion.
 */
#include "RTL8187.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/network/IONetworkMedium.h>
#include <libkern/OSAtomic.h>
#include <sys/mbuf.h>

extern "C" {
#include <kern/clock.h>
#include <sys/random.h>
}

/*
 * Packet buffers.  With the Mac OS X 10.3.9 SDK an mbuf is an open
 * structure; from the 10.4 SDK on it is opaque and has accessor
 * functions.  A driver built against the 10.3.9 SDK runs on 10.3.9
 * through 10.5 on PowerPC.
 */
#ifdef RTW_USE_KPI_MBUF
#include <sys/kpi_mbuf.h>
#define MB_NEXT(m)		((struct mbuf *)mbuf_next((mbuf_t)(m)))
#define MB_DATA(m)		((UInt8 *)mbuf_data((mbuf_t)(m)))
#define MB_LEN(m)		((UInt32)mbuf_len((mbuf_t)(m)))
#define MB_PKTLEN(m)		((UInt32)mbuf_pkthdr_len((mbuf_t)(m)))
#define MB_SETLEN(m, n)		do { \
	mbuf_setlen((mbuf_t)(m), (n)); \
	mbuf_pkthdr_setlen((mbuf_t)(m), (n)); \
} while (0)
#else
#define MB_NEXT(m)		((m)->m_next)
#define MB_DATA(m)		((UInt8 *)(m)->m_data)
#define MB_LEN(m)		((UInt32)(m)->m_len)
#define MB_PKTLEN(m)		((UInt32)(m)->m_pkthdr.len)
#define MB_SETLEN(m, n)		do { \
	(m)->m_len = (n); \
	(m)->m_pkthdr.len = (n); \
} while (0)
#endif

#define super IOEthernetController
OSDefineMetaClassAndStructors(com_osxwifi_driver_RTL8187, IOEthernetController)

#define LOG(fmt, args...)	IOLog("RTL8187: " fmt "\n" , ## args)

enum {
	kControlTimeoutMS	= 1000,
	kTxNoDataTimeoutMS	= 2000,
	kTxCompletionTimeoutMS	= 5000,
	kMaxEthernetFrame	= 1514,
	kRxMaxErrors		= 8,
	kRadioResetAfterScans	= 3
};

/* The network to rejoin after the adapter is re-enumerated (it loses
 * power across sleep on most Macs, which looks like unplug and replug).
 * Lives as long as the kext stays loaded. */
static struct rtw_join	gSavedJoin;
static bool		gHaveSavedJoin;

/* ------------------------------------------------------------------ */
/* Life cycle                                                         */

bool
RTL8187Driver::init(OSDictionary *properties)
{
	if (!super::init(properties))
		return false;
	fDevice = 0;
	fInterface = 0;
	fInPipe = fOutPipe = 0;
	fDeviceOpen = fInterfaceOpen = false;
	fTerminating = false;
	fWorkLoop = 0;
	fGate = 0;
	fTimer = 0;
	fRxSource = 0;
	fNetif = 0;
	fNetStats = 0;
	fEtherStats = 0;
	fOutputQueue = 0;
	fMediumDict = 0;
	fMedium = 0;
	fEnabled = false;
	bzero(fTx, sizeof(fTx));
	fTxStalled = 0;
	fRxDesc = 0;
	fRxRing = 0;
	fRxLock = 0;
	fRxHead = fRxTail = 0;
	fRxPending = fRxFailed = false;
	fRxErrors = 0;
	fEmptyScans = 0;
	fScanCount = 0;
	fPublished = 0;
	return true;
}

bool
RTL8187Driver::createWorkLoop()
{
	fWorkLoop = IOWorkLoop::workLoop();
	return fWorkLoop != 0;
}

IOWorkLoop *
RTL8187Driver::getWorkLoop() const
{
	return fWorkLoop;
}

IOOutputQueue *
RTL8187Driver::createOutputQueue()
{
	/* Gated: outputPacket() is then called under the work loop gate. */
	return IOGatedOutputQueue::withTarget(this, getWorkLoop());
}

bool
RTL8187Driver::openDevice(IOService *provider)
{
	const IOUSBConfigurationDescriptor *cd;
	IOUSBFindInterfaceRequest ireq;
	IOUSBFindEndpointRequest ereq;
	IOUSBPipe *pipe = 0, *out3 = 0;

	fDevice = OSDynamicCast(IOUSBDevice, provider);
	if (fDevice == 0)
		return false;
	fDevice->retain();
	if (!fDevice->open(this)) {
		LOG("cannot open the USB device");
		return false;
	}
	fDeviceOpen = true;

	if (fDevice->GetNumConfigurations() < 1 ||
	    (cd = fDevice->GetFullConfigurationDescriptor(0)) == 0) {
		LOG("no USB configuration");
		return false;
	}
	if (fDevice->SetConfiguration(this, cd->bConfigurationValue, true) !=
	    kIOReturnSuccess) {
		LOG("cannot set the USB configuration");
		return false;
	}

	ireq.bInterfaceClass = kIOUSBFindInterfaceDontCare;
	ireq.bInterfaceSubClass = kIOUSBFindInterfaceDontCare;
	ireq.bInterfaceProtocol = kIOUSBFindInterfaceDontCare;
	ireq.bAlternateSetting = kIOUSBFindInterfaceDontCare;
	fInterface = fDevice->FindNextInterface(0, &ireq);
	if (fInterface == 0) {
		LOG("no USB interface");
		return false;
	}
	fInterface->retain();
	if (!fInterface->open(this)) {
		LOG("cannot open the USB interface");
		return false;
	}
	fInterfaceOpen = true;

	/* The endpoints cannot be told apart by their descriptors, only
	 * by number: 1 IN carries received frames, 2 OUT transmits (3 OUT
	 * is an equivalent second transmit queue). */
	for (;;) {
		ereq.type = kUSBBulk;
		ereq.direction = kUSBAnyDirn;
		ereq.maxPacketSize = 0;
		ereq.interval = 0;
		pipe = fInterface->FindNextPipe(pipe, &ereq);
		if (pipe == 0)
			break;
		if (pipe->GetDirection() == kUSBIn) {
			if (pipe->GetEndpointNumber() == (RTL8187_EP_RX & 0x0f))
				fInPipe = pipe;
		} else if (pipe->GetEndpointNumber() == RTL8187_EP_TX) {
			fOutPipe = pipe;
		} else if (pipe->GetEndpointNumber() == 3) {
			out3 = pipe;
		}
	}
	if (fOutPipe == 0)
		fOutPipe = out3;
	if (fInPipe == 0 || fOutPipe == 0) {
		LOG("bulk endpoints not found");
		fInPipe = fOutPipe = 0;
		return false;
	}
	fInPipe->retain();
	fOutPipe->retain();
	return true;
}

/* Close the provider.  On unplug (final == false) the objects are kept
 * until stop(), because a USB completion may still be looking at them. */
void
RTL8187Driver::closeDevice(bool final)
{
	if (fInterface && fInterfaceOpen) {
		fInterface->close(this);
		fInterfaceOpen = false;
	}
	if (fDevice && fDeviceOpen) {
		fDevice->close(this);
		fDeviceOpen = false;
	}
	if (!final)
		return;
	if (fInPipe) {
		fInPipe->release();
		fInPipe = 0;
	}
	if (fOutPipe) {
		fOutPipe->release();
		fOutPipe = 0;
	}
	if (fInterface) {
		fInterface->release();
		fInterface = 0;
	}
	if (fDevice) {
		fDevice->release();
		fDevice = 0;
	}
}

bool
RTL8187Driver::allocateBuffers()
{
	int i;

	fRxLock = IOLockAlloc();
	fRxRing = (RxSlot *)IOMalloc(kRxRingSize * sizeof(RxSlot));
	fRxDesc = IOBufferMemoryDescriptor::withCapacity(RTL8187_XFER_MAX,
	    kIODirectionIn);
	if (fRxLock == 0 || fRxRing == 0 || fRxDesc == 0)
		return false;
	fRxCompletion.target = this;
	fRxCompletion.action = rxCompleteTramp;
	fRxCompletion.parameter = 0;

	for (i = 0; i < kTxBufferCount; i++) {
		TxBuffer *tb = &fTx[i];

		tb->desc = IOBufferMemoryDescriptor::withCapacity(
		    RTL8187_XFER_MAX, kIODirectionOut);
		if (tb->desc == 0)
			return false;
		tb->owner = this;
		tb->data = (UInt8 *)tb->desc->getBytesNoCopy();
		tb->busy = 0;
		tb->completion.target = this;
		tb->completion.action = txCompleteTramp;
		tb->completion.parameter = tb;
	}
	return true;
}

void
RTL8187Driver::releaseBuffers()
{
	int i;

	for (i = 0; i < kTxBufferCount; i++) {
		if (fTx[i].desc) {
			fTx[i].desc->release();
			fTx[i].desc = 0;
		}
	}
	if (fRxDesc) {
		fRxDesc->release();
		fRxDesc = 0;
	}
	if (fRxRing) {
		IOFree(fRxRing, kRxRingSize * sizeof(RxSlot));
		fRxRing = 0;
	}
	if (fRxLock) {
		IOLockFree(fRxLock);
		fRxLock = 0;
	}
}

bool
RTL8187Driver::start(IOService *provider)
{
	struct rtl8187_io io;
	struct rtw_sta_ops ops;
	IONetworkMedium *medium;
	int err;

	if (!super::start(provider))
		return false;

	if (getWorkLoop() == 0 || !openDevice(provider) || !allocateBuffers())
		goto fail;

	fGate = IOCommandGate::commandGate(this);
	fTimer = IOTimerEventSource::timerEventSource(this, timerFired);
	fRxSource = IOInterruptEventSource::interruptEventSource(this,
	    rxSignalled, 0, 0);
	if (fGate == 0 || fTimer == 0 || fRxSource == 0 ||
	    fWorkLoop->addEventSource(fGate) != kIOReturnSuccess ||
	    fWorkLoop->addEventSource(fTimer) != kIOReturnSuccess ||
	    fWorkLoop->addEventSource(fRxSource) != kIOReturnSuccess) {
		LOG("cannot set up the work loop");
		goto fail;
	}
	fRxSource->enable();

	/* Identify the chip.  This reads the EEPROM one bit per control
	 * request and takes a few seconds. */
	io.ctx = this;
	io.read = hwRead;
	io.write = hwWrite;
	io.msleep = hwSleep;
	io.udelay = hwDelay;
	err = rtl8187_probe(&fHw, &io);
	if (err == RTL8187_E_UNSUPPORTED) {
		LOG("this adapter is an RTL8187B or has an unknown radio; "
		    "only the RTL8187L with RTL8225 is supported");
		goto fail;
	}
	if (err != 0) {
		LOG("cannot read the adapter's configuration (error %d)", err);
		goto fail;
	}
	LOG("RTL8187L rev %u, radio RTL8225%s, address "
	    "%02x:%02x:%02x:%02x:%02x:%02x", fHw.hwrev,
	    fHw.rf_v2 ? "z2" : "", fHw.macaddr[0], fHw.macaddr[1],
	    fHw.macaddr[2], fHw.macaddr[3], fHw.macaddr[4], fHw.macaddr[5]);

	ops.ctx = this;
	ops.set_channel = staSetChannel;
	ops.set_bss = staSetBss;
	ops.tx = staTx;
	ops.rx_deliver = staDeliver;
	ops.link = staLink;
	ops.scan_done = staScanDone;
	ops.set_timer = staSetTimer;
	ops.random = staRandom;
	ops.now_ms = staNow;
	rtw_sta_init(&fSta, &ops, fHw.macaddr);
	if (gHaveSavedJoin)
		(void)rtw_sta_join(&fSta, &gSavedJoin);

	/* To the rest of the system this is an Ethernet interface whose
	 * "cable" is plugged in while we are associated. */
	fMediumDict = OSDictionary::withCapacity(1);
	medium = IONetworkMedium::medium(kIOMediumEthernetAuto, 0);
	if (fMediumDict == 0 || medium == 0) {
		if (medium)
			medium->release();
		goto fail;
	}
	IONetworkMedium::addMedium(fMediumDict, medium);
	medium->release();
	fMedium = IONetworkMedium::getMediumWithType(fMediumDict,
	    kIOMediumEthernetAuto);
	if (!publishMediumDictionary(fMediumDict) || fMedium == 0)
		goto fail;
	setCurrentMedium(fMedium);
	setLinkStatus(kIONetworkLinkValid, fMedium, 0);

	fOutputQueue = getOutputQueue();
	if (fOutputQueue == 0)
		goto fail;
	fOutputQueue->retain();

	setProperty(kRTWRadio, fHw.rf_v2 ? "RTL8225z2" : "RTL8225");
	publishStatus(true);

	if (!attachInterface((IONetworkInterface **)&fNetif, true)) {
		LOG("cannot attach the network interface");
		goto fail;
	}
	registerService();
	return true;

fail:
	stop(provider);
	return false;
}

void
RTL8187Driver::stop(IOService *provider)
{
	if (fGate)
		fGate->runAction(gatedDisable);
	if (fNetif) {
		detachInterface(fNetif, true);
		fNetif->release();
		fNetif = 0;
	}
	if (fWorkLoop) {
		if (fTimer) {
			fTimer->cancelTimeout();
			fWorkLoop->removeEventSource(fTimer);
		}
		if (fRxSource) {
			fRxSource->disable();
			fWorkLoop->removeEventSource(fRxSource);
		}
		if (fGate)
			fWorkLoop->removeEventSource(fGate);
	}
	closeDevice(true);
	super::stop(provider);
}

void
RTL8187Driver::free()
{
	if (fTimer)
		fTimer->release();
	if (fRxSource)
		fRxSource->release();
	if (fGate)
		fGate->release();
	if (fOutputQueue)
		fOutputQueue->release();
	if (fMediumDict)
		fMediumDict->release();
	releaseBuffers();
	if (fWorkLoop)
		fWorkLoop->release();
	super::free();
}

IOReturn
RTL8187Driver::message(UInt32 type, IOService *provider, void *argument)
{
	if (type == kIOMessageServiceIsTerminated) {
		/* Unplugged.  Stop touching the hardware and let go of the
		 * provider so that its termination can complete. */
		fTerminating = true;
		if (fGate)
			fGate->runAction(gatedTerminated);
		return kIOReturnSuccess;
	}
	return super::message(type, provider, argument);
}

IOReturn
RTL8187Driver::doTerminated()
{
	disableHardware();
	closeDevice(false);
	return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/* Network controller                                                 */

bool
RTL8187Driver::configureInterface(IONetworkInterface *netif)
{
	IONetworkData *d;

	if (!super::configureInterface(netif))
		return false;
	d = netif->getNetworkData(kIONetworkStatsKey);
	if (d == 0 || (fNetStats = (IONetworkStats *)d->getBuffer()) == 0)
		return false;
	d = netif->getParameter(kIOEthernetStatsKey);
	if (d == 0 || (fEtherStats = (IOEthernetStats *)d->getBuffer()) == 0)
		return false;
	return true;
}

IOReturn
RTL8187Driver::getHardwareAddress(IOEthernetAddress *addr)
{
	bcopy(fHw.macaddr, addr->bytes, kIOEthernetAddressSize);
	return kIOReturnSuccess;
}

const OSString *
RTL8187Driver::newVendorString() const
{
	return OSString::withCString("Realtek");
}

const OSString *
RTL8187Driver::newModelString() const
{
	return OSString::withCString("RTL8187L");
}

IOReturn
RTL8187Driver::enable(IONetworkInterface *netif)
{
	return fGate->runAction(gatedEnable);
}

IOReturn
RTL8187Driver::disable(IONetworkInterface *netif)
{
	return fGate->runAction(gatedDisable);
}

IOReturn
RTL8187Driver::enableHardware()
{
	int err;

	if (fEnabled)
		return kIOReturnSuccess;
	if (fTerminating || fDevice == 0)
		return kIOReturnNoDevice;

	err = rtl8187_start(&fHw);
	if (err != 0) {
		LOG("cannot initialise the adapter (error %d)", err);
		return kIOReturnIOError;
	}
	fRxErrors = 0;
	fRxFailed = false;
	fEmptyScans = 0;
	if (startRead() != kIOReturnSuccess) {
		LOG("cannot start receiving");
		rtl8187_stop(&fHw);
		return kIOReturnIOError;
	}
	fEnabled = true;
	fOutputQueue->setCapacity(64);
	fOutputQueue->start();
	rtw_sta_up(&fSta);
	publishStatus(false);
	return kIOReturnSuccess;
}

IOReturn
RTL8187Driver::disableHardware()
{
	if (!fEnabled)
		return kIOReturnSuccess;
	fEnabled = false;
	if (fTimer)
		fTimer->cancelTimeout();
	rtw_sta_down(&fSta);		/* says goodbye to the access point */
	fOutputQueue->stop();
	fOutputQueue->flush();
	abortPipes();
	if (!fTerminating)
		rtl8187_stop(&fHw);
	setLinkStatus(kIONetworkLinkValid, fMedium, 0);
	publishStatus(false);
	return kIOReturnSuccess;
}

void
RTL8187Driver::abortPipes()
{
	if (fInPipe)
		fInPipe->Abort();
	if (fOutPipe)
		fOutPipe->Abort();
}

IOReturn
RTL8187Driver::setPromiscuousMode(bool active)
{
	return fGate->runAction(gatedPromisc, (void *)(active ? 1 : 0));
}

IOReturn
RTL8187Driver::setMulticastMode(bool active)
{
	/* The chip passes all multicast frames; the stack filters. */
	return kIOReturnSuccess;
}

IOReturn
RTL8187Driver::setMulticastList(IOEthernetAddress *addrs, UInt32 count)
{
	return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ */
/* Transmit                                                           */

RTL8187Driver::TxBuffer *
RTL8187Driver::allocTx()
{
	int i;

	for (i = 0; i < kTxBufferCount; i++) {
		if (OSCompareAndSwap(0, 1, (UInt32 *)&fTx[i].busy))
			return &fTx[i];
	}
	return 0;
}

void
RTL8187Driver::releaseTx(TxBuffer *tb)
{
	OSCompareAndSwap(1, 0, (UInt32 *)&tb->busy);
}

IOReturn
RTL8187Driver::submitTx(TxBuffer *tb, UInt32 length)
{
	IOReturn rc;

	if (fOutPipe == 0 || fTerminating) {
		releaseTx(tb);
		return kIOReturnNoDevice;
	}
	tb->desc->setLength(length);
	rc = fOutPipe->Write(tb->desc, kTxNoDataTimeoutMS,
	    kTxCompletionTimeoutMS, &tb->completion);
	if (rc != kIOReturnSuccess)
		releaseTx(tb);
	return rc;
}

static void
mbufCopyOut(struct mbuf *m, UInt32 offset, UInt32 length, UInt8 *dst)
{
	while (m != 0 && length > 0) {
		UInt32 n = MB_LEN(m);

		if (offset >= n) {
			offset -= n;
		} else {
			n -= offset;
			if (n > length)
				n = length;
			bcopy(MB_DATA(m) + offset, dst, n);
			dst += n;
			length -= n;
			offset = 0;
		}
		m = MB_NEXT(m);
	}
}

/* Called by the output queue, under the work loop gate. */
UInt32
RTL8187Driver::outputPacket(struct mbuf *m, void *param)
{
	UInt8 eth[RTW_ETH_HLEN];
	unsigned head, tail;
	UInt32 total = MB_PKTLEN(m);
	TxBuffer *tb;
	size_t flen;
	int rate;

	if (!fEnabled || total < RTW_ETH_HLEN || total > kMaxEthernetFrame)
		goto drop;
	mbufCopyOut(m, 0, RTW_ETH_HLEN, eth);
	if (rtw_sta_tx_prepare(&fSta, eth, &head, &tail) != 0)
		goto drop;	/* not associated */

	tb = allocTx();
	if (tb == 0) {
		/* All buffers are in flight.  Ask for the queue to be
		 * restarted by the next completion, then look once more in
		 * case that completion has just happened. */
		OSCompareAndSwap(0, 1, (UInt32 *)&fTxStalled);
		tb = allocTx();
		if (tb == 0)
			return kIOReturnOutputStall;
	}

	/* [descriptor][802.11 header etc.][payload][MIC]: the payload is
	 * copied straight to its final place and encrypted there. */
	mbufCopyOut(m, RTW_ETH_HLEN, total - RTW_ETH_HLEN,
	    tb->data + RTL8187_TX_DESC_LEN + head);
	flen = rtw_sta_tx_finish(&fSta, eth, tb->data + RTL8187_TX_DESC_LEN,
	    total - RTW_ETH_HLEN, &rate);
	if (submitTx(tb, rtl8187_tx_desc(tb->data, flen, rate)) !=
	    kIOReturnSuccess)
		goto drop;

	fNetStats->outputPackets++;
	freePacket(m);
	return kIOReturnOutputSuccess;

drop:
	fNetStats->outputErrors++;
	freePacket(m);
	return kIOReturnOutputDropped;
}

/* USB completion context. */
void
RTL8187Driver::txComplete(TxBuffer *tb, IOReturn status)
{
	releaseTx(tb);
	if (OSCompareAndSwap(1, 0, (UInt32 *)&fTxStalled) && fOutputQueue)
		fOutputQueue->service(IOBasicOutputQueue::kServiceAsync);
}

void
RTL8187Driver::txCompleteTramp(void *target, void *param, IOReturn status,
    UInt32 remaining)
{
	((RTL8187Driver *)target)->txComplete((TxBuffer *)param, status);
}

/* ------------------------------------------------------------------ */
/* Receive                                                            */

IOReturn
RTL8187Driver::startRead()
{
	IOReturn rc;

	if (fInPipe == 0 || fTerminating)
		return kIOReturnNoDevice;
	fRxPending = true;
	rc = fInPipe->Read(fRxDesc, &fRxCompletion, 0);
	if (rc != kIOReturnSuccess)
		fRxPending = false;
	return rc;
}

/* USB completion context: queue the transfer and ask for the next. */
void
RTL8187Driver::rxComplete(IOReturn status, UInt32 remaining)
{
	bool queued = false;

	fRxPending = false;
	if (status == kIOReturnSuccess || status == kIOReturnUnderrun) {
		UInt32 length = RTL8187_XFER_MAX - remaining;

		fRxErrors = 0;
		IOLockLock(fRxLock);
		if (length > 0 && length <= RTL8187_XFER_MAX &&
		    ((fRxHead + 1) % kRxRingSize) != fRxTail) {
			RxSlot *slot = &fRxRing[fRxHead];

			slot->length = length;
			bcopy(fRxDesc->getBytesNoCopy(), slot->data, length);
			fRxHead = (fRxHead + 1) % kRxRingSize;
			queued = true;
		}
		IOLockUnlock(fRxLock);
	} else if (status == kIOReturnAborted ||
	    status == kIOReturnNotResponding || status == kIOReturnNoDevice) {
		return;		/* disabled or unplugged */
	} else {
		fRxErrors++;
	}

	if (!fEnabled || fTerminating)
		return;
	if (fRxErrors >= kRxMaxErrors || startRead() != kIOReturnSuccess) {
		/* Let the work loop clear the stall and start again. */
		fRxFailed = true;
		queued = true;
	}
	if (queued)
		fRxSource->interruptOccurred(0, 0, 0);
}

void
RTL8187Driver::rxCompleteTramp(void *target, void *param, IOReturn status,
    UInt32 remaining)
{
	((RTL8187Driver *)target)->rxComplete(status, remaining);
}

/* Work loop: hand queued transfers to the 802.11 layer. */
void
RTL8187Driver::rxService()
{
	struct rtl8187_rxinfo ri;

	for (;;) {
		RxSlot *slot;

		IOLockLock(fRxLock);
		slot = (fRxTail != fRxHead) ? &fRxRing[fRxTail] : 0;
		IOLockUnlock(fRxLock);
		if (slot == 0)
			break;
		/* The slot stays ours until fRxTail moves on. */
		if (fEnabled) {
			if (rtl8187_rx_parse(slot->data, slot->length, &ri) == 0)
				rtw_sta_rx(&fSta, slot->data, ri.len, ri.rssi,
				    ri.rate);
			else
				fNetStats->inputErrors++;
		}
		IOLockLock(fRxLock);
		fRxTail = (fRxTail + 1) % kRxRingSize;
		IOLockUnlock(fRxLock);
	}

	if (fRxFailed && fEnabled && !fTerminating && !fRxPending) {
		fRxFailed = false;
		fRxErrors = 0;
		IOSleep(100);
		if (fInPipe)
			fInPipe->ClearStall();
		if (startRead() != kIOReturnSuccess)
			LOG("receive pipe failed; unplug and replug the adapter");
	}
	publishStatus(false);
}

void
RTL8187Driver::rxSignalled(OSObject *owner, IOInterruptEventSource *src,
    int count)
{
	((RTL8187Driver *)owner)->rxService();
}

void
RTL8187Driver::timerFired(OSObject *owner, IOTimerEventSource *src)
{
	RTL8187Driver *self = (RTL8187Driver *)owner;

	if (self->fEnabled && !self->fTerminating) {
		rtw_sta_timer(&self->fSta);
		self->publishStatus(false);
	}
}

/* ------------------------------------------------------------------ */
/* Chip layer callbacks                                               */

int
RTL8187Driver::controlRequest(bool in, uint16_t value, uint16_t index,
    void *buf, unsigned len)
{
	IOUSBDevRequest req;

	if (fTerminating || fDevice == 0)
		return -1;
	req.bmRequestType = USBmakebmRequestType(in ? kUSBIn : kUSBOut,
	    kUSBVendor, kUSBDevice);
	req.bRequest = RTL8187_REQ_REG;
	req.wValue = value;
	req.wIndex = index;
	req.wLength = len;
	req.pData = buf;
	req.wLenDone = 0;
	if (fDevice->DeviceRequest(&req, kControlTimeoutMS, kControlTimeoutMS,
	    0) != kIOReturnSuccess)
		return -1;
	return (in && req.wLenDone != len) ? -1 : 0;
}

int
RTL8187Driver::hwRead(void *ctx, uint16_t value, uint16_t index, uint8_t *buf,
    unsigned len)
{
	return ((RTL8187Driver *)ctx)->controlRequest(true, value, index, buf,
	    len);
}

int
RTL8187Driver::hwWrite(void *ctx, uint16_t value, uint16_t index,
    const uint8_t *buf, unsigned len)
{
	return ((RTL8187Driver *)ctx)->controlRequest(false, value, index,
	    (void *)buf, len);
}

void
RTL8187Driver::hwSleep(void *ctx, unsigned ms)
{
	IOSleep(ms);
}

void
RTL8187Driver::hwDelay(void *ctx, unsigned us)
{
	IODelay(us);
}

/* ------------------------------------------------------------------ */
/* 802.11 layer callbacks (all under the work loop gate)              */

int
RTL8187Driver::staSetChannel(void *ctx, int chan)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;

	return rtl8187_set_channel(&self->fHw, chan);
}

int
RTL8187Driver::staSetBss(void *ctx, const uint8_t *bssid, int linked,
    int short_slot)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;

	return rtl8187_set_bss(&self->fHw, bssid, linked, short_slot);
}

int
RTL8187Driver::staTx(void *ctx, const uint8_t *frame, size_t len, int hwrate)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;
	TxBuffer *tb;

	if (len + RTL8187_TX_DESC_LEN + 1 > RTL8187_XFER_MAX)
		return -1;
	tb = self->allocTx();
	if (tb == 0)
		return -1;	/* the 802.11 layer retries on its timer */
	bcopy(frame, tb->data + RTL8187_TX_DESC_LEN, len);
	return (self->submitTx(tb, rtl8187_tx_desc(tb->data, len, hwrate)) ==
	    kIOReturnSuccess) ? 0 : -1;
}

void
RTL8187Driver::staDeliver(void *ctx, const uint8_t *eth, size_t len)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;
	struct mbuf *m;

	if (self->fNetif == 0 || len < RTW_ETH_HLEN ||
	    len > kMaxEthernetFrame) {
		self->fNetStats->inputErrors++;
		return;
	}
	m = self->allocatePacket(len);
	if (m == 0) {
		self->fNetStats->inputErrors++;
		return;
	}
	bcopy(eth, MB_DATA(m), len);
	MB_SETLEN(m, len);
	self->fNetif->inputPacket(m, len);
	self->fNetStats->inputPackets++;
}

void
RTL8187Driver::reportLink(bool up)
{
	if (up) {
		UInt64 bps = (fSta.rates & RTW_RATES_OFDM) ? 54000000ULL :
		    11000000ULL;

		setLinkStatus(kIONetworkLinkValid | kIONetworkLinkActive,
		    fMedium, bps);
		LOG("joined \"%.32s\" on channel %u", fSta.cur.ssid,
		    fSta.cur.chan);
	} else {
		setLinkStatus(kIONetworkLinkValid, fMedium, 0);
		LOG("link down (%s)", rtw_error_name(fSta.last_error));
	}
}

void
RTL8187Driver::staLink(void *ctx, int up)
{
	((RTL8187Driver *)ctx)->reportLink(up != 0);
}

void
RTL8187Driver::staScanDone(void *ctx)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;

	self->fScanCount++;
	self->publishScanResults();

	/* Hearing nothing at all several scans in a row, while not
	 * associated, usually means the radio lost its state (for
	 * instance over a sleep that kept the port powered).
	 * Reinitialise it. */
	if (self->fSta.nbss != 0 || self->fSta.scan_resume == RTW_S_RUN) {
		self->fEmptyScans = 0;
	} else if (++self->fEmptyScans >= kRadioResetAfterScans) {
		self->fEmptyScans = 0;
		if (rtl8187_start(&self->fHw) != 0)
			LOG("radio reset failed");
	}
}

void
RTL8187Driver::staSetTimer(void *ctx, unsigned ms)
{
	RTL8187Driver *self = (RTL8187Driver *)ctx;

	if (ms == 0)
		self->fTimer->cancelTimeout();
	else
		self->fTimer->setTimeoutMS(ms);
}

void
RTL8187Driver::staRandom(void *ctx, uint8_t *buf, size_t len)
{
	read_random(buf, len);
}

uint32_t
RTL8187Driver::staNow(void *ctx)
{
	uint32_t secs, usecs;

	/* Time since boot; only differences are ever used. */
	clock_get_system_microtime(&secs, &usecs);
	return secs * 1000 + usecs / 1000;
}

/* ------------------------------------------------------------------ */
/* Control from user space                                            */

IOReturn
RTL8187Driver::setProperties(OSObject *properties)
{
	OSDictionary *dict = OSDynamicCast(OSDictionary, properties);

	if (dict == 0)
		return kIOReturnBadArgument;
	/* Choosing the network is allowed for root and for the user logged
	 * in at the console (so the GUI needs no password prompt), but not
	 * for remote or background users. */
	if (IOUserClient::clientHasPrivilege(current_task(),
	    kIOClientPrivilegeAdministrator) != kIOReturnSuccess &&
	    IOUserClient::clientHasPrivilege(current_task(),
	    kIOClientPrivilegeLocalUser) != kIOReturnSuccess)
		return kIOReturnNotPrivileged;
	if (fGate == 0 || fTerminating)
		return kIOReturnNoDevice;
	return fGate->runAction(gatedCommand, dict);
}

static bool
getData(OSDictionary *dict, const char *key, void *dst, UInt32 minlen,
    UInt32 maxlen, UInt32 *lenp)
{
	OSData *d = OSDynamicCast(OSData, dict->getObject(key));

	if (d == 0 || d->getLength() < minlen || d->getLength() > maxlen)
		return false;
	bcopy(d->getBytesNoCopy(), dst, d->getLength());
	*lenp = d->getLength();
	return true;
}

static UInt32
getNumber(OSDictionary *dict, const char *key, UInt32 dflt)
{
	OSNumber *n = OSDynamicCast(OSNumber, dict->getObject(key));

	return n ? n->unsigned32BitValue() : dflt;
}

IOReturn
RTL8187Driver::doCommand(OSDictionary *dict)
{
	OSString *cmd = OSDynamicCast(OSString, dict->getObject(kRTWCommand));
	IOReturn rc = kIOReturnBadArgument;

	if (cmd == 0)
		return kIOReturnBadArgument;

	if (cmd->isEqualTo("scan")) {
		if (!fEnabled)
			rc = kIOReturnNotReady;	/* interface is down */
		else
			rc = (rtw_sta_scan(&fSta) == 0) ? kIOReturnSuccess :
			    kIOReturnBusy;
	} else if (cmd->isEqualTo("join")) {
		struct rtw_join j;
		UInt32 len = 0;

		bzero(&j, sizeof(j));
		if (!getData(dict, kRTWArgSSID, j.ssid, 1, RTW_SSID_MAX, &len))
			return kIOReturnBadArgument;
		j.ssid_len = len;
		j.security = getNumber(dict, kRTWArgSecurity, RTW_SEC_OPEN);
		if (getData(dict, kRTWArgBSSID, j.bssid, 6, 6, &len))
			j.have_bssid = 1;
		if (j.security == RTW_SEC_WEP) {
			if (!getData(dict, kRTWArgKey, j.wep_key, 5, 13, &len))
				return kIOReturnBadArgument;
			j.wep_key_len = len;
			j.wep_key_id = getNumber(dict, kRTWArgKeyIndex, 0);
		} else if (j.security == RTW_SEC_WPA2_PSK) {
			if (!getData(dict, kRTWArgKey, j.pmk, RTW_PMK_LEN,
			    RTW_PMK_LEN, &len))
				return kIOReturnBadArgument;
		}
		if (rtw_sta_join(&fSta, &j) == 0) {
			gSavedJoin = j;
			gHaveSavedJoin = true;
			rc = kIOReturnSuccess;
		}
		bzero(&j, sizeof(j));
	} else if (cmd->isEqualTo("leave")) {
		rtw_sta_leave(&fSta);
		bzero(&gSavedJoin, sizeof(gSavedJoin));
		gHaveSavedJoin = false;
		rc = kIOReturnSuccess;
	} else if (cmd->isEqualTo("rate")) {
		UInt32 r = getNumber(dict, kRTWArgRate, 0);
		int hw = (r == 0) ? RTW_RATE_AUTO : rtw_rate_from_500k(r);

		if (hw >= 0 && rtw_sta_set_rate(&fSta, hw) == 0)
			rc = kIOReturnSuccess;
	}
	publishStatus(true);
	return rc;
}

/* Mirror the driver state into the I/O Registry for `rtlwifi status`. */
void
RTL8187Driver::publishStatus(bool force)
{
	UInt32 digest = fSta.state | (fSta.last_error << 8) |
	    (fSta.txrate << 16) | (fSta.cur.chan << 24);
	bool joined = fSta.state >= RTW_S_AUTH && fSta.state != RTW_S_SCAN;
	OSData *d;

	if (fSta.state == RTW_S_SCAN && fSta.scan_resume == RTW_S_RUN)
		joined = true;
	if (!force && digest == fPublished)
		return;
	fPublished = digest;

	setProperty(kRTWState, rtw_state_name(fSta.state));
	setProperty(kRTWLastError, rtw_error_name(fSta.last_error));
	if (joined) {
		d = OSData::withBytes(fSta.cur.ssid, fSta.cur.ssid_len);
		if (d) {
			setProperty(kRTWSSID, d);
			d->release();
		}
		d = OSData::withBytes(fSta.cur.bssid, RTW_ETH_ALEN);
		if (d) {
			setProperty(kRTWBSSID, d);
			d->release();
		}
		setProperty(kRTWChannel, fSta.cur.chan, 32);
		setProperty(kRTWSecurity, rtw_security_name(fSta.cfg.security));
		setProperty(kRTWTxRate, rtw_rate_to_500k(fSta.txrate), 32);
	} else {
		removeProperty(kRTWSSID);
		removeProperty(kRTWBSSID);
		removeProperty(kRTWChannel);
		removeProperty(kRTWSecurity);
		removeProperty(kRTWTxRate);
	}
}

void
RTL8187Driver::publishScanResults()
{
	OSArray *list = OSArray::withCapacity(fSta.nbss ? fSta.nbss : 1);
	unsigned i;

	if (list == 0)
		return;
	for (i = 0; i < fSta.nbss; i++) {
		const struct rtw_bss *b = &fSta.bss[i];
		OSDictionary *e = OSDictionary::withCapacity(5);
		OSObject *o;

		if (e == 0)
			break;
		if ((o = OSData::withBytes(b->ssid, b->ssid_len)) != 0) {
			e->setObject("SSID", o);
			o->release();
		}
		if ((o = OSData::withBytes(b->bssid, RTW_ETH_ALEN)) != 0) {
			e->setObject("BSSID", o);
			o->release();
		}
		if ((o = OSNumber::withNumber(b->chan, 32)) != 0) {
			e->setObject("Channel", o);
			o->release();
		}
		if ((o = OSNumber::withNumber(b->rssi, 32)) != 0) {
			e->setObject("Signal", o);
			o->release();
		}
		if ((o = OSNumber::withNumber(b->security, 32)) != 0) {
			e->setObject("Security", o);
			o->release();
		}
		list->setObject(e);
		e->release();
	}
	setProperty(kRTWScanResults, list);
	list->release();
	setProperty(kRTWScanCount, fScanCount, 32);
}

/* ------------------------------------------------------------------ */
/* Command gate trampolines                                           */

IOReturn
RTL8187Driver::gatedEnable(OSObject *owner, void *, void *, void *, void *)
{
	return ((RTL8187Driver *)owner)->enableHardware();
}

IOReturn
RTL8187Driver::gatedDisable(OSObject *owner, void *, void *, void *, void *)
{
	return ((RTL8187Driver *)owner)->disableHardware();
}

IOReturn
RTL8187Driver::gatedCommand(OSObject *owner, void *arg0, void *, void *,
    void *)
{
	return ((RTL8187Driver *)owner)->doCommand((OSDictionary *)arg0);
}

IOReturn
RTL8187Driver::gatedTerminated(OSObject *owner, void *, void *, void *,
    void *)
{
	return ((RTL8187Driver *)owner)->doTerminated();
}

IOReturn
RTL8187Driver::gatedPromisc(OSObject *owner, void *arg0, void *, void *,
    void *)
{
	RTL8187Driver *self = (RTL8187Driver *)owner;

	if (self->fTerminating)
		return kIOReturnNoDevice;
	/* Remembered by the chip layer and applied on the next start if
	 * the interface is down. */
	self->fHw.promisc = (arg0 != 0);
	if (self->fEnabled && rtl8187_set_promisc(&self->fHw, arg0 != 0) != 0)
		return kIOReturnIOError;
	return kIOReturnSuccess;
}
