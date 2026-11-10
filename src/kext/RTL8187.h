/*
 * Mac OS X kernel driver for Realtek RTL8187L USB wireless adapters.
 *
 * The driver presents the adapter to the system as an Ethernet interface
 * (enX).  Wireless-specific control -- scanning, choosing a network,
 * keys -- goes through I/O Registry properties, set by the rtlwifi
 * command line tool; see setProperties() and publishStatus().
 */
#ifndef RTL8187_KEXT_H
#define RTL8187_KEXT_H

#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/network/IOEthernetController.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IOGatedOutputQueue.h>
#include <IOKit/usb/IOUSBDevice.h>
#include <IOKit/usb/IOUSBInterface.h>
#include <IOKit/usb/IOUSBPipe.h>

#include "rtl8187.h"
#include "rtw_sta.h"

#define RTL8187Driver com_osxwifi_driver_RTL8187

/* Property keys shared with the command line tool. */
#define kRTWCommand		"RTWCommand"	/* "scan", "join", "leave", "rate" */
#define kRTWArgSSID		"SSID"		/* OSData */
#define kRTWArgBSSID		"BSSID"		/* OSData, 6 bytes, optional */
#define kRTWArgSecurity		"Security"	/* OSNumber, enum rtw_security */
#define kRTWArgKey		"Key"		/* OSData: WEP key or 32 byte PSK */
#define kRTWArgKeyIndex		"KeyIndex"	/* OSNumber, WEP key 0..3 */
#define kRTWArgRate		"Rate"		/* OSNumber, 500 kbit/s units; 0 = auto */

#define kRTWState		"RTWState"
#define kRTWLastError		"RTWLastError"
#define kRTWSSID		"RTWSSID"
#define kRTWBSSID		"RTWBSSID"
#define kRTWChannel		"RTWChannel"
#define kRTWSecurity		"RTWSecurity"
#define kRTWTxRate		"RTWTxRate"
#define kRTWRadio		"RTWRadio"
#define kRTWScanResults		"RTWScanResults"
#define kRTWScanCount		"RTWScanCount"

enum {
	kTxBufferCount	= 8,
	kRxRingSize	= 32
};

class RTL8187Driver : public IOEthernetController
{
	OSDeclareDefaultStructors(com_osxwifi_driver_RTL8187)

public:
	virtual bool		init(OSDictionary *properties);
	virtual bool		start(IOService *provider);
	virtual void		stop(IOService *provider);
	virtual void		free();
	virtual IOReturn	message(UInt32 type, IOService *provider,
				    void *argument = 0);
	virtual IOReturn	setProperties(OSObject *properties);

	virtual bool		createWorkLoop();
	virtual IOWorkLoop *	getWorkLoop() const;
	virtual IOOutputQueue *	createOutputQueue();
	virtual bool		configureInterface(IONetworkInterface *netif);
	virtual IOReturn	enable(IONetworkInterface *netif);
	virtual IOReturn	disable(IONetworkInterface *netif);
	virtual UInt32		outputPacket(struct mbuf *m, void *param);
	virtual IOReturn	getHardwareAddress(IOEthernetAddress *addr);
	virtual IOReturn	setPromiscuousMode(bool active);
	virtual IOReturn	setMulticastMode(bool active);
	virtual IOReturn	setMulticastList(IOEthernetAddress *addrs,
				    UInt32 count);
	virtual const OSString *newVendorString() const;
	virtual const OSString *newModelString() const;

private:
	struct TxBuffer {
		RTL8187Driver *			owner;
		IOBufferMemoryDescriptor *	desc;
		UInt8 *				data;
		volatile SInt32			busy;
		IOUSBCompletion			completion;
	};
	struct RxSlot {
		UInt32	length;
		UInt8	data[RTL8187_XFER_MAX];
	};

	/* Provider and pipes. */
	IOUSBDevice *		fDevice;
	IOUSBInterface *	fInterface;
	IOUSBPipe *		fInPipe;
	IOUSBPipe *		fOutPipe;
	bool			fDeviceOpen;
	bool			fInterfaceOpen;
	volatile bool		fTerminating;	/* device unplugged */

	/* Work loop: every call into the driver core is made under its
	 * gate, which is what serialises the core. */
	IOWorkLoop *		fWorkLoop;
	IOCommandGate *		fGate;
	IOTimerEventSource *	fTimer;
	IOInterruptEventSource *fRxSource;

	/* Networking. */
	IOEthernetInterface *	fNetif;
	IONetworkStats *	fNetStats;
	IOEthernetStats *	fEtherStats;
	IOOutputQueue *		fOutputQueue;
	OSDictionary *		fMediumDict;
	const IONetworkMedium *	fMedium;
	bool			fEnabled;

	/* Transmit buffers.  `busy` is claimed under the gate and released
	 * by the USB completion, hence the atomic flag. */
	TxBuffer		fTx[kTxBufferCount];
	volatile SInt32		fTxStalled;

	/* Receive: the USB completion copies each transfer into a ring and
	 * signals fRxSource; the work loop then processes it.  Completions
	 * run on the USB work loop, where blocking register access (which
	 * the core needs when it reacts to a frame) is not possible. */
	IOBufferMemoryDescriptor *fRxDesc;
	IOUSBCompletion		fRxCompletion;
	RxSlot *		fRxRing;
	IOLock *		fRxLock;
	UInt32			fRxHead;	/* next slot to fill */
	UInt32			fRxTail;	/* next slot to process */
	volatile bool		fRxPending;	/* a read is outstanding */
	volatile bool		fRxFailed;	/* read needs restarting */
	UInt32			fRxErrors;

	/* Chip and 802.11 state. */
	struct rtl8187		fHw;
	struct rtw_sta		fSta;
	UInt32			fEmptyScans;
	UInt32			fScanCount;
	UInt32			fPublished;	/* digest of last status */

	bool		openDevice(IOService *provider);
	void		closeDevice(bool final);
	bool		allocateBuffers();
	void		releaseBuffers();
	void		abortPipes();

	IOReturn	startRead();
	void		rxComplete(IOReturn status, UInt32 remaining);
	void		rxService();
	TxBuffer *	allocTx();
	void		releaseTx(TxBuffer *tb);
	IOReturn	submitTx(TxBuffer *tb, UInt32 length);
	void		txComplete(TxBuffer *tb, IOReturn status);

	IOReturn	enableHardware();
	IOReturn	disableHardware();
	IOReturn	doCommand(OSDictionary *dict);
	IOReturn	doTerminated();
	void		publishStatus(bool force);
	void		publishScanResults();
	void		reportLink(bool up);

	/* Trampolines. */
	static IOReturn	gatedEnable(OSObject *owner, void *, void *, void *,
			    void *);
	static IOReturn	gatedDisable(OSObject *owner, void *, void *, void *,
			    void *);
	static IOReturn	gatedCommand(OSObject *owner, void *arg0, void *,
			    void *, void *);
	static IOReturn	gatedTerminated(OSObject *owner, void *, void *,
			    void *, void *);
	static IOReturn	gatedPromisc(OSObject *owner, void *arg0, void *,
			    void *, void *);
	static void	timerFired(OSObject *owner, IOTimerEventSource *src);
	static void	rxSignalled(OSObject *owner, IOInterruptEventSource *src,
			    int count);
	static void	rxCompleteTramp(void *target, void *param,
			    IOReturn status, UInt32 remaining);
	static void	txCompleteTramp(void *target, void *param,
			    IOReturn status, UInt32 remaining);

	/* Callbacks from the chip layer (struct rtl8187_io). */
	static int	hwRead(void *ctx, uint16_t value, uint16_t index,
			    uint8_t *buf, unsigned len);
	static int	hwWrite(void *ctx, uint16_t value, uint16_t index,
			    const uint8_t *buf, unsigned len);
	static void	hwSleep(void *ctx, unsigned ms);
	static void	hwDelay(void *ctx, unsigned us);
	int		controlRequest(bool in, uint16_t value, uint16_t index,
			    void *buf, unsigned len);

	/* Callbacks from the 802.11 layer (struct rtw_sta_ops). */
	static int	staSetChannel(void *ctx, int chan);
	static int	staSetBss(void *ctx, const uint8_t *bssid, int linked,
			    int short_slot);
	static int	staTx(void *ctx, const uint8_t *frame, size_t len,
			    int hwrate);
	static void	staDeliver(void *ctx, const uint8_t *eth, size_t len);
	static void	staLink(void *ctx, int up);
	static void	staScanDone(void *ctx);
	static void	staSetTimer(void *ctx, unsigned ms);
	static void	staRandom(void *ctx, uint8_t *buf, size_t len);
	static uint32_t	staNow(void *ctx);
};

#endif /* RTL8187_KEXT_H */
