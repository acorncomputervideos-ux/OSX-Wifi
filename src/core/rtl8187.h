/*
 * Realtek RTL8187L (USB 802.11b/g MAC/baseband) with the RTL8225 or
 * RTL8225z2 radio: register level driver.
 *
 * All chip registers are reached through vendor control requests, which
 * the platform supplies in struct rtl8187_io.  These calls may sleep, so
 * every function here must run in a context that can block.
 */
#ifndef RTL8187_H
#define RTL8187_H

#include "rtw_os.h"

RTW_EXTERN_C_BEGIN

#define RTL8187_REQ_REG		5	/* bRequest for register access */
#define RTL8187_EP_TX		0x02	/* bulk OUT endpoint address */
#define RTL8187_EP_RX		0x81	/* bulk IN endpoint address */

#define RTL8187_TX_DESC_LEN	12
#define RTL8187_RX_DESC_LEN	16
#define RTL8187_FCS_LEN		4
/* Largest bulk transfer in either direction. */
#define RTL8187_XFER_MAX	2500

struct rtl8187_io {
	void *ctx;
	/* Vendor device requests; return 0 on success. */
	int (*read)(void *ctx, uint16_t value, uint16_t index, uint8_t *buf,
	    unsigned len);
	int (*write)(void *ctx, uint16_t value, uint16_t index,
	    const uint8_t *buf, unsigned len);
	void (*msleep)(void *ctx, unsigned ms);
	void (*udelay)(void *ctx, unsigned us);
};

struct rtl8187 {
	struct rtl8187_io io;
	int      err;			/* first I/O error of an operation */
	uint8_t  macaddr[6];
	uint8_t  hwrev;			/* TX_CONF hardware revision field */
	uint8_t  eeprom_addr_bits;	/* 6 (93C46) or 8 (93C56) */
	uint8_t  rf_v2;			/* RTL8225z2 instead of RTL8225 */
	uint8_t  chan;
	uint8_t  short_slot;
	uint8_t  linked;
	uint8_t  promisc;
	uint8_t  txpwr_cck_base;
	uint8_t  txpwr_ofdm_base;
	uint8_t  txpwr_cck[15];		/* per channel, index 1..14 */
	uint8_t  txpwr_ofdm[15];
};

#define RTL8187_E_IO		(-1)	/* control request failed */
#define RTL8187_E_UNSUPPORTED	(-2)	/* RTL8187B or unknown radio */
#define RTL8187_E_TIMEOUT	(-3)	/* chip did not come out of reset */

/* Identify the chip and radio and read the MAC address and calibration
 * data from the EEPROM.  Call once at attach. */
int rtl8187_probe(struct rtl8187 *hw, const struct rtl8187_io *io);
/* Reset and fully initialise; leaves the receiver and transmitter on,
 * tuned to channel 1. */
int rtl8187_start(struct rtl8187 *hw);
int rtl8187_stop(struct rtl8187 *hw);
int rtl8187_set_channel(struct rtl8187 *hw, int chan);
/* bssid == NULL: not joined. */
int rtl8187_set_bss(struct rtl8187 *hw, const uint8_t *bssid, int linked,
    int short_slot);
int rtl8187_set_promisc(struct rtl8187 *hw, int on);

/* Fill in the transmit descriptor in the RTL8187_TX_DESC_LEN bytes at
 * buf; the 802.11 frame of frame_len bytes follows it.  buf must have one
 * spare byte after the frame.  Returns the bulk transfer length. */
size_t rtl8187_tx_desc(uint8_t *buf, size_t frame_len, int hwrate);

struct rtl8187_rxinfo {
	size_t  len;		/* 802.11 frame length without FCS */
	uint8_t rate;		/* chip rate index */
	uint8_t rssi;		/* 0..100 */
};
/* Parse a completed bulk IN transfer; the frame starts at buf.  Returns
 * 0, or -1 if the transfer is malformed or the frame failed its CRC. */
int rtl8187_rx_parse(const uint8_t *buf, size_t actlen,
    struct rtl8187_rxinfo *ri);

RTW_EXTERN_C_END

#endif /* RTL8187_H */
