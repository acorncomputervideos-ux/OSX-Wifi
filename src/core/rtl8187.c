/*
 * RTL8187L / RTL8225 register level driver.
 *
 * The initialisation sequences and radio tables in this file are taken
 * from the OpenBSD urtw(4) driver, which carries this notice:
 *
 * Copyright (c) 2009 Martynas Venckus <martynas@openbsd.org>
 * Copyright (c) 2008 Weongyo Jeong <weongyo@FreeBSD.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "rtl8187.h"

/* MAC registers */
#define R_MAC0			0x00	/* 6 bytes */
#define R_BRSR			0x2c	/* 16 bit: basic rate set */
#define R_BSSID			0x2e	/* 6 bytes */
#define R_RESP_RATE		0x34
#define R_EIFS			0x35
#define R_CMD			0x37
#define  CMD_TX_ENABLE		0x04
#define  CMD_RX_ENABLE		0x08
#define  CMD_RST		0x10
#define R_INTR_MASK		0x3c	/* 16 bit */
#define R_TX_CONF		0x40	/* 32 bit */
#define  TX_HWREV_MASK		(7U << 25)
#define  TX_HWREV_8187B_D	(6U << 25)
#define  TX_CWMIN		(1U << 31)
#define  TX_SWPLCPLEN		(1U << 24)
#define  TX_MXDMA_MASK		0x00e00000U
#define  TX_MXDMA_2048		(7U << 21)
#define  TX_DISCW		(1U << 20)
#define  TX_NOICV		0x00080000U
#define  TX_LOOPBACK_MASK	0x00060000U
#define  TX_LOOPBACK_MAC	(1U << 17)
#define  TX_NOCRC		0x00010000U
#define  TX_DPRETRY_MASK	0x0000ff00U
#define  TX_RTSRETRY_MASK	0x000000ffU
#define R_RX_CONF		0x44	/* 32 bit */
#define  RX_ONLYERLPKT		(1U << 31)
#define  RX_AUTORESETPHY	(1U << 28)
#define  RX_CHECK_BSSID		0x00800000U
#define  RX_FILTER_PWR		0x00400000U
#define  RX_FILTER_MNG		0x00100000U
#define  RX_FILTER_CTL		0x00080000U
#define  RX_FILTER_DATA		0x00040000U
#define  RX_FIFO_THRESHOLD_MASK	0x0000e000U
#define  RX_FIFO_THRESHOLD_NONE	(7U << 13)
#define  RX_FILTER_ICVERR	0x00001000U
#define  RX_MAX_DMA_MASK	0x00001c00U
#define  RX_MAX_DMA_2048	(7U << 10)
#define  RX_9356SEL		(1U << 6)
#define  RX_FILTER_CRCERR	0x00000020U
#define  RX_FILTER_BCAST	0x00000008U
#define  RX_FILTER_MCAST	0x00000004U
#define  RX_FILTER_NICMAC	0x00000002U
#define  RX_FILTER_ALLMAC	0x00000001U
#define  RX_FILTER_MASK \
	(RX_FILTER_ALLMAC | RX_FILTER_NICMAC | RX_FILTER_MCAST | \
	 RX_FILTER_BCAST | RX_FILTER_CRCERR | RX_FILTER_ICVERR | \
	 RX_FILTER_DATA | RX_FILTER_CTL | RX_FILTER_MNG | (1U << 21) | \
	 RX_FILTER_PWR | RX_CHECK_BSSID)
#define R_INT_TIMEOUT		0x48	/* 32 bit */
#define R_EPROM_CMD		0x50
#define  EPROM_READBIT		0x01
#define  EPROM_WRITEBIT		0x02
#define  EPROM_CK		0x04
#define  EPROM_CS		0x08
#define  EPROM_MODE_SHIFT	6
#define  EPROM_MODE_MASK	0xc0
#define  EPROM_MODE_NORMAL	0
#define  EPROM_MODE_LOAD	1
#define  EPROM_MODE_PROGRAM	2
#define  EPROM_MODE_CONFIG	3
#define R_ANAPARAM		0x54	/* 32 bit */
#define  ANAPARAM_ON		0xa0000a59U
#define R_MSR			0x58
#define  MSR_LINK_MASK		0x0c
#define  MSR_LINK_STA		(2 << 2)
#define R_CONFIG3		0x59
#define  CONFIG3_ANAPARAM_WRITE	0x40
#define R_ANAPARAM2		0x60	/* 32 bit */
#define  ANAPARAM2_ON		0x860c7312U
#define R_BEACON_INTERVAL	0x70	/* 16 bit */
#define R_ATIM_WND		0x72	/* 16 bit */
#define R_BEACON_INTERVAL_TIME	0x74	/* 16 bit */
#define R_ATIM_TR_ITV		0x76	/* 16 bit */
#define R_PHY			0x7c	/* 4 bytes: baseband write port */
#define R_RF_PINS_OUTPUT	0x80	/* 16 bit */
#define  BB_HOST_BANG_CLK	0x02
#define  BB_HOST_BANG_EN	0x04
#define  BB_HOST_BANG_RW	0x08
#define R_RF_PINS_ENABLE	0x82	/* 16 bit */
#define R_RF_PINS_SELECT	0x84	/* 16 bit */
#define R_RF_PINS_INPUT		0x86	/* 16 bit */
#define R_RF_PARA		0x88	/* 32 bit */
#define R_RF_TIMING		0x8c	/* 32 bit */
#define R_GP_ENABLE		0x90
#define R_GPIO			0x91
#define R_HSSI_PARA		0x94	/* 32 bit */
#define R_TX_AGC_CTL		0x9c
#define R_TX_GAIN_CCK		0x9d
#define R_TX_GAIN_OFDM		0x9e
#define R_TX_ANTENNA		0x9f
#define R_WPA_CONFIG		0xb0
#define R_SIFS			0xb4
#define R_DIFS			0xb5
#define R_SLOT			0xb6
#define R_CW_CONF		0xbc
#define R_CW_VAL		0xbd
#define R_RATE_FALLBACK		0xbe
#define R_TALLY_SEL		0xfc

/* EEPROM word addresses */
#define EE_TXPW_BASE		0x05
#define EE_RFCHIPID		0x06
#define  EE_RFCHIPID_RTL8225U	5
#define EE_MACADDR		0x07
#define EE_TXPW0		0x16
#define EE_TXPW2		0x1b
#define EE_TXPW1		0x3d

/* Chip rate indices used in register fields. */
#define RATE_1M			0
#define RATE_24M		8

#define TX_RETRY		7
#define RTS_RETRY		7

struct regpair {
	uint8_t  reg;
	uint16_t val;
};

#define NITEMS(a) (sizeof(a) / sizeof((a)[0]))

static const uint8_t rtl8225_agc[] = {
	0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9e, 0x9d, 0x9c, 0x9b,
	0x9a, 0x99, 0x98, 0x97, 0x96, 0x95, 0x94, 0x93, 0x92, 0x91, 0x90,
	0x8f, 0x8e, 0x8d, 0x8c, 0x8b, 0x8a, 0x89, 0x88, 0x87, 0x86, 0x85,
	0x84, 0x83, 0x82, 0x81, 0x80, 0x3f, 0x3e, 0x3d, 0x3c, 0x3b, 0x3a,
	0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2f,
	0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24,
	0x23, 0x22, 0x21, 0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
	0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03,
	0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

static const uint16_t rtl8225_channel[] = {
	0x0000,		/* dummy channel 0 */
	0x085c,		/* 1 */
	0x08dc,		/* 2 */
	0x095c,		/* 3 */
	0x09dc,		/* 4 */
	0x0a5c,		/* 5 */
	0x0adc,		/* 6 */
	0x0b5c,		/* 7 */
	0x0bdc,		/* 8 */
	0x0c5c,		/* 9 */
	0x0cdc,		/* 10 */
	0x0d5c,		/* 11 */
	0x0ddc,		/* 12 */
	0x0e5c,		/* 13 */
	0x0f72,		/* 14 */
};

static const uint8_t rtl8225_gain[] = {
	0x23, 0x88, 0x7c, 0xa5,		/* -82dbm */
	0x23, 0x88, 0x7c, 0xb5,		/* -82dbm */
	0x23, 0x88, 0x7c, 0xc5,		/* -82dbm */
	0x33, 0x80, 0x79, 0xc5,		/* -78dbm */
	0x43, 0x78, 0x76, 0xc5,		/* -74dbm */
	0x53, 0x60, 0x73, 0xc5,		/* -70dbm */
	0x63, 0x58, 0x70, 0xc5,		/* -66dbm */
};

static const struct regpair rtl8225_rf_part1[] = {
	{ 0x00, 0x0067 }, { 0x01, 0x0fe0 }, { 0x02, 0x044d }, { 0x03, 0x0441 },
	{ 0x04, 0x0486 }, { 0x05, 0x0bc0 }, { 0x06, 0x0ae6 }, { 0x07, 0x082a },
	{ 0x08, 0x001f }, { 0x09, 0x0334 }, { 0x0a, 0x0fd4 }, { 0x0b, 0x0391 },
	{ 0x0c, 0x0050 }, { 0x0d, 0x06db }, { 0x0e, 0x0029 }, { 0x0f, 0x0914 }
};

static const struct regpair rtl8225_rf_part2[] = {
	{ 0x00, 0x01 }, { 0x01, 0x02 }, { 0x02, 0x42 }, { 0x03, 0x00 },
	{ 0x04, 0x00 }, { 0x05, 0x00 }, { 0x06, 0x40 }, { 0x07, 0x00 },
	{ 0x08, 0x40 }, { 0x09, 0xfe }, { 0x0a, 0x09 }, { 0x0b, 0x80 },
	{ 0x0c, 0x01 }, { 0x0e, 0xd3 }, { 0x0f, 0x38 }, { 0x10, 0x84 },
	{ 0x11, 0x06 }, { 0x12, 0x20 }, { 0x13, 0x20 }, { 0x14, 0x00 },
	{ 0x15, 0x40 }, { 0x16, 0x00 }, { 0x17, 0x40 }, { 0x18, 0xef },
	{ 0x19, 0x19 }, { 0x1a, 0x20 }, { 0x1b, 0x76 }, { 0x1c, 0x04 },
	{ 0x1e, 0x95 }, { 0x1f, 0x75 }, { 0x20, 0x1f }, { 0x21, 0x27 },
	{ 0x22, 0x16 }, { 0x24, 0x46 }, { 0x25, 0x20 }, { 0x26, 0x90 },
	{ 0x27, 0x88 }
};

static const struct regpair rtl8225_rf_part3[] = {
	{ 0x00, 0x98 }, { 0x03, 0x20 }, { 0x04, 0x7e }, { 0x05, 0x12 },
	{ 0x06, 0xfc }, { 0x07, 0x78 }, { 0x08, 0x2e }, { 0x10, 0x9b },
	{ 0x11, 0x88 }, { 0x12, 0x47 }, { 0x13, 0xd0 }, { 0x19, 0x00 },
	{ 0x1a, 0xa0 }, { 0x1b, 0x08 }, { 0x40, 0x86 }, { 0x41, 0x8d },
	{ 0x42, 0x15 }, { 0x43, 0x18 }, { 0x44, 0x1f }, { 0x45, 0x1e },
	{ 0x46, 0x1a }, { 0x47, 0x15 }, { 0x48, 0x10 }, { 0x49, 0x0a },
	{ 0x4a, 0x05 }, { 0x4b, 0x02 }, { 0x4c, 0x05 }
};

static const uint16_t rtl8225_rxgain[] = {
	0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0408, 0x0409,
	0x040a, 0x040b, 0x0502, 0x0503, 0x0504, 0x0505, 0x0540, 0x0541,
	0x0542, 0x0543, 0x0544, 0x0545, 0x0580, 0x0581, 0x0582, 0x0583,
	0x0584, 0x0585, 0x0588, 0x0589, 0x058a, 0x058b, 0x0643, 0x0644,
	0x0645, 0x0680, 0x0681, 0x0682, 0x0683, 0x0684, 0x0685, 0x0688,
	0x0689, 0x068a, 0x068b, 0x068c, 0x0742, 0x0743, 0x0744, 0x0745,
	0x0780, 0x0781, 0x0782, 0x0783, 0x0784, 0x0785, 0x0788, 0x0789,
	0x078a, 0x078b, 0x078c, 0x078d, 0x0790, 0x0791, 0x0792, 0x0793,
	0x0794, 0x0795, 0x0798, 0x0799, 0x079a, 0x079b, 0x079c, 0x079d,
	0x07a0, 0x07a1, 0x07a2, 0x07a3, 0x07a4, 0x07a5, 0x07a8, 0x07a9,
	0x07aa, 0x07ab, 0x07ac, 0x07ad, 0x07b0, 0x07b1, 0x07b2, 0x07b3,
	0x07b4, 0x07b5, 0x07b8, 0x07b9, 0x07ba, 0x07bb, 0x07bb
};

static const uint8_t rtl8225_threshold[] = {
	0x8d, 0x8d, 0x8d, 0x8d, 0x9d, 0xad, 0xbd
};

static const uint8_t rtl8225_tx_gain_cck_ofdm[] = {
	0x02, 0x06, 0x0e, 0x1e, 0x3e, 0x7e
};

static const uint8_t rtl8225_txpwr_cck[] = {
	0x18, 0x17, 0x15, 0x11, 0x0c, 0x08, 0x04, 0x02,
	0x1b, 0x1a, 0x17, 0x13, 0x0e, 0x09, 0x04, 0x02,
	0x1f, 0x1e, 0x1a, 0x15, 0x10, 0x0a, 0x05, 0x02,
	0x22, 0x21, 0x1d, 0x18, 0x11, 0x0b, 0x06, 0x02,
	0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03,
	0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03
};

static const uint8_t rtl8225_txpwr_cck_ch14[] = {
	0x18, 0x17, 0x15, 0x0c, 0x00, 0x00, 0x00, 0x00,
	0x1b, 0x1a, 0x17, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x1f, 0x1e, 0x1a, 0x0f, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x21, 0x1d, 0x11, 0x00, 0x00, 0x00, 0x00,
	0x26, 0x25, 0x21, 0x13, 0x00, 0x00, 0x00, 0x00,
	0x2b, 0x2a, 0x25, 0x15, 0x00, 0x00, 0x00, 0x00
};

static const uint8_t rtl8225_txpwr_ofdm[] = {
	0x80, 0x90, 0xa2, 0xb5, 0xcb, 0xe4
};

static const uint8_t rtl8225z2_gain_bg[] = {
	0x23, 0x15, 0xa5,		/* -82-1dbm */
	0x23, 0x15, 0xb5,		/* -82-2dbm */
	0x23, 0x15, 0xc5,		/* -82-3dbm */
	0x33, 0x15, 0xc5,		/* -78dbm */
	0x43, 0x15, 0xc5,		/* -74dbm */
	0x53, 0x15, 0xc5,		/* -70dbm */
	0x63, 0x15, 0xc5,		/* -66dbm */
};

static const struct regpair rtl8225z2_rf_part1[] = {
	{ 0x00, 0x02bf }, { 0x01, 0x0ee0 }, { 0x02, 0x044d }, { 0x03, 0x0441 },
	{ 0x04, 0x08c3 }, { 0x05, 0x0c72 }, { 0x06, 0x00e6 }, { 0x07, 0x082a },
	{ 0x08, 0x003f }, { 0x09, 0x0335 }, { 0x0a, 0x09d4 }, { 0x0b, 0x07bb },
	{ 0x0c, 0x0850 }, { 0x0d, 0x0cdf }, { 0x0e, 0x002b }, { 0x0f, 0x0114 }
};

static const struct regpair rtl8225z2_rf_part2[] = {
	{ 0x00, 0x01 }, { 0x01, 0x02 }, { 0x02, 0x42 }, { 0x03, 0x00 },
	{ 0x04, 0x00 }, { 0x05, 0x00 }, { 0x06, 0x40 }, { 0x07, 0x00 },
	{ 0x08, 0x40 }, { 0x09, 0xfe }, { 0x0a, 0x08 }, { 0x0b, 0x80 },
	{ 0x0c, 0x01 }, { 0x0d, 0x43 }, { 0x0e, 0xd3 }, { 0x0f, 0x38 },
	{ 0x10, 0x84 }, { 0x11, 0x07 }, { 0x12, 0x20 }, { 0x13, 0x20 },
	{ 0x14, 0x00 }, { 0x15, 0x40 }, { 0x16, 0x00 }, { 0x17, 0x40 },
	{ 0x18, 0xef }, { 0x19, 0x19 }, { 0x1a, 0x20 }, { 0x1b, 0x15 },
	{ 0x1c, 0x04 }, { 0x1d, 0xc5 }, { 0x1e, 0x95 }, { 0x1f, 0x75 },
	{ 0x20, 0x1f }, { 0x21, 0x17 }, { 0x22, 0x16 }, { 0x23, 0x80 },
	{ 0x24, 0x46 }, { 0x25, 0x00 }, { 0x26, 0x90 }, { 0x27, 0x88 }
};

static const struct regpair rtl8225z2_rf_part3[] = {
	{ 0x00, 0x98 }, { 0x03, 0x20 }, { 0x04, 0x7e }, { 0x05, 0x12 },
	{ 0x06, 0xfc }, { 0x07, 0x78 }, { 0x08, 0x2e }, { 0x09, 0x11 },
	{ 0x0a, 0x17 }, { 0x0b, 0x11 }, { 0x10, 0x9b }, { 0x11, 0x88 },
	{ 0x12, 0x47 }, { 0x13, 0xd0 }, { 0x19, 0x00 }, { 0x1a, 0xa0 },
	{ 0x1b, 0x08 }, { 0x1d, 0x00 }, { 0x40, 0x86 }, { 0x41, 0x9d },
	{ 0x42, 0x15 }, { 0x43, 0x18 }, { 0x44, 0x36 }, { 0x45, 0x35 },
	{ 0x46, 0x2e }, { 0x47, 0x25 }, { 0x48, 0x1c }, { 0x49, 0x12 },
	{ 0x4a, 0x09 }, { 0x4b, 0x04 }, { 0x4c, 0x05 }
};

static const uint16_t rtl8225z2_rxgain[] = {
	0x0400, 0x0401, 0x0402, 0x0403, 0x0404, 0x0405, 0x0408, 0x0409,
	0x040a, 0x040b, 0x0502, 0x0503, 0x0504, 0x0505, 0x0540, 0x0541,
	0x0542, 0x0543, 0x0544, 0x0545, 0x0580, 0x0581, 0x0582, 0x0583,
	0x0584, 0x0585, 0x0588, 0x0589, 0x058a, 0x058b, 0x0643, 0x0644,
	0x0645, 0x0680, 0x0681, 0x0682, 0x0683, 0x0684, 0x0685, 0x0688,
	0x0689, 0x068a, 0x068b, 0x068c, 0x0742, 0x0743, 0x0744, 0x0745,
	0x0780, 0x0781, 0x0782, 0x0783, 0x0784, 0x0785, 0x0788, 0x0789,
	0x078a, 0x078b, 0x078c, 0x078d, 0x0790, 0x0791, 0x0792, 0x0793,
	0x0794, 0x0795, 0x0798, 0x0799, 0x079a, 0x079b, 0x079c, 0x079d,
	0x07a0, 0x07a1, 0x07a2, 0x07a3, 0x07a4, 0x07a5, 0x07a8, 0x07a9,
	0x03aa, 0x03ab, 0x03ac, 0x03ad, 0x03b0, 0x03b1, 0x03b2, 0x03b3,
	0x03b4, 0x03b5, 0x03b8, 0x03b9, 0x03ba, 0x03bb, 0x03bb
};

static const uint8_t rtl8225z2_tx_gain_cck_ofdm[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
	0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
	0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23
};

static const uint8_t rtl8225z2_txpwr_cck[] = {
	0x36, 0x35, 0x2e, 0x25, 0x1c, 0x12, 0x09, 0x04,
	0x30, 0x2f, 0x29, 0x21, 0x19, 0x10, 0x08, 0x03,
	0x2b, 0x2a, 0x25, 0x1e, 0x16, 0x0e, 0x07, 0x03,
	0x26, 0x25, 0x21, 0x1b, 0x14, 0x0d, 0x06, 0x03
};

static const uint8_t rtl8225z2_txpwr_cck_ch14[] = {
	0x36, 0x35, 0x2e, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x30, 0x2f, 0x29, 0x15, 0x00, 0x00, 0x00, 0x00,
	0x30, 0x2f, 0x29, 0x15, 0x00, 0x00, 0x00, 0x00,
	0x30, 0x2f, 0x29, 0x15, 0x00, 0x00, 0x00, 0x00
};

/* ------------------------------------------------------------------ */
/* Register access.  The first failure is latched in hw->err and turns
 * every later access into a no-op, so sequences need no per-call
 * checks; the public entry points return the latched error. */

static void
reg_read(struct rtl8187 *hw, uint16_t value, uint8_t *buf, unsigned len)
{
	memset(buf, 0, len);
	if (hw->err == 0 && hw->io.read(hw->io.ctx, value, 0, buf, len) != 0)
		hw->err = RTL8187_E_IO;
}

static void
reg_write(struct rtl8187 *hw, uint16_t value, uint16_t index,
    const uint8_t *buf, unsigned len)
{
	if (hw->err == 0 &&
	    hw->io.write(hw->io.ctx, value, index, buf, len) != 0)
		hw->err = RTL8187_E_IO;
}

static uint8_t
rd8(struct rtl8187 *hw, unsigned reg)
{
	uint8_t b[1];

	reg_read(hw, (uint16_t)(reg | 0xff00), b, 1);
	return b[0];
}

static uint16_t
rd16(struct rtl8187 *hw, unsigned reg)
{
	uint8_t b[2];

	reg_read(hw, (uint16_t)(reg | 0xff00), b, 2);
	return RTW_GET_LE16(b);
}

static uint32_t
rd32(struct rtl8187 *hw, unsigned reg)
{
	uint8_t b[4];

	reg_read(hw, (uint16_t)(reg | 0xff00), b, 4);
	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	    ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void
wr8(struct rtl8187 *hw, unsigned reg, unsigned val)
{
	uint8_t b[1];

	b[0] = (uint8_t)val;
	reg_write(hw, (uint16_t)(reg | 0xff00), 0, b, 1);
}

static void
wr16(struct rtl8187 *hw, unsigned reg, unsigned val)
{
	uint8_t b[2];

	RTW_PUT_LE16(b, val);
	reg_write(hw, (uint16_t)(reg | 0xff00), 0, b, 2);
}

static void
wr32(struct rtl8187 *hw, unsigned reg, uint32_t val)
{
	uint8_t b[4];

	b[0] = (uint8_t)val;
	b[1] = (uint8_t)(val >> 8);
	b[2] = (uint8_t)(val >> 16);
	b[3] = (uint8_t)(val >> 24);
	reg_write(hw, (uint16_t)(reg | 0xff00), 0, b, 4);
}

/* A second register page, selected by 0xfe in the high byte. */
static uint8_t
rd8e(struct rtl8187 *hw, unsigned reg)
{
	uint8_t b[1];

	reg_read(hw, (uint16_t)(reg | 0xfe00), b, 1);
	return b[0];
}

static void
wr8e(struct rtl8187 *hw, unsigned reg, unsigned val)
{
	uint8_t b[1];

	b[0] = (uint8_t)val;
	reg_write(hw, (uint16_t)(reg | 0xfe00), 0, b, 1);
}

static void
msleep(struct rtl8187 *hw, unsigned ms)
{
	if (hw->err == 0)
		hw->io.msleep(hw->io.ctx, ms);
}

static void
udelay(struct rtl8187 *hw, unsigned us)
{
	if (hw->err == 0)
		hw->io.udelay(hw->io.ctx, us);
}

/* ------------------------------------------------------------------ */
/* Configuration lock and analog parameters                           */

static void
set_mode(struct rtl8187 *hw, unsigned mode)
{
	uint8_t d = rd8(hw, R_EPROM_CMD);

	d = (uint8_t)((d & ~EPROM_MODE_MASK) | (mode << EPROM_MODE_SHIFT));
	d &= (uint8_t)~(EPROM_CS | EPROM_CK);
	wr8(hw, R_EPROM_CMD, d);
}

static void
set_anaparam(struct rtl8187 *hw, unsigned reg, uint32_t val)
{
	uint8_t d;

	set_mode(hw, EPROM_MODE_CONFIG);
	d = rd8(hw, R_CONFIG3);
	wr8(hw, R_CONFIG3, d | CONFIG3_ANAPARAM_WRITE);
	wr32(hw, reg, val);
	d = rd8(hw, R_CONFIG3);
	wr8(hw, R_CONFIG3, d & ~CONFIG3_ANAPARAM_WRITE);
	set_mode(hw, EPROM_MODE_NORMAL);
}

/* ------------------------------------------------------------------ */
/* Serial EEPROM (93C46 / 93C56), bit-banged through R_EPROM_CMD       */

#define EPROM_DELAY 10

static void
eprom_cs(struct rtl8187 *hw, int on)
{
	uint8_t d = rd8(hw, R_EPROM_CMD);

	wr8(hw, R_EPROM_CMD, on ? (d | EPROM_CS) : (d & ~EPROM_CS));
	udelay(hw, EPROM_DELAY);
}

static void
eprom_ck(struct rtl8187 *hw)
{
	uint8_t d = rd8(hw, R_EPROM_CMD);

	wr8(hw, R_EPROM_CMD, d | EPROM_CK);
	udelay(hw, EPROM_DELAY);
	d = rd8(hw, R_EPROM_CMD);
	wr8(hw, R_EPROM_CMD, d & ~EPROM_CK);
	udelay(hw, EPROM_DELAY);
}

static void
eprom_writebit(struct rtl8187 *hw, int bit)
{
	uint8_t d = rd8(hw, R_EPROM_CMD);

	wr8(hw, R_EPROM_CMD, bit ? (d | EPROM_WRITEBIT) :
	    (d & ~EPROM_WRITEBIT));
	udelay(hw, EPROM_DELAY);
}

static void
eprom_sendbit(struct rtl8187 *hw, int bit)
{
	eprom_writebit(hw, bit);
	eprom_ck(hw);
}

static uint16_t
eprom_read(struct rtl8187 *hw, unsigned addr)
{
	uint16_t data = 0;
	int i;

	wr8(hw, R_EPROM_CMD, EPROM_MODE_PROGRAM << EPROM_MODE_SHIFT);
	udelay(hw, EPROM_DELAY);
	eprom_cs(hw, 1);
	eprom_ck(hw);
	/* Start bit and the READ opcode (10), then the address, MSB first. */
	eprom_sendbit(hw, 1);
	eprom_sendbit(hw, 1);
	eprom_sendbit(hw, 0);
	for (i = hw->eeprom_addr_bits - 1; i >= 0; i--)
		eprom_sendbit(hw, (addr >> i) & 1);
	eprom_writebit(hw, 0);
	for (i = 15; i >= 0; i--) {
		eprom_ck(hw);
		if (rd8(hw, R_EPROM_CMD) & EPROM_READBIT)
			data |= (uint16_t)(1 << i);
		udelay(hw, EPROM_DELAY);
	}
	eprom_cs(hw, 0);
	eprom_ck(hw);
	wr8(hw, R_EPROM_CMD, EPROM_MODE_NORMAL << EPROM_MODE_SHIFT);
	return data;
}

/* ------------------------------------------------------------------ */
/* RTL8225 radio: three-wire register interface and baseband port      */

static void
rf_write(struct rtl8187 *hw, unsigned addr, unsigned data)
{
	uint16_t d80, d82, d84;
	uint8_t b[2];

	d80 = (uint16_t)(rd16(hw, R_RF_PINS_OUTPUT) & 0xfff3);
	d82 = rd16(hw, R_RF_PINS_ENABLE);
	d84 = (uint16_t)(rd16(hw, R_RF_PINS_SELECT) & 0xfff0);

	wr16(hw, R_RF_PINS_ENABLE, d82 | 0x0007);
	wr16(hw, R_RF_PINS_SELECT, d84 | 0x0007);
	udelay(hw, 10);
	wr16(hw, R_RF_PINS_OUTPUT, d80 | BB_HOST_BANG_EN);
	udelay(hw, 2);
	wr16(hw, R_RF_PINS_OUTPUT, d80);
	udelay(hw, 10);

	/* The chip's firmware clocks the word out for us. */
	RTW_PUT_LE16(b, data);
	reg_write(hw, (uint16_t)addr, 0x8225, b, 2);

	wr16(hw, R_RF_PINS_OUTPUT, d80 | BB_HOST_BANG_EN);
	udelay(hw, 10);
	wr16(hw, R_RF_PINS_OUTPUT, d80 | BB_HOST_BANG_EN);
	wr16(hw, R_RF_PINS_SELECT, d84);
	msleep(hw, 2);
}

static uint16_t
rf_read(struct rtl8187 *hw, unsigned addr)
{
	uint32_t d2w = ((uint32_t)(addr & 0x1f)) << 27;
	uint32_t mask = 0x80000000U;
	uint16_t o1, o2, o3, value = 0, rmask;
	unsigned bit = 0;
	int i;

	o1 = rd16(hw, R_RF_PINS_OUTPUT);
	o2 = rd16(hw, R_RF_PINS_ENABLE);
	o3 = rd16(hw, R_RF_PINS_SELECT);
	wr16(hw, R_RF_PINS_ENABLE, o2 | 0xf);
	wr16(hw, R_RF_PINS_SELECT, o3 | 0xf);
	o1 &= (uint16_t)~0xf;
	wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_EN);
	udelay(hw, 5);
	wr16(hw, R_RF_PINS_OUTPUT, o1);
	udelay(hw, 5);

	/* Clock out the address, two bits per iteration. */
	for (i = 0; i < 3; i++, mask >>= 1) {
		bit = (d2w & mask) ? 1 : 0;
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_CLK);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_CLK);
		udelay(hw, 2);
		mask >>= 1;
		if (i == 2)
			break;
		bit = (d2w & mask) ? 1 : 0;
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_CLK);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_CLK);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, bit | o1);
		udelay(hw, 1);
	}
	wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_RW |
	    BB_HOST_BANG_CLK);
	udelay(hw, 2);
	wr16(hw, R_RF_PINS_OUTPUT, bit | o1 | BB_HOST_BANG_RW);
	udelay(hw, 2);
	wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW);
	udelay(hw, 2);

	/* Clock in twelve data bits. */
	for (rmask = 0x800; rmask != 0; rmask >>= 1) {
		wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW |
		    BB_HOST_BANG_CLK);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW |
		    BB_HOST_BANG_CLK);
		udelay(hw, 2);
		wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW |
		    BB_HOST_BANG_CLK);
		udelay(hw, 2);
		if (rd16(hw, R_RF_PINS_INPUT) & BB_HOST_BANG_CLK)
			value |= rmask;
		wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_RW);
		udelay(hw, 2);
	}

	wr16(hw, R_RF_PINS_OUTPUT, o1 | BB_HOST_BANG_EN | BB_HOST_BANG_RW);
	udelay(hw, 2);
	wr16(hw, R_RF_PINS_ENABLE, o2);
	wr16(hw, R_RF_PINS_SELECT, o3);
	wr16(hw, R_RF_PINS_OUTPUT, 0x3a0);
	return value;
}

static void
phy_write(struct rtl8187 *hw, unsigned addr, uint32_t data)
{
	uint32_t w = (data << 8) | (addr | 0x80);

	wr8(hw, R_PHY + 3, (w >> 24) & 0xff);
	wr8(hw, R_PHY + 2, (w >> 16) & 0xff);
	wr8(hw, R_PHY + 1, (w >> 8) & 0xff);
	wr8(hw, R_PHY, w & 0xff);
}

static void
phy_ofdm(struct rtl8187 *hw, unsigned addr, unsigned data)
{
	phy_write(hw, addr, data & 0xff);
}

static void
phy_cck(struct rtl8187 *hw, unsigned addr, unsigned data)
{
	phy_write(hw, addr, (data & 0xff) | 0x10000);
}

/* Tell the two radio revisions apart by reading back two registers. */
static int
rf_is_v2(struct rtl8187 *hw)
{
	uint16_t r8, r9;

	wr16(hw, R_RF_PINS_OUTPUT, 0x0080);
	wr16(hw, R_RF_PINS_SELECT, 0x0080);
	wr16(hw, R_RF_PINS_ENABLE, 0x0080);
	msleep(hw, 500);
	rf_write(hw, 0x0, 0x1b7);
	r8 = rf_read(hw, 0x8);
	r9 = rf_read(hw, 0x9);
	rf_write(hw, 0x0, 0xb7);
	return r8 == 0x588 && r9 == 0x700;
}

/* ------------------------------------------------------------------ */
/* Transmit power and channel                                         */

static void
rtl8225_set_txpwr(struct rtl8187 *hw, int chan)
{
	const uint8_t *tbl;
	unsigned cck = hw->txpwr_cck[chan], ofdm = hw->txpwr_ofdm[chan];
	unsigned idx, set;
	int i;

	if (cck > 11)
		cck = 11;
	idx = cck % 6;
	set = cck / 6;
	tbl = (chan == 14) ? rtl8225_txpwr_cck_ch14 : rtl8225_txpwr_cck;
	wr8(hw, R_TX_GAIN_CCK, rtl8225_tx_gain_cck_ofdm[set] >> 1);
	for (i = 0; i < 8; i++)
		phy_cck(hw, 0x44 + i, tbl[idx * 8 + i]);
	msleep(hw, 1);

	ofdm = (ofdm > 25 - 10) ? 25 : ofdm + 10;
	if (ofdm > 35)
		ofdm = 35;
	idx = ofdm % 6;
	set = ofdm / 6;
	set_anaparam(hw, R_ANAPARAM2, ANAPARAM2_ON);
	phy_ofdm(hw, 2, 0x42);
	phy_ofdm(hw, 6, 0);
	phy_ofdm(hw, 8, 0);
	wr8(hw, R_TX_GAIN_OFDM, rtl8225_tx_gain_cck_ofdm[set] >> 1);
	phy_ofdm(hw, 0x5, rtl8225_txpwr_ofdm[idx]);
	phy_ofdm(hw, 0x7, rtl8225_txpwr_ofdm[idx]);
	msleep(hw, 1);
}

static void
rtl8225z2_set_txpwr(struct rtl8187 *hw, int chan)
{
	const uint8_t *tbl;
	unsigned cck = hw->txpwr_cck[chan], ofdm = hw->txpwr_ofdm[chan];
	int i;

	if (cck > 15)
		cck = 15;
	cck += hw->txpwr_cck_base;
	if (cck > 35)
		cck = 35;
	tbl = (chan == 14) ? rtl8225z2_txpwr_cck_ch14 : rtl8225z2_txpwr_cck;
	for (i = 0; i < 8; i++)
		phy_cck(hw, 0x44 + i, tbl[i]);
	wr8(hw, R_TX_GAIN_CCK, rtl8225z2_tx_gain_cck_ofdm[cck]);
	msleep(hw, 1);

	ofdm = (ofdm > 25 - 10) ? 25 : ofdm + 10;
	ofdm += hw->txpwr_ofdm_base;
	if (ofdm > 35)
		ofdm = 35;
	set_anaparam(hw, R_ANAPARAM2, ANAPARAM2_ON);
	phy_ofdm(hw, 2, 0x42);
	phy_ofdm(hw, 5, 0x0);
	phy_ofdm(hw, 6, 0x40);
	phy_ofdm(hw, 7, 0x0);
	phy_ofdm(hw, 8, 0x40);
	wr8(hw, R_TX_GAIN_OFDM, rtl8225z2_tx_gain_cck_ofdm[ofdm]);
	msleep(hw, 1);
}

/* Slot time and the interframe spaces derived from it. */
static void
set_slot(struct rtl8187 *hw)
{
	wr8(hw, R_SIFS, 0x22);
	if (hw->short_slot) {
		wr8(hw, R_SLOT, 9);
		wr8(hw, R_DIFS, 0x14);
		wr8(hw, R_EIFS, 0x5b - 0x14);
		wr8(hw, R_CW_VAL, 0x73);
	} else {
		wr8(hw, R_SLOT, 20);
		wr8(hw, R_DIFS, 0x24);
		wr8(hw, R_EIFS, 0x5b - 0x24);
		wr8(hw, R_CW_VAL, 0xa5);
	}
}

static void
rf_set_chan(struct rtl8187 *hw, int chan)
{
	if (hw->rf_v2)
		rtl8225z2_set_txpwr(hw, chan);
	else
		rtl8225_set_txpwr(hw, chan);
	rf_write(hw, 0x7, rtl8225_channel[chan]);
	msleep(hw, 10);
	set_slot(hw);
	hw->chan = (uint8_t)chan;
}

/* ------------------------------------------------------------------ */
/* Radio initialisation                                               */

static void
rf_init_common(struct rtl8187 *hw)
{
	uint8_t d;

	set_anaparam(hw, R_ANAPARAM, ANAPARAM_ON);

	wr8(hw, R_RF_PINS_SELECT + 1, 0);
	wr8(hw, R_GPIO, 0);
	d = rd8e(hw, 0x53);
	wr8e(hw, 0x53, d | 0x80);
	wr8(hw, R_RF_PINS_SELECT + 1, 4);
	wr8(hw, R_GPIO, 0x20);
	wr8(hw, R_GP_ENABLE, 0);
	wr16(hw, R_RF_PINS_OUTPUT, 0x80);
	wr16(hw, R_RF_PINS_SELECT, 0x80);
	wr16(hw, R_RF_PINS_ENABLE, 0x80);
	msleep(hw, 500);

	wr32(hw, R_RF_TIMING, 0x000a8008);
	(void)rd16(hw, R_BRSR);
	wr16(hw, R_BRSR, 0xffff);
	wr32(hw, R_RF_PARA, 0x100044);
	set_mode(hw, EPROM_MODE_CONFIG);
	wr8(hw, R_CONFIG3, 0x44);
	set_mode(hw, EPROM_MODE_NORMAL);
	wr16(hw, R_RF_PINS_ENABLE, 0x1ff7);
}

static void
rf_init_agc(struct rtl8187 *hw)
{
	unsigned i;

	for (i = 0; i < NITEMS(rtl8225_agc); i++) {
		phy_ofdm(hw, 0xb, rtl8225_agc[i]);
		phy_ofdm(hw, 0xa, i + 0x80);
	}
}

static void
rtl8225_rf_init(struct rtl8187 *hw)
{
	unsigned i;

	rf_init_common(hw);
	msleep(hw, 500);

	for (i = 0; i < NITEMS(rtl8225_rf_part1); i++)
		rf_write(hw, rtl8225_rf_part1[i].reg, rtl8225_rf_part1[i].val);
	msleep(hw, 50);
	rf_write(hw, 0x2, 0xc4d);
	msleep(hw, 200);
	rf_write(hw, 0x2, 0x44d);
	msleep(hw, 200);
	rf_write(hw, 0x0, 0x127);
	for (i = 0; i < NITEMS(rtl8225_rxgain); i++) {
		rf_write(hw, 0x1, i + 1);
		rf_write(hw, 0x2, rtl8225_rxgain[i]);
	}
	rf_write(hw, 0x0, 0x27);
	rf_write(hw, 0x0, 0x22f);

	rf_init_agc(hw);
	for (i = 0; i < NITEMS(rtl8225_rf_part2); i++) {
		phy_ofdm(hw, rtl8225_rf_part2[i].reg, rtl8225_rf_part2[i].val);
		msleep(hw, 1);
	}
	/* Receive gain for the default sensitivity. */
	phy_ofdm(hw, 0x0d, rtl8225_gain[4 * 4]);
	phy_ofdm(hw, 0x1b, rtl8225_gain[4 * 4 + 2]);
	phy_ofdm(hw, 0x1d, rtl8225_gain[4 * 4 + 3]);
	phy_ofdm(hw, 0x23, rtl8225_gain[4 * 4 + 1]);
	for (i = 0; i < NITEMS(rtl8225_rf_part3); i++) {
		phy_cck(hw, rtl8225_rf_part3[i].reg, rtl8225_rf_part3[i].val);
		msleep(hw, 1);
	}
	wr8(hw, 0x5b, 0x0d);
	rtl8225_set_txpwr(hw, 1);
	phy_cck(hw, 0x10, 0x9b);
	msleep(hw, 1);
	phy_ofdm(hw, 0x26, 0x90);
	msleep(hw, 1);
	wr8(hw, R_TX_ANTENNA, 0x3);		/* antenna A */
	msleep(hw, 1);
	wr32(hw, R_HSSI_PARA, 0x3dc00002);
	rf_set_chan(hw, 1);

	/* Sensitivity setting 4: gain row 6 - 4 = 2. */
	rf_write(hw, 0x0c, 0x50);
	phy_ofdm(hw, 0x0d, rtl8225_gain[2 * 4]);
	phy_ofdm(hw, 0x1b, rtl8225_gain[2 * 4 + 2]);
	phy_ofdm(hw, 0x1d, rtl8225_gain[2 * 4 + 3]);
	phy_ofdm(hw, 0x23, rtl8225_gain[2 * 4 + 1]);
	phy_cck(hw, 0x41, rtl8225_threshold[2]);
}

static void
rtl8225z2_rf_init(struct rtl8187 *hw)
{
	unsigned i;

	rf_init_common(hw);
	msleep(hw, 1000);

	for (i = 0; i < NITEMS(rtl8225z2_rf_part1); i++) {
		rf_write(hw, rtl8225z2_rf_part1[i].reg,
		    rtl8225z2_rf_part1[i].val);
		msleep(hw, 1);
	}
	msleep(hw, 50);
	rf_write(hw, 0x0, 0x1b7);
	for (i = 0; i < NITEMS(rtl8225z2_rxgain); i++) {
		rf_write(hw, 0x1, i + 1);
		rf_write(hw, 0x2, rtl8225z2_rxgain[i]);
	}
	rf_write(hw, 0x3, 0x2);
	rf_write(hw, 0x5, 0x4);
	rf_write(hw, 0x0, 0xb7);
	rf_write(hw, 0x2, 0xc4d);
	msleep(hw, 100);
	rf_write(hw, 0x2, 0x44d);
	msleep(hw, 100);
	/* Bit 7 of register 6 reports that the synthesiser calibrated;
	 * retry once if it did not. */
	if (!(rf_read(hw, 0x6) & 0x80)) {
		rf_write(hw, 0x02, 0x0c4d);
		msleep(hw, 200);
		rf_write(hw, 0x02, 0x044d);
		msleep(hw, 100);
	}
	msleep(hw, 100);
	rf_write(hw, 0x0, 0x2bf);

	rf_init_agc(hw);
	for (i = 0; i < NITEMS(rtl8225z2_rf_part2); i++)
		phy_ofdm(hw, rtl8225z2_rf_part2[i].reg,
		    rtl8225z2_rf_part2[i].val);
	phy_ofdm(hw, 0x0d, rtl8225z2_gain_bg[4 * 3]);
	msleep(hw, 1);
	phy_ofdm(hw, 0x1b, rtl8225z2_gain_bg[4 * 3 + 1]);
	msleep(hw, 1);
	phy_ofdm(hw, 0x1d, rtl8225z2_gain_bg[4 * 3 + 2]);
	msleep(hw, 1);
	phy_ofdm(hw, 0x21, 0x17);
	msleep(hw, 1);
	for (i = 0; i < NITEMS(rtl8225z2_rf_part3); i++)
		phy_cck(hw, rtl8225z2_rf_part3[i].reg,
		    rtl8225z2_rf_part3[i].val);
	wr8(hw, 0x5b, 0x0d);
	rtl8225z2_set_txpwr(hw, 1);
	phy_cck(hw, 0x10, 0x9b);
	phy_ofdm(hw, 0x26, 0x90);
	wr8(hw, R_TX_ANTENNA, 0x3);		/* antenna A */
	msleep(hw, 1);
	wr32(hw, R_HSSI_PARA, 0x3dc00002);
	rf_set_chan(hw, 1);
}

/* ------------------------------------------------------------------ */
/* MAC                                                                */

static void
set_rx_conf(struct rtl8187 *hw)
{
	uint32_t d = rd32(hw, R_RX_CONF);

	d &= ~RX_FILTER_MASK;
	d |= RX_FILTER_MNG | RX_FILTER_DATA | RX_FILTER_BCAST |
	    RX_FILTER_MCAST;
	if (hw->promisc) {
		d |= RX_FILTER_ALLMAC;
	} else {
		d |= RX_FILTER_NICMAC;
		/* Only filter on BSSID once there is one; scanning needs
		 * to hear every network. */
		if (hw->linked)
			d |= RX_CHECK_BSSID;
	}
	d &= ~RX_FIFO_THRESHOLD_MASK;
	d |= RX_FIFO_THRESHOLD_NONE | RX_AUTORESETPHY;
	d &= ~RX_MAX_DMA_MASK;
	d |= RX_MAX_DMA_2048 | RX_ONLYERLPKT;
	wr32(hw, R_RX_CONF, d);
}

static void
set_msr(struct rtl8187 *hw)
{
	uint8_t d = rd8(hw, R_MSR);

	d &= (uint8_t)~MSR_LINK_MASK;
	if (hw->linked)
		d |= MSR_LINK_STA;
	wr8(hw, R_MSR, d);
}

static void
chip_reset(struct rtl8187 *hw)
{
	uint8_t d;

	set_anaparam(hw, R_ANAPARAM, ANAPARAM_ON);
	set_anaparam(hw, R_ANAPARAM2, ANAPARAM2_ON);
	wr16(hw, R_INTR_MASK, 0);
	msleep(hw, 100);
	wr8e(hw, 0x18, 0x10);
	wr8e(hw, 0x18, 0x11);
	wr8e(hw, 0x18, 0x00);
	msleep(hw, 100);

	d = rd8(hw, R_CMD);
	wr8(hw, R_CMD, (d & 2) | CMD_RST);
	msleep(hw, 100);
	if (hw->err == 0 && (rd8(hw, R_CMD) & CMD_RST)) {
		hw->err = RTL8187_E_TIMEOUT;
		return;
	}
	set_mode(hw, EPROM_MODE_LOAD);
	msleep(hw, 100);
	set_anaparam(hw, R_ANAPARAM, ANAPARAM_ON);
	set_anaparam(hw, R_ANAPARAM2, ANAPARAM2_ON);
}

int
rtl8187_probe(struct rtl8187 *hw, const struct rtl8187_io *io)
{
	uint16_t w;
	int i, j;

	memset(hw, 0, sizeof(*hw));
	hw->io = *io;

	/* Some RTL8187B devices reuse RTL8187 USB IDs; the 8187B is a
	 * different chip that this driver does not support. */
	hw->hwrev = (uint8_t)((rd32(hw, R_TX_CONF) & TX_HWREV_MASK) >> 25);
	if (hw->err)
		return hw->err;
	if (hw->hwrev == (TX_HWREV_8187B_D >> 25))
		return RTL8187_E_UNSUPPORTED;

	hw->eeprom_addr_bits = (rd32(hw, R_RX_CONF) & RX_9356SEL) ? 8 : 6;

	if ((eprom_read(hw, EE_RFCHIPID) & 0xff) != EE_RFCHIPID_RTL8225U)
		return hw->err ? hw->err : RTL8187_E_UNSUPPORTED;

	/* The radio must be powered before it can be identified. */
	set_anaparam(hw, R_ANAPARAM, ANAPARAM_ON);
	set_anaparam(hw, R_ANAPARAM2, ANAPARAM2_ON);
	hw->rf_v2 = (uint8_t)rf_is_v2(hw);

	for (i = 0; i < 3; i++) {
		w = eprom_read(hw, EE_MACADDR + i);
		hw->macaddr[2 * i] = (uint8_t)(w & 0xff);
		hw->macaddr[2 * i + 1] = (uint8_t)(w >> 8);
	}

	/* Per-channel transmit power, two channels per EEPROM word. */
	w = eprom_read(hw, EE_TXPW_BASE);
	hw->txpwr_cck_base = (uint8_t)(w & 0xf);
	hw->txpwr_ofdm_base = (uint8_t)((w >> 4) & 0xf);
	for (i = 1, j = 0; i <= 14; i += 2, j++) {
		unsigned addr;

		if (i < 7)
			addr = EE_TXPW0 + j;		/* channels 1..6 */
		else if (i < 11)
			addr = EE_TXPW1 + (j - 3);	/* channels 7..10 */
		else
			addr = EE_TXPW2 + (j - 5);	/* channels 11..14 */
		w = eprom_read(hw, addr);
		hw->txpwr_cck[i] = (uint8_t)(w & 0xf);
		hw->txpwr_cck[i + 1] = (uint8_t)((w >> 8) & 0xf);
		hw->txpwr_ofdm[i] = (uint8_t)((w >> 4) & 0xf);
		hw->txpwr_ofdm[i + 1] = (uint8_t)((w >> 12) & 0xf);
	}
	return hw->err;
}

int
rtl8187_start(struct rtl8187 *hw)
{
	const uint8_t *a = hw->macaddr;
	uint32_t d;
	uint8_t d8;

	hw->err = 0;
	hw->linked = 0;
	hw->short_slot = 0;

	chip_reset(hw);
	wr8(hw, 0x85, 0);
	wr8(hw, R_GPIO, 0);
	wr8(hw, 0x85, 4);

	set_mode(hw, EPROM_MODE_CONFIG);
	wr32(hw, R_MAC0, (uint32_t)a[0] | ((uint32_t)a[1] << 8) |
	    ((uint32_t)a[2] << 16) | ((uint32_t)a[3] << 24));
	wr16(hw, R_MAC0 + 4, a[4] | (a[5] << 8));
	set_mode(hw, EPROM_MODE_NORMAL);

	set_msr(hw);
	wr32(hw, R_INT_TIMEOUT, 0);
	wr8(hw, R_WPA_CONFIG, 0);	/* all encryption is done in software */
	wr8(hw, R_RATE_FALLBACK, 0x81);	/* automatic rate fallback on retry */

	/* ACK/CTS response rates from 1 up to 24 Mbit/s, and the same set
	 * of basic rates. */
	wr8(hw, R_RESP_RATE, (RATE_24M << 4) | RATE_1M);
	d = rd16(hw, R_BRSR);
	wr16(hw, R_BRSR, (d & ~0x0fffU) | ((1U << (RATE_24M + 1)) - 1));

	if (hw->rf_v2)
		rtl8225z2_rf_init(hw);
	else
		rtl8225_rf_init(hw);

	wr16(hw, 0x5e, 1);
	wr16(hw, 0xfe, 0x10);
	wr8(hw, R_TALLY_SEL, 0x80);
	wr8(hw, 0xff, 0x60);
	wr16(hw, 0x5e, 0);
	wr8(hw, 0x85, 4);
	wr16(hw, R_INTR_MASK, 0xffff);

	/* Receiver. */
	set_rx_conf(hw);
	d8 = rd8(hw, R_CMD);
	wr8(hw, R_CMD, d8 | CMD_RX_ENABLE);

	/* Transmitter: retry limits and contention window come from the
	 * registers, not the per-packet descriptor. */
	d8 = rd8(hw, R_CW_CONF);
	wr8(hw, R_CW_CONF, d8 & ~0x03);
	d8 = rd8(hw, R_TX_AGC_CTL);
	wr8(hw, R_TX_AGC_CTL, d8 & ~0x07);
	d = rd32(hw, R_TX_CONF);
	d &= ~(TX_LOOPBACK_MASK | TX_DPRETRY_MASK | TX_RTSRETRY_MASK |
	    TX_NOCRC | TX_MXDMA_MASK | TX_SWPLCPLEN);
	d |= (TX_RETRY << 0) | (RTS_RETRY << 8);
	d |= TX_MXDMA_2048 | TX_CWMIN | TX_DISCW | TX_NOICV;
	wr32(hw, R_TX_CONF, d);
	d8 = rd8(hw, R_CMD);
	wr8(hw, R_CMD, d8 | CMD_TX_ENABLE);

	return hw->err;
}

int
rtl8187_stop(struct rtl8187 *hw)
{
	uint8_t d;

	hw->err = 0;
	wr16(hw, R_INTR_MASK, 0);
	d = rd8(hw, R_CMD);
	wr8(hw, R_CMD, d & ~(CMD_TX_ENABLE | CMD_RX_ENABLE));
	hw->linked = 0;
	return hw->err;
}

int
rtl8187_set_channel(struct rtl8187 *hw, int chan)
{
	uint32_t d;

	if (chan < 1 || chan > 14)
		return RTL8187_E_UNSUPPORTED;
	hw->err = 0;
	/* Put the transmitter in loopback while the synthesiser moves. */
	d = rd32(hw, R_TX_CONF) & ~TX_LOOPBACK_MASK;
	wr32(hw, R_TX_CONF, d | TX_LOOPBACK_MAC);
	rf_set_chan(hw, chan);
	msleep(hw, 10);
	wr32(hw, R_TX_CONF, d);
	return hw->err;
}

int
rtl8187_set_bss(struct rtl8187 *hw, const uint8_t *bssid, int linked,
    int short_slot)
{
	static const uint8_t none[6] = { 0, 0, 0, 0, 0, 0 };
	const uint8_t *b = bssid ? bssid : none;

	hw->err = 0;
	hw->linked = (uint8_t)(bssid != NULL && linked);
	hw->short_slot = (uint8_t)(hw->linked && short_slot);

	wr32(hw, R_BSSID, (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	    ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
	wr16(hw, R_BSSID + 4, b[4] | (b[5] << 8));
	set_msr(hw);
	if (hw->linked) {
		wr16(hw, R_ATIM_WND, 2);
		wr16(hw, R_ATIM_TR_ITV, 100);
		wr16(hw, R_BEACON_INTERVAL, 100);
		wr16(hw, R_BEACON_INTERVAL_TIME, 0x3ff);
	}
	set_slot(hw);
	set_rx_conf(hw);
	return hw->err;
}

int
rtl8187_set_promisc(struct rtl8187 *hw, int on)
{
	hw->err = 0;
	hw->promisc = (uint8_t)(on != 0);
	set_rx_conf(hw);
	return hw->err;
}

/* ------------------------------------------------------------------ */
/* Bulk transfer framing                                              */

size_t
rtl8187_tx_desc(uint8_t *buf, size_t frame_len, int hwrate)
{
	size_t xfer = RTL8187_TX_DESC_LEN + frame_len;

	/* flags: length [11:0], no hardware encryption [15], RTS rate
	 * [22:19] (1 Mbit/s), data rate [27:24] */
	buf[0] = (uint8_t)(frame_len & 0xff);
	buf[1] = (uint8_t)(((frame_len >> 8) & 0x0f) | 0x80);
	buf[2] = 0;
	buf[3] = (uint8_t)(hwrate & 0x0f);
	buf[4] = buf[5] = 0;		/* RTS duration */
	buf[6] = buf[7] = 0;
	buf[8] = 3 | (7 << 4);		/* contention window min, max */
	buf[9] = 11;			/* retry limit */
	buf[10] = buf[11] = 0;

	/* A transfer that is an exact multiple of the endpoint packet size
	 * would need a zero length packet to terminate; pad instead. */
	if ((xfer % 64) == 0) {
		buf[xfer] = 0;
		xfer++;
	}
	return xfer;
}

int
rtl8187_rx_parse(const uint8_t *buf, size_t actlen, struct rtl8187_rxinfo *ri)
{
	const uint8_t *desc;
	uint32_t flags;
	size_t flen;
	unsigned agc;

	/* The frame comes first; a 16 byte status block ends the transfer. */
	if (actlen < RTL8187_RX_DESC_LEN + RTL8187_FCS_LEN)
		return -1;
	desc = buf + actlen - RTL8187_RX_DESC_LEN;
	flags = (uint32_t)desc[0] | ((uint32_t)desc[1] << 8) |
	    ((uint32_t)desc[2] << 16) | ((uint32_t)desc[3] << 24);
	flen = flags & 0x0fff;
	if (flen < RTL8187_FCS_LEN || flen > actlen - RTL8187_RX_DESC_LEN)
		return -1;
	if (flags & (1U << 13))		/* CRC error */
		return -1;
	ri->len = flen - RTL8187_FCS_LEN;
	ri->rate = (uint8_t)((flags >> 20) & 0x0f);

	/* The AGC reading falls as the signal gets stronger. */
	agc = desc[6] >> 1;
	if (ri->rate > 3) {		/* OFDM */
		agc = (agc > 90) ? 90 : (agc < 25) ? 25 : agc;
		ri->rssi = (uint8_t)(((90 - agc) * 100) / 65);
	} else {
		agc = (agc > 95) ? 95 : (agc < 30) ? 30 : agc;
		ri->rssi = (uint8_t)(((95 - agc) * 100) / 65);
	}
	return 0;
}
