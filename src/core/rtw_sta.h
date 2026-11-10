/*
 * 802.11 station (client) logic: scanning, joining a network, the WPA2-PSK
 * key handshake, and conversion between Ethernet and 802.11 data frames.
 *
 * This layer knows nothing about the radio chip or the operating system.
 * It is driven by four kinds of event -- a command, a received frame, the
 * timer, or an Ethernet frame to send -- and acts through the callbacks
 * in struct rtw_sta_ops.  All entry points must be serialised by the
 * caller (the kernel extension runs them on its work loop).
 */
#ifndef RTW_STA_H
#define RTW_STA_H

#include "rtw_os.h"
#include "rtw_aes.h"
#include "rtw_sha1.h"

RTW_EXTERN_C_BEGIN

#define RTW_ETH_ALEN		6
#define RTW_ETH_HLEN		14
#define RTW_SSID_MAX		32
#define RTW_MAX_BSS		32
#define RTW_PMK_LEN		32

/* Largest 802.11 frame body we build or accept, excluding the FCS. */
#define RTW_MAX_FRAME		2342

/* Room the encapsulation can need in front of / behind an Ethernet
 * payload: 802.11 header (24) + CCMP header (8) + LLC/SNAP (8), and the
 * CCMP MIC (8). */
#define RTW_TX_HEADROOM_MAX	40
#define RTW_TX_TAILROOM_MAX	8

/* Transmit rates are identified by the chip's rate index throughout. */
enum {
	RTW_RATE_1M = 0, RTW_RATE_2M, RTW_RATE_5_5M, RTW_RATE_11M,
	RTW_RATE_6M, RTW_RATE_9M, RTW_RATE_12M, RTW_RATE_18M,
	RTW_RATE_24M, RTW_RATE_36M, RTW_RATE_48M, RTW_RATE_54M,
	RTW_RATE_COUNT
};
#define RTW_RATE_AUTO		0xff
#define RTW_RATES_CCK		0x000f
#define RTW_RATES_OFDM		0x0ff0

/* Rate in units of 500 kbit/s (the 802.11 encoding), or 0. */
unsigned rtw_rate_to_500k(unsigned hwrate);
/* Chip rate index for a rate in 500 kbit/s units, or -1. */
int rtw_rate_from_500k(unsigned rate);

enum rtw_state {
	RTW_S_DOWN = 0,		/* interface not running */
	RTW_S_IDLE,		/* running, not associated */
	RTW_S_SCAN,
	RTW_S_AUTH,
	RTW_S_ASSOC,
	RTW_S_HANDSHAKE,	/* associated, WPA2 keys not yet installed */
	RTW_S_RUN
};

enum rtw_security {
	RTW_SEC_OPEN = 0,
	RTW_SEC_WEP,
	RTW_SEC_WPA2_PSK,	/* WPA2-Personal with AES-CCMP */
	RTW_SEC_UNSUPPORTED	/* WPA/TKIP, WPA3-only, 802.1X, ... */
};

/* Why the last join attempt failed (rtw_sta.last_error). */
enum rtw_error {
	RTW_ERR_NONE = 0,
	RTW_ERR_NOT_FOUND,	/* no matching network in range */
	RTW_ERR_SECURITY,	/* network found, security mismatch */
	RTW_ERR_AUTH_TIMEOUT,
	RTW_ERR_AUTH_REJECTED,
	RTW_ERR_ASSOC_TIMEOUT,
	RTW_ERR_ASSOC_REJECTED,
	RTW_ERR_HANDSHAKE,	/* key handshake failed: wrong password? */
	RTW_ERR_DEAUTH,		/* access point disconnected us */
	RTW_ERR_BEACON_LOSS
};

struct rtw_bss {
	uint8_t  bssid[RTW_ETH_ALEN];
	uint8_t  ssid[RTW_SSID_MAX];
	uint8_t  ssid_len;
	uint8_t  chan;
	uint8_t  rssi;		/* 0..100, larger is stronger */
	uint8_t  security;	/* enum rtw_security */
	uint16_t capinfo;
	uint16_t beacon_int;
	uint16_t rates;		/* bit per chip rate index */
};

struct rtw_join {
	uint8_t  ssid[RTW_SSID_MAX];
	uint8_t  ssid_len;
	uint8_t  security;	/* OPEN, WEP or WPA2_PSK */
	uint8_t  have_bssid;	/* restrict to one access point */
	uint8_t  bssid[RTW_ETH_ALEN];
	uint8_t  wep_key[13];
	uint8_t  wep_key_len;	/* 5 or 13 */
	uint8_t  wep_key_id;	/* 0..3 */
	uint8_t  pmk[RTW_PMK_LEN];
};

struct rtw_sta_ops {
	void *ctx;
	/* Tune the radio.  May block. */
	int (*set_channel)(void *ctx, int chan);
	/* Tell the chip which BSS we belong to.  bssid == NULL means none.
	 * linked is nonzero once associated; short_slot selects 9us slots. */
	int (*set_bss)(void *ctx, const uint8_t *bssid, int linked,
	    int short_slot);
	/* Transmit a complete 802.11 frame (no FCS) built by the core. */
	int (*tx)(void *ctx, const uint8_t *frame, size_t len, int hwrate);
	/* Hand a received Ethernet frame to the network stack. */
	void (*rx_deliver)(void *ctx, const uint8_t *eth, size_t len);
	/* The link came up (keys installed, data may flow) or went down. */
	void (*link)(void *ctx, int up);
	/* A scan finished; the results are in sta->bss[]. */
	void (*scan_done)(void *ctx);
	/* Arm the single one-shot timer (replacing any pending one); when
	 * it fires call rtw_sta_timer().  ms == 0 cancels. */
	void (*set_timer)(void *ctx, unsigned ms);
	void (*random)(void *ctx, uint8_t *buf, size_t len);
	uint32_t (*now_ms)(void *ctx);
};

struct rtw_sta_stats {
	uint32_t rx_data;
	uint32_t rx_mgmt;
	uint32_t rx_dropped;	/* malformed, misaddressed, unencrypted */
	uint32_t rx_decrypt_fail;
	uint32_t rx_replay;
	uint32_t rx_dup;
	uint32_t rx_frag;	/* fragmented frames (not reassembled) */
	uint32_t tx_data;
	uint32_t tx_dropped;
};

struct rtw_gtk {
	struct rtw_aes_key key;
	uint8_t  raw[16];
	uint8_t  rx_pn[6];
	uint8_t  valid;
};

struct rtw_sta {
	struct rtw_sta_ops ops;
	uint8_t  addr[RTW_ETH_ALEN];
	uint8_t  state;			/* enum rtw_state */
	uint8_t  last_error;		/* enum rtw_error */
	uint8_t  max_chan;		/* highest channel scanned (11..14) */

	/* scan */
	uint8_t  scan_chan;
	uint8_t  scan_resume;		/* state to return to afterwards */
	uint8_t  join_pending;		/* join when the scan completes */
	unsigned nbss;
	struct rtw_bss bss[RTW_MAX_BSS];

	/* the network we want and the access point we chose */
	uint8_t  have_cfg;
	struct rtw_join cfg;
	struct rtw_bss cur;
	uint16_t aid;
	uint8_t  tries;
	uint8_t  link_up;
	uint8_t  short_slot;
	uint32_t last_beacon_ms;

	/* transmit */
	uint16_t seq;
	uint16_t rates;			/* rates both ends support */
	uint8_t  txrate;		/* current data rate (chip index) */
	uint8_t  fixed_rate;		/* RTW_RATE_AUTO or a chip index */
	uint8_t  mgmt_rate;
	uint32_t wep_iv;

	/* duplicate detection: [0] unicast, [1] group addressed */
	uint16_t last_seq[2];
	uint8_t  last_seq_valid[2];

	/* WPA2 pairwise and group keys */
	struct rtw_aes_key ptk_key;
	uint8_t  tk[16];
	uint8_t  ptk_valid;
	uint8_t  tx_pn[6];		/* little-endian: tx_pn[0] is PN0 */
	uint8_t  rx_pn[6];
	struct rtw_gtk gtk[4];

	/* WPA2 4-way handshake */
	uint8_t  anonce[32];
	uint8_t  snonce[32];
	uint8_t  have_snonce;
	uint8_t  ptk_derived;
	uint8_t  pend_kck[16];		/* derived, not yet confirmed */
	uint8_t  pend_kek[16];
	uint8_t  pend_tk[16];
	uint8_t  kck[16];		/* confirmed by message 3 */
	struct rtw_aes_key kek;
	uint8_t  replay[8];
	uint8_t  replay_valid;

	struct rtw_sta_stats stats;

	/* scratch space, kept here instead of on the (small) kernel stack */
	struct rtw_hmac_sha1 hmac;
	uint8_t  txbuf[512];
	uint8_t  keydata[256];
};

/* Lifecycle.  rtw_sta_init() once; rtw_sta_up()/down() as the interface
 * is enabled and disabled. */
void rtw_sta_init(struct rtw_sta *sta, const struct rtw_sta_ops *ops,
    const uint8_t addr[RTW_ETH_ALEN]);
void rtw_sta_up(struct rtw_sta *sta);
void rtw_sta_down(struct rtw_sta *sta);

/* Commands. */
int  rtw_sta_scan(struct rtw_sta *sta);
int  rtw_sta_join(struct rtw_sta *sta, const struct rtw_join *cfg);
void rtw_sta_leave(struct rtw_sta *sta);
/* hwrate is a chip rate index, or RTW_RATE_AUTO. */
int  rtw_sta_set_rate(struct rtw_sta *sta, unsigned hwrate);

/* Events. */
void rtw_sta_timer(struct rtw_sta *sta);
/* frame is modified in place (decryption, header rewriting). */
void rtw_sta_rx(struct rtw_sta *sta, uint8_t *frame, size_t len, int rssi,
    int hwrate);

/*
 * Transmit path.  The caller copies the Ethernet payload (everything
 * after the 14 byte header) to frame + headroom, leaving tailroom bytes
 * free after it, then calls rtw_sta_tx_finish() which builds the 802.11
 * header in the headroom, encrypts in place and returns the frame length.
 * rtw_sta_tx_prepare() returns -1 if the frame cannot be sent now.
 */
int rtw_sta_tx_prepare(struct rtw_sta *sta, const uint8_t *eth_hdr,
    unsigned *headroom, unsigned *tailroom);
size_t rtw_sta_tx_finish(struct rtw_sta *sta, const uint8_t *eth_hdr,
    uint8_t *frame, size_t payload_len, int *hwrate);

/* Derive the WPA pre-shared key from a passphrase and SSID. */
void rtw_wpa_passphrase_to_pmk(const char *pass, const uint8_t *ssid,
    size_t ssid_len, uint8_t pmk[RTW_PMK_LEN]);

const char *rtw_state_name(unsigned state);
const char *rtw_error_name(unsigned err);
const char *rtw_security_name(unsigned sec);

RTW_EXTERN_C_END

#endif /* RTW_STA_H */
