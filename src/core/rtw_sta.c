/*
 * 802.11 station logic.  See rtw_sta.h for the interface.
 *
 * What is implemented: active scanning, open-system authentication,
 * association, WEP, WPA2-PSK with CCMP (4-way and group key handshakes),
 * Ethernet <-> 802.11 conversion, and automatic rejoin.  What is not:
 * WPA/TKIP, WPA3, 802.1X, power save, fragmentation, QoS/WMM, ad-hoc.
 */
#include "rtw_sta.h"
#include "rtw_wep.h"

/* Frame control, first byte: type and subtype. */
#define FC0_TYPE_MASK		0x0c
#define FC0_TYPE_MGMT		0x00
#define FC0_TYPE_DATA		0x08
#define FC0_SUBTYPE_MASK	0xf0
#define FC0_ASSOC_REQ		0x00
#define FC0_ASSOC_RESP		0x10
#define FC0_PROBE_REQ		0x40
#define FC0_PROBE_RESP		0x50
#define FC0_BEACON		0x80
#define FC0_DISASSOC		0xa0
#define FC0_AUTH		0xb0
#define FC0_DEAUTH		0xc0
#define FC0_DATA_NULL_BIT	0x40	/* data subtypes that carry no data */
#define FC0_DATA_QOS_BIT	0x80
/* Frame control, second byte: flags. */
#define FC1_TODS		0x01
#define FC1_FROMDS		0x02
#define FC1_MORE_FRAG		0x04
#define FC1_RETRY		0x08
#define FC1_PROTECTED		0x40
#define FC1_ORDER		0x80

#define CAP_ESS			0x0001
#define CAP_IBSS		0x0002
#define CAP_PRIVACY		0x0010
#define CAP_SHORT_SLOT		0x0400

#define IE_SSID			0
#define IE_RATES		1
#define IE_DS			3
#define IE_RSN			48
#define IE_XRATES		50
#define IE_VENDOR		221

#define HDR_LEN			24
#define CCMP_HDR_LEN		8
#define CCMP_MIC_LEN		8
#define LLC_LEN			8

#define ETHERTYPE_EAPOL		0x888e
#define ETHERTYPE_AARP		0x80f3
#define ETHERTYPE_IPX		0x8137

#define REASON_LEAVING		3

/* Timing, in milliseconds. */
#define SCAN_DWELL_MS		120
#define MGMT_TIMEOUT_MS		400
#define MGMT_TRIES		4
#define HANDSHAKE_TIMEOUT_MS	5000
#define RUN_TICK_MS		1000
#define BEACON_LOSS_MS		10000
#define REJOIN_MS		10000
#define REJOIN_FAST_MS		1000

/* EAPOL-Key frame layout (IEEE 802.11i, figure 43u). */
#define EK_TYPE			1	/* 802.1X packet type, 3 = key */
#define EK_BODYLEN		2
#define EK_DESC			4	/* 2 = RSN */
#define EK_INFO			5
#define EK_KEYLEN		7
#define EK_REPLAY		9
#define EK_NONCE		17
#define EK_RSC			65
#define EK_MIC			81
#define EK_DATALEN		97
#define EK_DATA			99
#define EK_INFO_VER_MASK	0x0007
#define EK_INFO_VER_AES		0x0002	/* HMAC-SHA1 MIC, AES key wrap */
#define EK_INFO_PAIRWISE	0x0008
#define EK_INFO_ACK		0x0080
#define EK_INFO_MIC		0x0100
#define EK_INFO_SECURE		0x0200
#define EK_INFO_ENCRYPTED	0x1000
/* Where EAPOL payloads are built inside sta->txbuf. */
#define EAPOL_TXOFF		RTW_TX_HEADROOM_MAX

static const uint8_t rate_500k[RTW_RATE_COUNT] = {
	2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108
};
static const uint8_t bcast[RTW_ETH_ALEN] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const uint8_t suite_ccmp[4] = { 0x00, 0x0f, 0xac, 0x04 };
static const uint8_t suite_psk[4] = { 0x00, 0x0f, 0xac, 0x02 };
static const uint8_t oui_wpa1[4] = { 0x00, 0x50, 0xf2, 0x01 };
static const uint8_t kde_gtk[4] = { 0x00, 0x0f, 0xac, 0x01 };
/* The RSN element we send: WPA2, CCMP group and pairwise, PSK. */
static const uint8_t our_rsn_ie[22] = {
	IE_RSN, 20, 0x01, 0x00,
	0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
	0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
	0x00, 0x00
};
static const uint8_t llc_rfc1042[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
static const uint8_t llc_tunnel[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

static void scan_next(struct rtw_sta *sta);
static void disconnect(struct rtw_sta *sta, int send_deauth);

#define ADDR_EQ(a, b)	(rtw_memcmp((a), (b), RTW_ETH_ALEN) == 0)
#define IS_GROUP(a)	(((const uint8_t *)(a))[0] & 0x01)

unsigned
rtw_rate_to_500k(unsigned hwrate)
{
	return (hwrate < RTW_RATE_COUNT) ? rate_500k[hwrate] : 0;
}

int
rtw_rate_from_500k(unsigned rate)
{
	int i;

	for (i = 0; i < RTW_RATE_COUNT; i++) {
		if (rate_500k[i] == rate)
			return i;
	}
	return -1;
}

const char *
rtw_state_name(unsigned state)
{
	static const char *const names[] = {
		"down", "idle", "scanning", "authenticating", "associating",
		"key handshake", "connected"
	};

	return (state < sizeof(names) / sizeof(names[0])) ? names[state] : "?";
}

const char *
rtw_error_name(unsigned err)
{
	static const char *const names[] = {
		"none", "network not found",
		"network uses a different or unsupported security type",
		"authentication timed out", "authentication rejected",
		"association timed out", "association rejected",
		"key handshake failed (wrong password?)",
		"disconnected by access point", "access point lost"
	};

	return (err < sizeof(names) / sizeof(names[0])) ? names[err] : "?";
}

const char *
rtw_security_name(unsigned sec)
{
	static const char *const names[] = {
		"open", "WEP", "WPA2-PSK", "unsupported"
	};

	return (sec < sizeof(names) / sizeof(names[0])) ? names[sec] : "?";
}

void
rtw_wpa_passphrase_to_pmk(const char *pass, const uint8_t *ssid,
    size_t ssid_len, uint8_t pmk[RTW_PMK_LEN])
{
	rtw_pbkdf2_sha1(pass, strlen(pass), ssid, ssid_len, 4096, pmk,
	    RTW_PMK_LEN);
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */

static int
lowest_rate(uint16_t mask)
{
	int i;

	for (i = 0; i < RTW_RATE_COUNT; i++) {
		if (mask & (1 << i))
			return i;
	}
	return RTW_RATE_1M;
}

/* Highest rate in the set by speed; chip indices are not speed ordered
 * (11 Mbit/s is index 3, 6 Mbit/s is index 4). */
static int
highest_rate(uint16_t mask)
{
	int i, best = -1;

	for (i = 0; i < RTW_RATE_COUNT; i++) {
		if ((mask & (1 << i)) &&
		    (best < 0 || rate_500k[i] > rate_500k[best]))
			best = i;
	}
	return (best < 0) ? RTW_RATE_1M : best;
}

/* Duration field for a frame that will be acknowledged: SIFS plus the
 * ACK at the lowest rate of the same modulation. */
static unsigned
ack_duration(int hwrate)
{
	return (hwrate <= RTW_RATE_11M) ? 314 : 60;
}

static void
pn_inc(uint8_t pn[6])
{
	int i;

	for (i = 0; i < 6; i++) {
		if (++pn[i] != 0)
			break;
	}
}

static int
pn_greater(const uint8_t a[6], const uint8_t b[6])
{
	int i;

	for (i = 5; i >= 0; i--) {
		if (a[i] != b[i])
			return a[i] > b[i];
	}
	return 0;
}

static void
clear_keys(struct rtw_sta *sta)
{
	memset(&sta->ptk_key, 0, sizeof(sta->ptk_key));
	memset(sta->tk, 0, sizeof(sta->tk));
	memset(sta->tx_pn, 0, sizeof(sta->tx_pn));
	memset(sta->rx_pn, 0, sizeof(sta->rx_pn));
	memset(sta->gtk, 0, sizeof(sta->gtk));
	memset(sta->kck, 0, sizeof(sta->kck));
	memset(&sta->kek, 0, sizeof(sta->kek));
	memset(sta->pend_kck, 0, sizeof(sta->pend_kck));
	memset(sta->pend_kek, 0, sizeof(sta->pend_kek));
	memset(sta->pend_tk, 0, sizeof(sta->pend_tk));
	sta->ptk_valid = 0;
	sta->ptk_derived = 0;
	sta->have_snonce = 0;
	sta->replay_valid = 0;
	sta->last_seq_valid[0] = sta->last_seq_valid[1] = 0;
}

static uint16_t
next_seqctl(struct rtw_sta *sta)
{
	sta->seq = (uint16_t)((sta->seq + 1) & 0x0fff);
	return (uint16_t)(sta->seq << 4);
}

/* ------------------------------------------------------------------ */
/* Management frame transmission                                      */

static uint8_t *
mgmt_hdr(struct rtw_sta *sta, uint8_t subtype, const uint8_t *da,
    const uint8_t *bssid)
{
	uint8_t *f = sta->txbuf;
	unsigned dur = IS_GROUP(da) ? 0 : ack_duration(sta->mgmt_rate);

	f[0] = (uint8_t)(FC0_TYPE_MGMT | subtype);
	f[1] = 0;
	RTW_PUT_LE16(f + 2, dur);
	memcpy(f + 4, da, RTW_ETH_ALEN);
	memcpy(f + 10, sta->addr, RTW_ETH_ALEN);
	memcpy(f + 16, bssid, RTW_ETH_ALEN);
	RTW_PUT_LE16(f + 22, next_seqctl(sta));
	return f + HDR_LEN;
}

static uint8_t *
put_ssid_rates(uint8_t *p, const uint8_t *ssid, size_t ssid_len)
{
	/* 1, 2, 5.5, 11 flagged basic; then 6, 9, 12, 18 ... */
	static const uint8_t rates[] = {
		IE_RATES, 8, 0x82, 0x84, 0x8b, 0x96, 12, 18, 24, 36,
		IE_XRATES, 4, 48, 72, 96, 108
	};

	*p++ = IE_SSID;
	*p++ = (uint8_t)ssid_len;
	if (ssid_len) {
		memcpy(p, ssid, ssid_len);
		p += ssid_len;
	}
	memcpy(p, rates, sizeof(rates));
	return p + sizeof(rates);
}

static void
mgmt_send(struct rtw_sta *sta, const uint8_t *end)
{
	(void)sta->ops.tx(sta->ops.ctx, sta->txbuf,
	    (size_t)(end - sta->txbuf), sta->mgmt_rate);
}

static void
send_probe_req(struct rtw_sta *sta, const uint8_t *ssid, size_t ssid_len)
{
	uint8_t *p = mgmt_hdr(sta, FC0_PROBE_REQ, bcast, bcast);

	mgmt_send(sta, put_ssid_rates(p, ssid, ssid_len));
}

static void
send_auth(struct rtw_sta *sta)
{
	uint8_t *p = mgmt_hdr(sta, FC0_AUTH, sta->cur.bssid, sta->cur.bssid);

	RTW_PUT_LE16(p, 0);		/* open system */
	RTW_PUT_LE16(p + 2, 1);		/* transaction sequence */
	RTW_PUT_LE16(p + 4, 0);		/* status */
	mgmt_send(sta, p + 6);
}

static void
send_assoc_req(struct rtw_sta *sta)
{
	uint8_t *p = mgmt_hdr(sta, FC0_ASSOC_REQ, sta->cur.bssid,
	    sta->cur.bssid);
	uint16_t cap = CAP_ESS;

	if (sta->cfg.security != RTW_SEC_OPEN)
		cap |= CAP_PRIVACY;
	if (sta->short_slot)
		cap |= CAP_SHORT_SLOT;
	RTW_PUT_LE16(p, cap);
	RTW_PUT_LE16(p + 2, 10);	/* listen interval */
	p = put_ssid_rates(p + 4, sta->cur.ssid, sta->cur.ssid_len);
	if (sta->cfg.security == RTW_SEC_WPA2_PSK) {
		memcpy(p, our_rsn_ie, sizeof(our_rsn_ie));
		p += sizeof(our_rsn_ie);
	}
	mgmt_send(sta, p);
}

static void
send_deauth(struct rtw_sta *sta)
{
	uint8_t *p = mgmt_hdr(sta, FC0_DEAUTH, sta->cur.bssid, sta->cur.bssid);

	RTW_PUT_LE16(p, REASON_LEAVING);
	mgmt_send(sta, p + 2);
}

/* ------------------------------------------------------------------ */
/* State transitions                                                  */

static void
set_timer(struct rtw_sta *sta, unsigned ms)
{
	sta->ops.set_timer(sta->ops.ctx, ms);
}

/* Drop the association and return to IDLE.  The caller arms the rejoin
 * timer if it wants one. */
static void
disconnect(struct rtw_sta *sta, int deauth)
{
	if (deauth && sta->state >= RTW_S_ASSOC && sta->state != RTW_S_SCAN)
		send_deauth(sta);
	clear_keys(sta);
	if (sta->state >= RTW_S_AUTH)
		(void)sta->ops.set_bss(sta->ops.ctx, NULL, 0, 0);
	sta->state = RTW_S_IDLE;
	set_timer(sta, 0);
	if (sta->link_up) {
		sta->link_up = 0;
		sta->ops.link(sta->ops.ctx, 0);
	}
}

static void
join_fail(struct rtw_sta *sta, unsigned err, int deauth)
{
	sta->last_error = (uint8_t)err;
	disconnect(sta, deauth);
	if (sta->have_cfg)
		set_timer(sta, REJOIN_MS);
}

static void
enter_run(struct rtw_sta *sta)
{
	sta->state = RTW_S_RUN;
	sta->last_error = RTW_ERR_NONE;
	sta->last_beacon_ms = sta->ops.now_ms(sta->ops.ctx);
	sta->link_up = 1;
	sta->ops.link(sta->ops.ctx, 1);
	set_timer(sta, RUN_TICK_MS);
}

static void
start_auth(struct rtw_sta *sta, const struct rtw_bss *bss)
{
	sta->cur = *bss;
	clear_keys(sta);

	sta->rates = bss->rates;
	if (sta->rates == 0)
		sta->rates = RTW_RATES_CCK;
	sta->mgmt_rate = (uint8_t)lowest_rate(sta->rates);
	if (sta->fixed_rate != RTW_RATE_AUTO &&
	    (sta->rates & (1 << sta->fixed_rate))) {
		sta->txrate = sta->fixed_rate;
	} else if (sta->rates & RTW_RATES_CCK) {
		/* Start conservatively; the rate then follows whatever the
		 * access point uses towards us (see rx_data). */
		sta->txrate = (uint8_t)highest_rate(sta->rates & RTW_RATES_CCK);
	} else {
		sta->txrate = (uint8_t)lowest_rate(sta->rates);
	}
	sta->short_slot = (uint8_t)((bss->capinfo & CAP_SHORT_SLOT) &&
	    (bss->rates & RTW_RATES_OFDM));

	(void)sta->ops.set_channel(sta->ops.ctx, bss->chan);
	(void)sta->ops.set_bss(sta->ops.ctx, bss->bssid, 0, 0);
	sta->state = RTW_S_AUTH;
	sta->tries = 0;
	send_auth(sta);
	set_timer(sta, MGMT_TIMEOUT_MS);
}

static int
bss_matches(const struct rtw_sta *sta, const struct rtw_bss *b)
{
	const struct rtw_join *c = &sta->cfg;

	if (b->ssid_len != c->ssid_len ||
	    rtw_memcmp(b->ssid, c->ssid, c->ssid_len) != 0)
		return 0;
	if (c->have_bssid && !ADDR_EQ(b->bssid, c->bssid))
		return 0;
	return 1;
}

/* After a scan: pick the strongest access point for the configured
 * network and start joining it. */
static void
join_select(struct rtw_sta *sta)
{
	const struct rtw_bss *best = NULL;
	int seen = 0;
	unsigned i;

	sta->join_pending = 0;
	for (i = 0; i < sta->nbss; i++) {
		const struct rtw_bss *b = &sta->bss[i];

		if (!bss_matches(sta, b))
			continue;
		seen = 1;
		if (b->security != sta->cfg.security)
			continue;
		if (best == NULL || b->rssi > best->rssi)
			best = b;
	}
	if (best == NULL) {
		sta->last_error = (uint8_t)(seen ? RTW_ERR_SECURITY :
		    RTW_ERR_NOT_FOUND);
		set_timer(sta, REJOIN_MS);
		return;
	}
	start_auth(sta, best);
}

static void
scan_finish(struct rtw_sta *sta)
{
	sta->ops.scan_done(sta->ops.ctx);
	if (sta->scan_resume == RTW_S_RUN) {
		/* Back to the channel of the network we are still on. */
		(void)sta->ops.set_channel(sta->ops.ctx, sta->cur.chan);
		sta->state = RTW_S_RUN;
		sta->last_beacon_ms = sta->ops.now_ms(sta->ops.ctx);
		set_timer(sta, RUN_TICK_MS);
		return;
	}
	sta->state = RTW_S_IDLE;
	if (sta->join_pending)
		join_select(sta);
	else if (sta->have_cfg)
		set_timer(sta, REJOIN_MS);
}

static void
scan_next(struct rtw_sta *sta)
{
	sta->scan_chan++;
	if (sta->scan_chan > sta->max_chan) {
		scan_finish(sta);
		return;
	}
	(void)sta->ops.set_channel(sta->ops.ctx, sta->scan_chan);
	send_probe_req(sta, NULL, 0);
	/* A directed probe finds networks that hide their name. */
	if (sta->join_pending && sta->cfg.ssid_len)
		send_probe_req(sta, sta->cfg.ssid, sta->cfg.ssid_len);
	set_timer(sta, SCAN_DWELL_MS);
}

static void
scan_start(struct rtw_sta *sta)
{
	sta->scan_resume = (uint8_t)((sta->state == RTW_S_RUN) ? RTW_S_RUN :
	    RTW_S_IDLE);
	sta->state = RTW_S_SCAN;
	sta->nbss = 0;
	sta->scan_chan = 0;
	sta->mgmt_rate = (sta->scan_resume == RTW_S_RUN) ? sta->mgmt_rate :
	    RTW_RATE_1M;
	scan_next(sta);
}

/* ------------------------------------------------------------------ */
/* Public commands                                                    */

void
rtw_sta_init(struct rtw_sta *sta, const struct rtw_sta_ops *ops,
    const uint8_t addr[RTW_ETH_ALEN])
{
	memset(sta, 0, sizeof(*sta));
	sta->ops = *ops;
	memcpy(sta->addr, addr, RTW_ETH_ALEN);
	sta->state = RTW_S_DOWN;
	sta->max_chan = 13;
	sta->fixed_rate = RTW_RATE_AUTO;
	sta->mgmt_rate = RTW_RATE_1M;
	sta->txrate = RTW_RATE_1M;
}

void
rtw_sta_up(struct rtw_sta *sta)
{
	uint8_t r[6];

	if (sta->state != RTW_S_DOWN)
		return;
	sta->ops.random(sta->ops.ctx, r, sizeof(r));
	sta->seq = (uint16_t)(RTW_GET_LE16(r) & 0x0fff);
	sta->wep_iv = ((uint32_t)r[2] << 16) | ((uint32_t)r[3] << 8) | r[4];
	sta->state = RTW_S_IDLE;
	if (sta->have_cfg) {
		sta->join_pending = 1;
		scan_start(sta);
	}
}

void
rtw_sta_down(struct rtw_sta *sta)
{
	if (sta->state == RTW_S_DOWN)
		return;
	if (sta->state == RTW_S_SCAN && sta->scan_resume == RTW_S_RUN)
		sta->state = RTW_S_RUN;
	disconnect(sta, 1);
	sta->join_pending = 0;
	sta->state = RTW_S_DOWN;
}

int
rtw_sta_scan(struct rtw_sta *sta)
{
	if (sta->state != RTW_S_IDLE && sta->state != RTW_S_RUN)
		return -1;	/* down, or busy scanning/joining */
	sta->join_pending = 0;
	scan_start(sta);
	return 0;
}

int
rtw_sta_join(struct rtw_sta *sta, const struct rtw_join *cfg)
{
	if (cfg->ssid_len == 0 || cfg->ssid_len > RTW_SSID_MAX)
		return -1;
	if (cfg->security != RTW_SEC_OPEN && cfg->security != RTW_SEC_WEP &&
	    cfg->security != RTW_SEC_WPA2_PSK)
		return -1;
	if (cfg->security == RTW_SEC_WEP &&
	    ((cfg->wep_key_len != 5 && cfg->wep_key_len != 13) ||
	    cfg->wep_key_id > 3))
		return -1;

	sta->cfg = *cfg;
	sta->have_cfg = 1;
	sta->last_error = RTW_ERR_NONE;
	if (sta->state == RTW_S_DOWN)
		return 0;	/* joins when the interface comes up */
	if (sta->state == RTW_S_SCAN && sta->scan_resume == RTW_S_RUN)
		sta->state = RTW_S_RUN;
	disconnect(sta, 1);
	sta->join_pending = 1;
	scan_start(sta);
	return 0;
}

void
rtw_sta_leave(struct rtw_sta *sta)
{
	memset(&sta->cfg, 0, sizeof(sta->cfg));
	sta->have_cfg = 0;
	sta->join_pending = 0;
	sta->last_error = RTW_ERR_NONE;
	if (sta->state == RTW_S_DOWN)
		return;
	if (sta->state == RTW_S_SCAN) {
		/* Let the scan finish, but do not go back to the network. */
		if (sta->scan_resume == RTW_S_RUN) {
			sta->state = RTW_S_RUN;
			disconnect(sta, 0);
			sta->state = RTW_S_SCAN;
			sta->scan_resume = RTW_S_IDLE;
			set_timer(sta, SCAN_DWELL_MS);
		}
		return;
	}
	disconnect(sta, 1);
}

int
rtw_sta_set_rate(struct rtw_sta *sta, unsigned hwrate)
{
	if (hwrate != RTW_RATE_AUTO && hwrate >= RTW_RATE_COUNT)
		return -1;
	sta->fixed_rate = (uint8_t)hwrate;
	if (hwrate != RTW_RATE_AUTO && sta->state >= RTW_S_AUTH &&
	    (sta->rates & (1 << hwrate)))
		sta->txrate = (uint8_t)hwrate;
	return 0;
}

void
rtw_sta_timer(struct rtw_sta *sta)
{
	switch (sta->state) {
	case RTW_S_IDLE:
		if (sta->have_cfg) {
			sta->join_pending = 1;
			scan_start(sta);
		}
		break;
	case RTW_S_SCAN:
		scan_next(sta);
		break;
	case RTW_S_AUTH:
		if (++sta->tries >= MGMT_TRIES) {
			join_fail(sta, RTW_ERR_AUTH_TIMEOUT, 0);
		} else {
			send_auth(sta);
			set_timer(sta, MGMT_TIMEOUT_MS);
		}
		break;
	case RTW_S_ASSOC:
		if (++sta->tries >= MGMT_TRIES) {
			join_fail(sta, RTW_ERR_ASSOC_TIMEOUT, 1);
		} else {
			send_assoc_req(sta);
			set_timer(sta, MGMT_TIMEOUT_MS);
		}
		break;
	case RTW_S_HANDSHAKE:
		join_fail(sta, RTW_ERR_HANDSHAKE, 1);
		break;
	case RTW_S_RUN:
		if ((uint32_t)(sta->ops.now_ms(sta->ops.ctx) -
		    sta->last_beacon_ms) > BEACON_LOSS_MS) {
			sta->last_error = RTW_ERR_BEACON_LOSS;
			disconnect(sta, 0);
			set_timer(sta, REJOIN_FAST_MS);
		} else {
			set_timer(sta, RUN_TICK_MS);
		}
		break;
	default:
		break;
	}
}

/* ------------------------------------------------------------------ */
/* Data frame encapsulation                                           */

static int
ethertype_needs_tunnel(unsigned type)
{
	/* IEEE 802.1H: these two keep the bridge-tunnel encapsulation. */
	return type == ETHERTYPE_AARP || type == ETHERTYPE_IPX;
}

static void
tx_layout(const struct rtw_sta *sta, unsigned ethertype, unsigned *head,
    unsigned *tail)
{
	unsigned iv = 0, trailer = 0;

	if (sta->cfg.security == RTW_SEC_WEP) {
		iv = RTW_WEP_IV_LEN;
		trailer = RTW_WEP_ICV_LEN;
	} else if (sta->cfg.security == RTW_SEC_WPA2_PSK && sta->ptk_valid) {
		iv = CCMP_HDR_LEN;
		trailer = CCMP_MIC_LEN;
	}
	/* Below 0x600 the field is an 802.3 length and the payload already
	 * starts with an LLC header. */
	*head = HDR_LEN + iv + ((ethertype >= 0x600) ? LLC_LEN : 0);
	*tail = trailer;
}

static void
ccmp_aad_nonce(const uint8_t *hdr, const uint8_t pn[6], uint8_t *aad,
    size_t *aadlen, uint8_t nonce[RTW_CCM_NONCE_LEN])
{
	int qos = (hdr[0] & FC0_DATA_QOS_BIT) != 0;
	uint8_t prio = 0;
	int i;

	/* Fields that may change on retransmission are masked out. */
	aad[0] = (uint8_t)(hdr[0] & 0x8f);
	aad[1] = (uint8_t)((hdr[1] & 0xc7) | FC1_PROTECTED);
	memcpy(aad + 2, hdr + 4, 18);		/* the three addresses */
	aad[20] = (uint8_t)(hdr[22] & 0x0f);	/* fragment number */
	aad[21] = 0;
	*aadlen = 22;
	if (qos) {
		aad[1] &= (uint8_t)~FC1_ORDER;
		prio = (uint8_t)(hdr[24] & 0x0f);
		aad[22] = prio;
		aad[23] = 0;
		*aadlen = 24;
	}
	nonce[0] = prio;
	memcpy(nonce + 1, hdr + 10, RTW_ETH_ALEN);	/* transmitter */
	for (i = 0; i < 6; i++)
		nonce[7 + i] = pn[5 - i];
}

static size_t
tx_build(struct rtw_sta *sta, const uint8_t *eth, uint8_t *f,
    size_t payload_len)
{
	unsigned ethertype = RTW_GET_BE16(eth + 12);
	unsigned head, tail, plain;
	uint8_t *p;

	tx_layout(sta, ethertype, &head, &tail);

	f[0] = FC0_TYPE_DATA;
	f[1] = (uint8_t)(FC1_TODS | (tail ? FC1_PROTECTED : 0));
	RTW_PUT_LE16(f + 2, ack_duration(sta->txrate));
	memcpy(f + 4, sta->cur.bssid, RTW_ETH_ALEN);
	memcpy(f + 10, sta->addr, RTW_ETH_ALEN);
	memcpy(f + 16, eth, RTW_ETH_ALEN);	/* final destination */
	RTW_PUT_LE16(f + 22, next_seqctl(sta));

	p = f + head;
	plain = (unsigned)payload_len;
	if (ethertype >= 0x600) {
		p -= LLC_LEN;
		memcpy(p, ethertype_needs_tunnel(ethertype) ? llc_tunnel :
		    llc_rfc1042, 6);
		p[6] = eth[12];
		p[7] = eth[13];
		plain += LLC_LEN;
	}

	if (tail == CCMP_MIC_LEN) {
		uint8_t aad[24], nonce[RTW_CCM_NONCE_LEN];
		uint8_t *h = f + HDR_LEN;
		size_t aadlen;

		pn_inc(sta->tx_pn);
		h[0] = sta->tx_pn[0];
		h[1] = sta->tx_pn[1];
		h[2] = 0;
		h[3] = 0x20;		/* extended IV present, key id 0 */
		h[4] = sta->tx_pn[2];
		h[5] = sta->tx_pn[3];
		h[6] = sta->tx_pn[4];
		h[7] = sta->tx_pn[5];
		ccmp_aad_nonce(f, sta->tx_pn, aad, &aadlen, nonce);
		rtw_ccm_encrypt(&sta->ptk_key, nonce, aad, aadlen, p, plain,
		    p + plain);
	} else if (tail == RTW_WEP_ICV_LEN) {
		uint8_t *h = f + HDR_LEN;

		sta->wep_iv = (sta->wep_iv + 1) & 0x00ffffffU;
		h[0] = (uint8_t)(sta->wep_iv >> 16);
		h[1] = (uint8_t)(sta->wep_iv >> 8);
		h[2] = (uint8_t)sta->wep_iv;
		h[3] = (uint8_t)(sta->cfg.wep_key_id << 6);
		rtw_wep_encrypt(sta->cfg.wep_key, sta->cfg.wep_key_len, h,
		    plain);
	}
	return head + payload_len + tail;
}

int
rtw_sta_tx_prepare(struct rtw_sta *sta, const uint8_t *eth_hdr,
    unsigned *headroom, unsigned *tailroom)
{
	if (sta->state != RTW_S_RUN) {
		sta->stats.tx_dropped++;
		return -1;
	}
	tx_layout(sta, RTW_GET_BE16(eth_hdr + 12), headroom, tailroom);
	return 0;
}

size_t
rtw_sta_tx_finish(struct rtw_sta *sta, const uint8_t *eth_hdr, uint8_t *frame,
    size_t payload_len, int *hwrate)
{
	sta->stats.tx_data++;
	*hwrate = sta->txrate;
	return tx_build(sta, eth_hdr, frame, payload_len);
}

/* ------------------------------------------------------------------ */
/* WPA2 key handshake                                                 */

static void
eapol_mic(struct rtw_sta *sta, const uint8_t kck[16], const uint8_t *e,
    size_t len, uint8_t mic[16])
{
	uint8_t d[RTW_SHA1_LEN];

	rtw_hmac_sha1_init(&sta->hmac, kck, 16);
	rtw_hmac_sha1_update(&sta->hmac, e, len);
	rtw_hmac_sha1_final(&sta->hmac, d);
	memcpy(mic, d, 16);
}

/* Build and send an EAPOL-Key frame.  It goes out through the normal
 * data path, so it is encrypted once the pairwise key is installed. */
static void
wpa_send_key(struct rtw_sta *sta, uint8_t version, unsigned info,
    const uint8_t *replay, const uint8_t *nonce, const uint8_t *kd,
    size_t kdlen, const uint8_t kck[16])
{
	uint8_t *e = sta->txbuf + EAPOL_TXOFF;
	size_t len = EK_DATA + kdlen, n;
	unsigned head, tail;
	uint8_t eth[RTW_ETH_HLEN];

	memset(e, 0, EK_DATA);
	e[0] = version;
	e[EK_TYPE] = 3;
	RTW_PUT_BE16(e + EK_BODYLEN, len - 4);
	e[EK_DESC] = 2;
	RTW_PUT_BE16(e + EK_INFO, info);
	memcpy(e + EK_REPLAY, replay, 8);
	if (nonce != NULL)
		memcpy(e + EK_NONCE, nonce, 32);
	RTW_PUT_BE16(e + EK_DATALEN, kdlen);
	if (kdlen)
		memcpy(e + EK_DATA, kd, kdlen);
	eapol_mic(sta, kck, e, len, e + EK_MIC);

	memcpy(eth, sta->cur.bssid, RTW_ETH_ALEN);
	memcpy(eth + 6, sta->addr, RTW_ETH_ALEN);
	RTW_PUT_BE16(eth + 12, ETHERTYPE_EAPOL);
	tx_layout(sta, ETHERTYPE_EAPOL, &head, &tail);
	n = tx_build(sta, eth, e - head, len);
	(void)sta->ops.tx(sta->ops.ctx, e - head, n, sta->mgmt_rate);
}

static int
wpa_check_mic(struct rtw_sta *sta, const uint8_t kck[16], uint8_t *e,
    size_t len)
{
	uint8_t theirs[16], ours[16];

	memcpy(theirs, e + EK_MIC, 16);
	memset(e + EK_MIC, 0, 16);
	eapol_mic(sta, kck, e, len, ours);
	return rtw_memeq_ct(theirs, ours, 16);
}

/* Decrypt the key data of message 3 or a group message into
 * sta->keydata and return the group key it carries. */
static const uint8_t *
wpa_unwrap_gtk(struct rtw_sta *sta, const uint8_t *e, unsigned info,
    size_t kdlen, unsigned *keyid)
{
	const uint8_t *p, *end;

	if (!(info & EK_INFO_ENCRYPTED) || kdlen < 16 ||
	    kdlen - 8 > sizeof(sta->keydata))
		return NULL;
	if (rtw_aes_unwrap(&sta->kek, e + EK_DATA, kdlen, sta->keydata) != 0)
		return NULL;
	p = sta->keydata;
	end = p + kdlen - 8;
	while (end - p >= 2) {
		size_t l = p[1];

		if (p[0] == IE_VENDOR && l == 0)
			break;		/* padding */
		if ((size_t)(end - p) < 2 + l)
			break;
		/* GTK KDE: OUI/type, key id, reserved, 16 byte CCMP key. */
		if (p[0] == IE_VENDOR && l == 4 + 2 + 16 &&
		    rtw_memcmp(p + 2, kde_gtk, 4) == 0) {
			*keyid = p[6] & 0x03;
			return p + 8;
		}
		p += 2 + l;
	}
	return NULL;
}

static void
install_gtk(struct rtw_sta *sta, unsigned keyid, const uint8_t *key,
    const uint8_t *rsc)
{
	struct rtw_gtk *g = &sta->gtk[keyid & 3];

	/* Never reset the replay counter of a key already in use. */
	if (g->valid && rtw_memcmp(g->raw, key, 16) == 0)
		return;
	memcpy(g->raw, key, 16);
	rtw_aes_set_key(&g->key, key);
	memcpy(g->rx_pn, rsc, 6);
	g->valid = 1;
}

static void
wpa_msg1(struct rtw_sta *sta, const uint8_t *e)
{
	uint8_t data[2 * RTW_ETH_ALEN + 64], ptk[48];
	const uint8_t *aa = sta->cur.bssid, *spa = sta->addr;
	const uint8_t *an = e + EK_NONCE, *sn;

	if (!sta->have_snonce || rtw_memcmp(sta->anonce, an, 32) != 0) {
		sta->ops.random(sta->ops.ctx, sta->snonce, 32);
		sta->have_snonce = 1;
	}
	memcpy(sta->anonce, an, 32);
	sn = sta->snonce;

	/* PTK = PRF-384(PMK, "Pairwise key expansion",
	 *     min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(...)) */
	if (rtw_memcmp(aa, spa, RTW_ETH_ALEN) < 0) {
		memcpy(data, aa, 6);
		memcpy(data + 6, spa, 6);
	} else {
		memcpy(data, spa, 6);
		memcpy(data + 6, aa, 6);
	}
	if (rtw_memcmp(an, sn, 32) < 0) {
		memcpy(data + 12, an, 32);
		memcpy(data + 44, sn, 32);
	} else {
		memcpy(data + 12, sn, 32);
		memcpy(data + 44, an, 32);
	}
	rtw_prf_sha1(&sta->hmac, sta->cfg.pmk, RTW_PMK_LEN,
	    "Pairwise key expansion", data, sizeof(data), ptk, sizeof(ptk));
	memcpy(sta->pend_kck, ptk, 16);
	memcpy(sta->pend_kek, ptk + 16, 16);
	memcpy(sta->pend_tk, ptk + 32, 16);
	memset(ptk, 0, sizeof(ptk));
	sta->ptk_derived = 1;

	wpa_send_key(sta, e[0], EK_INFO_VER_AES | EK_INFO_PAIRWISE |
	    EK_INFO_MIC, e + EK_REPLAY, sta->snonce, our_rsn_ie,
	    sizeof(our_rsn_ie), sta->pend_kck);
}

static void
wpa_msg3(struct rtw_sta *sta, uint8_t *e, size_t len, unsigned info,
    size_t kdlen)
{
	const uint8_t *gtk;
	unsigned keyid = 0;

	if (!sta->ptk_derived ||
	    rtw_memcmp(e + EK_NONCE, sta->anonce, 32) != 0)
		return;
	if (!wpa_check_mic(sta, sta->pend_kck, e, len)) {
		sta->stats.rx_decrypt_fail++;
		return;
	}
	memcpy(sta->replay, e + EK_REPLAY, 8);
	sta->replay_valid = 1;

	/* The MIC proves the access point holds the same PMK, so the
	 * derived keys are now confirmed. */
	memcpy(sta->kck, sta->pend_kck, 16);
	rtw_aes_set_key(&sta->kek, sta->pend_kek);
	gtk = wpa_unwrap_gtk(sta, e, info, kdlen, &keyid);
	if (gtk == NULL) {
		if (sta->state == RTW_S_HANDSHAKE)
			join_fail(sta, RTW_ERR_HANDSHAKE, 1);
		return;
	}

	/* Message 4 must go out in the clear (or under the old key when
	 * rekeying), so send it before installing the new key. */
	wpa_send_key(sta, e[0], EK_INFO_VER_AES | EK_INFO_PAIRWISE |
	    EK_INFO_MIC | (info & EK_INFO_SECURE), e + EK_REPLAY, NULL, NULL,
	    0, sta->kck);

	/* A retransmitted message 3 must not reset the packet numbers of
	 * a key that is already in use (key reinstallation attack). */
	if (!sta->ptk_valid || rtw_memcmp(sta->tk, sta->pend_tk, 16) != 0) {
		memcpy(sta->tk, sta->pend_tk, 16);
		rtw_aes_set_key(&sta->ptk_key, sta->tk);
		memset(sta->tx_pn, 0, sizeof(sta->tx_pn));
		memset(sta->rx_pn, 0, sizeof(sta->rx_pn));
		sta->ptk_valid = 1;
	}
	install_gtk(sta, keyid, gtk, e + EK_RSC);

	if (sta->state == RTW_S_HANDSHAKE)
		enter_run(sta);
}

static void
wpa_group_msg1(struct rtw_sta *sta, uint8_t *e, size_t len, unsigned info,
    size_t kdlen)
{
	const uint8_t *gtk;
	unsigned keyid = 0;

	if (!sta->ptk_valid)
		return;
	if (!wpa_check_mic(sta, sta->kck, e, len)) {
		sta->stats.rx_decrypt_fail++;
		return;
	}
	memcpy(sta->replay, e + EK_REPLAY, 8);
	sta->replay_valid = 1;
	gtk = wpa_unwrap_gtk(sta, e, info, kdlen, &keyid);
	if (gtk == NULL)
		return;
	install_gtk(sta, keyid, gtk, e + EK_RSC);
	wpa_send_key(sta, e[0], EK_INFO_VER_AES | EK_INFO_MIC |
	    (info & EK_INFO_SECURE), e + EK_REPLAY, NULL, NULL, 0, sta->kck);
}

static void
rx_eapol(struct rtw_sta *sta, uint8_t *e, size_t len)
{
	unsigned info;
	size_t body, kdlen;

	if (sta->cfg.security != RTW_SEC_WPA2_PSK || len < EK_DATA ||
	    e[EK_TYPE] != 3 || e[EK_DESC] != 2)
		return;
	body = RTW_GET_BE16(e + EK_BODYLEN);
	if (body + 4 > len || body + 4 < EK_DATA)
		return;
	len = body + 4;			/* ignore any padding */
	info = RTW_GET_BE16(e + EK_INFO);
	kdlen = RTW_GET_BE16(e + EK_DATALEN);
	if ((info & EK_INFO_VER_MASK) != EK_INFO_VER_AES ||
	    EK_DATA + kdlen > len)
		return;
	if (sta->replay_valid &&
	    rtw_memcmp(e + EK_REPLAY, sta->replay, 8) <= 0)
		return;

	if (info & EK_INFO_PAIRWISE) {
		if (!(info & EK_INFO_ACK))
			return;
		if (info & EK_INFO_MIC)
			wpa_msg3(sta, e, len, info, kdlen);
		else
			wpa_msg1(sta, e);
	} else if ((info & (EK_INFO_MIC | EK_INFO_ACK)) ==
	    (EK_INFO_MIC | EK_INFO_ACK)) {
		wpa_group_msg1(sta, e, len, info, kdlen);
	}
}

/* ------------------------------------------------------------------ */
/* Receive path                                                       */

/* Is the RSN element one we can work with: CCMP for both group and
 * pairwise traffic, pre-shared key, management frame protection not
 * mandatory? */
static int
rsn_usable(const uint8_t *p, size_t len)
{
	size_t n, i;
	int ok;

	if (len < 2 + 4 + 2 || RTW_GET_LE16(p) != 1)
		return 0;
	if (rtw_memcmp(p + 2, suite_ccmp, 4) != 0)
		return 0;
	p += 6; len -= 6;

	n = RTW_GET_LE16(p);
	p += 2; len -= 2;
	if (len < n * 4 + 2)
		return 0;
	for (ok = 0, i = 0; i < n; i++)
		ok |= (rtw_memcmp(p + 4 * i, suite_ccmp, 4) == 0);
	if (!ok)
		return 0;
	p += n * 4; len -= n * 4;

	n = RTW_GET_LE16(p);
	p += 2; len -= 2;
	if (len < n * 4)
		return 0;
	for (ok = 0, i = 0; i < n; i++)
		ok |= (rtw_memcmp(p + 4 * i, suite_psk, 4) == 0);
	if (!ok)
		return 0;
	p += n * 4; len -= n * 4;

	if (len >= 2 && (RTW_GET_LE16(p) & 0x0040))
		return 0;	/* management frame protection required */
	return 1;
}

static void
rx_beacon(struct rtw_sta *sta, const uint8_t *f, size_t len, int rssi)
{
	const uint8_t *bssid = f + 16, *p, *end, *ssid = NULL;
	struct rtw_bss *b = NULL;
	size_t ssid_len = 0;
	uint16_t cap, rates = 0;
	int chan = sta->scan_chan, have_rsn = 0, rsn_ok = 0, have_wpa1 = 0;
	unsigned i;

	if (len < HDR_LEN + 12)
		return;
	if (sta->state >= RTW_S_AUTH && ADDR_EQ(bssid, sta->cur.bssid))
		sta->last_beacon_ms = sta->ops.now_ms(sta->ops.ctx);
	if (sta->state != RTW_S_SCAN)
		return;

	cap = RTW_GET_LE16(f + HDR_LEN + 10);
	if (!(cap & CAP_ESS) || (cap & CAP_IBSS))
		return;		/* infrastructure networks only */

	p = f + HDR_LEN + 12;
	end = f + len;
	while (end - p >= 2) {
		size_t l = p[1];
		const uint8_t *d = p + 2;

		if ((size_t)(end - d) < l)
			break;
		switch (p[0]) {
		case IE_SSID:
			if (l <= RTW_SSID_MAX) {
				ssid = d;
				ssid_len = l;
			}
			break;
		case IE_RATES:
		case IE_XRATES:
			for (i = 0; i < l; i++) {
				int r = rtw_rate_from_500k(d[i] & 0x7f);

				if (r >= 0)
					rates |= (uint16_t)(1 << r);
			}
			break;
		case IE_DS:
			if (l >= 1)
				chan = d[0];
			break;
		case IE_RSN:
			have_rsn = 1;
			rsn_ok = rsn_usable(d, l);
			break;
		case IE_VENDOR:
			if (l >= 4 && rtw_memcmp(d, oui_wpa1, 4) == 0)
				have_wpa1 = 1;
			break;
		default:
			break;
		}
		p = d + l;
	}
	if (chan < 1 || chan > 14)
		return;

	for (i = 0; i < sta->nbss; i++) {
		if (ADDR_EQ(sta->bss[i].bssid, bssid)) {
			b = &sta->bss[i];
			break;
		}
	}
	if (b == NULL) {
		if (sta->nbss >= RTW_MAX_BSS)
			return;
		b = &sta->bss[sta->nbss++];
		memset(b, 0, sizeof(*b));
		memcpy(b->bssid, bssid, RTW_ETH_ALEN);
	}
	/* Hidden networks beacon an empty or all-zero name; keep a name
	 * learned from a probe response. */
	if (ssid != NULL && ssid_len > 0) {
		for (i = 0; i < ssid_len && ssid[i] == 0; i++)
			;
		if (i < ssid_len) {
			memcpy(b->ssid, ssid, ssid_len);
			b->ssid_len = (uint8_t)ssid_len;
		}
	}
	b->chan = (uint8_t)chan;
	b->rssi = (uint8_t)((rssi < 0) ? 0 : (rssi > 100) ? 100 : rssi);
	b->capinfo = cap;
	b->beacon_int = RTW_GET_LE16(f + HDR_LEN + 8);
	b->rates = rates;
	if (!(cap & CAP_PRIVACY))
		b->security = RTW_SEC_OPEN;
	else if (have_rsn)
		b->security = (uint8_t)(rsn_ok ? RTW_SEC_WPA2_PSK :
		    RTW_SEC_UNSUPPORTED);
	else if (have_wpa1)
		b->security = RTW_SEC_UNSUPPORTED;
	else
		b->security = RTW_SEC_WEP;
}

static void
rx_mgmt(struct rtw_sta *sta, const uint8_t *f, size_t len, int rssi)
{
	unsigned subtype = f[0] & FC0_SUBTYPE_MASK;
	const uint8_t *body = f + HDR_LEN;
	size_t blen;

	if (len < HDR_LEN)
		return;
	blen = len - HDR_LEN;
	sta->stats.rx_mgmt++;

	if (subtype == FC0_BEACON || subtype == FC0_PROBE_RESP) {
		rx_beacon(sta, f, len, rssi);
		return;
	}
	/* Everything else must come from the access point we are joining
	 * or joined. */
	if (sta->state < RTW_S_AUTH || !ADDR_EQ(f + 10, sta->cur.bssid) ||
	    !ADDR_EQ(f + 16, sta->cur.bssid))
		return;

	switch (subtype) {
	case FC0_AUTH:
		if (sta->state != RTW_S_AUTH || blen < 6 ||
		    !ADDR_EQ(f + 4, sta->addr) || RTW_GET_LE16(body + 2) != 2)
			break;
		if (RTW_GET_LE16(body) != 0 || RTW_GET_LE16(body + 4) != 0) {
			join_fail(sta, RTW_ERR_AUTH_REJECTED, 0);
			break;
		}
		sta->state = RTW_S_ASSOC;
		sta->tries = 0;
		send_assoc_req(sta);
		set_timer(sta, MGMT_TIMEOUT_MS);
		break;
	case FC0_ASSOC_RESP:
		if (sta->state != RTW_S_ASSOC || blen < 6 ||
		    !ADDR_EQ(f + 4, sta->addr))
			break;
		if (RTW_GET_LE16(body + 2) != 0) {
			join_fail(sta, RTW_ERR_ASSOC_REJECTED, 1);
			break;
		}
		sta->aid = (uint16_t)(RTW_GET_LE16(body + 4) & 0x3fff);
		(void)sta->ops.set_bss(sta->ops.ctx, sta->cur.bssid, 1,
		    sta->short_slot);
		if (sta->cfg.security == RTW_SEC_WPA2_PSK) {
			sta->state = RTW_S_HANDSHAKE;
			sta->last_beacon_ms = sta->ops.now_ms(sta->ops.ctx);
			set_timer(sta, HANDSHAKE_TIMEOUT_MS);
		} else {
			enter_run(sta);
		}
		break;
	case FC0_DEAUTH:
	case FC0_DISASSOC:
		if (!ADDR_EQ(f + 4, sta->addr) && !IS_GROUP(f + 4))
			break;
		/* Being thrown out in the middle of the key handshake is
		 * what a wrong password looks like. */
		sta->last_error = (uint8_t)((sta->state == RTW_S_HANDSHAKE) ?
		    RTW_ERR_HANDSHAKE : RTW_ERR_DEAUTH);
		disconnect(sta, 0);
		if (sta->have_cfg)
			set_timer(sta, (sta->last_error == RTW_ERR_HANDSHAKE) ?
			    REJOIN_MS : REJOIN_FAST_MS);
		break;
	default:
		break;
	}
}

static void
rx_data(struct rtw_sta *sta, uint8_t *f, size_t len, int hwrate)
{
	uint8_t da[RTW_ETH_ALEN], sa[RTW_ETH_ALEN];
	unsigned hdrlen = HDR_LEN, ethertype, seqctl;
	int group, is_eapol = 0;
	uint8_t *p;
	size_t plen;

	if (sta->state != RTW_S_RUN && sta->state != RTW_S_HANDSHAKE)
		return;
	if (f[0] & FC0_DATA_NULL_BIT)
		return;
	if (f[0] & FC0_DATA_QOS_BIT) {
		hdrlen += 2;
		if (f[1] & FC1_ORDER)
			hdrlen += 4;	/* HT control */
	}
	/* From the distribution system to us: A1 = destination,
	 * A2 = BSSID, A3 = original source. */
	if (len < hdrlen || (f[1] & (FC1_TODS | FC1_FROMDS)) != FC1_FROMDS ||
	    !ADDR_EQ(f + 10, sta->cur.bssid))
		goto drop;
	memcpy(da, f + 4, RTW_ETH_ALEN);
	memcpy(sa, f + 16, RTW_ETH_ALEN);
	group = IS_GROUP(da);
	if (!group && !ADDR_EQ(da, sta->addr))
		goto drop;
	if (ADDR_EQ(sa, sta->addr))
		goto drop;	/* our own broadcast, echoed by the AP */

	seqctl = RTW_GET_LE16(f + 22);
	if ((f[1] & FC1_MORE_FRAG) || (seqctl & 0x000f)) {
		sta->stats.rx_frag++;
		return;
	}
	if ((f[1] & FC1_RETRY) && sta->last_seq_valid[group] &&
	    sta->last_seq[group] == seqctl) {
		sta->stats.rx_dup++;
		return;
	}
	sta->last_seq[group] = (uint16_t)seqctl;
	sta->last_seq_valid[group] = 1;

	p = f + hdrlen;
	plen = len - hdrlen;
	if (f[1] & FC1_PROTECTED) {
		if (sta->cfg.security == RTW_SEC_WEP) {
			if (plen < RTW_WEP_IV_LEN + RTW_WEP_ICV_LEN ||
			    rtw_wep_decrypt(sta->cfg.wep_key,
			    sta->cfg.wep_key_len, p, plen - RTW_WEP_IV_LEN)
			    != 0)
				goto undecryptable;
			p += RTW_WEP_IV_LEN;
			plen -= RTW_WEP_IV_LEN + RTW_WEP_ICV_LEN;
		} else if (sta->cfg.security == RTW_SEC_WPA2_PSK) {
			uint8_t aad[24], nonce[RTW_CCM_NONCE_LEN], pn[6];
			const struct rtw_aes_key *key;
			uint8_t *last_pn;
			size_t aadlen;

			if (plen < CCMP_HDR_LEN + CCMP_MIC_LEN ||
			    !(p[3] & 0x20))
				goto undecryptable;
			if (group) {
				struct rtw_gtk *g = &sta->gtk[p[3] >> 6];

				if (!g->valid)
					goto undecryptable;
				key = &g->key;
				last_pn = g->rx_pn;
			} else {
				if (!sta->ptk_valid || (p[3] >> 6) != 0)
					goto undecryptable;
				key = &sta->ptk_key;
				last_pn = sta->rx_pn;
			}
			pn[0] = p[0]; pn[1] = p[1]; pn[2] = p[4];
			pn[3] = p[5]; pn[4] = p[6]; pn[5] = p[7];
			if (!pn_greater(pn, last_pn)) {
				sta->stats.rx_replay++;
				return;
			}
			p += CCMP_HDR_LEN;
			plen -= CCMP_HDR_LEN + CCMP_MIC_LEN;
			ccmp_aad_nonce(f, pn, aad, &aadlen, nonce);
			if (rtw_ccm_decrypt(key, nonce, aad, aadlen, p, plen,
			    p + plen) != 0)
				goto undecryptable;
			memcpy(last_pn, pn, 6);
		} else {
			goto drop;
		}
	} else if (sta->cfg.security != RTW_SEC_OPEN) {
		/* On a secured network the only cleartext frames allowed
		 * are the handshake messages before the key exists. */
		if (sta->cfg.security != RTW_SEC_WPA2_PSK || sta->ptk_valid ||
		    group)
			goto drop;
		is_eapol = 1;	/* must turn out to be EAPOL, checked below */
	}

	/* Convert the LLC/SNAP encapsulation back to an Ethernet header,
	 * written in place just in front of the payload. */
	if (plen >= LLC_LEN && (rtw_memcmp(p, llc_tunnel, 6) == 0 ||
	    (rtw_memcmp(p, llc_rfc1042, 6) == 0 &&
	    !ethertype_needs_tunnel(RTW_GET_BE16(p + 6))))) {
		ethertype = RTW_GET_BE16(p + 6);
		p += LLC_LEN;
		plen -= LLC_LEN;
	} else {
		if (plen > 1500)
			goto drop;
		ethertype = (unsigned)plen;	/* 802.3 length */
	}

	if (ethertype == ETHERTYPE_EAPOL) {
		if (!group)
			rx_eapol(sta, p, plen);
		return;
	}
	if (is_eapol || sta->state != RTW_S_RUN)
		goto drop;

	if (!group && sta->fixed_rate == RTW_RATE_AUTO && hwrate >= 0 &&
	    hwrate < RTW_RATE_COUNT && (sta->rates & (1 << hwrate)))
		sta->txrate = (uint8_t)hwrate;

	p -= RTW_ETH_HLEN;
	memcpy(p, da, RTW_ETH_ALEN);
	memcpy(p + 6, sa, RTW_ETH_ALEN);
	RTW_PUT_BE16(p + 12, ethertype);
	sta->stats.rx_data++;
	sta->ops.rx_deliver(sta->ops.ctx, p, plen + RTW_ETH_HLEN);
	return;

undecryptable:
	sta->stats.rx_decrypt_fail++;
	return;
drop:
	sta->stats.rx_dropped++;
}

void
rtw_sta_rx(struct rtw_sta *sta, uint8_t *frame, size_t len, int rssi,
    int hwrate)
{
	if (sta->state == RTW_S_DOWN || len < 10 || len > RTW_MAX_FRAME ||
	    (frame[0] & 0x03) != 0)
		return;
	switch (frame[0] & FC0_TYPE_MASK) {
	case FC0_TYPE_MGMT:
		rx_mgmt(sta, frame, len, rssi);
		break;
	case FC0_TYPE_DATA:
		rx_data(sta, frame, len, hwrate);
		break;
	default:
		break;
	}
}
