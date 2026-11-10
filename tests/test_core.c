/*
 * Host-side tests for the driver core.
 *
 * The expected values in vectors.h come from tests/gen_vectors.py, an
 * independent model built on Python's hashlib and the `cryptography`
 * package, so agreement here means two separate implementations of the
 * 802.11/WPA2 formats and algorithms produce identical bytes.
 *
 * Build and run with `make test` (and `make test-ppc` to repeat the run
 * on an emulated big-endian PowerPC).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/rtw_sta.h"
#include "../src/core/rtw_wep.h"
#include "../src/core/rtl8187.h"
#include "vectors.h"

static int failures, checks;

#define CHECK(cond) do { \
	checks++; \
	if (!(cond)) { \
		failures++; \
		printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
	} \
} while (0)

static void
check_bytes(const char *what, int line, const uint8_t *got, size_t gotlen,
    const uint8_t *want, size_t wantlen, int skip_seq)
{
	size_t i;

	checks++;
	if (gotlen != wantlen) {
		failures++;
		printf("FAIL line %d: %s: length %lu, expected %lu\n", line,
		    what, (unsigned long)gotlen, (unsigned long)wantlen);
		return;
	}
	for (i = 0; i < gotlen; i++) {
		if (skip_seq && (i == 22 || i == 23))
			continue;	/* 802.11 sequence control */
		if (got[i] != want[i]) {
			failures++;
			printf("FAIL line %d: %s: byte %lu is %02x, "
			    "expected %02x\n", line, what, (unsigned long)i,
			    got[i], want[i]);
			return;
		}
	}
}
#define CHECK_BYTES(got, gotlen, want) \
	check_bytes(#want, __LINE__, got, gotlen, want, want##_len, 0)
#define CHECK_FRAME(got, gotlen, want) \
	check_bytes(#want, __LINE__, got, gotlen, want, want##_len, 1)

/* ------------------------------------------------------------------ */
/* Primitives                                                         */

static void
test_primitives(void)
{
	static const uint8_t key[16] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	};
	struct rtw_sha1 sha;
	struct rtw_hmac_sha1 hm;
	struct rtw_aes_key ak;
	uint8_t d[64], buf[1600], mic[8];
	size_t i;

	/* SHA-1, fed in awkward pieces to exercise the buffering. */
	rtw_sha1_init(&sha);
	for (i = 0; i < v_hmac_msg_len; i += 7)
		rtw_sha1_update(&sha, v_hmac_msg + i,
		    (v_hmac_msg_len - i < 7) ? v_hmac_msg_len - i : 7);
	rtw_sha1_final(&sha, d);
	CHECK_BYTES(d, 20, v_sha1_out);

	/* HMAC with a key longer than the block size. */
	rtw_hmac_sha1_init(&hm, v_hmac_key, v_hmac_key_len);
	rtw_hmac_sha1_update(&hm, v_hmac_msg, v_hmac_msg_len);
	rtw_hmac_sha1_final(&hm, d);
	CHECK_BYTES(d, 20, v_hmac_out);

	/* The well known WPA test vector: "password" / "IEEE". */
	rtw_wpa_passphrase_to_pmk("password", (const uint8_t *)"IEEE", 4, d);
	CHECK_BYTES(d, 32, v_pbkdf2_psk);

	rtw_prf_sha1(&hm, key, 16, "Pairwise key expansion", v_prf_data,
	    v_prf_data_len, d, 48);
	CHECK_BYTES(d, 48, v_prf_out);

	rtw_aes_set_key(&ak, key);
	rtw_aes_encrypt(&ak, v_aes_pt, d);
	CHECK_BYTES(d, 16, v_aes_ct);		/* FIPS 197 appendix C.1 */
	rtw_aes_decrypt(&ak, v_aes_ct, d);
	CHECK_BYTES(d, 16, v_aes_pt);

#define UNWRAP(n) do { \
	CHECK(rtw_aes_unwrap(&ak, v_wrap##n##_ct, v_wrap##n##_ct_len, buf) \
	    == 0); \
	CHECK_BYTES(buf, n, v_wrap##n##_pt); \
	memcpy(buf + 100, v_wrap##n##_ct, v_wrap##n##_ct_len); \
	buf[100 + 9] ^= 0x10; \
	CHECK(rtw_aes_unwrap(&ak, buf + 100, v_wrap##n##_ct_len, buf) != 0); \
} while (0)
	UNWRAP(16);
	UNWRAP(24);
	UNWRAP(40);
	CHECK(rtw_aes_unwrap(&ak, v_wrap16_ct, 8, buf) != 0);
	CHECK(rtw_aes_unwrap(&ak, v_wrap16_ct, 23, buf) != 0);

#define CCM(n) do { \
	size_t plen = v_ccm##n##_pt_len; \
	memcpy(buf, v_ccm##n##_pt, plen); \
	rtw_ccm_encrypt(&ak, v_ccm_nonce, v_ccm##n##_aad, \
	    v_ccm##n##_aad_len, buf, plen, mic); \
	memcpy(buf + plen, mic, 8); \
	CHECK_BYTES(buf, plen + 8, v_ccm##n##_ct); \
	CHECK(rtw_ccm_decrypt(&ak, v_ccm_nonce, v_ccm##n##_aad, \
	    v_ccm##n##_aad_len, buf, plen, mic) == 0); \
	CHECK_BYTES(buf, plen, v_ccm##n##_pt); \
	memcpy(buf, v_ccm##n##_ct, plen + 8); \
	buf[plen + 3] ^= 0x80; \
	CHECK(rtw_ccm_decrypt(&ak, v_ccm_nonce, v_ccm##n##_aad, \
	    v_ccm##n##_aad_len, buf, plen, buf + plen) != 0); \
} while (0)
	CCM(0); CCM(1); CCM(2); CCM(3); CCM(4); CCM(5); CCM(6); CCM(7);

	CHECK(rtw_crc32((const uint8_t *)"123456789", 9) == 0xcbf43926U);
}

/* ------------------------------------------------------------------ */
/* A fake platform under the station logic                             */

#define MAX_TX 64

struct env {
	struct rtw_sta sta;
	uint32_t now;
	unsigned timer_ms;		/* 0 = not armed */
	unsigned rng_pos;
	int chan;
	uint8_t bssid[6];
	int have_bssid, linked, short_slot;
	int link, link_events, scans_done;
	unsigned ntx;
	struct { uint8_t f[600]; size_t len; int rate; } tx[MAX_TX];
	uint8_t rx_eth[2400];
	size_t rx_eth_len;
	unsigned rx_count;
	uint8_t work[2500];
};

static int
env_set_channel(void *ctx, int chan)
{
	((struct env *)ctx)->chan = chan;
	return 0;
}

static int
env_set_bss(void *ctx, const uint8_t *bssid, int linked, int short_slot)
{
	struct env *e = (struct env *)ctx;

	e->have_bssid = (bssid != NULL);
	if (bssid != NULL)
		memcpy(e->bssid, bssid, 6);
	e->linked = linked;
	e->short_slot = short_slot;
	return 0;
}

static int
env_tx(void *ctx, const uint8_t *frame, size_t len, int rate)
{
	struct env *e = (struct env *)ctx;

	if (e->ntx < MAX_TX && len <= sizeof(e->tx[0].f)) {
		memcpy(e->tx[e->ntx].f, frame, len);
		e->tx[e->ntx].len = len;
		e->tx[e->ntx].rate = rate;
	}
	e->ntx++;
	return 0;
}

static void
env_rx_deliver(void *ctx, const uint8_t *eth, size_t len)
{
	struct env *e = (struct env *)ctx;

	memcpy(e->rx_eth, eth, len);
	e->rx_eth_len = len;
	e->rx_count++;
}

static void
env_link(void *ctx, int up)
{
	struct env *e = (struct env *)ctx;

	e->link = up;
	e->link_events++;
}

static void
env_scan_done(void *ctx)
{
	((struct env *)ctx)->scans_done++;
}

static void
env_set_timer(void *ctx, unsigned ms)
{
	((struct env *)ctx)->timer_ms = ms;
}

/* Must match class Rng in gen_vectors.py. */
static void
env_random(void *ctx, uint8_t *buf, size_t len)
{
	struct env *e = (struct env *)ctx;
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] = (uint8_t)((e->rng_pos++ * 7 + 13) & 0xff);
}

static uint32_t
env_now(void *ctx)
{
	return ((struct env *)ctx)->now;
}

static void
env_init(struct env *e)
{
	struct rtw_sta_ops ops;

	memset(e, 0, sizeof(*e));
	ops.ctx = e;
	ops.set_channel = env_set_channel;
	ops.set_bss = env_set_bss;
	ops.tx = env_tx;
	ops.rx_deliver = env_rx_deliver;
	ops.link = env_link;
	ops.scan_done = env_scan_done;
	ops.set_timer = env_set_timer;
	ops.random = env_random;
	ops.now_ms = env_now;
	rtw_sta_init(&e->sta, &ops, w_sta);
	e->now = 1000;
}

/* Let the armed timer expire. */
static void
env_fire(struct env *e)
{
	unsigned ms = e->timer_ms;

	if (ms == 0)
		return;
	e->timer_ms = 0;
	e->now += ms;
	rtw_sta_timer(&e->sta);
}

/* Deliver a frame as the radio would (the core modifies it in place). */
static void
env_rx(struct env *e, const uint8_t *f, size_t len, int rate)
{
	memcpy(e->work, f, len);
	rtw_sta_rx(&e->sta, e->work, len, 60, rate);
}
#define RX(e, name)		env_rx(e, name, name##_len, RTW_RATE_1M)
#define RX_RATE(e, name, r)	env_rx(e, name, name##_len, r)

/* Send an Ethernet frame the way the kernel extension does. */
static size_t
env_send_eth(struct env *e, const uint8_t *eth, size_t len, uint8_t *out,
    int *rate)
{
	unsigned head, tail;

	if (rtw_sta_tx_prepare(&e->sta, eth, &head, &tail) != 0)
		return 0;
	CHECK(head <= RTW_TX_HEADROOM_MAX && tail <= RTW_TX_TAILROOM_MAX);
	memset(out, 0xee, 2400);
	memcpy(out + head, eth + RTW_ETH_HLEN, len - RTW_ETH_HLEN);
	return rtw_sta_tx_finish(&e->sta, eth, out, len - RTW_ETH_HLEN, rate);
}

/* Run a scan to completion, injecting `beacons` while on W_CHAN. */
static void
env_run_scan(struct env *e, void (*beacons)(struct env *))
{
	int guard = 0;

	while (e->sta.state == RTW_S_SCAN && guard++ < 40) {
		if (e->chan == W_CHAN && beacons != NULL)
			beacons(e);
		env_fire(e);
	}
	CHECK(e->sta.state != RTW_S_SCAN);
}

static void
all_beacons(struct env *e)
{
	RX(e, w_beacon);
	RX(e, w_beacon_hidden);
	RX(e, w_beacon_wpa1);
	RX(e, w_beacon_open);
	RX(e, w_beacon_wep);
	RX(e, w_beacon_wpa3);
	RX(e, w_beacon);	/* seen twice: must not be listed twice */
}

static const struct rtw_bss *
find_bss(const struct env *e, const char *ssid)
{
	unsigned i;

	for (i = 0; i < e->sta.nbss; i++) {
		const struct rtw_bss *b = &e->sta.bss[i];

		if (b->ssid_len == strlen(ssid) &&
		    memcmp(b->ssid, ssid, b->ssid_len) == 0)
			return b;
	}
	return NULL;
}

static void
join_cfg(struct rtw_join *j, const char *ssid, int sec)
{
	memset(j, 0, sizeof(*j));
	j->ssid_len = (uint8_t)strlen(ssid);
	memcpy(j->ssid, ssid, j->ssid_len);
	j->security = (uint8_t)sec;
}

/* ------------------------------------------------------------------ */

static void
test_scan(void)
{
	static struct env e;
	const struct rtw_bss *b;

	env_init(&e);
	CHECK(rtw_sta_scan(&e.sta) != 0);	/* interface is down */
	rtw_sta_up(&e.sta);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(rtw_sta_scan(&e.sta) == 0);
	CHECK(e.sta.state == RTW_S_SCAN && e.chan == 1);
	CHECK(rtw_sta_scan(&e.sta) != 0);	/* already scanning */
	CHECK(e.ntx == 1);
	CHECK_FRAME(e.tx[0].f, e.tx[0].len, x_probe_bcast);
	CHECK(e.tx[0].rate == RTW_RATE_1M);
	env_run_scan(&e, all_beacons);

	CHECK(e.scans_done == 1);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(e.ntx == 13);			/* one probe per channel */
	CHECK(e.timer_ms == 0);			/* nothing to rejoin */
	CHECK(e.sta.nbss == 6);

	b = find_bss(&e, "TestNet");
	CHECK(b != NULL);
	if (b != NULL) {
		CHECK(b->security == RTW_SEC_WPA2_PSK);
		CHECK(b->chan == W_CHAN);
		CHECK(memcmp(b->bssid, w_ap, 6) == 0);
		CHECK(b->rates == 0x0fff);
		CHECK(b->beacon_int == 100);
	}
	b = find_bss(&e, "OldNet");
	CHECK(b != NULL && b->security == RTW_SEC_UNSUPPORTED &&
	    b->chan == 1);
	b = find_bss(&e, "Modern");
	CHECK(b != NULL && b->security == RTW_SEC_UNSUPPORTED);
	b = find_bss(&e, "Cafe");
	CHECK(b != NULL && b->security == RTW_SEC_OPEN && b->chan == 11);
	b = find_bss(&e, "Vintage");
	CHECK(b != NULL && b->security == RTW_SEC_WEP && b->rates == 0x000f);
	b = find_bss(&e, "");			/* the hidden network */
	CHECK(b != NULL && b->security == RTW_SEC_WPA2_PSK);

	/* Truncated and garbage frames must be ignored, not crash. */
	{
		size_t n;

		for (n = 0; n < w_beacon_len; n++)
			env_rx(&e, w_beacon, n, 0);
		rtw_sta_scan(&e.sta);
		for (n = 0; n < w_beacon_len; n++)
			env_rx(&e, w_beacon, n, 0);
		env_run_scan(&e, NULL);
	}
}

/* Join the WPA2 test network up to (not including) the key handshake. */
static void
wpa_associate(struct env *e)
{
	struct rtw_join j;

	env_init(e);
	join_cfg(&j, "TestNet", RTW_SEC_WPA2_PSK);
	rtw_wpa_passphrase_to_pmk(W_PASSPHRASE, w_ssid, w_ssid_len, j.pmk);
	CHECK_BYTES(j.pmk, 32, w_pmk);
	CHECK(rtw_sta_join(&e->sta, &j) == 0);	/* remembered while down */
	CHECK(e->sta.state == RTW_S_DOWN);
	rtw_sta_up(&e->sta);
	CHECK(e->sta.state == RTW_S_SCAN);
	/* Joining probes for the network by name as well. */
	CHECK(e->ntx == 2);
	CHECK_FRAME(e->tx[1].f, e->tx[1].len, x_probe_ssid);
	env_run_scan(e, all_beacons);

	CHECK(e->sta.state == RTW_S_AUTH);
	CHECK(e->chan == W_CHAN);
	CHECK(e->have_bssid && memcmp(e->bssid, w_ap, 6) == 0 && !e->linked);
	CHECK(e->ntx == 27);
	CHECK_FRAME(e->tx[26].f, e->tx[26].len, x_auth);

	/* A lost authentication frame is retried. */
	env_fire(e);
	CHECK(e->ntx == 28);
	CHECK_FRAME(e->tx[27].f, e->tx[27].len, x_auth);

	RX(e, w_auth_resp);
	CHECK(e->sta.state == RTW_S_ASSOC);
	CHECK(e->ntx == 29);
	CHECK_FRAME(e->tx[28].f, e->tx[28].len, x_assoc);

	RX(e, w_assoc_resp);
	CHECK(e->sta.state == RTW_S_HANDSHAKE);
	CHECK(e->sta.aid == 1);
	CHECK(e->linked && e->short_slot);
	CHECK(e->link == 0 && e->link_events == 0);
	e->ntx = 0;
}

static void
test_wpa2(void)
{
	static struct env e;
	static uint8_t out[2400];
	size_t n;
	int rate;

	wpa_associate(&e);

	/* No data may flow before the keys are in place. */
	CHECK(env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate) == 0);
	RX(&e, w_rx_plain);
	CHECK(e.rx_count == 0);

	RX(&e, w_m1);
	CHECK(e.ntx == 1);
	CHECK_FRAME(e.tx[0].f, e.tx[0].len, x_m2);
	CHECK(e.sta.state == RTW_S_HANDSHAKE);

	/* A forged message 3 changes nothing. */
	RX(&e, w_m3_badmic);
	CHECK(e.ntx == 1 && e.sta.state == RTW_S_HANDSHAKE && !e.sta.ptk_valid);

	RX(&e, w_m3);
	CHECK(e.ntx == 2);
	CHECK_FRAME(e.tx[1].f, e.tx[1].len, x_m4);	/* sent in the clear */
	CHECK(e.sta.state == RTW_S_RUN);
	CHECK(e.link == 1 && e.link_events == 1);
	CHECK(e.sta.ptk_valid && e.sta.gtk[1].valid && !e.sta.gtk[0].valid);
	CHECK(e.rx_count == 0);		/* EAPOL is never passed up */

	/* Transmit: Ethernet in, CCMP-encrypted 802.11 out. */
	n = env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_tx_data);
	CHECK(rate == RTW_RATE_11M);
	n = env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_tx_data2);

	/* Receive: unicast under the pairwise key. */
	RX_RATE(&e, w_rx_data, RTW_RATE_54M);
	CHECK(e.rx_count == 1);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_eth);
	/* The transmit rate follows what the access point used. */
	n = env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate);
	CHECK(rate == RTW_RATE_54M && n > 0);
	e.sta.tx_pn[0]--;			/* keep the PN script simple */

	/* Replay of the same frame is rejected. */
	RX(&e, w_rx_data);
	CHECK(e.rx_count == 1 && e.sta.stats.rx_replay == 1);
	/* Unencrypted data on an encrypted network is rejected. */
	RX(&e, w_rx_plain);
	CHECK(e.rx_count == 1);
	/* A corrupted frame fails its MIC and does not advance the PN. */
	n = e.sta.stats.rx_decrypt_fail;
	memcpy(e.work, w_rx_qos, w_rx_qos_len);
	e.work[40] ^= 1;
	rtw_sta_rx(&e.sta, e.work, w_rx_qos_len, 60, 0);
	CHECK(e.rx_count == 1 && e.sta.stats.rx_decrypt_fail == n + 1);
	/* The intact QoS-data frame is accepted. */
	RX(&e, w_rx_qos);
	CHECK(e.rx_count == 2);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_eth);

	/* Broadcast under the group key; its replay counter starts at the
	 * value given in message 3. */
	RX(&e, w_rx_bcast_old);
	CHECK(e.rx_count == 2);
	RX(&e, w_rx_bcast);
	CHECK(e.rx_count == 3);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_bcast_eth);
	/* Our own broadcast echoed back by the access point is dropped. */
	RX(&e, w_rx_own_bcast);
	CHECK(e.rx_count == 3);

	/* Group key update. */
	e.ntx = 0;
	RX(&e, w_rx_bcast_new);			/* key not known yet */
	CHECK(e.rx_count == 3);
	RX(&e, w_g1);
	CHECK(e.ntx == 1);
	CHECK_FRAME(e.tx[0].f, e.tx[0].len, x_g2);
	CHECK(e.sta.gtk[2].valid);
	RX(&e, w_rx_bcast_new);
	CHECK(e.rx_count == 4);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_bcast_eth);
	/* The same group message again is a replay. */
	RX(&e, w_g1);
	CHECK(e.ntx == 1);

	/* Retransmitted message 3: answered, but the packet number must
	 * carry on (a reset here is the KRACK vulnerability). */
	RX(&e, w_m3_retx);
	CHECK(e.ntx == 2);
	CHECK_FRAME(e.tx[1].f, e.tx[1].len, x_m4_retx);
	n = env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_tx_data5);
	CHECK(e.link_events == 1);

	/* Scanning while connected returns to the network afterwards. */
	e.ntx = 0;
	CHECK(rtw_sta_scan(&e.sta) == 0);
	CHECK(env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate) == 0);
	env_run_scan(&e, all_beacons);
	CHECK(e.sta.state == RTW_S_RUN && e.chan == W_CHAN && e.link == 1);
	CHECK(e.sta.nbss == 6 && e.link_events == 1);
	CHECK(env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate) > 0);

	/* Beacons keep the link alive ... */
	for (n = 0; n < 30; n++) {
		RX(&e, w_beacon);
		env_fire(&e);
	}
	CHECK(e.sta.state == RTW_S_RUN);
	/* ... and their absence brings it down and starts a rejoin. */
	for (n = 0; n < 12 && e.sta.state == RTW_S_RUN; n++)
		env_fire(&e);
	CHECK(e.sta.state == RTW_S_IDLE && e.link == 0);
	CHECK(e.sta.last_error == RTW_ERR_BEACON_LOSS);
	CHECK(!e.have_bssid && !e.sta.ptk_valid);
	env_fire(&e);
	CHECK(e.sta.state == RTW_S_SCAN);
	env_run_scan(&e, all_beacons);
	CHECK(e.sta.state == RTW_S_AUTH);

	/* Leaving forgets the network and stops retrying. */
	rtw_sta_leave(&e.sta);
	CHECK(e.sta.state == RTW_S_IDLE && e.timer_ms == 0 && !e.sta.have_cfg);
}

static void
test_wpa2_failures(void)
{
	static struct env e;
	int i;

	/* Wrong password: the access point never accepts message 2, so
	 * message 3 never arrives. */
	wpa_associate(&e);
	e.sta.cfg.pmk[0] ^= 1;
	RX(&e, w_m1);
	CHECK(e.ntx == 1);
	RX(&e, w_m3);				/* MIC cannot verify */
	CHECK(e.sta.state == RTW_S_HANDSHAKE && !e.sta.ptk_valid);
	env_fire(&e);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(e.sta.last_error == RTW_ERR_HANDSHAKE);
	CHECK(e.link_events == 0);
	CHECK(e.ntx == 2);
	CHECK_FRAME(e.tx[1].f, e.tx[1].len, x_deauth);
	CHECK(e.timer_ms != 0);			/* will try again later */

	/* Deauthentication during the handshake reads as a bad password. */
	wpa_associate(&e);
	RX(&e, w_m1);
	RX(&e, w_deauth);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(e.sta.last_error == RTW_ERR_HANDSHAKE);

	/* Deauthentication while connected drops the link and rejoins. */
	wpa_associate(&e);
	RX(&e, w_m1);
	RX(&e, w_m3);
	CHECK(e.link == 1);
	RX(&e, w_deauth);
	CHECK(e.sta.state == RTW_S_IDLE && e.link == 0 && e.link_events == 2);
	CHECK(e.sta.last_error == RTW_ERR_DEAUTH);
	env_fire(&e);
	CHECK(e.sta.state == RTW_S_SCAN);

	/* Authentication that is never answered gives up. */
	env_init(&e);
	{
		struct rtw_join j;

		join_cfg(&j, "TestNet", RTW_SEC_WPA2_PSK);
		rtw_sta_up(&e.sta);
		rtw_sta_join(&e.sta, &j);
	}
	env_run_scan(&e, all_beacons);
	CHECK(e.sta.state == RTW_S_AUTH);
	for (i = 0; i < 4; i++)
		env_fire(&e);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(e.sta.last_error == RTW_ERR_AUTH_TIMEOUT);

	/* The network exists but with other security than configured. */
	env_init(&e);
	{
		struct rtw_join j;

		join_cfg(&j, "TestNet", RTW_SEC_OPEN);
		rtw_sta_up(&e.sta);
		rtw_sta_join(&e.sta, &j);
		env_run_scan(&e, all_beacons);
		CHECK(e.sta.state == RTW_S_IDLE);
		CHECK(e.sta.last_error == RTW_ERR_SECURITY);

		join_cfg(&j, "OldNet", RTW_SEC_WPA2_PSK);
		rtw_sta_join(&e.sta, &j);
		env_run_scan(&e, all_beacons);
		CHECK(e.sta.last_error == RTW_ERR_SECURITY);

		join_cfg(&j, "Nowhere", RTW_SEC_OPEN);
		rtw_sta_join(&e.sta, &j);
		env_run_scan(&e, all_beacons);
		CHECK(e.sta.last_error == RTW_ERR_NOT_FOUND);
		CHECK(e.timer_ms != 0);

		/* Invalid requests are refused. */
		join_cfg(&j, "", RTW_SEC_OPEN);
		CHECK(rtw_sta_join(&e.sta, &j) != 0);
		join_cfg(&j, "x", RTW_SEC_UNSUPPORTED);
		CHECK(rtw_sta_join(&e.sta, &j) != 0);
		join_cfg(&j, "x", RTW_SEC_WEP);
		j.wep_key_len = 7;
		CHECK(rtw_sta_join(&e.sta, &j) != 0);
	}
}

static void
test_wep(void)
{
	static struct env e;
	static uint8_t out[2400];
	struct rtw_join j;
	size_t n;
	int rate;

	env_init(&e);
	join_cfg(&j, "Vintage", RTW_SEC_WEP);
	memcpy(j.wep_key, e_key, e_key_len);
	j.wep_key_len = (uint8_t)e_key_len;
	j.wep_key_id = 2;
	rtw_sta_up(&e.sta);
	CHECK(rtw_sta_join(&e.sta, &j) == 0);
	env_run_scan(&e, all_beacons);
	CHECK(e.sta.state == RTW_S_AUTH && e.chan == 3);
	RX(&e, e_auth_resp);
	RX(&e, e_assoc_resp);
	CHECK(e.sta.state == RTW_S_RUN && e.link == 1);
	CHECK(e.linked && !e.short_slot);	/* 802.11b only network */

	n = env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_wep_tx);
	RX(&e, e_rx);
	CHECK(e.rx_count == 1);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_eth);
	RX(&e, e_rx_bad);
	CHECK(e.rx_count == 1 && e.sta.stats.rx_decrypt_fail == 1);
}

static void
test_open(void)
{
	static struct env e;
	static uint8_t out[2400];
	struct rtw_join j;
	size_t n;
	int rate;

	env_init(&e);
	join_cfg(&j, "Cafe", RTW_SEC_OPEN);
	rtw_sta_up(&e.sta);
	rtw_sta_join(&e.sta, &j);
	env_run_scan(&e, all_beacons);
	CHECK(e.sta.state == RTW_S_AUTH && e.chan == 11);

	/* Rejections are reported. */
	RX(&e, o_auth_reject);
	CHECK(e.sta.state == RTW_S_IDLE);
	CHECK(e.sta.last_error == RTW_ERR_AUTH_REJECTED);
	env_fire(&e);
	env_run_scan(&e, all_beacons);
	RX(&e, o_auth_resp);
	RX(&e, o_assoc_reject);
	CHECK(e.sta.last_error == RTW_ERR_ASSOC_REJECTED);
	env_fire(&e);
	env_run_scan(&e, all_beacons);
	RX(&e, w_auth_resp);			/* from some other AP */
	CHECK(e.sta.state == RTW_S_AUTH);
	RX(&e, o_auth_resp);
	RX(&e, o_assoc_resp);
	CHECK(e.sta.state == RTW_S_RUN && e.link == 1);
	CHECK(e.sta.last_error == RTW_ERR_NONE);

	/* AppleTalk ARP keeps the bridge-tunnel encapsulation, and
	 * 802.3 length frames pass through without one. */
	n = env_send_eth(&e, o_tx_aarp_eth, o_tx_aarp_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_o_tx_aarp);
	n = env_send_eth(&e, o_tx_raw_eth, o_tx_raw_eth_len, out, &rate);
	CHECK_FRAME(out, n, x_o_tx_raw);
	RX(&e, o_rx_raw);
	CHECK(e.rx_count == 1);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_o_rx_raw_eth);

	RX(&e, o_rx_ip);
	CHECK(e.rx_count == 2);
	CHECK_BYTES(e.rx_eth, e.rx_eth_len, x_rx_eth);
	RX(&e, o_rx_ip_retry);			/* link-layer duplicate */
	CHECK(e.rx_count == 2 && e.sta.stats.rx_dup == 1);
	RX(&e, o_rx_frag);			/* fragments unsupported */
	CHECK(e.rx_count == 2 && e.sta.stats.rx_frag == 1);
	RX(&e, o_rx_other_bss);
	CHECK(e.rx_count == 2);
	RX(&e, o_rx_enc);			/* encrypted on an open net */
	CHECK(e.rx_count == 2);
	for (n = 0; n < 24; n++)		/* truncated headers */
		env_rx(&e, o_rx_ip, n, 0);
	CHECK(e.rx_count == 2);

	/* A fixed rate overrides rate following. */
	CHECK(rtw_sta_set_rate(&e.sta, RTW_RATE_18M) == 0);
	n = env_send_eth(&e, o_tx_aarp_eth, o_tx_aarp_eth_len, out, &rate);
	CHECK(n > 0 && rate == RTW_RATE_18M);
	/* ... unless the access point does not support it. */
	CHECK(rtw_sta_set_rate(&e.sta, RTW_RATE_54M) == 0);
	n = env_send_eth(&e, o_tx_aarp_eth, o_tx_aarp_eth_len, out, &rate);
	CHECK(n > 0 && rate == RTW_RATE_18M);
	CHECK(rtw_sta_set_rate(&e.sta, 12) != 0);

	rtw_sta_down(&e.sta);
	CHECK(e.sta.state == RTW_S_DOWN && e.link == 0);
	CHECK(env_send_eth(&e, w_tx_eth, w_tx_eth_len, out, &rate) == 0);
	RX(&e, o_rx_ip);
	CHECK(e.rx_count == 2);
}

/* ------------------------------------------------------------------ */
/* A model of the chip's register interface, enough to test probing    */

struct chip {
	uint8_t  reg[256];
	uint16_t eeprom[64];
	uint16_t rf[16];
	/* 93C46 state machine */
	int      ee_cs, ee_ck, ee_bits, ee_out_bits;
	uint32_t ee_shift;
	uint16_t ee_out;
	unsigned writes, sleeps_ms;
	int      fail_after;		/* -1: never */
	int      reset_sticks;
};

static void
chip_eeprom_clock(struct chip *c, int di)
{
	if (c->ee_out_bits > 0) {
		c->ee_out_bits--;
		c->reg[0x50] = (uint8_t)((c->reg[0x50] & ~1) |
		    ((c->ee_out >> c->ee_out_bits) & 1));
		return;
	}
	if (c->ee_bits == 0 && !di)
		return;			/* idle clocks before the start bit */
	c->ee_shift = (c->ee_shift << 1) | (uint32_t)di;
	c->ee_bits++;
	/* start bit, opcode 10 (read), six address bits */
	if (c->ee_bits == 9 && (c->ee_shift >> 6) == 0x6) {
		c->ee_out = c->eeprom[c->ee_shift & 0x3f];
		c->ee_out_bits = 16;
	}
}

static int
chip_read(void *ctx, uint16_t value, uint16_t index, uint8_t *buf,
    unsigned len)
{
	struct chip *c = (struct chip *)ctx;
	unsigned reg = value & 0xff, i;

	(void)index;
	if (c->fail_after == 0)
		return -1;
	if (c->fail_after > 0)
		c->fail_after--;
	if ((value >> 8) != 0xff) {
		memset(buf, 0, len);
		return 0;
	}
	for (i = 0; i < len; i++)
		buf[i] = c->reg[(reg + i) & 0xff];
	return 0;
}

static int
chip_write(void *ctx, uint16_t value, uint16_t index, const uint8_t *buf,
    unsigned len)
{
	struct chip *c = (struct chip *)ctx;
	unsigned reg = value & 0xff, i;

	if (c->fail_after == 0)
		return -1;
	if (c->fail_after > 0)
		c->fail_after--;
	c->writes++;
	if (index == 0x8225) {		/* radio register write */
		c->rf[value & 0xf] = (uint16_t)(buf[0] | (buf[1] << 8));
		return 0;
	}
	if ((value >> 8) != 0xff)
		return 0;
	for (i = 0; i < len; i++) {
		uint8_t v = buf[i];
		unsigned r = (reg + i) & 0xff;

		if (r == 0x50) {	/* EEPROM pins */
			int cs = (v >> 3) & 1, ck = (v >> 2) & 1;

			if (!cs) {
				c->ee_bits = 0;
				c->ee_shift = 0;
				c->ee_out_bits = 0;
			} else if (ck && !c->ee_ck) {
				chip_eeprom_clock(c, (v >> 1) & 1);
			}
			c->ee_cs = cs;
			c->ee_ck = ck;
			v = (uint8_t)((v & ~1) | (c->reg[0x50] & 1));
		}
		if (r == 0x37 && (v & 0x10) && !c->reset_sticks)
			v &= (uint8_t)~0x10;	/* reset self-clears */
		c->reg[r] = v;
	}
	return 0;
}

static void
chip_msleep(void *ctx, unsigned ms)
{
	((struct chip *)ctx)->sleeps_ms += ms;
}

static void
chip_udelay(void *ctx, unsigned us)
{
	(void)ctx; (void)us;
}

static void
chip_init(struct chip *c, struct rtl8187_io *io)
{
	int i;

	memset(c, 0, sizeof(*c));
	c->fail_after = -1;
	c->eeprom[0x06] = 0x0005;	/* RTL8225 radio */
	c->eeprom[0x07] = 0x1100;	/* MAC 00:11:22:33:44:55 */
	c->eeprom[0x08] = 0x3322;
	c->eeprom[0x09] = 0x5544;
	c->eeprom[0x05] = 0x0073;	/* power bases: cck 3, ofdm 7 */
	/* word = cck[n] | ofdm[n] << 4 | cck[n+1] << 8 | ofdm[n+1] << 12 */
	c->eeprom[0x16] = 0x2a19;	/* channels 1, 2 */
	c->eeprom[0x17] = 0x4c3b;	/* 3, 4 */
	c->eeprom[0x18] = 0x6e5d;	/* 5, 6 */
	c->eeprom[0x3d] = 0x807f;	/* 7, 8 */
	c->eeprom[0x3e] = 0xa291;	/* 9, 10 */
	c->eeprom[0x1b] = 0xc4b3;	/* 11, 12 */
	c->eeprom[0x1c] = 0xe6d5;	/* 13, 14 */
	for (i = 0; i < 4; i++)
		c->reg[0x40 + i] = 0;
	c->reg[0x43] = 5 << 1;		/* TX_CONF hardware revision 5 */
	io->ctx = c;
	io->read = chip_read;
	io->write = chip_write;
	io->msleep = chip_msleep;
	io->udelay = chip_udelay;
}

static void
test_hw(void)
{
	static const uint8_t mac[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
	static struct chip c;
	static struct rtl8187 hw;
	struct rtl8187_io io;
	struct rtl8187_rxinfo ri;
	uint8_t buf[400];
	size_t n;
	int i;

	chip_init(&c, &io);
	CHECK(rtl8187_probe(&hw, &io) == 0);
	CHECK(memcmp(hw.macaddr, mac, 6) == 0);
	CHECK(hw.hwrev == 5 && hw.eeprom_addr_bits == 6);
	CHECK(hw.rf_v2 == 0);		/* model returns 0 for radio reads */
	CHECK(hw.txpwr_cck_base == 3 && hw.txpwr_ofdm_base == 7);
	for (i = 1; i <= 14; i++) {
		CHECK(hw.txpwr_cck[i] == ((8 + i) & 0xf));
		CHECK(hw.txpwr_ofdm[i] == i);
	}

	CHECK(rtl8187_start(&hw) == 0);
	CHECK((c.reg[0x37] & 0x0c) == 0x0c);	/* RX and TX enabled */
	CHECK(memcmp(c.reg, mac, 6) == 0);	/* MAC address programmed */
	CHECK(c.reg[0xb0] == 0);		/* hardware crypto off */
	CHECK(hw.chan == 1 && c.rf[7] == 0x085c);
	CHECK(c.reg[0xb6] == 20);		/* long slot */
	CHECK(!(c.reg[0x46] & 0x80));		/* no BSSID filtering yet */

	CHECK(rtl8187_set_channel(&hw, 11) == 0);
	CHECK(hw.chan == 11 && c.rf[7] == 0x0d5c);
	CHECK(!(c.reg[0x42] & 0x06));		/* loopback released */
	CHECK(rtl8187_set_channel(&hw, 0) != 0);
	CHECK(rtl8187_set_channel(&hw, 15) != 0);

	CHECK(rtl8187_set_bss(&hw, w_ap, 1, 1) == 0);
	CHECK(memcmp(c.reg + 0x2e, w_ap, 6) == 0);
	CHECK((c.reg[0x58] & 0x0c) == 0x08);	/* link state: station */
	CHECK(c.reg[0xb6] == 9);		/* short slot */
	CHECK(c.reg[0x46] & 0x80);		/* BSSID filter on */
	CHECK(rtl8187_set_bss(&hw, NULL, 0, 0) == 0);
	CHECK((c.reg[0x58] & 0x0c) == 0 && c.reg[0xb6] == 20);
	CHECK(rtl8187_set_promisc(&hw, 1) == 0 && (c.reg[0x44] & 1));
	CHECK(rtl8187_set_promisc(&hw, 0) == 0 && !(c.reg[0x44] & 1));

	CHECK(rtl8187_stop(&hw) == 0);
	CHECK((c.reg[0x37] & 0x0c) == 0);

	/* An I/O failure anywhere surfaces as an error, never a hang. */
	for (i = 0; i < 400; i += 7) {
		chip_init(&c, &io);
		c.fail_after = i;
		CHECK(rtl8187_probe(&hw, &io) == RTL8187_E_IO);
	}
	chip_init(&c, &io);
	CHECK(rtl8187_probe(&hw, &io) == 0);
	c.fail_after = 500;
	CHECK(rtl8187_start(&hw) == RTL8187_E_IO);
	c.fail_after = -1;
	c.reset_sticks = 1;
	CHECK(rtl8187_start(&hw) == RTL8187_E_TIMEOUT);

	/* Chips this driver must refuse. */
	chip_init(&c, &io);
	c.reg[0x43] = 6 << 1;			/* RTL8187B */
	CHECK(rtl8187_probe(&hw, &io) == RTL8187_E_UNSUPPORTED);
	chip_init(&c, &io);
	c.eeprom[0x06] = 0x0003;		/* some other radio */
	CHECK(rtl8187_probe(&hw, &io) == RTL8187_E_UNSUPPORTED);

	/* Transmit descriptor. */
	memset(buf, 0xee, sizeof(buf));
	n = rtl8187_tx_desc(buf, 100, RTW_RATE_54M);
	CHECK(n == 112);
	CHECK(buf[0] == 100 && buf[1] == 0x80 && buf[2] == 0 && buf[3] == 11);
	n = rtl8187_tx_desc(buf, 0x134, RTW_RATE_1M);	/* 320 = 5 * 64 */
	CHECK(n == 321 && buf[0] == 0x34 && buf[1] == 0x81 && buf[320] == 0);

	/* Receive status block: 30 byte frame + FCS, 12 Mbit/s. */
	memset(buf, 0, sizeof(buf));
	buf[34] = 34; buf[35] = 0; buf[36] = 6 << 4;
	buf[34 + 6] = 50 << 1;
	CHECK(rtl8187_rx_parse(buf, 50, &ri) == 0);
	CHECK(ri.len == 30 && ri.rate == RTW_RATE_12M && ri.rssi == 61);
	buf[35] = 0x20;				/* CRC error flag */
	CHECK(rtl8187_rx_parse(buf, 50, &ri) != 0);
	buf[35] = 0; buf[34] = 35;		/* longer than the transfer */
	CHECK(rtl8187_rx_parse(buf, 50, &ri) != 0);
	buf[34] = 3;				/* shorter than an FCS */
	CHECK(rtl8187_rx_parse(buf, 50, &ri) != 0);
	CHECK(rtl8187_rx_parse(buf, 19, &ri) != 0);
}

int
main(void)
{
	test_primitives();
	test_scan();
	test_wpa2();
	test_wpa2_failures();
	test_wep();
	test_open();
	test_hw();
	printf("%d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
