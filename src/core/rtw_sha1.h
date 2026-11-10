/* SHA-1, HMAC-SHA1 and the key derivation functions built on them
 * (PBKDF2 for WPA passphrases, the IEEE 802.11i PRF). */
#ifndef RTW_SHA1_H
#define RTW_SHA1_H

#include "rtw_os.h"

RTW_EXTERN_C_BEGIN

#define RTW_SHA1_LEN 20

struct rtw_sha1 {
	uint32_t h[5];
	uint32_t count_lo;	/* message length in bytes, low word */
	uint32_t count_hi;
	uint32_t w[80];		/* schedule; kept here to stay off the stack */
	uint8_t  buf[64];
};

void rtw_sha1_init(struct rtw_sha1 *c);
void rtw_sha1_update(struct rtw_sha1 *c, const void *data, size_t len);
void rtw_sha1_final(struct rtw_sha1 *c, uint8_t out[RTW_SHA1_LEN]);

struct rtw_hmac_sha1 {
	struct rtw_sha1 inner;
	struct rtw_sha1 outer;
};

void rtw_hmac_sha1_init(struct rtw_hmac_sha1 *c, const uint8_t *key,
    size_t keylen);
void rtw_hmac_sha1_update(struct rtw_hmac_sha1 *c, const void *data,
    size_t len);
void rtw_hmac_sha1_final(struct rtw_hmac_sha1 *c, uint8_t out[RTW_SHA1_LEN]);

/* PBKDF2-HMAC-SHA1.  WPA uses 4096 iterations and a 32 byte result. */
void rtw_pbkdf2_sha1(const char *pass, size_t passlen, const uint8_t *salt,
    size_t saltlen, unsigned iterations, uint8_t *out, size_t outlen);

/* IEEE 802.11i PRF: out = PRF-(8*outlen)(key, label, data).  ctx is caller
 * supplied scratch so the kernel never puts it on its small stack. */
void rtw_prf_sha1(struct rtw_hmac_sha1 *ctx, const uint8_t *key,
    size_t keylen, const char *label, const uint8_t *data, size_t datalen,
    uint8_t *out, size_t outlen);

RTW_EXTERN_C_END

#endif
