/* AES-128, RFC 3394 key unwrap, and CCM as used by CCMP. */
#ifndef RTW_AES_H
#define RTW_AES_H

#include "rtw_os.h"

RTW_EXTERN_C_BEGIN

struct rtw_aes_key {
	uint32_t rk[44];
};

void rtw_aes_set_key(struct rtw_aes_key *k, const uint8_t key[16]);
void rtw_aes_encrypt(const struct rtw_aes_key *k, const uint8_t in[16],
    uint8_t out[16]);
void rtw_aes_decrypt(const struct rtw_aes_key *k, const uint8_t in[16],
    uint8_t out[16]);

/* RFC 3394 unwrap.  inlen must be a multiple of 8 and at least 16; out
 * receives inlen - 8 bytes.  Returns 0 on success, -1 if the integrity
 * check fails or the length is invalid. */
int rtw_aes_unwrap(const struct rtw_aes_key *kek, const uint8_t *in,
    size_t inlen, uint8_t *out);

#define RTW_CCM_NONCE_LEN 13
#define RTW_CCM_MIC_LEN   8

/* CCM with M=8, L=2.  data is transformed in place. */
void rtw_ccm_encrypt(const struct rtw_aes_key *k,
    const uint8_t nonce[RTW_CCM_NONCE_LEN], const uint8_t *aad, size_t aadlen,
    uint8_t *data, size_t len, uint8_t mic[RTW_CCM_MIC_LEN]);
/* Returns 0 if the MIC verifies, -1 otherwise. */
int rtw_ccm_decrypt(const struct rtw_aes_key *k,
    const uint8_t nonce[RTW_CCM_NONCE_LEN], const uint8_t *aad, size_t aadlen,
    uint8_t *data, size_t len, const uint8_t mic[RTW_CCM_MIC_LEN]);

RTW_EXTERN_C_END

#endif
