/* WEP: RC4 with a per-frame IV and a CRC-32 integrity value. */
#ifndef RTW_WEP_H
#define RTW_WEP_H

#include "rtw_os.h"

RTW_EXTERN_C_BEGIN

#define RTW_WEP_IV_LEN  4	/* 3 byte IV + key id byte */
#define RTW_WEP_ICV_LEN 4

uint32_t rtw_crc32(const uint8_t *p, size_t len);

/* body points at the 4 byte IV field (already filled in); it is followed
 * by len plaintext bytes and 4 bytes of room for the ICV. */
void rtw_wep_encrypt(const uint8_t *key, size_t keylen, uint8_t *body,
    size_t len);
/* body points at the IV; len counts the ciphertext including the ICV.
 * Returns 0 if the ICV verifies. */
int rtw_wep_decrypt(const uint8_t *key, size_t keylen, uint8_t *body,
    size_t len);

RTW_EXTERN_C_END

#endif
