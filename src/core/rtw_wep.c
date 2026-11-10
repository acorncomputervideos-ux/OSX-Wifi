#include "rtw_wep.h"

struct rc4 {
	uint8_t s[256];
	uint8_t i, j;
};

static void
rc4_init(struct rc4 *c, const uint8_t *key, size_t keylen)
{
	unsigned i;
	uint8_t j = 0, t;

	for (i = 0; i < 256; i++)
		c->s[i] = (uint8_t)i;
	for (i = 0; i < 256; i++) {
		j = (uint8_t)(j + c->s[i] + key[i % keylen]);
		t = c->s[i]; c->s[i] = c->s[j]; c->s[j] = t;
	}
	c->i = c->j = 0;
}

static void
rc4_crypt(struct rc4 *c, uint8_t *p, size_t len)
{
	uint8_t t;

	while (len--) {
		c->i++;
		c->j = (uint8_t)(c->j + c->s[c->i]);
		t = c->s[c->i]; c->s[c->i] = c->s[c->j]; c->s[c->j] = t;
		*p++ ^= c->s[(uint8_t)(c->s[c->i] + c->s[c->j])];
	}
}

uint32_t
rtw_crc32(const uint8_t *p, size_t len)
{
	/* Reflected CRC-32 (polynomial 0xedb88320), one nibble at a time. */
	static const uint32_t t[16] = {
		0x00000000U, 0x1db71064U, 0x3b6e20c8U, 0x26d930acU,
		0x76dc4190U, 0x6b6b51f4U, 0x4db26158U, 0x5005713cU,
		0xedb88320U, 0xf00f9344U, 0xd6d6a3e8U, 0xcb61b38cU,
		0x9b64c2b0U, 0x86d3d2d4U, 0xa00ae278U, 0xbdbdf21cU
	};
	uint32_t crc = 0xffffffffU;

	while (len--) {
		crc ^= *p++;
		crc = t[crc & 0xf] ^ (crc >> 4);
		crc = t[crc & 0xf] ^ (crc >> 4);
	}
	return ~crc;
}

static void
wep_seed(struct rc4 *c, const uint8_t *key, size_t keylen, const uint8_t *iv)
{
	uint8_t seed[3 + 16];

	if (keylen > 16)
		keylen = 16;
	memcpy(seed, iv, 3);
	memcpy(seed + 3, key, keylen);
	rc4_init(c, seed, 3 + keylen);
	memset(seed, 0, sizeof(seed));
}

void
rtw_wep_encrypt(const uint8_t *key, size_t keylen, uint8_t *body, size_t len)
{
	struct rc4 c;
	uint8_t *data = body + RTW_WEP_IV_LEN;
	uint32_t icv = rtw_crc32(data, len);

	data[len] = (uint8_t)icv;
	data[len + 1] = (uint8_t)(icv >> 8);
	data[len + 2] = (uint8_t)(icv >> 16);
	data[len + 3] = (uint8_t)(icv >> 24);
	wep_seed(&c, key, keylen, body);
	rc4_crypt(&c, data, len + RTW_WEP_ICV_LEN);
}

int
rtw_wep_decrypt(const uint8_t *key, size_t keylen, uint8_t *body, size_t len)
{
	struct rc4 c;
	uint8_t *data = body + RTW_WEP_IV_LEN;
	uint32_t icv;

	if (len < RTW_WEP_ICV_LEN)
		return -1;
	wep_seed(&c, key, keylen, body);
	rc4_crypt(&c, data, len);
	len -= RTW_WEP_ICV_LEN;
	icv = rtw_crc32(data, len);
	if (data[len] != (uint8_t)icv || data[len + 1] != (uint8_t)(icv >> 8) ||
	    data[len + 2] != (uint8_t)(icv >> 16) ||
	    data[len + 3] != (uint8_t)(icv >> 24))
		return -1;
	return 0;
}
