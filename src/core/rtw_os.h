/*
 * Portability shim for the driver core.
 *
 * Everything under src/core is plain C with no OS dependencies beyond a
 * few fixed-width types and memcpy/memset, so the same sources build into
 * the Mac OS X kernel extension, the command line tool, and the host-side
 * unit tests.
 */
#ifndef RTW_OS_H
#define RTW_OS_H

#ifdef KERNEL
#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#endif

#ifdef __cplusplus
#define RTW_EXTERN_C_BEGIN extern "C" {
#define RTW_EXTERN_C_END   }
#else
#define RTW_EXTERN_C_BEGIN
#define RTW_EXTERN_C_END
#endif

/* Byte-wise accessors: the code never casts buffers to wider types, so it
 * is correct on big-endian PowerPC and has no alignment requirements. */
#define RTW_GET_LE16(p) \
	((uint16_t)((uint16_t)((const uint8_t *)(p))[0] | \
	    ((uint16_t)((const uint8_t *)(p))[1] << 8)))
#define RTW_GET_BE16(p) \
	((uint16_t)(((uint16_t)((const uint8_t *)(p))[0] << 8) | \
	    (uint16_t)((const uint8_t *)(p))[1]))
#define RTW_GET_BE32(p) \
	(((uint32_t)((const uint8_t *)(p))[0] << 24) | \
	 ((uint32_t)((const uint8_t *)(p))[1] << 16) | \
	 ((uint32_t)((const uint8_t *)(p))[2] << 8) | \
	  (uint32_t)((const uint8_t *)(p))[3])
#define RTW_PUT_LE16(p, v) do { \
	((uint8_t *)(p))[0] = (uint8_t)((v) & 0xff); \
	((uint8_t *)(p))[1] = (uint8_t)(((v) >> 8) & 0xff); \
} while (0)
#define RTW_PUT_BE16(p, v) do { \
	((uint8_t *)(p))[0] = (uint8_t)(((v) >> 8) & 0xff); \
	((uint8_t *)(p))[1] = (uint8_t)((v) & 0xff); \
} while (0)
#define RTW_PUT_BE32(p, v) do { \
	((uint8_t *)(p))[0] = (uint8_t)(((v) >> 24) & 0xff); \
	((uint8_t *)(p))[1] = (uint8_t)(((v) >> 16) & 0xff); \
	((uint8_t *)(p))[2] = (uint8_t)(((v) >> 8) & 0xff); \
	((uint8_t *)(p))[3] = (uint8_t)((v) & 0xff); \
} while (0)

/* Lexicographic compare, like memcmp().  The core carries its own so that
 * it does not depend on which string functions a given kernel version
 * exports to extensions. */
static __inline__ int
rtw_memcmp(const void *a, const void *b, size_t n)
{
	const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
	size_t i;

	for (i = 0; i < n; i++) {
		if (x[i] != y[i])
			return (x[i] < y[i]) ? -1 : 1;
	}
	return 0;
}

/* Comparison whose running time does not depend on where the buffers
 * differ; used for MICs. */
static __inline__ int
rtw_memeq_ct(const void *a, const void *b, size_t n)
{
	const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
	uint8_t d = 0;
	size_t i;

	for (i = 0; i < n; i++)
		d |= (uint8_t)(x[i] ^ y[i]);
	return d == 0;
}

#endif /* RTW_OS_H */
