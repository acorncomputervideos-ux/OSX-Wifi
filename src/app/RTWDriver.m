#import "RTWDriver.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>
#include <string.h>

#include "rtw_sha1.h"

#define DRIVER_CLASS	"com_osxwifi_driver_RTL8187"
#define KEYCHAIN_SERVICE "RTL8187 Wireless"

static io_service_t
findDriver(void)
{
	return IOServiceGetMatchingService(kIOMasterPortDefault,
	    IOServiceMatching(DRIVER_CLASS));
}

@implementation RTWDriver

+ (NSDictionary *)properties
{
	io_service_t service = findDriver();
	CFMutableDictionaryRef props = NULL;

	if (service == 0)
		return nil;
	if (IORegistryEntryCreateCFProperties(service, &props,
	    kCFAllocatorDefault, 0) != KERN_SUCCESS)
		props = NULL;
	IOObjectRelease(service);
	return [(NSDictionary *)props autorelease];
}

+ (int)sendCommand:(NSDictionary *)command
{
	io_service_t service = findDriver();
	kern_return_t kr;

	if (service == 0)
		return RTWResultNoAdapter;
	kr = IORegistryEntrySetCFProperties(service, (CFDictionaryRef)command);
	IOObjectRelease(service);
	return (int)kr;
}

+ (int)scan
{
	return [self sendCommand:
	    [NSDictionary dictionaryWithObject:@"scan" forKey:@"RTWCommand"]];
}

+ (int)leave
{
	return [self sendCommand:
	    [NSDictionary dictionaryWithObject:@"leave" forKey:@"RTWCommand"]];
}

+ (int)joinSSID:(NSData *)ssid security:(int)security key:(NSData *)key
{
	NSMutableDictionary *cmd = [NSMutableDictionary dictionary];

	[cmd setObject:@"join" forKey:@"RTWCommand"];
	[cmd setObject:ssid forKey:@"SSID"];
	[cmd setObject:[NSNumber numberWithInt:security] forKey:@"Security"];
	if (key != nil)
		[cmd setObject:key forKey:@"Key"];
	return [self sendCommand:cmd];
}

static int
hexValue(unichar c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Exactly `digits` hexadecimal digits, or nil. */
static NSData *
dataFromHex(NSString *s, unsigned digits)
{
	unsigned char buf[32];
	unsigned i;

	if ([s length] != digits || digits > 2 * sizeof(buf))
		return nil;
	for (i = 0; i < digits; i += 2) {
		int hi = hexValue([s characterAtIndex:i]);
		int lo = hexValue([s characterAtIndex:i + 1]);

		if (hi < 0 || lo < 0)
			return nil;
		buf[i / 2] = (unsigned char)((hi << 4) | lo);
	}
	return [NSData dataWithBytes:buf length:digits / 2];
}

+ (NSData *)keyFromPassword:(NSString *)password ssid:(NSData *)ssid
    security:(int)security
{
	NSData *utf8 = [password dataUsingEncoding:NSUTF8StringEncoding];
	unsigned len = [utf8 length];

	if (utf8 == nil)
		return nil;
	if (security == RTWSecurityWPA2) {
		unsigned char pmk[32];
		NSData *d;

		/* Either the 64 digit key itself or a passphrase. */
		if (len == 64 && (d = dataFromHex(password, 64)) != nil)
			return d;
		if (len < 8 || len > 63)
			return nil;
		rtw_pbkdf2_sha1((const char *)[utf8 bytes], len,
		    (const uint8_t *)[ssid bytes], [ssid length], 4096, pmk,
		    sizeof(pmk));
		d = [NSData dataWithBytes:pmk length:sizeof(pmk)];
		memset(pmk, 0, sizeof(pmk));
		return d;
	}
	if (security == RTWSecurityWEP) {
		if (len == 5 || len == 13)
			return utf8;
		if (len == 10 || len == 26)
			return dataFromHex(password, len);
		return nil;
	}
	return nil;
}

+ (NSData *)savedKeyForSSID:(NSData *)ssid
{
	UInt32 len = 0;
	void *bytes = NULL;
	NSData *key;

	if (SecKeychainFindGenericPassword(NULL, strlen(KEYCHAIN_SERVICE),
	    KEYCHAIN_SERVICE, [ssid length], (const char *)[ssid bytes], &len,
	    &bytes, NULL) != noErr)
		return nil;
	key = [NSData dataWithBytes:bytes length:len];
	SecKeychainItemFreeContent(NULL, bytes);
	return key;
}

+ (void)forgetKeyForSSID:(NSData *)ssid
{
	SecKeychainItemRef item = NULL;

	if (SecKeychainFindGenericPassword(NULL, strlen(KEYCHAIN_SERVICE),
	    KEYCHAIN_SERVICE, [ssid length], (const char *)[ssid bytes], NULL,
	    NULL, &item) == noErr && item != NULL) {
		SecKeychainItemDelete(item);
		CFRelease(item);
	}
}

+ (void)saveKey:(NSData *)key forSSID:(NSData *)ssid
{
	[self forgetKeyForSSID:ssid];
	SecKeychainAddGenericPassword(NULL, strlen(KEYCHAIN_SERVICE),
	    KEYCHAIN_SERVICE, [ssid length], (const char *)[ssid bytes],
	    [key length], [key bytes], NULL);
}

+ (NSString *)displayNameForSSID:(NSData *)ssid
{
	NSString *s;

	if (ssid == nil || [ssid length] == 0)
		return @"(hidden network)";
	s = [[[NSString alloc] initWithData:ssid
	    encoding:NSUTF8StringEncoding] autorelease];
	if (s == nil)
		s = [[[NSString alloc] initWithData:ssid
		    encoding:NSISOLatin1StringEncoding] autorelease];
	return s ? s : @"?";
}

@end
