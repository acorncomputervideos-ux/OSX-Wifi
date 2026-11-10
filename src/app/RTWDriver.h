/*
 * Thin Objective-C wrapper around the driver's I/O Registry interface
 * (see src/kext/RTL8187.h for the property keys) and the Keychain.
 */
#import <Foundation/Foundation.h>

/* enum rtw_security in the driver */
enum {
	RTWSecurityOpen = 0,
	RTWSecurityWEP,
	RTWSecurityWPA2,
	RTWSecurityUnsupported
};

/* IOKit result codes the driver returns for commands. */
enum {
	RTWResultOK		= 0,
	RTWResultNoAdapter	= -1,
	RTWResultNotPrivileged	= (int)0xe00002c1,
	RTWResultBusy		= (int)0xe00002d5,
	RTWResultNotReady	= (int)0xe00002d8
};

@interface RTWDriver : NSObject

/* All of the driver's registry properties, or nil if no adapter (or no
 * driver) is present. */
+ (NSDictionary *)properties;

/* Send a command dictionary; returns one of the RTWResult codes or
 * another IOKit error. */
+ (int)sendCommand:(NSDictionary *)command;

+ (int)scan;
+ (int)leave;
+ (int)joinSSID:(NSData *)ssid security:(int)security key:(NSData *)key;

/* Turn what the user typed into key bytes.  Returns nil if it is not a
 * valid passphrase/key for that kind of network. */
+ (NSData *)keyFromPassword:(NSString *)password ssid:(NSData *)ssid
    security:(int)security;

/* Keys of remembered networks live in the user's login keychain. */
+ (NSData *)savedKeyForSSID:(NSData *)ssid;
+ (void)saveKey:(NSData *)key forSSID:(NSData *)ssid;
+ (void)forgetKeyForSSID:(NSData *)ssid;

/* A network name for display (names are arbitrary bytes). */
+ (NSString *)displayNameForSSID:(NSData *)ssid;

@end
