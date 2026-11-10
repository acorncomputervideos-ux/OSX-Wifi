/*
 * rtlwifi -- control the RTL8187 wireless driver.
 *
 * The driver publishes its state as I/O Registry properties and accepts
 * commands as a property dictionary (see src/kext/RTL8187.h); this tool
 * is a thin front end to that.  Commands that change anything must be
 * run as an administrator (sudo).
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include "rtw_sha1.h"

#define DRIVER_CLASS	"com_osxwifi_driver_RTL8187"

/* enum rtw_security in the driver */
enum { SEC_OPEN = 0, SEC_WEP, SEC_WPA2_PSK, SEC_UNSUPPORTED };

static const char *const security_names[] = {
	"open", "WEP", "WPA2", "unsupported"
};

static void
usage(void)
{
	fprintf(stderr,
"usage: rtlwifi status\n"
"       rtlwifi scan\n"
"       rtlwifi join <network name> [options]\n"
"           -p <passphrase>   WPA2 passphrase (8 to 63 characters)\n"
"           -P                ask for the WPA2 passphrase\n"
"           -k <64 hex>       WPA2 pre-shared key in hexadecimal\n"
"           -w <key>          WEP key: 5 or 13 characters, or 10 or 26\n"
"                             hexadecimal digits\n"
"           -i <1-4>          WEP key number (default 1)\n"
"           -b <bssid>        use only this access point (aa:bb:cc:dd:ee:ff)\n"
"       rtlwifi leave\n"
"       rtlwifi rate auto|1|2|5.5|11|6|9|12|18|24|36|48|54\n");
	exit(2);
}

static io_service_t
find_driver(void)
{
	io_service_t s = IOServiceGetMatchingService(kIOMasterPortDefault,
	    IOServiceMatching(DRIVER_CLASS));

	if (s == 0) {
		fprintf(stderr, "rtlwifi: no RTL8187 adapter found (is it "
		    "plugged in, and is RTL8187.kext installed?)\n");
		exit(1);
	}
	return s;
}

static CFTypeRef
get_prop(io_service_t s, const char *key)
{
	CFStringRef k = CFStringCreateWithCString(NULL, key,
	    kCFStringEncodingASCII);
	CFTypeRef v = IORegistryEntryCreateCFProperty(s, k, NULL, 0);

	CFRelease(k);
	return v;
}

static int
get_string(io_service_t s, const char *key, char *buf, size_t len)
{
	CFTypeRef v = get_prop(s, key);
	int ok = 0;

	buf[0] = '\0';
	if (v != NULL) {
		if (CFGetTypeID(v) == CFStringGetTypeID())
			ok = CFStringGetCString((CFStringRef)v, buf, len,
			    kCFStringEncodingASCII);
		CFRelease(v);
	}
	return ok;
}

static long
number_value(CFTypeRef v, long dflt)
{
	long n = dflt;

	if (v != NULL && CFGetTypeID(v) == CFNumberGetTypeID())
		CFNumberGetValue((CFNumberRef)v, kCFNumberLongType, &n);
	return n;
}

static long
get_number(io_service_t s, const char *key, long dflt)
{
	CFTypeRef v = get_prop(s, key);
	long n = number_value(v, dflt);

	if (v != NULL)
		CFRelease(v);
	return n;
}

/* Copy a CFData into buf; returns its length or -1. */
static int
data_value(CFTypeRef v, unsigned char *buf, int max)
{
	int n;

	if (v == NULL || CFGetTypeID(v) != CFDataGetTypeID())
		return -1;
	n = (int)CFDataGetLength((CFDataRef)v);
	if (n > max)
		n = max;
	CFDataGetBytes((CFDataRef)v, CFRangeMake(0, n), buf);
	return n;
}

/* Network names are arbitrary bytes; show unprintable ones as '?'. */
static void
print_ssid(const unsigned char *ssid, int len, int width)
{
	int i;

	if (len <= 0) {
		printf("%-*s", width, "(hidden)");
		return;
	}
	for (i = 0; i < len; i++)
		putchar(isprint(ssid[i]) ? ssid[i] : '?');
	for (; i < width; i++)
		putchar(' ');
}

static void
dict_set_string(CFMutableDictionaryRef d, const char *key, const char *val)
{
	CFStringRef k = CFStringCreateWithCString(NULL, key,
	    kCFStringEncodingASCII);
	CFStringRef v = CFStringCreateWithCString(NULL, val,
	    kCFStringEncodingASCII);

	CFDictionarySetValue(d, k, v);
	CFRelease(k);
	CFRelease(v);
}

static void
dict_set_number(CFMutableDictionaryRef d, const char *key, int val)
{
	CFStringRef k = CFStringCreateWithCString(NULL, key,
	    kCFStringEncodingASCII);
	CFNumberRef v = CFNumberCreate(NULL, kCFNumberIntType, &val);

	CFDictionarySetValue(d, k, v);
	CFRelease(k);
	CFRelease(v);
}

static void
dict_set_data(CFMutableDictionaryRef d, const char *key,
    const unsigned char *val, int len)
{
	CFStringRef k = CFStringCreateWithCString(NULL, key,
	    kCFStringEncodingASCII);
	CFDataRef v = CFDataCreate(NULL, val, len);

	CFDictionarySetValue(d, k, v);
	CFRelease(k);
	CFRelease(v);
}

static CFMutableDictionaryRef
new_command(const char *name)
{
	CFMutableDictionaryRef d = CFDictionaryCreateMutable(NULL, 0,
	    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

	dict_set_string(d, "RTWCommand", name);
	return d;
}

static void
send_command(io_service_t s, CFMutableDictionaryRef cmd)
{
	kern_return_t kr = IORegistryEntrySetCFProperties(s, cmd);

	CFRelease(cmd);
	if (kr == kIOReturnSuccess)
		return;
	if (kr == kIOReturnNotPrivileged)
		fprintf(stderr, "rtlwifi: permission denied; run with sudo\n");
	else if (kr == kIOReturnNotReady)
		fprintf(stderr, "rtlwifi: the interface is switched off; "
		    "enable it in Network preferences or with "
		    "\"sudo ifconfig <enX> up\"\n");
	else if (kr == kIOReturnBusy)
		fprintf(stderr, "rtlwifi: the adapter is busy scanning or "
		    "joining; try again in a moment\n");
	else if (kr == kIOReturnBadArgument)
		fprintf(stderr, "rtlwifi: the driver rejected the request\n");
	else
		fprintf(stderr, "rtlwifi: request failed (0x%08x)\n", kr);
	exit(1);
}

/* Parse hexadecimal digits (optionally separated by ':') into bytes. */
static int
parse_hex(const char *s, unsigned char *out, int max)
{
	int n = 0, hi = -1;

	for (; *s; s++) {
		int v;

		if (*s == ':' && hi < 0)
			continue;
		if (!isxdigit((unsigned char)*s))
			return -1;
		v = isdigit((unsigned char)*s) ? *s - '0' :
		    tolower((unsigned char)*s) - 'a' + 10;
		if (hi < 0) {
			hi = v;
		} else {
			if (n >= max)
				return -1;
			out[n++] = (unsigned char)((hi << 4) | v);
			hi = -1;
		}
	}
	return (hi < 0) ? n : -1;
}

/* ------------------------------------------------------------------ */

static int
cmd_status(io_service_t s)
{
	char state[64], err[128], sec[32], radio[32];
	unsigned char ssid[32], bssid[6];
	CFTypeRef v;
	int n;
	long rate;

	get_string(s, "RTWState", state, sizeof(state));
	get_string(s, "RTWLastError", err, sizeof(err));
	get_string(s, "RTWRadio", radio, sizeof(radio));
	printf("adapter:  RTL8187L, radio %s\n", radio);
	printf("state:    %s\n", state);

	v = get_prop(s, "RTWSSID");
	n = data_value(v, ssid, sizeof(ssid));
	if (v != NULL)
		CFRelease(v);
	if (n >= 0) {
		printf("network:  ");
		print_ssid(ssid, n, 0);
		printf("\n");
		v = get_prop(s, "RTWBSSID");
		if (data_value(v, bssid, 6) == 6)
			printf("access point: %02x:%02x:%02x:%02x:%02x:%02x\n",
			    bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
			    bssid[5]);
		if (v != NULL)
			CFRelease(v);
		printf("channel:  %ld\n", get_number(s, "RTWChannel", 0));
		if (get_string(s, "RTWSecurity", sec, sizeof(sec)))
			printf("security: %s\n", sec);
		rate = get_number(s, "RTWTxRate", 0);
		printf("tx rate:  %ld%s Mbit/s\n", rate / 2,
		    (rate & 1) ? ".5" : "");
	}
	if (strcmp(err, "none") != 0 && err[0] != '\0')
		printf("last problem: %s\n", err);
	return strcmp(state, "connected") == 0 ? 0 : 1;
}

static int
cmd_scan(io_service_t s)
{
	long before = get_number(s, "RTWScanCount", 0);
	CFTypeRef list;
	CFIndex i, count;
	int tries;

	send_command(s, new_command("scan"));
	for (tries = 0; tries < 40; tries++) {
		usleep(250000);
		if (get_number(s, "RTWScanCount", 0) != before)
			break;
	}
	if (tries == 40) {
		fprintf(stderr, "rtlwifi: the scan did not finish\n");
		return 1;
	}

	list = get_prop(s, "RTWScanResults");
	if (list == NULL || CFGetTypeID(list) != CFArrayGetTypeID()) {
		fprintf(stderr, "rtlwifi: no scan results\n");
		return 1;
	}
	count = CFArrayGetCount((CFArrayRef)list);
	if (count == 0)
		printf("No networks found.\n");
	else
		printf("%-32s  %-17s  %2s  %6s  %s\n", "NETWORK", "ACCESS POINT",
		    "CH", "SIGNAL", "SECURITY");
	for (i = 0; i < count; i++) {
		CFDictionaryRef e = (CFDictionaryRef)
		    CFArrayGetValueAtIndex((CFArrayRef)list, i);
		unsigned char ssid[32], b[6];
		long sec;
		int n;

		if (CFGetTypeID(e) != CFDictionaryGetTypeID())
			continue;
		n = data_value(CFDictionaryGetValue(e, CFSTR("SSID")), ssid,
		    sizeof(ssid));
		memset(b, 0, sizeof(b));
		data_value(CFDictionaryGetValue(e, CFSTR("BSSID")), b, 6);
		sec = number_value(CFDictionaryGetValue(e, CFSTR("Security")),
		    SEC_UNSUPPORTED);
		if (sec < 0 || sec > SEC_UNSUPPORTED)
			sec = SEC_UNSUPPORTED;
		print_ssid(ssid, n, 32);
		printf("  %02x:%02x:%02x:%02x:%02x:%02x  %2ld  %5ld%%  %s\n",
		    b[0], b[1], b[2], b[3], b[4], b[5],
		    number_value(CFDictionaryGetValue(e, CFSTR("Channel")), 0),
		    number_value(CFDictionaryGetValue(e, CFSTR("Signal")), 0),
		    security_names[sec]);
	}
	CFRelease(list);
	return 0;
}

static int
cmd_join(io_service_t s, int argc, char **argv)
{
	CFMutableDictionaryRef cmd;
	const char *ssid, *pass = NULL, *psk_hex = NULL, *wep = NULL;
	const char *bssid_str = NULL;
	unsigned char key[32], bssid[6];
	char state[64], err[128];
	int keyidx = 1, security = SEC_OPEN, keylen = 0, ask = 0, c, tries;
	size_t ssid_len;

	if (argc < 2)
		usage();
	ssid = argv[1];
	ssid_len = strlen(ssid);
	if (ssid_len == 0 || ssid_len > 32) {
		fprintf(stderr, "rtlwifi: a network name is 1 to 32 "
		    "characters long\n");
		return 2;
	}
	optind = 2;
	while ((c = getopt(argc, argv, "p:Pk:w:i:b:")) != -1) {
		switch (c) {
		case 'p': pass = optarg; break;
		case 'P': ask = 1; break;
		case 'k': psk_hex = optarg; break;
		case 'w': wep = optarg; break;
		case 'i': keyidx = atoi(optarg); break;
		case 'b': bssid_str = optarg; break;
		default: usage();
		}
	}
	if (optind != argc || (pass != NULL) + ask + (psk_hex != NULL) +
	    (wep != NULL) > 1)
		usage();

	if (ask) {
		pass = getpass("Passphrase: ");
		if (pass == NULL)
			return 1;
	}
	if (pass != NULL) {
		size_t n = strlen(pass);

		if (n < 8 || n > 63) {
			fprintf(stderr, "rtlwifi: a WPA2 passphrase is 8 to "
			    "63 characters long\n");
			return 2;
		}
		/* Takes a second or two on a G3. */
		rtw_pbkdf2_sha1(pass, n, (const uint8_t *)ssid, ssid_len, 4096,
		    key, 32);
		security = SEC_WPA2_PSK;
		keylen = 32;
	} else if (psk_hex != NULL) {
		if (strlen(psk_hex) != 64 || parse_hex(psk_hex, key, 32) != 32) {
			fprintf(stderr, "rtlwifi: -k takes exactly 64 "
			    "hexadecimal digits\n");
			return 2;
		}
		security = SEC_WPA2_PSK;
		keylen = 32;
	} else if (wep != NULL) {
		size_t n = strlen(wep);

		if (n == 5 || n == 13) {
			memcpy(key, wep, n);
			keylen = (int)n;
		} else if ((n == 10 || n == 26) &&
		    parse_hex(wep, key, 13) == (int)n / 2) {
			keylen = (int)n / 2;
		} else {
			fprintf(stderr, "rtlwifi: a WEP key is 5 or 13 "
			    "characters, or 10 or 26 hexadecimal digits\n");
			return 2;
		}
		if (keyidx < 1 || keyidx > 4) {
			fprintf(stderr, "rtlwifi: the WEP key number is 1 "
			    "to 4\n");
			return 2;
		}
		security = SEC_WEP;
	}
	if (bssid_str != NULL && parse_hex(bssid_str, bssid, 6) != 6) {
		fprintf(stderr, "rtlwifi: bad access point address\n");
		return 2;
	}

	cmd = new_command("join");
	dict_set_data(cmd, "SSID", (const unsigned char *)ssid, (int)ssid_len);
	dict_set_number(cmd, "Security", security);
	if (keylen)
		dict_set_data(cmd, "Key", key, keylen);
	if (security == SEC_WEP)
		dict_set_number(cmd, "KeyIndex", keyidx - 1);
	if (bssid_str != NULL)
		dict_set_data(cmd, "BSSID", bssid, 6);
	send_command(s, cmd);
	memset(key, 0, sizeof(key));

	/* The driver scans, then joins; watch how it goes. */
	printf("Joining \"%s\"...\n", ssid);
	for (tries = 0; tries < 80; tries++) {
		usleep(250000);
		get_string(s, "RTWState", state, sizeof(state));
		get_string(s, "RTWLastError", err, sizeof(err));
		if (strcmp(state, "connected") == 0) {
			printf("Connected.\n");
			return 0;
		}
		if (strcmp(state, "down") == 0) {
			printf("Saved.  The interface is switched off; the "
			    "driver will join when it is enabled.\n");
			return 0;
		}
		if (strcmp(err, "none") != 0 && err[0] != '\0' &&
		    strcmp(state, "idle") == 0) {
			fprintf(stderr, "rtlwifi: could not join: %s\n"
			    "(the driver keeps retrying; \"rtlwifi leave\" "
			    "stops it)\n", err);
			return 1;
		}
	}
	fprintf(stderr, "rtlwifi: still trying (state: %s)\n", state);
	return 1;
}

static int
cmd_rate(io_service_t s, const char *arg)
{
	static const struct { const char *name; int v; } rates[] = {
		{ "auto", 0 }, { "1", 2 }, { "2", 4 }, { "5.5", 11 },
		{ "11", 22 }, { "6", 12 }, { "9", 18 }, { "12", 24 },
		{ "18", 36 }, { "24", 48 }, { "36", 72 }, { "48", 96 },
		{ "54", 108 }
	};
	CFMutableDictionaryRef cmd;
	unsigned i;

	for (i = 0; i < sizeof(rates) / sizeof(rates[0]); i++) {
		if (strcmp(arg, rates[i].name) == 0) {
			cmd = new_command("rate");
			dict_set_number(cmd, "Rate", rates[i].v);
			send_command(s, cmd);
			return 0;
		}
	}
	usage();
	return 2;
}

int
main(int argc, char **argv)
{
	io_service_t s;

	if (argc < 2)
		usage();
	if (strcmp(argv[1], "status") == 0 && argc == 2)
		return cmd_status(find_driver());
	if (strcmp(argv[1], "scan") == 0 && argc == 2)
		return cmd_scan(find_driver());
	if (strcmp(argv[1], "join") == 0)
		return cmd_join(find_driver(), argc - 1, argv + 1);
	if (strcmp(argv[1], "leave") == 0 && argc == 2) {
		s = find_driver();
		send_command(s, new_command("leave"));
		return 0;
	}
	if (strcmp(argv[1], "rate") == 0 && argc == 3)
		return cmd_rate(find_driver(), argv[2]);
	usage();
	return 2;
}
