#import "AppController.h"
#import "RTWDriver.h"

#define kLastSSID	@"LastSSID"
#define kLastSecurity	@"LastSecurity"

/* Mac OS X 10.3 has no public call for installing the application menu
 * without a nib; this one has been there, undeclared, all along. */
@interface NSApplication (RTWAppleMenu)
- (void)setAppleMenu:(NSMenu *)menu;
@end

static NSString *
securityName(int security)
{
	switch (security) {
	case RTWSecurityOpen:	return @"None";
	case RTWSecurityWEP:	return @"WEP";
	case RTWSecurityWPA2:	return @"WPA2";
	default:		return @"Not supported";
	}
}

static NSComparisonResult
networkCompare(id a, id b, void *context)
{
	int sa = [[a objectForKey:@"Signal"] intValue];
	int sb = [[b objectForKey:@"Signal"] intValue];

	if (sa != sb)
		return (sa > sb) ? NSOrderedAscending : NSOrderedDescending;
	return NSOrderedSame;
}

@implementation AppController

/* ------------------------------------------------------------------ */
/* Building the interface                                             */

- (NSTextField *)labelWithFrame:(NSRect)frame text:(NSString *)text
{
	NSTextField *f = [[[NSTextField alloc] initWithFrame:frame] autorelease];

	[f setStringValue:text];
	[f setBezeled:NO];
	[f setDrawsBackground:NO];
	[f setEditable:NO];
	[f setSelectable:NO];
	return f;
}

- (NSButton *)buttonWithFrame:(NSRect)frame title:(NSString *)title
    action:(SEL)action
{
	NSButton *b = [[[NSButton alloc] initWithFrame:frame] autorelease];

	[b setTitle:title];
	[b setBezelStyle:NSRoundedBezelStyle];
	[b setTarget:self];
	[b setAction:action];
	return b;
}

- (void)addColumn:(NSString *)identifier title:(NSString *)title
    width:(float)width
{
	NSTableColumn *col = [[[NSTableColumn alloc]
	    initWithIdentifier:identifier] autorelease];

	[[col headerCell] setStringValue:title];
	[col setWidth:width];
	[col setEditable:NO];
	[table addTableColumn:col];
}

- (void)buildMenu
{
	NSMenu *mainMenu = [[[NSMenu alloc] initWithTitle:@"MainMenu"]
	    autorelease];
	NSMenu *appMenu = [[[NSMenu alloc] initWithTitle:@"Apple"] autorelease];
	NSMenu *editMenu = [[[NSMenu alloc] initWithTitle:@"Edit"] autorelease];
	NSMenuItem *item;

	[appMenu addItemWithTitle:@"About RTL Wireless"
	    action:@selector(orderFrontStandardAboutPanel:) keyEquivalent:@""];
	[appMenu addItem:[NSMenuItem separatorItem]];
	[appMenu addItemWithTitle:@"Hide RTL Wireless"
	    action:@selector(hide:) keyEquivalent:@"h"];
	[appMenu addItem:[NSMenuItem separatorItem]];
	[appMenu addItemWithTitle:@"Quit RTL Wireless"
	    action:@selector(terminate:) keyEquivalent:@"q"];
	item = [mainMenu addItemWithTitle:@"" action:NULL keyEquivalent:@""];
	[mainMenu setSubmenu:appMenu forItem:item];

	/* Needed for Command-V and friends in the password field. */
	[editMenu addItemWithTitle:@"Cut" action:@selector(cut:)
	    keyEquivalent:@"x"];
	[editMenu addItemWithTitle:@"Copy" action:@selector(copy:)
	    keyEquivalent:@"c"];
	[editMenu addItemWithTitle:@"Paste" action:@selector(paste:)
	    keyEquivalent:@"v"];
	[editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:)
	    keyEquivalent:@"a"];
	item = [mainMenu addItemWithTitle:@"Edit" action:NULL
	    keyEquivalent:@""];
	[mainMenu setSubmenu:editMenu forItem:item];

	[NSApp setMainMenu:mainMenu];
	if ([NSApp respondsToSelector:@selector(setAppleMenu:)])
		[NSApp setAppleMenu:appMenu];
}

- (void)buildWindow
{
	NSRect frame = NSMakeRect(0, 0, 520, 380);
	NSScrollView *scroll;
	NSView *content;

	window = [[NSWindow alloc] initWithContentRect:frame
	    styleMask:(NSTitledWindowMask | NSClosableWindowMask |
	    NSMiniaturizableWindowMask | NSResizableWindowMask)
	    backing:NSBackingStoreBuffered defer:NO];
	[window setTitle:@"RTL Wireless"];
	[window setMinSize:NSMakeSize(460, 260)];
	[window setReleasedWhenClosed:NO];
	content = [window contentView];

	statusField = [self labelWithFrame:NSMakeRect(20, 344, 480, 20)
	    text:@""];
	[statusField setFont:[NSFont boldSystemFontOfSize:13]];
	[statusField setAutoresizingMask:(NSViewWidthSizable |
	    NSViewMinYMargin)];
	[content addSubview:statusField];

	detailField = [self labelWithFrame:NSMakeRect(20, 322, 480, 18)
	    text:@""];
	[detailField setFont:[NSFont systemFontOfSize:11]];
	[detailField setAutoresizingMask:(NSViewWidthSizable |
	    NSViewMinYMargin)];
	[content addSubview:detailField];

	scroll = [[[NSScrollView alloc]
	    initWithFrame:NSMakeRect(20, 60, 480, 254)] autorelease];
	[scroll setHasVerticalScroller:YES];
	[scroll setBorderType:NSBezelBorder];
	[scroll setAutoresizingMask:(NSViewWidthSizable |
	    NSViewHeightSizable)];
	table = [[[NSTableView alloc]
	    initWithFrame:[[scroll contentView] bounds]] autorelease];
	[self addColumn:@"Name" title:@"Network" width:215];
	[self addColumn:@"Signal" title:@"Signal" width:60];
	[self addColumn:@"Channel" title:@"Channel" width:75];
	[self addColumn:@"Security" title:@"Security" width:100];
	[table setUsesAlternatingRowBackgroundColors:YES];
	[table setAllowsMultipleSelection:NO];
	[table setDataSource:self];
	[table setDelegate:self];
	[table setTarget:self];
	[table setDoubleAction:@selector(join:)];
	[scroll setDocumentView:table];
	[content addSubview:scroll];

	scanButton = [self buttonWithFrame:NSMakeRect(14, 14, 100, 32)
	    title:@"Scan" action:@selector(scan:)];
	[content addSubview:scanButton];
	otherButton = [self buttonWithFrame:NSMakeRect(114, 14, 110, 32)
	    title:@"Other..." action:@selector(joinOther:)];
	[content addSubview:otherButton];
	leaveButton = [self buttonWithFrame:NSMakeRect(286, 14, 120, 32)
	    title:@"Disconnect" action:@selector(leave:)];
	[leaveButton setAutoresizingMask:NSViewMinXMargin];
	[content addSubview:leaveButton];
	joinButton = [self buttonWithFrame:NSMakeRect(406, 14, 100, 32)
	    title:@"Join" action:@selector(join:)];
	[joinButton setAutoresizingMask:NSViewMinXMargin];
	[joinButton setKeyEquivalent:@"\r"];
	[content addSubview:joinButton];

	[window center];
	[window setFrameAutosaveName:@"MainWindow"];
	[window makeKeyAndOrderFront:self];
}

/* A modal panel with OK and Cancel; the caller adds its own fields. */
- (NSPanel *)panelWithTitle:(NSString *)title height:(float)height
    okTitle:(NSString *)okTitle
{
	NSPanel *p = [[NSPanel alloc]
	    initWithContentRect:NSMakeRect(0, 0, 400, height)
	    styleMask:NSTitledWindowMask backing:NSBackingStoreBuffered
	    defer:YES];
	NSButton *ok, *cancel;

	[p setTitle:title];
	[p setReleasedWhenClosed:NO];
	ok = [self buttonWithFrame:NSMakeRect(294, 12, 92, 32) title:okTitle
	    action:@selector(endPanel:)];
	[ok setTag:1];
	[ok setKeyEquivalent:@"\r"];
	[[p contentView] addSubview:ok];
	cancel = [self buttonWithFrame:NSMakeRect(202, 12, 92, 32)
	    title:@"Cancel" action:@selector(endPanel:)];
	[cancel setTag:0];
	[cancel setKeyEquivalent:@"\033"];
	[[p contentView] addSubview:cancel];
	return p;
}

- (void)buildPanels
{
	NSView *v;

	passPanel = [self panelWithTitle:@"Password" height:150
	    okTitle:@"Join"];
	v = [passPanel contentView];
	passPrompt = [self labelWithFrame:NSMakeRect(20, 96, 360, 36)
	    text:@""];
	[v addSubview:passPrompt];
	passField = [[[NSSecureTextField alloc]
	    initWithFrame:NSMakeRect(20, 70, 360, 22)] autorelease];
	[v addSubview:passField];
	rememberBox = [[[NSButton alloc]
	    initWithFrame:NSMakeRect(18, 44, 240, 18)] autorelease];
	[rememberBox setButtonType:NSSwitchButton];
	[rememberBox setTitle:@"Remember this network"];
	[rememberBox setState:NSOnState];
	[v addSubview:rememberBox];
	[passPanel setInitialFirstResponder:passField];

	otherPanel = [self panelWithTitle:@"Join Other Network" height:140
	    okTitle:@"Continue"];
	v = [otherPanel contentView];
	[v addSubview:[self labelWithFrame:NSMakeRect(20, 100, 100, 18)
	    text:@"Network name:"]];
	otherName = [[[NSTextField alloc]
	    initWithFrame:NSMakeRect(124, 98, 256, 22)] autorelease];
	[v addSubview:otherName];
	[v addSubview:[self labelWithFrame:NSMakeRect(20, 66, 100, 18)
	    text:@"Security:"]];
	otherSecurity = [[[NSPopUpButton alloc]
	    initWithFrame:NSMakeRect(122, 60, 180, 26) pullsDown:NO]
	    autorelease];
	[otherSecurity addItemWithTitle:@"None"];
	[otherSecurity addItemWithTitle:@"WEP"];
	[otherSecurity addItemWithTitle:@"WPA2 Personal"];
	[otherSecurity selectItemAtIndex:RTWSecurityWPA2];
	[v addSubview:otherSecurity];
	[otherPanel setInitialFirstResponder:otherName];
}

- (void)endPanel:(id)sender
{
	[NSApp stopModalWithCode:[sender tag]];
}

- (BOOL)runPanel:(NSPanel *)panel
{
	int code;

	[panel center];
	code = [NSApp runModalForWindow:panel];
	[panel orderOut:self];
	return code == 1;
}

/* ------------------------------------------------------------------ */
/* Application life cycle                                             */

- (void)applicationDidFinishLaunching:(NSNotification *)note
{
	networks = [[NSArray alloc] init];
	scanCount = -1;
	[self buildMenu];
	[self buildWindow];
	[self buildPanels];
	[self refresh:nil];
	[NSTimer scheduledTimerWithTimeInterval:1.0 target:self
	    selector:@selector(refresh:) userInfo:nil repeats:YES];
	[NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)app
{
	return YES;
}

- (void)dealloc
{
	[networks release];
	[passPanel release];
	[otherPanel release];
	[window release];
	[super dealloc];
}

/* ------------------------------------------------------------------ */
/* Talking to the driver                                              */

- (void)explainResult:(int)result
{
	NSString *msg;

	switch (result) {
	case RTWResultOK:
		return;
	case RTWResultNoAdapter:
		msg = @"No RTL8187 adapter is connected.";
		break;
	case RTWResultNotReady:
		msg = @"The adapter's network port is switched off. Turn it "
		    @"on in the Network pane of System Preferences, then try "
		    @"again.";
		break;
	case RTWResultBusy:
		msg = @"The adapter is busy scanning or joining. Try again in "
		    @"a moment.";
		break;
	case RTWResultNotPrivileged:
		msg = @"This user is not allowed to change the wireless "
		    @"network. Only the user logged in at this Mac, or an "
		    @"administrator using the rtlwifi command, can.";
		break;
	default:
		msg = [NSString stringWithFormat:
		    @"The driver refused the request (error 0x%08x).", result];
		break;
	}
	NSRunAlertPanel(@"RTL Wireless", @"%@", @"OK", nil, nil, msg);
}

- (void)reloadNetworksFrom:(NSDictionary *)props
{
	NSArray *list = [props objectForKey:@"RTWScanResults"];

	[networks release];
	if ([list isKindOfClass:[NSArray class]])
		networks = [[list sortedArrayUsingFunction:networkCompare
		    context:NULL] retain];
	else
		networks = [[NSArray alloc] init];
	[table deselectAll:self];
	[table reloadData];
}

/* If nothing is joined yet, rejoin the network used last time. */
- (void)autoJoin
{
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	NSData *ssid = [defaults objectForKey:kLastSSID];
	int security = [defaults integerForKey:kLastSecurity];
	NSData *key = nil;

	if (![ssid isKindOfClass:[NSData class]] || [ssid length] == 0)
		return;
	if (security != RTWSecurityOpen) {
		key = [RTWDriver savedKeyForSSID:ssid];
		if (key == nil)
			return;
	}
	[RTWDriver joinSSID:ssid security:security key:key];
}

/* Once a second: mirror the driver's state into the window. */
- (void)refresh:(NSTimer *)timer
{
	NSDictionary *props = [RTWDriver properties];
	NSString *state = [props objectForKey:@"RTWState"];
	NSString *error = [props objectForKey:@"RTWLastError"];
	NSData *ssid = [props objectForKey:@"RTWSSID"];
	NSString *status, *detail = @"";
	BOOL present = (props != nil && state != nil);
	BOOL connected = [state isEqualToString:@"connected"];
	int count;

	if (!present) {
		status = @"No adapter";
		detail = @"Plug in an RTL8187 wireless adapter. (The "
		    @"RTL8187 driver must be installed.)";
		if (adapterPresent) {
			[networks release];
			networks = [[NSArray alloc] init];
			[table reloadData];
			scanCount = -1;
		}
	} else if (connected) {
		int rate = [[props objectForKey:@"RTWTxRate"] intValue];

		status = [NSString stringWithFormat:@"Connected to %@",
		    [RTWDriver displayNameForSSID:ssid]];
		detail = [NSString stringWithFormat:
		    @"Channel %d, %@ security, %d%@ Mbit/s",
		    [[props objectForKey:@"RTWChannel"] intValue],
		    [props objectForKey:@"RTWSecurity"], rate / 2,
		    (rate & 1) ? @".5" : @""];
	} else if ([state isEqualToString:@"down"]) {
		status = @"Adapter is off";
		detail = @"Turn the port on in the Network pane of System "
		    @"Preferences.";
	} else if (ssid != nil) {
		status = [NSString stringWithFormat:@"Joining %@...",
		    [RTWDriver displayNameForSSID:ssid]];
		detail = state;
	} else {
		status = [state isEqualToString:@"scanning"] ?
		    @"Scanning..." : @"Not connected";
		if (error != nil && ![error isEqualToString:@"none"])
			detail = [NSString stringWithFormat:
			    @"Last attempt failed: %@", error];
	}
	[statusField setStringValue:status];
	[detailField setStringValue:detail];

	if (present) {
		count = [[props objectForKey:@"RTWScanCount"] intValue];
		if (count != scanCount) {
			scanCount = count;
			scanning = NO;
			[self reloadNetworksFrom:props];
		}
		if (!adapterPresent) {
			/* The adapter has just appeared. */
			if (ssid == nil && !connected)
				[self autoJoin];
			if (![state isEqualToString:@"down"])
				[self scan:nil];
		}
	}
	adapterPresent = present;

	[scanButton setEnabled:(present && !scanning)];
	[otherButton setEnabled:present];
	[joinButton setEnabled:(present && [table selectedRow] >= 0)];
	[leaveButton setEnabled:(present && ssid != nil)];
}

- (void)scan:(id)sender
{
	int result = [RTWDriver scan];

	if (result == RTWResultOK)
		scanning = YES;
	else if (sender != nil && result != RTWResultBusy)
		[self explainResult:result];
	if (sender != nil)
		[self refresh:nil];
}

/* Ask for the key if needed, then tell the driver to join. */
- (void)joinSSID:(NSData *)ssid security:(int)security
{
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	NSData *key = nil;
	BOOL remember = NO;
	int result;

	if (security == RTWSecurityUnsupported) {
		NSRunAlertPanel(@"RTL Wireless",
		    @"\"%@\" uses a kind of security this driver does not "
		    @"support (WPA with TKIP, WPA3 only, or Enterprise). "
		    @"WPA2 Personal with AES, WEP and open networks work.",
		    @"OK", nil, nil, [RTWDriver displayNameForSSID:ssid]);
		return;
	}
	if (security != RTWSecurityOpen) {
		key = [RTWDriver savedKeyForSSID:ssid];
		while (key == nil) {
			[passPrompt setStringValue:[NSString stringWithFormat:
			    @"The network \"%@\" requires a %@.",
			    [RTWDriver displayNameForSSID:ssid],
			    (security == RTWSecurityWEP) ? @"WEP key" :
			    @"WPA2 password"]];
			[passField setStringValue:@""];
			[passPanel makeFirstResponder:passField];
			if (![self runPanel:passPanel])
				return;
			key = [RTWDriver keyFromPassword:[passField stringValue]
			    ssid:ssid security:security];
			[passField setStringValue:@""];
			if (key == nil)
				NSRunAlertPanel(@"RTL Wireless", @"%@", @"OK",
				    nil, nil, (security == RTWSecurityWEP) ?
				    @"A WEP key is 5 or 13 characters, or 10 "
				    @"or 26 hexadecimal digits." :
				    @"A WPA2 password is 8 to 63 characters "
				    @"long.");
			remember = ([rememberBox state] == NSOnState);
		}
	}

	result = [RTWDriver joinSSID:ssid security:security key:key];
	if (result != RTWResultOK) {
		[self explainResult:result];
		return;
	}
	if (remember)
		[RTWDriver saveKey:key forSSID:ssid];
	[defaults setObject:ssid forKey:kLastSSID];
	[defaults setInteger:security forKey:kLastSecurity];
	[defaults synchronize];
	[self refresh:nil];
}

- (void)join:(id)sender
{
	int row = [table selectedRow];
	NSDictionary *net;
	NSData *ssid;

	if (row < 0 || row >= (int)[networks count])
		return;
	net = [networks objectAtIndex:row];
	ssid = [net objectForKey:@"SSID"];
	if (![ssid isKindOfClass:[NSData class]] || [ssid length] == 0) {
		/* A hidden network: the user has to supply the name. */
		[self joinOther:sender];
		return;
	}
	[self joinSSID:ssid
	    security:[[net objectForKey:@"Security"] intValue]];
}

- (void)joinOther:(id)sender
{
	NSData *ssid;

	[otherPanel makeFirstResponder:otherName];
	if (![self runPanel:otherPanel])
		return;
	ssid = [[otherName stringValue]
	    dataUsingEncoding:NSUTF8StringEncoding];
	if ([ssid length] == 0 || [ssid length] > 32) {
		NSRunAlertPanel(@"RTL Wireless",
		    @"A network name is 1 to 32 characters long.", @"OK", nil,
		    nil);
		return;
	}
	[self joinSSID:ssid security:[otherSecurity indexOfSelectedItem]];
}

/* Disconnect, and forget the network so it is not rejoined. */
- (void)leave:(id)sender
{
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	NSData *ssid = [defaults objectForKey:kLastSSID];
	int result = [RTWDriver leave];

	if (result != RTWResultOK) {
		[self explainResult:result];
		return;
	}
	if ([ssid isKindOfClass:[NSData class]])
		[RTWDriver forgetKeyForSSID:ssid];
	[defaults removeObjectForKey:kLastSSID];
	[defaults removeObjectForKey:kLastSecurity];
	[defaults synchronize];
	[self refresh:nil];
}

/* ------------------------------------------------------------------ */
/* Table of networks                                                  */

- (int)numberOfRowsInTableView:(NSTableView *)view
{
	return [networks count];
}

- (id)tableView:(NSTableView *)view
    objectValueForTableColumn:(NSTableColumn *)column row:(int)row
{
	NSDictionary *net;
	NSString *ident = [column identifier];

	if (row < 0 || row >= (int)[networks count])
		return @"";
	net = [networks objectAtIndex:row];
	if ([ident isEqualToString:@"Name"])
		return [RTWDriver displayNameForSSID:
		    [net objectForKey:@"SSID"]];
	if ([ident isEqualToString:@"Signal"])
		return [NSString stringWithFormat:@"%d%%",
		    [[net objectForKey:@"Signal"] intValue]];
	if ([ident isEqualToString:@"Channel"])
		return [net objectForKey:@"Channel"];
	return securityName([[net objectForKey:@"Security"] intValue]);
}

- (void)tableViewSelectionDidChange:(NSNotification *)note
{
	[joinButton setEnabled:(adapterPresent && [table selectedRow] >= 0)];
}

@end
