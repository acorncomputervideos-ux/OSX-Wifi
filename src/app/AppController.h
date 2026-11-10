/*
 * RTL Wireless: a small window for choosing a network with the RTL8187
 * driver.  The interface is built in code (no nib file) so the whole
 * application builds with make, and it sticks to APIs present in
 * Mac OS X 10.3.
 */
#import <Cocoa/Cocoa.h>

@interface AppController : NSObject
{
	NSWindow	*window;
	NSTextField	*statusField;
	NSTextField	*detailField;
	NSTableView	*table;
	NSButton	*scanButton;
	NSButton	*joinButton;
	NSButton	*otherButton;
	NSButton	*leaveButton;

	/* password panel */
	NSPanel		*passPanel;
	NSTextField	*passPrompt;
	NSSecureTextField *passField;
	NSButton	*rememberBox;

	/* "other network" panel */
	NSPanel		*otherPanel;
	NSTextField	*otherName;
	NSPopUpButton	*otherSecurity;

	NSArray		*networks;	/* sorted scan results */
	int		scanCount;	/* driver's counter at last reload */
	BOOL		adapterPresent;
	BOOL		scanning;
}

- (void)refresh:(NSTimer *)timer;
- (void)scan:(id)sender;
- (void)join:(id)sender;
- (void)joinOther:(id)sender;
- (void)leave:(id)sender;
- (void)endPanel:(id)sender;

@end
