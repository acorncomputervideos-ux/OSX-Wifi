#import <Cocoa/Cocoa.h>
#import "AppController.h"

int
main(int argc, const char *argv[])
{
	NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
	AppController *controller;

	[NSApplication sharedApplication];
	controller = [[AppController alloc] init];
	[NSApp setDelegate:controller];
	[NSApp run];
	[pool release];
	return 0;
}
