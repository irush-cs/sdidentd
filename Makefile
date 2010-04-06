
all: sdidentd
sdidentd: sdidentd.c
	gcc -Wall -arch i386 -arch x86_64 sdidentd.c -o sdidentd

install: sdidentd
	[ -f /Library/LaunchDaemons/sdidentd.plist ] && /bin/launchctl unload /Library/LaunchDaemons/sdidentd.plist || true
	mkdir -p /usr/local/sbin
	cp sdidentd /usr/local/sbin/sdidentd
	mkdir -p /Library/LaunchDaemons
	cp sdidentd.plist /Library/LaunchDaemons
	/bin/launchctl load /Library/LaunchDaemons/sdidentd.plist

clean:
	rm -f sdidentd

.PHONY: clean
