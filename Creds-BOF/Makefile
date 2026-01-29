CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I ../_include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -s -c

all: bof

bof: clean
	@(mkdir _bin 2>/dev/null) && echo 'creating _bin directory' || echo '_bin directory exists'

	# 64-bit builds
	@($(CC64) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x64.o   && $(STRIP64) _bin/askcreds.x64.o) && echo '[+] askcreds (x64)' || echo '[!] askcreds (x64)'
	@($(CC64) $(CFLAGS) autologon/autologon.c -o _bin/autologon.x64.o && $(STRIP64) _bin/autologon.x64.o)  && echo '[+] autologon (x64)' || echo '[!] autologon (x64)'
	@($(CC64) $(CFLAGS) credman/credentialmanager.c -o _bin/credman.x64.o && $(STRIP64) _bin/credman.x64.o)  && echo '[+] credman (x64)' || echo '[!] credman (x64)'
	@($(CC64) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x64.o && $(STRIP64) _bin/cookie-monster-bof.x64.o)  && echo '[+] cookie-monster-bof (x64)' || echo '[!] cookie-monster-bof (x64)'
	@($(CC64) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x64.o && $(STRIP64) _bin/hashdump.x64.o)  && echo '[+] hashdump (x64)' || echo '[!] hashdump (x64)'
	@($(CC64) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x64.o && $(STRIP64) _bin/get-netntlm.x64.o)  && echo '[+] get-netntlm (x64)' || echo '[!] get-netntlm (x64)'
	@($(CC64) $(CFLAGS) -masm=intel UnderlayCopy/entry.c -o _bin/underlaycopy.x64.o && $(STRIP64) _bin/underlaycopy.x64.o)  && echo '[+] underlaycopy (x64)' || echo '[!] underlaycopy (x64)'

	# 32-bit builds
	@($(CC86) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x32.o   && $(STRIP86) _bin/askcreds.x32.o) && echo '[+] askcreds (x32)' || echo '[!] askcreds (x32)'
	@($(CC86) $(CFLAGS) autologon/autologon.c -o _bin/autologon.x32.o && $(STRIP86) _bin/autologon.x32.o)  && echo '[+] autologon (x32)' || echo '[!] autologon (x32)'
	@($(CC86) $(CFLAGS) credman/credentialmanager.c -o _bin/credman.x32.o && $(STRIP86) _bin/credman.x32.o)  && echo '[+] credman (x32)' || echo '[!] credman (x32)'
	@($(CC86) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x32.o && $(STRIP86) _bin/cookie-monster-bof.x32.o)  && echo '[+] cookie-monster-bof (x32)' || echo '[!] cookie-monster-bof (x32)'
	@($(CC86) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x32.o && $(STRIP86) _bin/hashdump.x32.o)  && echo '[+] hashdump (x32)' || echo '[!] hashdump (x32)'
	@($(CC86) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x32.o && $(STRIP86) _bin/get-netntlm.x32.o)  && echo '[+] get-netntlm (x32)' || echo '[!] get-netntlm (x32)'
	@($(CC86) $(CFLAGS) UnderlayCopy/entry.c -o _bin/underlaycopy.x32.o && $(STRIP86) _bin/underlaycopy.x32.o)  && echo '[+] underlaycopy (x32)' || echo '[!] underlaycopy (x32)'
	@($(CC64) $(CFLAGS) askcreds/askcreds.c -o _bin/askcreds.x64.o   && $(STRIP64) _bin/askcreds.x64.o) && echo '[+] askcreds' || echo '[!] askcreds'
	@($(CC64) $(CFLAGS) autologon/autologon.c -o _bin/autologon.x64.o && $(STRIP64) _bin/autologon.x64.o)  && echo '[+] autologon' || echo '[!] autologon'
	@($(CC64) $(CFLAGS) credman/credentialmanager.c -o _bin/credman.x64.o && $(STRIP64) _bin/credman.x64.o)  && echo '[+] credman' || echo '[!] credman'
	@($(CC64) $(CFLAGS) cookie-monster/cookie-monster-bof.c -o _bin/cookie-monster-bof.x64.o && $(STRIP64) _bin/cookie-monster-bof.x64.o)  && echo '[+] cookie-monster-bof' || echo '[!] cookie-monster-bof'
	@($(CC64) $(CFLAGS) hashdump/hashdump.c -o _bin/hashdump.x64.o && $(STRIP64) _bin/hashdump.x64.o)  && echo '[+] hashdump' || echo '[!] hashdump'
	@($(CC64) $(CFLAGS) get-netntlm/get-netntlm.c -o _bin/get-netntlm.x64.o && $(STRIP64) _bin/get-netntlm.x64.o)  && echo '[+] get-netntlm' || echo '[!] get-netntlm'
	@($(CC64) $(CFLAGS) -masm=intel UnderlayCopy/entry.c -o _bin/underlaycopy.x64.o && $(STRIP64) _bin/underlaycopy.x64.o)  && echo '[+] underlaycopy' || echo '[!] underlaycopy'
	@($(CC64) $(CFLAGS) lsadump/secrets.c -o _bin/lsadump_secrets.x64.o && $(STRIP64) _bin/lsadump_secrets.x64.o && $(CC64) $(CFLAGS) lsadump/sam.c -o _bin/lsadump_sam.x64.o && $(STRIP64) _bin/lsadump_sam.x64.o && $(CC64) $(CFLAGS) lsadump/cache.c -o _bin/lsadump_cache.x64.o && $(STRIP64) _bin/lsadump_cache.x64.o) && echo '[+] lsadump' || echo '[!] lsadump'

	@$(MAKE) --no-print-directory -C nanodump
	@cp nanodump/dist/*.o _bin/

clean:
	@(rm -rf _bin)
