BOFNAME := netview
COMINCLUDE := -s -w
LIBINCLUDE := -l netapi32 -l ws2_32
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc
STRIP_x64 := x86_64-w64-mingw32-strip
STRIP_x86 := i686-w64-mingw32-strip
CC=x86_64-w64-mingw32-clang

all:
	$(CC_x64) -o $(BOFNAME).x64.o $(COMINCLUDE) -Os -c entry.c -DBOF
	$(STRIP_x64) --strip-unneeded $(BOFNAME).x64.o
	$(CC_x86) -o $(BOFNAME).x86.o $(COMINCLUDE) -Os -c entry.c -DBOF
	$(STRIP_x86) --strip-unneeded $(BOFNAME).x86.o

test:
	$(CC_x64) entry.c -g $(COMINCLUDE) $(LIBINCLUDE)  -o $(BOFNAME).x64.exe
	$(CC_x86) entry.c -g $(COMINCLUDE) $(LIBINCLUDE) -o $(BOFNAME).x86.exe

scanbuild:
	$(CC) entry.c -o $(BOFNAME).scanbuild.exe $(COMINCLUDE) $(LIBINCLUDE)

check:
	cppcheck --enable=all $(COMINCLUDE) --platform=win64 entry.c

clean:
ifeq ($(OS),Windows_NT)
	del /f /q $(BOFNAME).*.o
	del /f /q $(BOFNAME).*.exe
else
	rm -f $(BOFNAME).*.o
	rm -f $(BOFNAME).*.exe
endif
