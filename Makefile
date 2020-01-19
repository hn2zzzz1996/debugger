objects = debugger.o breakpoint.o linenoise.o register.o
CC = g++ -std=c++14

export PKG_CONFIG_PATH=./libelfin/elf:./libelfin/dwarf
CPPFLAGS+=$$(pkg-config --cflags libelf++ libdwarf++)
# Statically link against our libs to keep the example binaries simple
# and dependencies correct.
LIBS=./libelfin/dwarf/libdwarf++.a ./libelfin/elf/libelf++.a

debugger : $(objects) $(LIBS)
	$(CC) -o $@ $(objects) $(LIBS)

debugger.o : debugger.cpp
	$(CC) -c -o $@ $< 

breakpoint.o : breakpoint.cpp
	$(CC) -c -o $@ $<

linenoise.o : linenoise.c
	gcc -c -o $@ $<

register.o : register.cpp
	$(CC) -c -o $@ $<

