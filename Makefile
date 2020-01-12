objects = debugger.o breakpoint.o linenoise.o register.o
CC = g++ -std=c++14

debugger : $(objects)
	$(CC) -o debugger $(objects)

debugger.o : debugger.cpp
	$(CC) -c -o $@ $<

breakpoint.o : breakpoint.cpp
	$(CC) -c -o $@ $<

linenoise.o : linenoise.c
	$(CC) -c -o $@ $<

register.o : register.cpp
	$(CC) -c -o $@ $<