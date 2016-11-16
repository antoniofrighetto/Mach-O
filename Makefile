all:
	clang main.c parser/mach-o.c -o mach-o

clean:
	rm mach-o
