all:
	gcc -g -o a.out main.c log.c

clean:
	rm -fr *.o a.out
