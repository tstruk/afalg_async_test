
FLAGS := -O3

ifdef UNALIGNED
FLAGS += -DUNALIGNED
endif

all:
	gcc -o test ${FLAGS} test.c

clean:
	rm -f *.o
	rm -f *.~
	rm -f test
