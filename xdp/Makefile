.RECIPEPREFIX := >
CLANG ?= clang
CC ?= cc
MULTIARCH := $(shell $(CC) -dumpmachine)
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -mcpu=v3 -I/usr/include/$(MULTIARCH)

.PHONY: all clean host-test approximate
all: kavach_xdp.o

kavach_xdp.o: kavach_xdp.c gcra.h Makefile
>$(CLANG) $(BPF_CFLAGS) -c kavach_xdp.c -o kavach_xdp.o

approximate: kavach_xdp_approx.o
kavach_xdp_approx.o: kavach_xdp.c gcra.h Makefile
>$(CLANG) $(filter-out -mcpu=v3,$(BPF_CFLAGS)) -mcpu=v2 -DKAVACH_APPROXIMATE -c kavach_xdp.c -o kavach_xdp_approx.o

host-test:
>$(CC) -O2 -Wall -Wextra -Werror -pthread tests/gcra_host.c -o tests/gcra_host
>./tests/gcra_host

clean:
>rm -f kavach_xdp.o kavach_xdp_approx.o tests/gcra_host tests/gcra_host.exe
