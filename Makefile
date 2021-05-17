CC = clang
LD = ld.ldd
# -g -O2 are necessary https://github.com/xdp-project/xdp-tutorial/issues/38#issuecomment-511726831
CFLAGS += -D__TARGET_ARCH_x86 $$(pkg-config --cflags libbpf) -g -O2 -Wall -Wextra
LDFLAGS += $$(pkg-config --libs libbpf)

OBJ = kprobe.o
OBJ_BPF = kprobe.bpf.o
HEADERS_BPF := $(OBJ_BPF:.bpf.o=.skel.h)
EXE = kprobe

.PHONY: all clean

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $^ -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $^ >$@

all: vmlinux.h $(HEADERS_BPF) $(OBJ_BPF) $(EXE)


vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(OBJ) $(OBJ_BPF) vmlinux.h $(HEADERS_BPF) $(EXE)
