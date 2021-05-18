CC = clang
LD = lld
# -g -O2 are necessary https://github.com/xdp-project/xdp-tutorial/issues/38#issuecomment-511726831
CFLAGS += -D__TARGET_ARCH_x86 $$(pkg-config --static --cflags libbpf) -fuse-ld=$(LD) -static -g -O2 -Wall -Wextra
LDFLAGS += -Wl,-Bstatic $$(pkg-config --static --libs libbpf)

OBJ = kprobe.o
OBJ_BPF = kprobe.bpf.o
HEADERS_BPF := $(OBJ_BPF:.bpf.o=.skel.h)
EXE = kprobe

.PHONY: all clean

all: vmlinux.h $(HEADERS_BPF) docker_make

docker_build:
	sudo docker build . -t bpf

docker_make: docker_build
	sudo docker run -v $$PWD:/build --rm bpf make docker_rule

docker_rule: $(OBJ_BPF) $(EXE)

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $^ -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $^ >$@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(OBJ) $(OBJ_BPF) vmlinux.h $(HEADERS_BPF) $(EXE)
