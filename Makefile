CC = clang
LD = lld
# -g -O2 are necessary https://github.com/xdp-project/xdp-tutorial/issues/38#issuecomment-511726831
CFLAGS += -D__TARGET_ARCH_x86 $$(pkg-config --cflags libbpf) -g -O2 -Wall -Wextra
LDFLAGS += $$(pkg-config --libs libbpf) -fuse-ld=$(LD)

OBJS = bootstrap.o	\
      vec/vec.o
OBJ_BPF = bootstrap.bpf.o
HEADERS_BPF := $(OBJ_BPF:.bpf.o=.skel.h)
EXE = bootstrap

.PHONY: all clean

all: vmlinux.h $(HEADERS_BPF) $(OBJ_BPF) $(EXE)

# docker_rule: $(OBJ_BPF) $(EXE)

$(EXE): $(OBJS)

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -target bpf -c $^ -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $^ >$@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(OBJS) $(OBJ_BPF) vmlinux.h $(HEADERS_BPF) $(EXE)
