FROM ubuntu:hirsute

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && apt-get -y upgrade

RUN apt-get -y install build-essential pkg-config clang lld libbpf-dev

# RUN ln -sf /usr/bin/ld.lld /usr/bin/ld

WORKDIR "/build"
