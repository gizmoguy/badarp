FROM ubuntu:18.04

RUN apt-get update && \
    apt-get -y install build-essential clang llvm linux-headers-generic libelf-dev
