FROM alpine:3.17
RUN apk add git alpine-sdk
RUN git clone git://git.musl-libc.org/musl
RUN cd /musl && git checkout v1.2.3
COPY malloc.c /musl/src/malloc/oldmalloc/malloc.c
RUN cd musl && ./configure --with-malloc=oldmalloc && make
