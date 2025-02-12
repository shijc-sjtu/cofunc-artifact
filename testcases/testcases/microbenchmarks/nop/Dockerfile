FROM alpine:3.17
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.sjtug.sjtu.edu.cn/g' /etc/apk/repositories
RUN apk add build-base
RUN apk add linux-headers
RUN mkdir /func
COPY main.c /func/main.c
RUN gcc -Werror -o /func/nop /func/main.c
