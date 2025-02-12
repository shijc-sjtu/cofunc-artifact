FROM alpine:3.17
RUN apk add build-base
RUN apk add linux-headers
RUN mkdir /func
COPY main.c /func/main.c
RUN gcc -Werror -o /func/cow /func/main.c
