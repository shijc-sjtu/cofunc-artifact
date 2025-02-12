FROM alpine:3.17
RUN apk add build-base protobuf-dev protobuf-c-dev openssl iptables \
            wget tar ip6tables linux-headers libnet-dev libnl3-dev libcap-dev python3 \
            libaio-dev pkgconfig asciidoc xmlto git py-pip
RUN git clone --depth=1 https://github.com/checkpoint-restore/criu.git
RUN cd /criu && make
