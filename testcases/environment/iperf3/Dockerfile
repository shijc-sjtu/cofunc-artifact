FROM alpine:3.17
ENV HTTP_PROXY=http://child-prc.intel.com:913
ENV HTTPS_PROXY=http://child-prc.intel.com:913
ENV NO_PROXY=127.0.0.1,127.0.0.1,.local
RUN apk add iperf3
