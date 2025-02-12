FROM node:18.17-alpine3.17
RUN sed -i 's#https\?://dl-cdn.alpinelinux.org/alpine#https://mirrors.tuna.tsinghua.edu.cn/alpine#g' /etc/apk/repositories
RUN apk add build-base python3
RUN npm install -g node-gyp
RUN mkdir js_binding
WORKDIR js_binding
COPY binding.cc binding.cc
COPY binding.gyp binding.gyp
RUN node-gyp configure
RUN node-gyp build
