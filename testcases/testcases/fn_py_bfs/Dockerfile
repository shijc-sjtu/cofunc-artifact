FROM python:3.11-alpine3.17
RUN apk add coreutils bash libtool m4 autoconf automake pkgconfig flex bison libxml2-dev zlib-dev build-base
SHELL ["/bin/bash", "-c"]
RUN pip install --upgrade setuptools==57.5.0
RUN pip install python-igraph==0.8.0
RUN mkdir func
COPY /tools/template.py /func/main.py
COPY prewarm.py /func/prewarm.py
COPY execute.py /func/execute.py
