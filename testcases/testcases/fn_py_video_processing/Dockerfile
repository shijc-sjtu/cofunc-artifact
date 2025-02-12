FROM alpine:3.17
RUN apk add py3-opencv
RUN apk add py3-pip
RUN pip install boto3
RUN mkdir func
COPY /tools/template.py /func/main.py
COPY prewarm.py /func/prewarm.py
COPY execute.py /func/execute.py
