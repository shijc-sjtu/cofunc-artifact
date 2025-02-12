FROM python:alpine3.17
RUN pip config set global.index-url https://mirror.sjtu.edu.cn/pypi/web/simple
RUN pip install minio
RUN mkdir func
COPY /tools/template.py /func/main.py
COPY prewarm.py /func/prewarm.py
COPY execute.py /func/execute.py
COPY storage.py /func/storage.py
