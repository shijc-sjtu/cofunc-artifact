FROM python:3.12-alpine3.17
RUN pip install minio Pillow==10.2.0
RUN mkdir func
COPY /tools/template.py /func/main.py
COPY prewarm.py /func/prewarm.py
COPY execute.py /func/execute.py
COPY storage.py /func/storage.py
