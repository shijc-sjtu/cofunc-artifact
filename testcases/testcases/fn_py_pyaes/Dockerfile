FROM python:alpine3.17
RUN pip install pyaes
RUN mkdir func
COPY /tools/template.py /func/main.py
COPY prewarm.py /func/prewarm.py
COPY execute.py /func/execute.py
