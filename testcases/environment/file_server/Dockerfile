FROM ubuntu:latest
RUN apt update
RUN apt install -y wget python3
RUN mkdir file_server
WORKDIR file_server
RUN wget https://github.com/STEllAR-GROUP/hpx/archive/refs/tags/1.4.0.zip
RUN wget https://corgis-edu.github.io/corgis/datasets/json/airlines/airlines.json
COPY yfinance.csv yfinance.csv
CMD ["python3", "-m", "http.server", "8080"]
