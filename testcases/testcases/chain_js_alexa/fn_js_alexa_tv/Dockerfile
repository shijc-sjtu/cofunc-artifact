FROM node:18.17-alpine3.17
RUN mkdir /func
COPY package.json /func
RUN cd /func && npm install
COPY tools/template.js /func/index.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
COPY tv-handler.js /func/tv-handler.js
COPY net.js /func/net.js
COPY infra /func/infra
WORKDIR /func
