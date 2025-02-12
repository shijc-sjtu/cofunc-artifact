FROM node:18.17-alpine3.17
RUN mkdir /func
COPY package.json /func
RUN cd /func && npm install
COPY tools/template.js /func/index.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
COPY models /func/models
COPY VirtualAlexa.js /func/VirtualAlexa.js
COPY en-US.json /func/en-US.json
COPY infra /func/infra
COPY net.js /func/net.js
WORKDIR /func
