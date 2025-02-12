FROM node:18.17-alpine3.17
COPY package.json /func/package.json
RUN cd /func && npm install
COPY tools/template.js /func/index.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
COPY net.js /func/net.js
WORKDIR /func
