FROM node:18.17-alpine3.17
RUN apk add build-base vips-dev
RUN mkdir func
COPY package.json /func/package.json
RUN cd /func && npm install
COPY detect-libc.js /func/node_modules/detect-libc/lib
COPY tools/template.js /func/main.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
COPY storage.js /func/storage.js
