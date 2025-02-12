FROM node:18.17-alpine3.17
COPY package.json /func/package.json
WORKDIR /func
RUN npm install
COPY tools/template.js /func/main.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
COPY storage.js /func/storage.js
