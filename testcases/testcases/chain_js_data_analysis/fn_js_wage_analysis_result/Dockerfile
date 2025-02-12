FROM node:18.17-alpine3.17
RUN mkdir func
WORKDIR /func
COPY package.json package.json
RUN npm config set registry https://registry.npmmirror.com
RUN npm install
COPY tools/template.js /func/main.js
COPY prewarm.js /func/prewarm.js
COPY execute.js /func/execute.js
