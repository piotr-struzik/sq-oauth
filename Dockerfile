FROM node:lts

WORKDIR /app
COPY *.json ./
COPY src ./

RUN npm install && npm run build && npm prune --production

ENV NODE_ENV=production

EXPOSE 3000
ENTRYPOINT [ "node" ]
CMD [ "dist/main.js" ]