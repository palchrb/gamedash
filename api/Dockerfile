FROM node:20-alpine

# Install docker CLI for start/stop of MC container
RUN apk add --no-cache docker-cli unzip

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev 2>/dev/null || npm install --omit=dev

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
