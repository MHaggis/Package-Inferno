FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --production || npm install --production
COPY src ./src
CMD ["node", "src/fetcher.js"]


