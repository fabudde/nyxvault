FROM node:20-alpine

WORKDIR /app

# Install build dependencies for argon2/sodium-native
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json ./
RUN npm ci --production

COPY server.js ./
COPY setup.sh ./
COPY public/ ./public/

# Create data and storage directories
RUN mkdir -p data storage

EXPOSE 3870

CMD ["node", "server.js"]
