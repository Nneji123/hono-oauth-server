FROM oven/bun:1.2.2-alpine

WORKDIR /app

COPY package.json bun.lock ./

RUN bun install

COPY . .

EXPOSE 5000

CMD ["bun", "start"]