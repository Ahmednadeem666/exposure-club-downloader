FROM node:22-slim

# system deps: ffmpeg (merge/audio/upscale) + curl/ca-certs to fetch yt-dlp
RUN apt-get update && apt-get install -y --no-install-recommends \
      ffmpeg ca-certificates curl python3 \
 && rm -rf /var/lib/apt/lists/*

# yt-dlp: pull the latest standalone binary (updates often — keep it fresh)
RUN curl -fsSL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp \
      -o /usr/local/bin/yt-dlp \
 && chmod a+rx /usr/local/bin/yt-dlp

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .

ENV PORT=3000
EXPOSE 3000
CMD ["node", "server.js"]
