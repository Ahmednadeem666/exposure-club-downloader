# Exposure Club — Video Downloader

Paste a TikTok link → get a clean, no-watermark **mp4** (or **mp3** audio-only).
Front end + backend ship together, so there's no CORS setup and nothing extra to host.

```
exposure-club-downloader/
├─ public/
│  └─ index.html      # the page members see
├─ server.js          # Express + yt-dlp
├─ package.json
├─ Dockerfile         # installs yt-dlp + ffmpeg
└─ README.md
```

## What it does
- **Best real quality** — sorts for the highest resolution TikTok actually serves (no watermark).
- **Audio only** — the `audio only` chip pulls an mp3 instead.
- **Auto-cleanup** — files are deleted right after download (and swept after 10 min).

## Deploy in ~3 minutes (Render)
1. Push this folder to a GitHub repo.
2. Go to Render → **New → Web Service** → connect the repo.
3. Render detects the `Dockerfile` automatically — leave build/start blank.
4. Deploy. When it's live, open the URL — the page is served at `/`.

Railway/Fly.io work the same way (both read the Dockerfile).

## Local run (need yt-dlp + ffmpeg installed)
```bash
npm install
npm start
# open http://localhost:3000
```

## Going live: flip the page out of demo mode
Open `public/index.html`, find the CONFIG block near the bottom, set:
```js
const DEMO = false;   // talk to the real backend
```
Since the backend serves the page, leave `API_BASE = ""` (same origin). Only set
`API_BASE` to a full URL if you host the page somewhere separate from the server.

## Lock it to the club (access code)
Set an env var on your host:
```
ACCESS_CODE=whatever-you-pick
```
Members hit a lock screen, type the code once, and they're in (it's remembered for
their session). Drop the code in a members-only Discord channel and change it anytime
by updating the env var and redeploying. Leave `ACCESS_CODE` unset and the tool stays open.

> Previewing `index.html` locally? It runs in demo mode and the code is **`exposure`**.

## Optional: 2x upscale
Set env var `ENABLE_UPSCALE=1` to double video dimensions (lanczos).
Heads up: this is **interpolation, not true super-resolution** — bigger file,
not sharper footage. Off by default.

## Notes
- yt-dlp is fetched fresh in the Docker build; if TikTok changes something, redeploy to grab the latest.
- Keep this an internal club tool — only download content you have the right to use.
