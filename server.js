import express from 'express';
import cors from 'cors';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const execFileP = promisify(execFile);

const app = express();
const PORT = process.env.PORT || 3000;
// Flip on (ENABLE_UPSCALE=1) to double video dimensions with lanczos.
// NOTE: this is interpolation, NOT true super-resolution — bigger file, not more detail.
const ENABLE_UPSCALE = process.env.ENABLE_UPSCALE === '1';

// Set ACCESS_CODE in your host's env to lock the tool behind a shared club code.
// Leave it unset and the tool stays open to anyone with the link.
const ACCESS_CODE = process.env.ACCESS_CODE || '';

function codeMatches(provided) {
  if (!ACCESS_CODE) return true;             // no code configured → open
  if (typeof provided !== 'string') return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(ACCESS_CODE);
  return a.length === b.length && timingSafeEqual(a, b); // constant-time
}

app.use(cors());
app.use(express.json({ limit: '16kb' }));
// Find index.html whether it's in ./public or sitting next to server.js,
// and use a path anchored to this file (not the process working dir).
const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
  ? path.join(__dirname, 'public')
  : __dirname;

app.use(express.static(PUBLIC_DIR)); // serves index.html at /

app.get('/', (_req, res) => {
  const idx = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(idx)) return res.sendFile(idx);
  res.status(500).send('index.html not found — make sure public/index.html is in your repo.');
});

// temp workspace
const WORK = path.join(os.tmpdir(), 'ecdl');
fs.mkdirSync(WORK, { recursive: true });

// only accept real tiktok links
const TT_RE = /^https?:\/\/([a-z0-9-]+\.)?(tiktok\.com|vt\.tiktok\.com|vm\.tiktok\.com)\//i;

// id -> { file, filename, mime, expires }
const store = new Map();
const TTL_MS = 10 * 60 * 1000;

// sweep abandoned files every minute
setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of store) {
    if (rec.expires < now) {
      fs.rm(rec.file, { force: true }, () => {});
      store.delete(id);
    }
  }
}, 60_000).unref();

function ytdlp(args) {
  return execFileP('yt-dlp', args, { maxBuffer: 64 * 1024 * 1024, timeout: 120_000 });
}

// verify the club code (also tells the page whether a code is even required)
app.post('/api/auth', (req, res) => {
  const { code } = req.body || {};
  if (!ACCESS_CODE) return res.json({ ok: true, open: true }); // no gate configured
  if (codeMatches(code)) return res.json({ ok: true });
  return res.status(401).json({ ok: false, error: 'wrong code.' });
});

app.post('/api/download', async (req, res) => {
  try {
    if (!codeMatches(req.get('x-access-code'))) {
      return res.status(401).json({ error: 'locked — enter the club code.' });
    }
    const { url, audioOnly } = req.body || {};
    if (!url || typeof url !== 'string' || !TT_RE.test(url.trim())) {
      return res.status(400).json({ error: "that's not a valid tiktok url." });
    }
    const clean = url.trim();

    // 1) metadata first (fast, no download)
    let meta = {};
    try {
      const { stdout } = await ytdlp(['-j', '--no-warnings', '--no-playlist', clean]);
      meta = JSON.parse(stdout.trim().split('\n')[0]);
    } catch { /* best-effort — keep going even if metadata fails */ }

    const id = randomUUID();
    const outTpl = path.join(WORK, `${id}.%(ext)s`);
    const base = ['--no-warnings', '--no-playlist', '--restrict-filenames',
                  '--force-overwrites', '--no-part', '-o', outTpl];

    // 2) download — audio (mp3) or best-quality clean mp4
    const args = audioOnly
      ? [...base, '-x', '--audio-format', 'mp3', '--audio-quality', '0', clean]
      : [...base,
         // sort so the HIGHEST resolution / fps / h264-mp4 wins → best real quality
         '-S', 'res,fps,vcodec:h264,ext:mp4:m4a',
         '-f', 'bv*+ba/b',
         '--merge-output-format', 'mp4',
         clean];

    await ytdlp(args);

    // locate what yt-dlp produced
    const produced = (await fsp.readdir(WORK)).find((f) => f.startsWith(`${id}.`));
    if (!produced) throw new Error('download produced no file');
    let filePath = path.join(WORK, produced);

    // optional interpolated 2x upscale (video only) — off by default
    if (!audioOnly && ENABLE_UPSCALE) {
      const up = path.join(WORK, `${id}.up.mp4`);
      await execFileP('ffmpeg',
        ['-y', '-i', filePath, '-vf', 'scale=iw*2:ih*2:flags=lanczos', '-c:a', 'copy', up],
        { timeout: 180_000, maxBuffer: 64 * 1024 * 1024 });
      fs.rm(filePath, { force: true }, () => {});
      filePath = up;
    }

    const ext = audioOnly ? 'mp3' : 'mp4';
    const author = (meta.uploader || meta.creator || 'exposure-club')
      .toString().replace(/[^a-z0-9_-]+/gi, '_').slice(0, 40) || 'exposure-club';
    const filename = `${author}_${id.slice(0, 6)}.${ext}`;

    store.set(id, {
      file: filePath,
      filename,
      mime: audioOnly ? 'audio/mpeg' : 'video/mp4',
      expires: Date.now() + TTL_MS,
    });

    res.json({
      url: `/api/file/${id}`,
      filename,
      title: meta.title || meta.description || 'untitled clip',
      author: meta.uploader || meta.creator || '',
      thumbnail: meta.thumbnail || '',
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "couldn't grab that one — link might be private or dead." });
  }
});

// stream the finished file, then clean it up
app.get('/api/file/:id', (req, res) => {
  const rec = store.get(req.params.id);
  if (!rec || !fs.existsSync(rec.file)) return res.status(404).send('gone or expired');

  res.setHeader('Content-Type', rec.mime);
  res.setHeader('Content-Disposition', `attachment; filename="${rec.filename}"`);

  const stream = fs.createReadStream(rec.file);
  stream.pipe(res);
  res.on('finish', () => {
    fs.rm(rec.file, { force: true }, () => {});
    store.delete(req.params.id);
  });
  stream.on('error', () => res.destroy());
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`exposure club downloader running on :${PORT}`));
