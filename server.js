import express from 'express';
import cors from 'cors';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createClient } from '@supabase/supabase-js';

const execFileP = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;
const ENABLE_UPSCALE = process.env.ENABLE_UPSCALE === '1';

// server-authoritative credit cost per tool (clients can't tamper with this)
const TOOL_COST = { downloader: 1 };

// Supabase — server side uses the SECRET service_role key (never in the frontend)
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';
const supabase = (SUPABASE_URL && SUPABASE_SERVICE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
  : null;

app.use(cors());
app.use(express.json({ limit: '16kb' }));

// serve the page (from ./public or next to this file)
const PUBLIC_DIR = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
  ? path.join(__dirname, 'public')
  : __dirname;
app.use(express.static(PUBLIC_DIR));
app.get('/', (_req, res) => {
  const idx = path.join(PUBLIC_DIR, 'index.html');
  return fs.existsSync(idx)
    ? res.sendFile(idx)
    : res.status(500).send('index.html not found — make sure public/index.html is in your repo.');
});

// temp workspace
const WORK = path.join(os.tmpdir(), 'ecdl');
fs.mkdirSync(WORK, { recursive: true });

// which platforms we accept, and what each costs
const TT_RE = /^https?:\/\/([a-z0-9-]+\.)?(tiktok\.com|vt\.tiktok\.com|vm\.tiktok\.com)\//i;
const YT_RE = /^https?:\/\/([a-z0-9-]+\.)?(youtube\.com|youtu\.be)\//i;
const IG_RE = /^https?:\/\/([a-z0-9-]+\.)?instagram\.com\//i;

function platformFor(url) {
  if (TT_RE.test(url)) return { name: 'tiktok', cost: 1 };
  if (YT_RE.test(url)) return { name: 'youtube', cost: 2 };
  if (IG_RE.test(url)) return { name: 'instagram', cost: 2 };
  return null;
}

// finished files, id -> { file, filename, mime, expires }
const store = new Map();
const TTL_MS = 10 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, rec] of store) {
    if (rec.expires < now) { fs.rm(rec.file, { force: true }, () => {}); store.delete(id); }
  }
}, 60_000).unref();

function ytdlp(args) {
  return execFileP('yt-dlp', args, { maxBuffer: 64 * 1024 * 1024, timeout: 120_000 });
}

// who is this request from? verify the Supabase access token, return the user or null
async function getUser(req) {
  if (!supabase) return null;
  const auth = req.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return null;
  const { data, error } = await supabase.auth.getUser(token);
  if (error) return null;
  return data.user || null;
}

app.post('/api/download', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });

    // 1) must be logged in
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    // 2) valid, supported link (tiktok / youtube / instagram)
    const { url, audioOnly } = req.body || {};
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: "paste a link first." });
    }
    const clean = url.trim();
    const platform = platformFor(clean);
    if (!platform) {
      return res.status(400).json({ error: "unsupported link — use TikTok, YouTube, or Instagram." });
    }

    // 3) metadata first — proves the video is real & reachable, so we don't
    //    charge a credit for dead / private links
    let meta = {};
    try {
      const { stdout } = await ytdlp(['-j', '--no-warnings', '--no-playlist', clean]);
      meta = JSON.parse(stdout.trim().split('\n')[0]);
    } catch {
      return res.status(422).json({ error: "couldn't reach that video — might be private or dead." });
    }

   // 4) spend this platform's credit cost atomically. false = not enough credits
    const cost = platform.cost;
    const { data: ok, error: cErr } = await supabase.rpc('spend_credits', { p_user: user.id, p_amount: cost });
    if (cErr) return res.status(500).json({ error: 'credit check failed — try again.' });
    if (!ok) return res.status(402).json({ error: 'out of credits' });

    // 5) download
    const id = randomUUID();
    const outTpl = path.join(WORK, `${id}.%(ext)s`);
    const base = ['--no-warnings', '--no-playlist', '--restrict-filenames',
                  '--force-overwrites', '--no-part', '-o', outTpl];
    const args = audioOnly
      ? [...base, '-x', '--audio-format', 'mp3', '--audio-quality', '0', clean]
      : [...base, '-S', 'res,fps,vcodec:h264,ext:mp4:m4a', '-f', 'bv*+ba/b', '--merge-output-format', 'mp4', clean];
    await ytdlp(args);

    const produced = (await fsp.readdir(WORK)).find((f) => f.startsWith(`${id}.`));
    if (!produced) throw new Error('download produced no file');
    let filePath = path.join(WORK, produced);

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
      file: filePath, filename,
      mime: audioOnly ? 'audio/mpeg' : 'video/mp4',
      expires: Date.now() + TTL_MS,
    });

    // remaining balance for the UI
    let creditsLeft = null;
    try {
      const { data: p } = await supabase.from('profiles').select('credits').eq('id', user.id).single();
      creditsLeft = p ? p.credits : null;
    } catch { /* non-fatal */ }

    res.json({
      url: `/api/file/${id}`,
      filename,
      title: meta.title || meta.description || 'untitled clip',
      author: meta.uploader || meta.creator || '',
      thumbnail: meta.thumbnail || '',
      creditsLeft,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "couldn't grab that one — try again." });
  }
});

app.get('/api/file/:id', (req, res) => {
  const rec = store.get(req.params.id);
  if (!rec || !fs.existsSync(rec.file)) return res.status(404).send('gone or expired');
  res.setHeader('Content-Type', rec.mime);
  res.setHeader('Content-Disposition', `attachment; filename="${rec.filename}"`);
  const s = fs.createReadStream(rec.file);
  s.pipe(res);
  res.on('finish', () => { fs.rm(rec.file, { force: true }, () => {}); store.delete(req.params.id); });
  s.on('error', () => res.destroy());
});

// redeem a coupon code for credits (server-authoritative, atomic in the DB)
app.post('/api/redeem', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });

    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    const { code } = req.body || {};
    if (!code || typeof code !== 'string' || !code.trim()) {
      return res.status(400).json({ error: 'enter a code.' });
    }

    const { data, error } = await supabase.rpc('redeem_coupon', {
      p_user: user.id,
      p_code: code.trim(),
    });
    if (error) return res.status(500).json({ error: 'redeem failed — try again.' });

    if (!data || !data.ok) {
      return res.status(400).json({ error: (data && data.error) || 'invalid code' });
    }
    return res.json({ creditsAdded: data.credits_added, balance: data.balance });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'redeem failed — try again.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, accounts: !!supabase }));
app.listen(PORT, () => console.log(`exposure club downloader running on :${PORT}`));
