import express from 'express';
import cors from 'cors';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID, createHmac, timingSafeEqual } from 'node:crypto';
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

// Paddle — webhook signature secret (from Paddle → Notifications → your destination)
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET || '';

// Anthropic (Claude) — powers the Hook Generator. Server-side only.
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const HOOK_COST = 3;                    // credits per generation (8 hooks)
const HOOK_MODEL = 'claude-haiku-4-5';  // cheapest/fast
const MAX_EXAMPLES_CHARS = 4000;

// UGC Script Generator
const SCRIPT_COST = 4;                   // credits per script (longer output)
const SCRIPT_MODEL = 'claude-haiku-4-5';
const MAX_TOPIC_CHARS = 600;

// AI Affiliate Advisor (chatbot Q&A)
const ADVISOR_COST = 1;                  // credits per question
const ADVISOR_MODEL = 'claude-sonnet-4-6';  // smarter answers for expert advice
const MAX_QUESTION_CHARS = 1500;

// Content Planner
const PLANNER_COST = 4;                   // credits per plan
const PLANNER_MODEL = 'claude-haiku-4-5';
const MAX_PLAN_TOPIC_CHARS = 600;
const ALLOWED_PLAN_DAYS = [3, 7, 14, 30];

app.use(cors());

// Paddle webhook MUST read the raw body to verify the signature,
// so it's registered with a raw parser BEFORE the global json middleware.
app.post('/api/paddle-webhook', express.raw({ type: '*/*', limit: '512kb' }), async (req, res) => {
  try {
    if (!supabase) return res.status(500).send('accounts not configured');
    if (!PADDLE_WEBHOOK_SECRET) { console.error('PADDLE_WEBHOOK_SECRET not set'); return res.status(500).send('webhook not configured'); }

    const raw = req.body; // Buffer
    const sigHeader = req.get('Paddle-Signature') || '';

    // header looks like: "ts=1699999999;h1=abcdef..."
    const parts = Object.fromEntries(sigHeader.split(';').map(kv => kv.split('=')));
    const ts = parts.ts, h1 = parts.h1;
    if (!ts || !h1) return res.status(400).send('bad signature header');

    // signed payload is "ts:rawBody"
    const signed = `${ts}:${raw.toString('utf8')}`;
    const expected = createHmac('sha256', PADDLE_WEBHOOK_SECRET).update(signed).digest('hex');

    // constant-time compare
    const a = Buffer.from(expected, 'hex'), b = Buffer.from(h1, 'hex');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      console.error('paddle signature mismatch');
      return res.status(401).send('bad signature');
    }

    const evt = JSON.parse(raw.toString('utf8'));
    const type = evt.event_type || '';
    const eventId = evt.event_id || evt.notification_id || '';
    const data = evt.data || {};

    // we grant credits when a transaction completes (covers both the first
    // subscription payment, each monthly renewal, AND one-time pack buys)
    if (type === 'transaction.completed') {
      // our Supabase user id was passed through at checkout as custom_data.user_id
      const userId = (data.custom_data && data.custom_data.user_id) || null;

      // each line item has a price id; grant for every known priced item
      const items = Array.isArray(data.items) ? data.items : [];
      const results = [];
      for (const it of items) {
        const priceId = (it.price && it.price.id) || it.price_id || null;
        if (!priceId) continue;
        // unique per (event, price) so multi-item carts don't collide in the ledger
        const grantEventId = `${eventId}:${priceId}`;
        const { data: r, error } = await supabase.rpc('grant_paddle_credits', {
          p_event_id: grantEventId, p_user: userId, p_price_id: priceId,
        });
        if (error) { console.error('grant rpc error', error); }
        results.push(r);
      }

      // track subscription id/status on the profile when present
      if (userId && data.subscription_id) {
        await supabase.from('profiles')
          .update({ paddle_subscription_id: data.subscription_id, paddle_status: 'active' })
          .eq('id', userId);
      }
      console.log('paddle transaction.completed granted:', JSON.stringify(results));
    } else if (type === 'subscription.canceled') {
      const userId = (data.custom_data && data.custom_data.user_id) || null;
      if (userId) await supabase.from('profiles').update({ paddle_status: 'canceled' }).eq('id', userId);
    }

    // always 200 fast so Paddle doesn't retry a handled event
    return res.status(200).send('ok');
  } catch (e) {
    console.error('paddle webhook error', e);
    return res.status(200).send('ok'); // swallow to avoid retry storms; we log it
  }
});

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
const IG_RE = /^https?:\/\/([a-z0-9-]+\.)?instagram\.com\//i;

function platformFor(url) {
  if (TT_RE.test(url)) return { name: 'tiktok', cost: 1 };
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

    // the function returns { ok, error?, credits_added?, balance? }
    if (!data || !data.ok) {
      return res.status(400).json({ error: (data && data.error) || 'invalid code' });
    }
    return res.json({ creditsAdded: data.credits_added, balance: data.balance });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'redeem failed — try again.' });
  }
});

app.post('/api/hooks', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'generator not configured yet.' });

    // 1) must be logged in
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    // 2) validate input
    const examples = (req.body && req.body.examples ? String(req.body.examples) : '').trim();
    if (!examples) return res.status(400).json({ error: 'add a few example hooks first — that\u2019s what it generates from.' });
    if (examples.length > MAX_EXAMPLES_CHARS) return res.status(400).json({ error: 'too many examples — trim it down a bit.' });

    // 3) spend credits up front (atomic). false = not enough
    const { data: ok, error: cErr } = await supabase.rpc('spend_credits', { p_user: user.id, p_amount: HOOK_COST });
    if (cErr) return res.status(500).json({ error: 'credit check failed — try again.' });
    if (!ok) return res.status(402).json({ error: 'out of credits' });

    // helper: give the credits back if the AI call fails, so nobody loses credits on our error
    const refund = async () => { try { await supabase.rpc('add_credits', { p_user: user.id, p_amount: HOOK_COST }); } catch (_) {} };

    const cleanExamples = examples
      .split('\n').filter((l) => l.trim()).map((l) => '- ' + l.trim()).join('\n');

    const prompt = `You are an elite TikTok organic copywriter. Below are example hooks that perform well. Study them extremely closely — their voice, rhythm, capitalization, slang, punctuation, length, and the structural patterns behind why they work.\n\nEXAMPLE HOOKS:\n${cleanExamples}\n\nNow generate 8 brand-new hooks that feel like they came from the exact same person who wrote those examples.\n\nRules:\n- Match the examples' DNA: same energy, same voice, same kind of structures and rhythm. If they're lowercase, you're lowercase.\n- Do NOT copy any example verbatim — these must be new.\n- Each hook is a scroll-stopping first line / text overlay. Native to TikTok, never salesy.\n- Vary the structure across the 8 so they don't all sound identical.\n- Keep each roughly the same length as the examples.\n- No hashtags. No emojis unless the examples use them.\n\nRespond ONLY with a JSON array of 8 strings, no preamble, no markdown, no backticks.`;

    let r;
    try {
      r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: HOOK_MODEL,
          max_tokens: 1000,
          messages: [{ role: 'user', content: prompt }],
        }),
      });
    } catch (e) {
      await refund();
      return res.status(502).json({ error: 'couldn\u2019t reach the generator. Try again — your credits were not charged.' });
    }

    if (!r.ok) {
      const errText = await r.text().catch(() => '');
      console.error('Anthropic API error:', errText);
      await refund();
      return res.status(502).json({ error: 'generation failed. Try again — your credits were not charged.' });
    }

    const data = await r.json();
    let text = (data.content || []).map((i) => (i.type === 'text' ? i.text : '')).join('');
    text = text.replace(/```json|```/g, '').trim();

    let hooks;
    try { hooks = JSON.parse(text); } catch (e) {
      await refund();
      return res.status(502).json({ error: 'got a malformed response. Try again — your credits were not charged.' });
    }
    if (!Array.isArray(hooks) || !hooks.length) {
      await refund();
      return res.status(502).json({ error: 'got an empty response. Try again — your credits were not charged.' });
    }

    // fresh balance so the UI updates
    let creditsLeft = null;
    try {
      const { data: prof } = await supabase.from('profiles').select('credits').eq('id', user.id).single();
      if (prof) creditsLeft = prof.credits;
    } catch (_) {}

    return res.json({ hooks, creditsLeft });
  } catch (e) {
    console.error('hooks handler error:', e);
    return res.status(500).json({ error: 'something went wrong. Try again.' });
  }
});

app.post('/api/script', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'generator not configured yet.' });

    // 1) must be logged in
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    // 2) validate input
    const topic = (req.body && req.body.topic ? String(req.body.topic) : '').trim();
    const vibe = (req.body && req.body.vibe ? String(req.body.vibe) : '').trim();
    const styleRaw = (req.body && req.body.style ? String(req.body.style) : 'faceless').trim().toLowerCase();
    const style = styleRaw === 'talking' ? 'talking' : 'faceless';
    if (!topic) return res.status(400).json({ error: 'tell it what the video is about first.' });
    if (topic.length > MAX_TOPIC_CHARS) return res.status(400).json({ error: 'keep the topic a bit shorter.' });
    if (vibe.length > MAX_TOPIC_CHARS) return res.status(400).json({ error: 'keep the vibe a bit shorter.' });

    // 3) spend credits up front (atomic)
    const { data: ok, error: cErr } = await supabase.rpc('spend_credits', { p_user: user.id, p_amount: SCRIPT_COST });
    if (cErr) return res.status(500).json({ error: 'credit check failed — try again.' });
    if (!ok) return res.status(402).json({ error: 'out of credits' });

    const refund = async () => { try { await supabase.rpc('add_credits', { p_user: user.id, p_amount: SCRIPT_COST }); } catch (_) {} };

    const styleLine = style === 'talking'
      ? 'STYLE: Talking-head UGC. A real person speaks to camera. Write it as natural spoken lines the creator says out loud — conversational, first-person, like they\u2019re talking to a friend.'
      : 'STYLE: Faceless voiceover. No person on camera. Write a voiceover narration meant to play over B-roll / slideshow images. Include brief [on-screen: ...] cues for what visual shows during each beat.';

    const vibeLine = vibe ? `\nVIBE / TONE: ${vibe}` : '';

    const prompt = `You are an elite short-form UGC scriptwriter for TikTok organic marketing. You write scripts that stop the scroll and drive action without feeling salesy.

${styleLine}

VIDEO TOPIC / OFFER: ${topic}${vibeLine}

Write ONE complete short-form video script (about 20-40 seconds spoken). Structure it clearly with these labeled beats:
- HOOK (first 1-2 lines — must stop the scroll instantly)
- BODY (2-4 short beats that build interest / show the value)
- CTA (a natural call to action — never pushy, native to TikTok)

Rules:
- Native TikTok voice. Casual, punchy, real. Never corporate or salesy.
- Keep total length realistic for 20-40 seconds of talking.
- ${style === 'talking' ? 'Write spoken lines only — what the person actually says.' : 'Write the voiceover lines, each with a short [on-screen: ...] visual cue.'}
- No hashtags. No emojis unless they fit the vibe.

Respond with ONLY the script, using the labeled beats above (HOOK / BODY / CTA). No preamble, no explanation, no markdown code fences.`;

    let r;
    try {
      r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: SCRIPT_MODEL,
          max_tokens: 1200,
          messages: [{ role: 'user', content: prompt }],
        }),
      });
    } catch (e) {
      await refund();
      return res.status(502).json({ error: 'couldn\u2019t reach the generator. Try again — your credits were not charged.' });
    }

    if (!r.ok) {
      const errText = await r.text().catch(() => '');
      console.error('Anthropic API error:', errText);
      await refund();
      return res.status(502).json({ error: 'generation failed. Try again — your credits were not charged.' });
    }

    const data = await r.json();
    let script = (data.content || []).map((i) => (i.type === 'text' ? i.text : '')).join('').trim();
    if (!script) {
      await refund();
      return res.status(502).json({ error: 'got an empty response. Try again — your credits were not charged.' });
    }

    let creditsLeft = null;
    try {
      const { data: prof } = await supabase.from('profiles').select('credits').eq('id', user.id).single();
      if (prof) creditsLeft = prof.credits;
    } catch (_) {}

    return res.json({ script, creditsLeft });
  } catch (e) {
    console.error('script handler error:', e);
    return res.status(500).json({ error: 'something went wrong. Try again.' });
  }
});

app.post('/api/advisor', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'advisor not configured yet.' });

    // 1) must be logged in
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    // 2) validate input
    const question = (req.body && req.body.question ? String(req.body.question) : '').trim();
    if (!question) return res.status(400).json({ error: 'ask a question first.' });
    if (question.length > MAX_QUESTION_CHARS) return res.status(400).json({ error: 'keep the question a bit shorter.' });

    // 3) spend credits up front (atomic)
    const { data: ok, error: cErr } = await supabase.rpc('spend_credits', { p_user: user.id, p_amount: ADVISOR_COST });
    if (cErr) return res.status(500).json({ error: 'credit check failed — try again.' });
    if (!ok) return res.status(402).json({ error: 'out of credits' });

    const refund = async () => { try { await supabase.rpc('add_credits', { p_user: user.id, p_amount: ADVISOR_COST }); } catch (_) {} };

    const system = `You are the Exposure Club AI Affiliate Advisor — a seasoned expert in affiliate and CPA marketing, especially TikTok organic. You know the space deeply: CPA networks, sweepstakes and CPI offers, faceless slideshow content, TikTok organic growth, traffic sources, offer selection, landing pages, compliance, tracking, and scaling. You advise like a sharp, experienced marketer talking to a fellow marketer — direct, practical, specific, no fluff.

Rules:
- Give actionable, specific advice — real tactics, not generic platitudes. Assume the person knows the basics.
- Match the casual, no-BS tone of the affiliate space. Be concise but complete.
- If something is risky, gray-hat, or against a network's/platform's terms, say so honestly rather than pretending — but still be helpful about legitimate approaches.
- Never help with anything outright illegal (fraud, fake leads, cookie stuffing, incentivized traffic where prohibited, etc.). Redirect to legitimate tactics.
- If a question is vague, give the best general answer AND note what detail would sharpen it.
- Format for readability: short paragraphs, and use bullet points when listing tactics or steps.`;

    let r;
    try {
      r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: ADVISOR_MODEL,
          max_tokens: 1500,
          system,
          messages: [{ role: 'user', content: question }],
        }),
      });
    } catch (e) {
      await refund();
      return res.status(502).json({ error: 'couldn\u2019t reach the advisor. Try again — your credits were not charged.' });
    }

    if (!r.ok) {
      const errText = await r.text().catch(() => '');
      console.error('Anthropic API error:', errText);
      await refund();
      return res.status(502).json({ error: 'the advisor failed. Try again — your credits were not charged.' });
    }

    const data = await r.json();
    let answer = (data.content || []).map((i) => (i.type === 'text' ? i.text : '')).join('').trim();
    if (!answer) {
      await refund();
      return res.status(502).json({ error: 'got an empty response. Try again — your credits were not charged.' });
    }

    let creditsLeft = null;
    try {
      const { data: prof } = await supabase.from('profiles').select('credits').eq('id', user.id).single();
      if (prof) creditsLeft = prof.credits;
    } catch (_) {}

    return res.json({ answer, creditsLeft });
  } catch (e) {
    console.error('advisor handler error:', e);
    return res.status(500).json({ error: 'something went wrong. Try again.' });
  }
});

// ---- Content Planner ----
// Generate a plan (spends credits), save it, and return it.
app.post('/api/plan/generate', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured on the server yet.' });
    if (!ANTHROPIC_API_KEY) return res.status(500).json({ error: 'planner not configured yet.' });

    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    const topic = (req.body && req.body.topic ? String(req.body.topic) : '').trim();
    let days = parseInt(req.body && req.body.days, 10);
    if (!topic) return res.status(400).json({ error: 'tell it what your content is about first.' });
    if (topic.length > MAX_PLAN_TOPIC_CHARS) return res.status(400).json({ error: 'keep the topic a bit shorter.' });
    if (!ALLOWED_PLAN_DAYS.includes(days)) days = 7;

    // spend credits up front
    const { data: ok, error: cErr } = await supabase.rpc('spend_credits', { p_user: user.id, p_amount: PLANNER_COST });
    if (cErr) return res.status(500).json({ error: 'credit check failed — try again.' });
    if (!ok) return res.status(402).json({ error: 'out of credits' });

    const refund = async () => { try { await supabase.rpc('add_credits', { p_user: user.id, p_amount: PLANNER_COST }); } catch (_) {} };

    const prompt = `You are an elite TikTok organic content strategist for affiliate/CPA marketers. Build a ${days}-day posting plan for this creator.

TOPIC / NICHE / OFFER: ${topic}

For each of the ${days} days, give 2 post ideas ("slots"). Each slot has:
- "text": the actual hook / concept for that post (a scroll-stopping idea they can shoot), written in casual TikTok voice
- "format": the content format (e.g. "faceless slideshow", "talking head", "green screen", "story time", "POV")

Vary formats and angles across the plan so it doesn't get repetitive. Keep each idea punchy and specific to the topic.

Respond ONLY with a JSON array of exactly ${days} objects, one per day, in this shape:
[{"day":1,"slots":[{"text":"...","format":"..."},{"text":"...","format":"..."}]}, ...]
No preamble, no markdown, no backticks.`;

    let r;
    try {
      r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: PLANNER_MODEL,
          max_tokens: 3000,
          messages: [{ role: 'user', content: prompt }],
        }),
      });
    } catch (e) {
      await refund();
      return res.status(502).json({ error: 'couldn\u2019t reach the planner. Try again — your credits were not charged.' });
    }

    if (!r.ok) {
      const errText = await r.text().catch(() => '');
      console.error('Anthropic API error:', errText);
      await refund();
      return res.status(502).json({ error: 'generation failed. Try again — your credits were not charged.' });
    }

    const data = await r.json();
    let text = (data.content || []).map((i) => (i.type === 'text' ? i.text : '')).join('');
    text = text.replace(/```json|```/g, '').trim();

    let rawDays;
    try { rawDays = JSON.parse(text); } catch (e) {
      await refund();
      return res.status(502).json({ error: 'got a malformed plan. Try again — your credits were not charged.' });
    }
    if (!Array.isArray(rawDays) || !rawDays.length) {
      await refund();
      return res.status(502).json({ error: 'got an empty plan. Try again — your credits were not charged.' });
    }

    // normalize into our stored shape: [{date, slots:[{text, format, posted}]}]
    const start = new Date();
    const planData = rawDays.slice(0, days).map((d, idx) => {
      const date = new Date(start);
      date.setDate(start.getDate() + idx);
      const slots = Array.isArray(d.slots) ? d.slots : [];
      return {
        date: date.toISOString().slice(0, 10),
        slots: slots.map((s) => ({
          text: String(s && s.text ? s.text : '').slice(0, 500),
          format: String(s && s.format ? s.format : '').slice(0, 60),
          posted: false,
        })),
      };
    });

    const title = topic.length > 48 ? topic.slice(0, 48) + '\u2026' : topic;

    const { data: inserted, error: insErr } = await supabase
      .from('content_plans')
      .insert({ user_id: user.id, title, days, topic, plan: planData })
      .select()
      .single();

    if (insErr) {
      console.error('plan insert error:', insErr);
      await refund();
      return res.status(500).json({ error: 'couldn\u2019t save the plan. Try again — your credits were not charged.' });
    }

    let creditsLeft = null;
    try {
      const { data: prof } = await supabase.from('profiles').select('credits').eq('id', user.id).single();
      if (prof) creditsLeft = prof.credits;
    } catch (_) {}

    return res.json({ plan: inserted, creditsLeft });
  } catch (e) {
    console.error('plan generate error:', e);
    return res.status(500).json({ error: 'something went wrong. Try again.' });
  }
});

// List the user's saved plans (newest first).
app.get('/api/plan/list', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured.' });
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });
    const { data, error } = await supabase
      .from('content_plans')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'couldn\u2019t load your plans.' });
    return res.json({ plans: data || [] });
  } catch (e) {
    console.error('plan list error:', e);
    return res.status(500).json({ error: 'something went wrong.' });
  }
});

// Toggle a single post slot's "posted" flag.
app.post('/api/plan/toggle', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured.' });
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    const planId = req.body && req.body.planId ? String(req.body.planId) : '';
    const dayIdx = parseInt(req.body && req.body.dayIdx, 10);
    const slotIdx = parseInt(req.body && req.body.slotIdx, 10);
    if (!planId || isNaN(dayIdx) || isNaN(slotIdx)) return res.status(400).json({ error: 'bad request.' });

    // load the plan (RLS ensures it's the user's own)
    const { data: row, error: getErr } = await supabase
      .from('content_plans').select('*').eq('id', planId).eq('user_id', user.id).single();
    if (getErr || !row) return res.status(404).json({ error: 'plan not found.' });

    const plan = Array.isArray(row.plan) ? row.plan : [];
    if (!plan[dayIdx] || !plan[dayIdx].slots || !plan[dayIdx].slots[slotIdx]) {
      return res.status(400).json({ error: 'slot not found.' });
    }
    plan[dayIdx].slots[slotIdx].posted = !plan[dayIdx].slots[slotIdx].posted;

    const { error: updErr } = await supabase
      .from('content_plans').update({ plan }).eq('id', planId).eq('user_id', user.id);
    if (updErr) return res.status(500).json({ error: 'couldn\u2019t update.' });

    return res.json({ ok: true, posted: plan[dayIdx].slots[slotIdx].posted });
  } catch (e) {
    console.error('plan toggle error:', e);
    return res.status(500).json({ error: 'something went wrong.' });
  }
});

// Delete a plan.
app.post('/api/plan/delete', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured.' });
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });
    const planId = req.body && req.body.planId ? String(req.body.planId) : '';
    if (!planId) return res.status(400).json({ error: 'bad request.' });
    const { error } = await supabase
      .from('content_plans').delete().eq('id', planId).eq('user_id', user.id);
    if (error) return res.status(500).json({ error: 'couldn\u2019t delete.' });
    return res.json({ ok: true });
  } catch (e) {
    console.error('plan delete error:', e);
    return res.status(500).json({ error: 'something went wrong.' });
  }
});

// Add the user's own custom hook/post slot to a day (free — no credits).
app.post('/api/plan/add-slot', async (req, res) => {
  try {
    if (!supabase) return res.status(500).json({ error: 'accounts not configured.' });
    const user = await getUser(req);
    if (!user) return res.status(401).json({ error: 'please log in.' });

    const planId = req.body && req.body.planId ? String(req.body.planId) : '';
    const dayIdx = parseInt(req.body && req.body.dayIdx, 10);
    const text = (req.body && req.body.text ? String(req.body.text) : '').trim();
    const format = (req.body && req.body.format ? String(req.body.format) : '').trim();
    if (!planId || isNaN(dayIdx)) return res.status(400).json({ error: 'bad request.' });
    if (!text) return res.status(400).json({ error: 'type your hook first.' });
    if (text.length > 500) return res.status(400).json({ error: 'keep it shorter.' });

    const { data: row, error: getErr } = await supabase
      .from('content_plans').select('*').eq('id', planId).eq('user_id', user.id).single();
    if (getErr || !row) return res.status(404).json({ error: 'plan not found.' });

    const plan = Array.isArray(row.plan) ? row.plan : [];
    if (!plan[dayIdx]) return res.status(400).json({ error: 'day not found.' });
    if (!Array.isArray(plan[dayIdx].slots)) plan[dayIdx].slots = [];
    plan[dayIdx].slots.push({ text, format: format.slice(0, 60), posted: false, custom: true });

    const { error: updErr } = await supabase
      .from('content_plans').update({ plan }).eq('id', planId).eq('user_id', user.id);
    if (updErr) return res.status(500).json({ error: 'couldn\u2019t save.' });

    return res.json({ ok: true });
  } catch (e) {
    console.error('plan add-slot error:', e);
    return res.status(500).json({ error: 'something went wrong.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true, accounts: !!supabase }));
app.listen(PORT, () => console.log(`exposure club downloader running on :${PORT}`));
