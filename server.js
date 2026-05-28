// Grooviq Cloud Stream Proxy
// Deployed on the VPS at 187.77.179.145:4568
//
// Gives every Android user (any WiFi, any country) the same track quality as
// the desktop app — full-length official recordings, not 30s previews.
//
// Endpoints:
//   GET /ping?token=...                                 → { ok: true }
//   GET /stream?token=...&title=...&artist=...&...      → { url, duration, headers }
//   GET /saavn?token=...&title=...&artist=...           → { results: [...] }
//
// Auth: all endpoints require ?token=<CLOUD_TOKEN>
// Token is hardcoded in the Android APK — acceptable for a test deployment.
// Change CLOUD_TOKEN env var to rotate without rebuilding the server.

import http   from 'http';
import https  from 'https';
import crypto from 'crypto';
import { parse as parseUrl } from 'url';
import { Innertube } from 'youtubei.js';

// Render.com sets $PORT automatically (usually 10000). On other hosts use 4568.
const PORT         = parseInt(process.env.PORT  || '4568', 10);
const CLOUD_TOKEN  = process.env.CLOUD_TOKEN    || 'grooviq-cloud-2026';

// ── Rate limiting ─────────────────────────────────────────────────────────────
const _rateMap = new Map();
function _checkRateLimit(ip, max = 60) {
  const now = Date.now();
  let e = _rateMap.get(ip);
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + 60_000 }; _rateMap.set(ip, e); }
  return ++e.count <= max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of _rateMap) { if (now > v.resetAt) _rateMap.delete(k); }
}, 60_000);

// ── JioSaavn DES-ECB decryption ───────────────────────────────────────────────
// JioSaavn encrypts media URLs with DES-ECB key '38346591'.
// React Native has no native DES crypto module; the proxy handles it here.
function _decryptSaavnUrl(encrypted) {
  try {
    const key  = Buffer.from('38346591');
    const data = Buffer.from(encrypted, 'base64');
    const d    = crypto.createDecipheriv('des-ecb', key, Buffer.alloc(0));
    d.setAutoPadding(false);
    const dec = Buffer.concat([d.update(data), d.final()]);
    return dec.toString('utf8').replace(/\0+$/, '').trim().replace(/^http:/, 'https:');
  } catch (e) {
    console.warn('[saavn] decrypt error:', e.message);
    return '';
  }
}

// ── YouTube InnerTube client ──────────────────────────────────────────────────
let _ytClient = null;
let _ytInitPromise = null;
async function getYtClient() {
  if (_ytClient) return _ytClient;
  if (_ytInitPromise) return _ytInitPromise;
  _ytInitPromise = Innertube.create({ gl: 'US', hl: 'en' }).then(c => {
    _ytClient = c;
    console.log('[yt] InnerTube client ready (gl=US)');
    return c;
  });
  _ytInitPromise.catch(() => { _ytInitPromise = null; });
  return _ytInitPromise;
}

// ── Content filters (same as PC app) ─────────────────────────────────────────
const REJECT_WORDS = [
  'instrumental', 'karaoke', 'backing track', 'minus one', 'cover version',
  '(slowed)', '(sped up)', 'sped up', 'slowed', 'reverb', 'lofi', 'lo-fi',
  'nightcore', 'pitched', '8d audio', 'bass boosted',
  'clean version', 'clean edit', 'clean audio', 'clean mix',
  'radio edit', 'radio version', 'radio mix',
  'edited version', 'edited audio', '(clean)', '[clean]', '- clean', '- radio edit',
];
function isBad(rt = '', qt = '') {
  rt = rt.toLowerCase(); qt = qt.toLowerCase();
  return REJECT_WORDS.some(w => rt.includes(w) && !qt.includes(w));
}
function artistOk(got = '', want = '') {
  if (!got || !want) return true;
  const words = want.toLowerCase().split(/[\s,&]+/).filter(w => w.length > 2);
  return !words.length || words.some(w => got.toLowerCase().includes(w));
}
function durOk(got, want) {
  if (!got || !want) return true;
  return Math.abs(got - want) <= Math.max(30, Math.round(want * 0.1));
}
function bestAudio(info) {
  const af = info.streaming_data?.adaptive_formats ?? [];
  const ao = af.filter(f => f.mime_type?.includes('audio') && !f.mime_type?.includes('video') && f.url);
  return ao.find(f => f.mime_type?.startsWith('audio/mp4')) ||
         ao.find(f => f.mime_type?.startsWith('audio/'));
}
const YT_HEADERS = {
  'User-Agent': 'com.google.android.youtube/19.09.37 (Linux; U; Android 14) gzip',
  'Origin':     'https://www.youtube.com',
  'Referer':    'https://www.youtube.com/',
};

// ── HTTPS helper ──────────────────────────────────────────────────────────────
function httpsGetJson(url, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, {
      headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36', ...extraHeaders },
    }, r => {
      let b = '';
      r.on('data', d => b += d);
      r.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    req.setTimeout(12000, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const clientIp = req.socket.remoteAddress || '';

  if (!_checkRateLimit(clientIp)) {
    res.writeHead(429);
    res.end(JSON.stringify({ error: 'Rate limit — wait 60s' }));
    return;
  }

  const parsed = parseUrl(req.url, true);
  const q      = parsed.query;

  // All endpoints require the shared token
  if (q.token !== CLOUD_TOKEN) {
    res.writeHead(401);
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  // ── /ping ────────────────────────────────────────────────────────────────
  if (parsed.pathname === '/ping') {
    res.writeHead(200);
    res.end(JSON.stringify({ ok: true, app: 'Grooviq Cloud' }));
    return;
  }

  // ── /saavn ───────────────────────────────────────────────────────────────
  if (parsed.pathname === '/saavn') {
    const sq    = `${q.title || ''} ${q.artist || ''}`.trim();
    const limit = Math.min(parseInt(q.limit || '5', 10), 10);
    try {
      const saavnData = await httpsGetJson(
        `https://www.jiosaavn.com/api.php?__call=search.getResults&_format=json&_marker=0&api_version=4&ctx=android&query=${encodeURIComponent(sq)}&n=${limit}&p=1`,
      );
      const items   = saavnData.results || [];
      const results = [];
      for (const item of items.slice(0, limit)) {
        const enc = item.encrypted_media_url || '';
        const url = enc ? _decryptSaavnUrl(enc) : '';
        if (!url) continue;
        results.push({
          title:    item.song || item.title || '',
          artist:   item.primary_artists || item.singers || '',
          duration: parseInt(item.duration || '0', 10) || 0,
          url,
          is320:    item['320kbps']       === 'true',
          explicit: item.explicit_content === '1',
        });
      }
      console.log(`[saavn] "${sq}" → ${results.length} results`);
      res.writeHead(200);
      res.end(JSON.stringify({ results }));
    } catch (e) {
      console.error('[saavn] error:', e.message);
      res.writeHead(502);
      res.end(JSON.stringify({ results: [], error: e.message }));
    }
    return;
  }

  // ── /stream ──────────────────────────────────────────────────────────────
  if (parsed.pathname !== '/stream') {
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'Not found. Use /stream, /saavn, or /ping' }));
    return;
  }

  const rawId       = (q.id       || '').trim();
  const title       = (q.title    || '').trim();
  const artist      = (q.artist   || '').trim();
  const isrc        = (q.isrc     || '').trim();
  const expectedDur = parseInt(q.duration, 10) || 0;
  const isYtId      = /^[A-Za-z0-9_-]{11}$/.test(rawId);

  function sendStream(videoId, url, duration, source) {
    console.log(`[cloud] ✓ "${title}" → ${source} (${duration}s)`);
    res.writeHead(200);
    res.end(JSON.stringify({ url, duration, videoId, headers: YT_HEADERS, source: source || 'youtube-cloud' }));
  }

  try {
    const yt = await getYtClient();

    // Direct lookup when a real YouTube video ID was supplied
    if (isYtId) {
      const info   = await yt.getBasicInfo(rawId, { client: 'ANDROID' });
      const format = bestAudio(info);
      if (!format?.url) {
        res.writeHead(404); res.end(JSON.stringify({ error: 'No audio format for supplied videoId' })); return;
      }
      sendStream(rawId, format.url, info.basic_info?.duration ?? expectedDur, 'youtube-direct');
      return;
    }

    // Search YouTube Music — ISRC first (most precise), then title+artist
    const queries = isrc ? [isrc, `${title} ${artist}`] : [`${title} ${artist}`];
    let songs = [];
    for (const sq of queries) {
      console.log('[cloud] YTM search:', sq);
      const r = await yt.music.search(sq, { type: 'song' });
      songs = Array.from(r.songs?.contents || []);
      if (songs.length) break;
    }

    if (!songs.length) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'No YTM search results' }));
      return;
    }

    // Candidate scoring — same logic as PC app
    let bestCandidate = null;
    let bestScore     = -1;

    for (const song of songs.slice(0, 5)) {
      const sid = song.id;
      if (!sid) continue;

      if (isBad(song.title ?? '', title)) {
        console.log(`[cloud] rejected "${song.title}" (bad filter)`); continue;
      }

      const songArtists = (song.artists ?? []).map(a => a.name ?? '').join(', ');
      if (!artistOk(songArtists, artist)) {
        console.log(`[cloud] artist mismatch: want "${artist}", got "${songArtists}"`); continue;
      }

      const info = await yt.getBasicInfo(sid, { client: 'ANDROID' });
      const dur  = info.basic_info?.duration ?? 0;
      if (!durOk(dur, expectedDur)) {
        console.log(`[cloud] duration mismatch: want ~${expectedDur}s, got ${dur}s`); continue;
      }

      const format = bestAudio(info);
      if (!format?.url) continue;

      const author     = info.basic_info?.author ?? '';
      const videoTitle = (info.basic_info?.title ?? song.title ?? '').toLowerCase();
      const mvType     = info.basic_info?.music_video_type ?? '';

      // Topic channel → auto-generated official recording, return immediately
      if (author.endsWith(' - Topic')) {
        sendStream(sid, format.url, dur, 'youtube-topic'); return;
      }

      // Art Track (AUD_TRACK) → can ONLY be created by a label, same reliability as Topic
      if (mvType === 'MUSIC_VIDEO_TYPE_AUD_TRACK') {
        sendStream(sid, format.url, dur, 'youtube-art-track'); return;
      }

      let score = 0;
      if (mvType === 'MUSIC_VIDEO_TYPE_OFFICIAL_SOURCE_MUSIC') score += 65;
      if (/\(official\s*(audio|video|music\s*video|lyric\s*video)\)/i.test(videoTitle) ||
          /\[official\s*(audio|video|music\s*video)\]/i.test(videoTitle) ||
          videoTitle.includes('(official)') || videoTitle.includes('[official]')) score += 50;
      if (author && artistOk(author, artist)) score += 20;

      if (score > bestScore) {
        bestCandidate = { url: format.url, duration: dur, videoId: sid };
        bestScore = score;
        const tag = score >= 65 ? '✓ official MV' : score >= 50 ? '✓ official release' : score >= 20 ? '✓ artist channel' : 'candidate';
        console.log(`[cloud] ${tag} (score ${score}) "${author}": "${title}"`);
      }
    }

    if (bestCandidate) {
      sendStream(bestCandidate.videoId, bestCandidate.url, bestCandidate.duration, 'youtube-cloud');
      return;
    }

    console.warn(`[cloud] no verified candidate for: "${title}" by "${artist}"`);
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'No verified YTM candidate found' }));

  } catch (err) {
    console.error('[cloud] /stream error:', err.message);
    res.writeHead(500);
    res.end(JSON.stringify({ error: err.message }));
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🎵 Grooviq Cloud Stream Proxy`);
  console.log(`   http://0.0.0.0:${PORT}/stream?token=...`);
  console.log(`   Token: ${CLOUD_TOKEN}\n`);
  // Pre-warm the YouTube client so the first request isn't slow
  getYtClient().catch(e => console.error('[yt] pre-warm failed:', e.message));
});

server.on('error', e => console.error('[cloud] server error:', e.message));
