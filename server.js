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
  const result = got.toLowerCase();
  const words = want.toLowerCase().split(/[\s,&]+/).filter(w => w.length > 2);
  // Word-boundary match: "Bien" must NOT match "Bienvenido" or "Ambience"
  return !words.length || words.some(w => {
    try { return new RegExp(`\\b${w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`).test(result); }
    catch (_) { return result.includes(w); }
  });
}
// Extract every artist name from a track: primary + any "feat." partners in the title.
// "Finale" by Bien ft. Alikiba  →  ["bien", "alikiba"]
function extractAllArtists(trackTitle = '', trackArtist = '') {
  const words = new Set();
  const esc = w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  (trackArtist)
    .split(/\s*(?:ft\.?|feat\.?|featuring|&|,|×)\s*/i)
    .flatMap(a => a.trim().split(/\s+/))
    .filter(w => w.length > 2)
    .forEach(w => words.add(esc(w.toLowerCase())));
  const fm = trackTitle.match(/(?:feat\.?|ft\.?|featuring)\s+([^)\]]+)/i);
  if (fm) fm[1].split(/[\s,&]+/).filter(w => w.length > 2)
    .forEach(w => words.add(esc(w.toLowerCase())));
  return [...words];
}
function durOk(got, want) {
  if (!got || !want) return true;
  return Math.abs(got - want) <= Math.max(30, Math.round(want * 0.1));
}
// Positive title match: ≥60% of significant words from expected must appear in result.
// Prevents accepting a completely different song just because it's not karaoke.
function titleOk(result = '', expected = '') {
  if (!result || !expected) return true;
  const clean = s => s.toLowerCase().replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim();
  const rt = clean(result), et = clean(expected);
  if (rt.includes(et) || et.includes(rt)) return true;
  const words = et.split(' ').filter(w => w.length > 2);
  if (!words.length) return true;
  return words.filter(w => rt.includes(w)).length / words.length >= 0.6;
}
function bestAudio(info) {
  const af = info.streaming_data?.adaptive_formats ?? [];
  const ao = af.filter(f => f.mime_type?.includes('audio') && !f.mime_type?.includes('video') && f.url);
  return ao.find(f => f.mime_type?.startsWith('audio/mp4')) ||
         ao.find(f => f.mime_type?.startsWith('audio/'));
}
// Try IOS → TV_EMBEDDED → ANDROID — avoids SABR (no direct URL) on ANDROID client
async function getAudioFormat(yt, videoId) {
  for (const client of ['IOS', 'TV_EMBEDDED', 'ANDROID']) {
    try {
      const info = await yt.getBasicInfo(videoId, { client });
      const fmt  = bestAudio(info);
      if (fmt?.url) return { info, fmt };
    } catch (e) {
      console.warn(`[cloud] ${client} client error for ${videoId}:`, e.message);
    }
  }
  return null;
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

// ── Share landing page ────────────────────────────────────────────────────────
// Served at /s?title=…&artist=…&art=… — opens the app via grooviq:// or offers
// the APK download. APK is downloaded from /grooviq.apk (served by Render static
// or, until then, the GitHub release asset linked below).
const APK_URL = 'https://github.com/Seinex/grooviq-proxy/releases/latest/download/Grooviq.apk';
function esc(s = '') {
  return String(s).replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function landingHtml(title, artist, art) {
  const t = esc(title), a = esc(artist), img = esc(art);
  const deep = `grooviq://track?title=${encodeURIComponent(title)}&artist=${encodeURIComponent(artist)}`;
  return `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<title>${t ? t + ' — Grooviq' : 'Grooviq'}</title>
<style>
:root{--bg:#121212;--bg2:#1f1f1f;--green:#1ED760;--white:#fff;--muted:#b3b3b3}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html,body{margin:0;height:100%;background:var(--bg);color:var(--white);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:32px 24px}
.logo{width:72px;height:72px;border-radius:50%;background:var(--green);display:flex;align-items:center;justify-content:center;margin-bottom:18px}
.logo svg{width:38px;height:38px}
.brand{font-size:30px;font-weight:900;letter-spacing:.5px;margin:0 0 6px}
.art{width:200px;height:200px;border-radius:10px;object-fit:cover;margin:24px 0 18px;box-shadow:0 12px 40px rgba(0,0,0,.6);background:var(--bg2)}
.title{font-size:22px;font-weight:800;margin:0 0 4px}
.artist{font-size:15px;color:var(--muted);margin:0 0 28px}
.btn{display:block;width:100%;max-width:340px;padding:15px 24px;border-radius:28px;font-size:16px;font-weight:800;text-decoration:none;border:none;cursor:pointer}
.btn-primary{background:var(--green);color:#000;margin-bottom:14px}
.btn-ghost{background:transparent;color:var(--white);border:1px solid #7c7c7c}
.hint{color:var(--muted);font-size:13px;margin-top:22px;max-width:320px;line-height:1.5}
.foot{color:#535353;font-size:12px;margin-top:34px}
</style></head><body><div class="wrap">
<div class="logo"><svg viewBox="0 0 24 24" fill="#121212"><path d="M12 3v10.55A4 4 0 1 0 14 17V7h4V3h-6z"/></svg></div>
<h1 class="brand">Grooviq</h1>
${img ? `<img class="art" src="${img}" alt=""/>` : ''}
${t ? `<div class="title">${t}</div>` : ''}
${a ? `<div class="artist">${a}</div>` : ''}
<a id="open" class="btn btn-primary" href="${deep}">Open in Grooviq</a>
<a class="btn btn-ghost" href="${APK_URL}">Get the app (free)</a>
<p class="hint">Have Grooviq? It should open automatically. New here? Tap <b>Get the app</b> to install.</p>
<div class="foot">Your global music radar.</div>
</div><script>
var isMobile=/Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
if(isMobile && ${t ? 'true' : 'false'}){setTimeout(function(){window.location.href=${JSON.stringify(deep)};},400);}
</script></body></html>`;
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

  // ── /s — public share landing page (NO token; this is meant to be shared) ──
  // grooviq://… deep links aren't clickable in most chat apps and do nothing for
  // people without the app. A shared song points here instead: the page tries to
  // open Grooviq, and falls back to the APK download for newcomers.
  if (parsed.pathname === '/s' || parsed.pathname === '/') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.writeHead(200);
    res.end(landingHtml(q.title || '', q.artist || '', q.art || ''));
    return;
  }

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
      const result = await getAudioFormat(yt, rawId);
      if (!result?.fmt?.url) {
        res.writeHead(404); res.end(JSON.stringify({ error: 'No audio format for supplied videoId' })); return;
      }
      sendStream(rawId, result.fmt.url, result.info.basic_info?.duration ?? expectedDur, 'youtube-direct');
      return;
    }

    // ── Phase 1: YouTube Music catalog (song + video types) ──────────────────
    // Search both 'song' AND 'video' — East African / regional artists are often
    // catalogued only as 'video' type in YTM. ISRC query first (globally unique).
    const queries = isrc ? [isrc, `${title} ${artist}`] : [`${title} ${artist}`, `${title} ${artist} official`];
    let songs = [];
    for (const sq of queries) {
      console.log('[cloud] YTM search:', sq);
      const [songRes, videoRes] = await Promise.allSettled([
        yt.music.search(sq, { type: 'song'  }),
        yt.music.search(sq, { type: 'video' }),
      ]);
      const songItems  = songRes.status  === 'fulfilled' ? Array.from(songRes.value.songs?.contents  || []) : [];
      const videoItems = videoRes.status === 'fulfilled' ? Array.from(videoRes.value.videos?.contents || []) : [];
      songs = [...songItems, ...videoItems];
      if (songs.length) { console.log(`[cloud] "${sq}" → ${songs.length} candidates`); break; }
    }

    // Candidate scoring — same logic as Android app
    let bestCandidate = null;
    let bestScore     = -1;

    for (const song of songs.slice(0, 8)) {
      const sid = song.id;
      if (!sid) continue;

      // Positive title match — reject completely different songs
      if (!titleOk(song.title ?? '', title)) {
        console.log(`[cloud] title mismatch: want "${title}", got "${song.title}"`); continue;
      }
      if (isBad(song.title ?? '', title)) {
        console.log(`[cloud] rejected "${song.title}" (bad filter)`); continue;
      }

      // Artist match on catalog metadata (includes ALL artists: "Bien, Alikiba")
      const songArtists = (song.artists ?? []).map(a => a.name ?? '').join(', ');
      if (songArtists && !artistOk(songArtists, artist)) {
        console.log(`[cloud] artist mismatch: want "${artist}", got "${songArtists}"`); continue;
      }

      const result = await getAudioFormat(yt, sid);
      if (!result) { console.warn(`[cloud] no CDN URL for ${sid} (all clients exhausted)`); continue; }
      const { info, fmt: format } = result;

      const dur = info.basic_info?.duration ?? 0;
      if (!durOk(dur, expectedDur)) {
        console.log(`[cloud] duration mismatch: want ~${expectedDur}s, got ${dur}s`); continue;
      }

      const author     = info.basic_info?.author ?? '';
      const videoTitle = (info.basic_info?.title ?? song.title ?? '').toLowerCase();
      const mvType     = info.basic_info?.music_video_type ?? '';

      // Topic / Art Track → official label delivery, return immediately
      if (author.endsWith(' - Topic')) {
        sendStream(sid, format.url, dur, 'youtube-topic'); return;
      }
      if (mvType === 'MUSIC_VIDEO_TYPE_AUD_TRACK') {
        sendStream(sid, format.url, dur, 'youtube-art-track'); return;
      }

      let score = 0;
      if (mvType === 'MUSIC_VIDEO_TYPE_OFFICIAL_SOURCE_MUSIC') score += 65;
      if (/\(official\s*(audio|video|music\s*video|lyric\s*video)\)/i.test(videoTitle) ||
          videoTitle.includes('(official)') || videoTitle.includes('[official]')) score += 50;
      if (author && artistOk(author, artist)) score += 20;

      // Require at least one confidence signal — prevents zero-score wrong songs
      if (score > 0 && score > bestScore) {
        bestCandidate = { url: format.url, duration: dur, videoId: sid };
        bestScore = score;
        const tag = score >= 65 ? '✓ official MV' : score >= 50 ? '✓ official release' : '✓ artist channel';
        console.log(`[cloud] ${tag} (score ${score}) "${author}": "${title}"`);
        if (bestScore >= 65) break; // confident enough
      }
    }

    if (bestCandidate) {
      sendStream(bestCandidate.videoId, bestCandidate.url, bestCandidate.duration, 'youtube-cloud');
      return;
    }

    // ── Phase 2: Regular YouTube search (for artists not in YTM catalog) ──────
    // Same strategy as Android app's Phase 2 — searches all of YouTube, not just
    // the music catalog. This is what yt-dlp does and why desktop works correctly.
    // Artist-channel match is NOT a hard filter: featured collabs (e.g. "Finale"
    // by Bien ft. Alikiba) are often uploaded to the featured artist's channel.
    console.log('[cloud] Phase 2 — regular YouTube search for:', title, 'by', artist);
    try {
      const p2Queries = [`${title} ${artist} official`, `${title} ${artist}`];
      const p2Artists = extractAllArtists(title, artist); // word list for channel filter
      for (const p2q of p2Queries) {
        if (bestScore >= 50) break;
        const ytSearch = await yt.search(p2q);
        const ytVideos = (ytSearch.results ?? []).filter(
          v => v.type === 'Video' || v.constructor?.name === 'Video',
        );
        console.log(`[cloud] Phase2 "${p2q}" → ${ytVideos.length} results`);

        for (const video of ytVideos.slice(0, 8)) {
          const vid = video.id;
          if (!vid || vid.length !== 11) continue;

          const ytTitle   = video.title?.text ?? video.title?.toString?.() ?? String(video.title ?? '');
          const ytChannel = (video.author?.name ?? '').toLowerCase();
          const ytDur     = video.duration?.seconds ?? 0;

          if (!titleOk(ytTitle, title)) continue;
          if (isBad(ytTitle, title)) continue;
          if (!durOk(ytDur, expectedDur)) continue;

          // Artist channel filter — word boundary, checks primary + featured artists
          if (p2Artists.length > 0) {
            const chOk = p2Artists.some(w => {
              try { return new RegExp(`\\b${w}\\b`).test(ytChannel); }
              catch (_) { return ytChannel.includes(w); }
            });
            if (!chOk) {
              console.log(`[cloud] Phase2 skip: "${video.author?.name}" ∉ {${p2Artists.join('|')}} for "${title}"`);
              continue;
            }
          }

          const result2 = await getAudioFormat(yt, vid);
          if (!result2) continue;
          const { info: info2, fmt: fmt2 } = result2;

          const dur2    = info2.basic_info?.duration ?? 0;
          if (!durOk(dur2, expectedDur)) continue;

          const author2  = info2.basic_info?.author ?? '';
          const title2   = (info2.basic_info?.title ?? ytTitle).toLowerCase();
          const mvType2  = info2.basic_info?.music_video_type ?? '';

          if (author2.endsWith(' - Topic') || mvType2 === 'MUSIC_VIDEO_TYPE_AUD_TRACK') {
            sendStream(vid, fmt2.url, dur2, 'youtube-topic'); return;
          }

          // Base score of 5: YouTube's own ranking already filtered by artist in the query
          let score2 = 5;
          if (mvType2 === 'MUSIC_VIDEO_TYPE_OFFICIAL_SOURCE_MUSIC')                  score2 += 65;
          if (/\(official\s*(audio|video|music\s*video|lyric\s*video)\)/i.test(title2) ||
              title2.includes('(official)') || title2.includes('[official]'))         score2 += 50;
          if (author2 && artistOk(author2, artist))                                  score2 += 20;

          if (score2 > bestScore) {
            bestCandidate = { url: fmt2.url, duration: dur2, videoId: vid };
            bestScore = score2;
            console.log(`[cloud] Phase2 candidate (score ${score2}) "${author2}": "${title}"`);
            if (bestScore >= 50) break;
          }
        }
      }
    } catch (p2err) {
      console.warn('[cloud] Phase2 failed:', p2err.message);
    }

    if (bestCandidate) {
      sendStream(bestCandidate.videoId, bestCandidate.url, bestCandidate.duration, 'youtube-cloud');
      return;
    }

    console.warn(`[cloud] no verified candidate for: "${title}" by "${artist}"`);
    res.writeHead(404);
    res.end(JSON.stringify({ error: 'No verified candidate found' }));

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
