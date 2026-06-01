// Deezer full-stream source. Deezer's catalog is huge and includes the Afrobeats /
// regional tracks JioSaavn lacks (e.g. "Finale" by Bien). The app already searches
// Deezer for metadata, so we have the EXACT track id → no matching guesswork →
// the wrong-song problem disappears.
//
// Flow (deemix-style): DEEZER_ARL cookie → gw-light getUserData (license_token +
// api_token) → song.getData (TRACK_TOKEN) → media.deezer.com/v1/get_url (encrypted
// url) → Blowfish-CBC-STRIPE decrypt → plain mp3. Decryption needs the OpenSSL
// legacy provider (start node with --openssl-legacy-provider).
//
// ⚠️ Uses a real Deezer account's ARL (ToS gray area; account can be flagged).
// Free account = MP3_128. Set DEEZER_ARL env on Render.

import crypto from 'crypto';
import { makeBlowfish, blowfishCbcDecrypt } from './blowfish.js';

// Multiple ARLs for resilience: put them comma/space/newline-separated in
// DEEZER_ARL, and/or in DEEZER_ARL_2 / DEEZER_ARL_3. If one account's cookie
// expires or gets flagged, the proxy automatically rotates to the next working
// one — that's the core of the self-healing.
const ARLS = (() => {
  const list = [];
  for (const v of [process.env.DEEZER_ARL, process.env.DEEZER_ARL_2, process.env.DEEZER_ARL_3]) {
    if (!v) continue;
    for (const a of String(v).split(/[\s,]+/)) { const t = a.trim(); if (t.length > 20) list.push(t); }
  }
  return [...new Set(list)];
})();
const BF_SECRET = 'g4el58wc0zvf9na1';
const BF_IV = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]);
const FORMAT = process.env.DEEZER_FORMAT || 'MP3_128'; // MP3_128 (free) | MP3_320 | FLAC (premium)
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';

export function deezerConfigured() { return ARLS.length > 0; }

let _session = null;   // { licenseToken, apiToken, sid, arl, userId, at }
let _arlIndex = 0;     // last-known-good ARL index (tried first next time)
const _mp3Cache = new Map(); // sngId -> { buf, at }

async function _gw(method, apiToken, body, cookie) {
  const url = `https://www.deezer.com/ajax/gw-light.php?method=${method}&input=3&api_version=1.0&api_token=${apiToken || ''}`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'User-Agent': UA, 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify(body || {}),
  });
  const setCookie = r.headers.get('set-cookie') || '';
  const json = await r.json();
  return { json, setCookie };
}

// Authenticate one specific ARL. Returns a session object or null if dead.
async function authWithArl(arl) {
  const { json, setCookie } = await _gw('deezer.getUserData', '', {}, `arl=${arl}`);
  const res = json?.results;
  const licenseToken = res?.USER?.OPTIONS?.license_token;
  const apiToken = res?.checkForm;
  const userId = res?.USER?.USER_ID;
  if (!licenseToken || !apiToken || !userId || userId === 0) return null;
  const sidMatch = /\bsid=([^;]+)/.exec(setCookie);
  return { licenseToken, apiToken, sid: sidMatch ? sidMatch[1] : '', arl, userId };
}

// Get a working session, rotating through ARLs. forceRefresh re-auths even if
// the cached session looks fresh (used after a mid-stream failure or for health).
async function getSession(forceRefresh = false) {
  if (!ARLS.length) throw new Error('DEEZER_ARL not configured');
  if (!forceRefresh && _session && Date.now() - _session.at < 50 * 60 * 1000) return _session;
  let lastErr = 'unknown';
  for (let i = 0; i < ARLS.length; i++) {
    const idx = (_arlIndex + i) % ARLS.length; // try last-good first
    try {
      const s = await authWithArl(ARLS[idx]);
      if (s) {
        _arlIndex = idx;
        _session = { ...s, at: Date.now() };
        console.log(`[deezer] session ok (user ${s.userId}, arl#${idx + 1}/${ARLS.length})`);
        return _session;
      }
      lastErr = `arl#${idx + 1} invalid/expired`;
    } catch (e) { lastErr = e.message; }
  }
  _session = null;
  throw new Error(`all ${ARLS.length} Deezer ARL(s) failed: ${lastErr}`);
}

async function getTrackToken(sngId, s) {
  const cookie = `arl=${s.arl}${s.sid ? '; sid=' + s.sid : ''}`;
  const { json } = await _gw('song.getData', s.apiToken, { sng_id: String(sngId), array_default: ['TRACK_TOKEN'] }, cookie);
  return json?.results?.TRACK_TOKEN || null;
}

async function getEncryptedUrl(trackToken, s) {
  const r = await fetch('https://media.deezer.com/v1/get_url', {
    method: 'POST',
    headers: { 'User-Agent': UA, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      license_token: s.licenseToken,
      media: [{ type: 'FULL', formats: [{ cipher: 'BF_CBC_STRIPE', format: FORMAT }] }],
      track_tokens: [trackToken],
    }),
  });
  const j = await r.json();
  return j?.data?.[0]?.media?.[0]?.sources?.[0]?.url || null;
}

function blowfishKey(sngId) {
  const md5 = crypto.createHash('md5').update(String(sngId)).digest('hex'); // 32 hex chars
  const key = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    key[i] = md5.charCodeAt(i) ^ md5.charCodeAt(i + 16) ^ BF_SECRET.charCodeAt(i);
  }
  return key;
}

// Deezer encrypts every 3rd 2048-byte chunk with Blowfish-CBC (null-ish IV 0..7).
// Pure-JS Blowfish (no OpenSSL) so it works on any Node version.
function decryptStripe(buf, key) {
  const bf = makeBlowfish(key);
  const out = Buffer.alloc(buf.length);
  let pos = 0, i = 0;
  while (pos < buf.length) {
    const chunk = buf.subarray(pos, pos + 2048);
    if (i % 3 === 0 && chunk.length === 2048) {
      blowfishCbcDecrypt(bf, chunk, BF_IV).copy(out, pos);
    } else {
      chunk.copy(out, pos);
    }
    pos += 2048; i++;
  }
  return out;
}

// Resolve session→token→encrypted url, self-healing: if the first attempt fails
// (silent session expiry / flagged ARL), force a fresh re-auth (rotating ARLs)
// and try once more before giving up.
async function resolveStreamUrl(sngId) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const s = await getSession(attempt === 1);
      const token = await getTrackToken(sngId, s);
      if (!token) { if (attempt === 0) { console.warn('[deezer] no token, re-auth…'); continue; } return null; }
      const url = await getEncryptedUrl(token, s);
      if (!url) { if (attempt === 0) { console.warn('[deezer] no url, re-auth…'); continue; } return null; }
      return url;
    } catch (e) { if (attempt === 1) throw e; console.warn('[deezer] session err, re-auth…', e.message); }
  }
  return null;
}

/** Resolve + decrypt a Deezer track to plain mp3 bytes. @returns Buffer|null */
export async function getDeezerMp3(sngId) {
  const c = _mp3Cache.get(String(sngId));
  if (c && Date.now() - c.at < 30 * 60 * 1000) return c.buf;
  try {
    const url = await resolveStreamUrl(sngId);
    if (!url) { console.warn('[deezer] no stream url (rights/expiry?) for', sngId); return null; }
    // cdnt-stream.dzcdn.net requires a Range header — a plain GET returns nothing.
    const r = await fetch(url, { headers: { 'User-Agent': UA, Range: 'bytes=0-' } });
    if (r.status !== 200 && r.status !== 206) { console.warn('[deezer] stream fetch', r.status); return null; }
    const enc = Buffer.from(await r.arrayBuffer());
    if (enc.length < 2048) { console.warn('[deezer] empty stream', enc.length); return null; }
    const dec = decryptStripe(enc, blowfishKey(sngId));
    _mp3Cache.set(String(sngId), { buf: dec, at: Date.now() });
    if (_mp3Cache.size > 30) _mp3Cache.delete(_mp3Cache.keys().next().value);
    console.log(`[deezer] ✓ ${sngId} → ${Math.round(dec.length / 1024)}KB ${FORMAT}`);
    return dec;
  } catch (e) { console.error('[deezer]', e.message); return null; }
}

// Cheap check (no download/decrypt): does this Deezer track resolve a stream url?
const _hasCache = new Map();
export async function deezerHasTrack(sngId) {
  if (!ARLS.length || !sngId) return false;
  if (_hasCache.has(String(sngId))) return _hasCache.get(String(sngId));
  let ok = false;
  try { ok = !!(await resolveStreamUrl(sngId)); } catch {}
  _hasCache.set(String(sngId), ok);
  if (_hasCache.size > 400) _hasCache.delete(_hasCache.keys().next().value);
  return ok;
}

// ── Self-healing health check ────────────────────────────────────────────────
// Forces a fresh end-to-end resolve (auth → token → stream url) against a known
// track. On failure, fires `alertCb` (debounced to once / 3h) so the owner knows
// to refresh DEEZER_ARL. Returns a status object for monitoring.
let _lastAlert = 0;
let _lastHealth = { healthy: null, at: 0 };
export async function deezerHealth(alertCb) {
  const out = { configured: ARLS.length > 0, arlCount: ARLS.length, format: FORMAT };
  if (!ARLS.length) { out.healthy = false; out.reason = 'no-arl-configured'; return out; }
  try {
    const s = await getSession(true);           // force fresh auth = truly tests the ARL
    out.activeArl = _arlIndex + 1;
    out.userId = s.userId;
    const url = await resolveStreamUrl('3135556'); // Daft Punk – stable catalog track
    out.healthy = !!url;
    out.reason = url ? 'ok' : 'no-stream-url';
  } catch (e) { out.healthy = false; out.reason = String(e.message || e).slice(0, 200); }
  _lastHealth = { healthy: out.healthy, at: Date.now() };
  if (!out.healthy && typeof alertCb === 'function' && Date.now() - _lastAlert > 3 * 60 * 60 * 1000) {
    _lastAlert = Date.now();
    try {
      await alertCb(
        `🟥 **Grooviq · Deezer source DOWN** — \`${out.reason}\` (${ARLS.length} ARL${ARLS.length > 1 ? 's' : ''} tried).\n` +
        `Refresh on Render → Environment → **DEEZER_ARL**. Get a fresh cookie: log into deezer.com → F12 → Application → Cookies → copy \`arl\`. ` +
        `Tip: set **DEEZER_ARL_2** as a backup so rotation keeps playback alive.`
      );
    } catch {}
  }
  return out;
}

export function deezerLastHealth() { return _lastHealth; }

// Lightweight diagnostic (no audio): is the ARL valid + can we get a stream url?
export async function deezerDiag(sngId = '3135556') { // 3135556 = "Harder Better Faster Stronger"
  const out = { arlSet: ARLS.length > 0, arlCount: ARLS.length, node: process.version };
  // Pure-JS Blowfish self-test (canonical vector key=0,pt=0 -> 4EF997456198DD78).
  try {
    const bf = makeBlowfish(Buffer.alloc(8));
    const iv = Buffer.from('4ef997456198dd78', 'hex'); // C(0) under bf -> decrypts to 0
    const dec = blowfishCbcDecrypt(bf, iv, Buffer.alloc(8));
    out.bfCbc = dec.equals(Buffer.alloc(8)) ? 'ok (pure-js)' : 'FAIL: vector mismatch';
  } catch (e) { out.bfCbc = 'FAIL: ' + e.message; }
  try {
    const s = await getSession();
    out.sessionOk = true;
    const token = await getTrackToken(sngId, s);
    out.trackToken = !!token;
    if (token) {
      const url = await getEncryptedUrl(token, s);
      out.streamUrl = !!url;
      out.urlHost = url ? new URL(url).host : null;
      if (url) {
        // Does the CDN actually serve bytes from THIS (datacenter) IP?
        try {
          const r = await fetch(url, { headers: { 'User-Agent': UA, Range: 'bytes=0-4095' } });
          out.cdnStatus = r.status;
          const b = Buffer.from(await r.arrayBuffer());
          out.cdnBytes = b.length;
        } catch (e) { out.cdnError = e.message; }
      }
    }
  } catch (e) { out.error = e.message; }
  return out;
}
