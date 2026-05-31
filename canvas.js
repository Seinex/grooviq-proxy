// Spotify Canvas resolver — fetches the short, looping, AD-FREE, audio-free .cnvs.mp4
// that artists upload (the loops behind songs on Spotify mobile). These play
// natively (plain MP4 on canvaz.scdn.co — no YouTube, no ads, no signature/n-param).
//
// Auth: needs an SP_DC cookie (env var) → a TOTP-signed token from
// open.spotify.com/api/token. Spotify rotates the TOTP secret every few days, so
// we pull the current secret list from a community-maintained repo. Undocumented /
// ToS gray area — may need occasional upkeep.

import * as OTPAuth from 'otpauth';

const SP_DC = process.env.SP_DC || '';
const SECRETS_URL = 'https://raw.githubusercontent.com/xyloflake/spot-secrets-go/refs/heads/main/secrets/secretDict.json';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';

let _totp = null, _totpVer = null, _secretsFetched = 0;
let _token = null, _tokenExp = 0;
const _canvasCache = new Map();   // trackUri -> { url, at }
const _trackCache  = new Map();   // "title|artist" -> trackUri

export function canvasConfigured() { return !!SP_DC; }

// ── TOTP secret (rotated by Spotify; pulled from community repo) ───────────────
async function ensureTotp() {
  const now = Date.now();
  if (_totp && now - _secretsFetched < 60 * 60 * 1000) return;
  try {
    const r = await fetch(SECRETS_URL, { headers: { 'User-Agent': UA } });
    const secrets = await r.json();
    const newest = Math.max(...Object.keys(secrets).map(Number)).toString();
    const data = secrets[newest];
    const mapped = data.map((v, i) => v ^ ((i % 33) + 9));
    const hex = Buffer.from(mapped.join(''), 'utf8').toString('hex');
    _totp = new OTPAuth.TOTP({ period: 30, digits: 6, algorithm: 'SHA1', secret: OTPAuth.Secret.fromHex(hex) });
    _totpVer = newest;
    _secretsFetched = now;
    console.log(`[canvas] TOTP secret v${newest} loaded`);
  } catch (e) {
    console.error('[canvas] TOTP secret fetch failed:', e.message);
    if (!_totp) throw e;
  }
}

async function serverTime() {
  try {
    const r = await fetch('https://open.spotify.com/api/server-time', {
      headers: { 'User-Agent': UA, Origin: 'https://open.spotify.com/', Referer: 'https://open.spotify.com/', Cookie: `sp_dc=${SP_DC}` },
    });
    const d = await r.json();
    const t = Number(d.serverTime);
    return isNaN(t) ? Date.now() : t * 1000;
  } catch { return Date.now(); }
}

async function getToken() {
  if (!SP_DC) throw new Error('SP_DC not configured');
  if (_token && Date.now() < _tokenExp - 30000) return _token;
  await ensureTotp();
  const local = Date.now();
  const srv = await serverTime();
  const params = new URLSearchParams({
    reason: 'init',
    productType: 'mobile-web-player',
    totp: _totp.generate({ timestamp: local }),
    totpVer: _totpVer || '19',
    totpServer: _totp.generate({ timestamp: Math.floor(srv / 30) }),
  });
  const r = await fetch(`https://open.spotify.com/api/token?${params}`, {
    headers: { 'User-Agent': UA, Origin: 'https://open.spotify.com/', Referer: 'https://open.spotify.com/', Cookie: `sp_dc=${SP_DC}` },
  });
  const _raw = await r.text();
  if (process.env.CANVAS_DEBUG) console.log('[canvas] token HTTP', r.status, '| totp', params.get('totp'), '| body:', _raw.slice(0, 120));
  let d; try { d = JSON.parse(_raw); } catch { throw new Error(`token ${r.status}: ${_raw.slice(0, 60)}`); }
  if (!d.accessToken) throw new Error('no accessToken (sp_dc expired or TOTP rejected)');
  _token = d.accessToken;
  _tokenExp = d.accessTokenExpirationTimestampMs || (Date.now() + 50 * 60 * 1000);
  return _token;
}

// ── Minimal protobuf (schema is tiny) ─────────────────────────────────────────
function varint(n) { const b = []; while (n > 0x7f) { b.push((n & 0x7f) | 0x80); n >>>= 7; } b.push(n); return Buffer.from(b); }
function encodeCanvasRequest(trackUri) {
  const u = Buffer.from(trackUri, 'utf8');
  const track = Buffer.concat([Buffer.from([0x0a]), varint(u.length), u]);          // Track.track_uri = field 1
  return Buffer.concat([Buffer.from([0x0a]), varint(track.length), track]);          // CanvasRequest.tracks = field 1
}
function readVarint(buf, pos) { let r = 0, s = 0, b; do { b = buf[pos++]; r |= (b & 0x7f) << s; s += 7; } while (b & 0x80); return [r >>> 0, pos]; }
function fields(buf, start, end) {
  const out = []; let pos = start;
  while (pos < end) {
    let key; [key, pos] = readVarint(buf, pos);
    const field = key >>> 3, wire = key & 7;
    if (wire === 2) { let len; [len, pos] = readVarint(buf, pos); out.push({ field, data: buf.subarray(pos, pos + len) }); pos += len; }
    else if (wire === 0) { let v; [v, pos] = readVarint(buf, pos); out.push({ field, val: v }); }
    else if (wire === 5) { pos += 4; } else if (wire === 1) { pos += 8; } else break;
  }
  return out;
}
function parseCanvasUrl(buf) {
  for (const f of fields(buf, 0, buf.length)) {            // CanvasResponse.canvases = field 1
    if (f.field === 1 && f.data) {
      for (const cf of fields(f.data, 0, f.data.length)) { // Canvas.canvas_url = field 2
        if (cf.field === 2 && cf.data) return cf.data.toString('utf8');
      }
    }
  }
  return null;
}

// ── Client-credentials token (for /v1/search) ─────────────────────────────────
// The sp_dc web-player token is blocked (429) on the public /v1/search endpoint,
// so to look up a Spotify track id from title+artist we use a normal app
// client-credentials token (proper rate limits). Configure SPOTIFY_CLIENT_ID +
// SPOTIFY_CLIENT_SECRET env vars; without them, search is skipped (tracks that
// already have a Spotify id still get canvases).
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID || '517db6a178194f7bbfe997448068f102';
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET || '';
let _ccToken = null, _ccExp = 0;
async function getCcToken() {
  if (!SPOTIFY_CLIENT_SECRET) return null;
  if (_ccToken && Date.now() < _ccExp - 30000) return _ccToken;
  const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
  const r = await fetch('https://accounts.spotify.com/api/token', {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials',
  });
  const d = await r.json();
  if (!d.access_token) return null;
  _ccToken = d.access_token;
  _ccExp = Date.now() + (d.expires_in || 3600) * 1000;
  return _ccToken;
}

// ── Spotify search (to resolve a track URI from title+artist) ─────────────────
async function searchTrackUri(title, artist) {
  const key = `${title}|${artist}`.toLowerCase();
  if (_trackCache.has(key)) return _trackCache.get(key);
  try {
    const token = await getCcToken();
    if (!token) { _trackCache.set(key, null); return null; }  // search not configured
    const q = encodeURIComponent(`${title} ${artist}`.trim());
    const r = await fetch(`https://api.spotify.com/v1/search?type=track&limit=1&q=${q}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!r.ok) { _trackCache.set(key, null); return null; }
    const d = await r.json();
    const uri = d?.tracks?.items?.[0]?.uri || null;
    _trackCache.set(key, uri);
    return uri;
  } catch {
    _trackCache.set(key, null);
    return null;
  }
}

// ── Canvas fetch ──────────────────────────────────────────────────────────────
async function fetchCanvas(trackUri) {
  const cached = _canvasCache.get(trackUri);
  if (cached && Date.now() - cached.at < 60 * 60 * 1000) return cached.url;
  const token = await getToken();
  const r = await fetch('https://spclient.wg.spotify.com/canvaz-cache/v0/canvases', {
    method: 'POST',
    headers: {
      Accept: 'application/protobuf',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept-Language': 'en',
      'User-Agent': 'Spotify/9.0.34.593 iOS/18.4 (iPhone15,3)',
      Authorization: `Bearer ${token}`,
    },
    body: encodeCanvasRequest(trackUri),
  });
  if (!r.ok) { console.warn('[canvas] fetch', r.status); return null; }
  const buf = Buffer.from(await r.arrayBuffer());
  const url = parseCanvasUrl(buf);
  _canvasCache.set(trackUri, { url: url || null, at: Date.now() });
  return url;
}

// Diagnostic: reports why search may be failing (no secret leaked).
export async function canvasDiag(title = 'Espresso', artist = 'Sabrina Carpenter') {
  const out = { secretSet: !!SPOTIFY_CLIENT_SECRET, clientId: SPOTIFY_CLIENT_ID.slice(0, 6) + '…' };
  try {
    const auth = Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64');
    const r = await fetch('https://accounts.spotify.com/api/token', {
      method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    });
    const d = await r.json();
    out.ccTokenStatus = r.status;
    out.ccTokenOk = !!d.access_token;
    if (d.error) out.ccError = `${d.error}: ${d.error_description || ''}`.slice(0, 80);
    if (d.access_token) {
      const sr = await fetch(`https://api.spotify.com/v1/search?type=track&limit=1&market=US&q=${encodeURIComponent(`${title} ${artist}`)}`, {
        headers: { Authorization: `Bearer ${d.access_token}` },
      });
      out.searchStatus = sr.status;
      const raw = await sr.text();
      try { const sd = JSON.parse(raw); out.foundUri = sd?.tracks?.items?.[0]?.uri || null; out.searchErr = sd?.error?.message; }
      catch { out.searchBody = raw.slice(0, 120); }
    }
  } catch (e) { out.exception = e.message; }
  return out;
}

/**
 * Resolve a Canvas mp4 URL for a track.
 * @param {{ id?: string, title?: string, artist?: string }} opts
 *   id = Spotify track id (preferred), else title+artist (we search).
 * @returns {Promise<string|null>} the .cnvs.mp4 URL, or null (no canvas for this track)
 */
export async function getCanvasUrl({ id, title, artist }) {
  let uri = null;
  if (id) uri = id.startsWith('spotify:') ? id : `spotify:track:${id}`;
  else if (title) uri = await searchTrackUri(title, artist || '');
  if (!uri) return null;
  return fetchCanvas(uri);
}
