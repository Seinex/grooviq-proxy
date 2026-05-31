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
let _token = null, _tokenExp = 0, _clientId = null;
let _clientToken = null, _clientTokenExp = 0;
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
  _clientId = d.clientId || _clientId;
  _tokenExp = d.accessTokenExpirationTimestampMs || (Date.now() + 50 * 60 * 1000);
  return _token;
}

// Client-token (required by the internal pathfinder API alongside the Bearer token).
async function getClientToken() {
  if (_clientToken && Date.now() < _clientTokenExp - 60000) return _clientToken;
  if (!_clientId) await getToken();
  const r = await fetch('https://clienttoken.spotify.com/v1/clienttoken', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': UA },
    body: JSON.stringify({ client_data: { client_version: '1.2.50', client_id: _clientId,
      js_sdk_data: { device_brand: 'unknown', device_model: 'unknown', os: 'windows', os_version: 'NT 10.0', device_id: '', device_type: 'computer' } } }),
  });
  const d = await r.json();
  _clientToken = d?.granted_token?.token || null;
  _clientTokenExp = Date.now() + ((d?.granted_token?.refresh_after_seconds || 1200) * 1000);
  return _clientToken;
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

// ── Spotify search via internal pathfinder API (works on FREE tier) ───────────
// The public /v1/search now requires the app owner to have Premium (Spotify Feb
// 2026 change → 403). So we use the same internal GraphQL endpoint the web player
// itself uses, driven by the sp_dc token + client-token. It needs a persistedQuery
// hash that Spotify rotates occasionally; if it goes stale the request fails and
// we return null → the app shows album art (never breaks). Update SEARCH_HASH then.
// One or more searchDesktop persistedQuery hashes (comma-separated env override).
// Spotify rotates these; we try each in turn, and self-alert (Discord) when ALL
// are dead so the hash can be refreshed — see _alertStaleHash().
const SEARCH_HASHES = (process.env.SEARCH_HASH || 'd9f785900f0710b31c07818d617f4f7600c1e21217e80f5b043d1e78d74e6026')
  .split(',').map((h) => h.trim()).filter(Boolean);
let _goodHash = SEARCH_HASHES[0];
let _lastAlert = 0;

async function _alertStaleHash() {
  // Debounce to once / 6h, and only if a webhook is configured.
  const wh = process.env.DISCORD_WEBHOOK;
  if (!wh || Date.now() - _lastAlert < 6 * 60 * 60 * 1000) return;
  _lastAlert = Date.now();
  try {
    await fetch(wh, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: '⚠️ **Grooviq canvas**: the Spotify searchDesktop hash is stale — canvases for non-imported songs are off until SEARCH_HASH is refreshed in Render env.' }) });
  } catch {}
}

async function _pathfinderSearch(token, clientToken, term, hash) {
  const variables = { searchTerm: term, offset: 0, limit: 5, numberOfTopResults: 5, includeAudiobooks: false, includePreReleases: false };
  const extensions = { persistedQuery: { version: 1, sha256Hash: hash } };
  const url = `https://api-partner.spotify.com/pathfinder/v1/query?operationName=searchDesktop&variables=${encodeURIComponent(JSON.stringify(variables))}&extensions=${encodeURIComponent(JSON.stringify(extensions))}`;
  return fetch(url, { headers: { Authorization: `Bearer ${token}`, 'client-token': clientToken || '', 'app-platform': 'WebPlayer', Accept: 'application/json', 'User-Agent': UA } });
}

function _norm(s = '') { return s.toLowerCase().replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim(); }
async function searchTrackUri(title, artist) {
  const key = `${title}|${artist}`.toLowerCase();
  if (_trackCache.has(key)) return _trackCache.get(key);
  try {
    const [token, clientToken] = await Promise.all([getToken(), getClientToken()]);
    const term = `${title} ${artist}`.trim();
    // Try the last-known-good hash first, then any other configured hashes.
    let r = await _pathfinderSearch(token, clientToken, term, _goodHash);
    if (!r.ok) {
      let recovered = false;
      for (const h of SEARCH_HASHES) {
        if (h === _goodHash) continue;
        const rr = await _pathfinderSearch(token, clientToken, term, h);
        if (rr.ok) { _goodHash = h; r = rr; recovered = true; break; }
      }
      if (!recovered) { _alertStaleHash(); _trackCache.set(key, null); return null; }
    }
    const j = await r.json();
    const items = j?.data?.searchV2?.tracksV2?.items || [];
    // Prefer a result whose artist matches; else take the top result.
    const wantA = _norm(artist), wantT = _norm(title);
    let pick = items.find((it) => {
      const d = it?.item?.data; if (!d?.uri) return false;
      const a = _norm(d?.artists?.items?.[0]?.profile?.name || '');
      const t = _norm(d?.name || '');
      return (wantA && a.includes(wantA.split(' ')[0])) && (wantT && (t.includes(wantT) || wantT.includes(t)));
    }) || items.find((it) => it?.item?.data?.uri);
    const uri = pick?.item?.data?.uri || null;
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

// Diagnostic: end-to-end check of the pathfinder search → canvas path.
export async function canvasDiag(title = 'Espresso', artist = 'Sabrina Carpenter') {
  const out = {};
  try {
    out.tokenOk = !!(await getToken());
    out.clientTokenOk = !!(await getClientToken());
    const uri = await searchTrackUri(title, artist);
    out.foundUri = uri;
    if (uri) out.canvasUrl = (await fetchCanvas(uri)) ? 'yes' : 'no-canvas-for-track';
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
