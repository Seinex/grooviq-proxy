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

const ARL = process.env.DEEZER_ARL || '';
const BF_SECRET = 'g4el58wc0zvf9na1';
const BF_IV = Buffer.from([0, 1, 2, 3, 4, 5, 6, 7]);
const FORMAT = process.env.DEEZER_FORMAT || 'MP3_128'; // MP3_128 (free) | MP3_320 | FLAC (premium)
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';

export function deezerConfigured() { return !!ARL; }

let _session = null; // { licenseToken, apiToken, sid, at }
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

async function getSession() {
  if (!ARL) throw new Error('DEEZER_ARL not configured');
  if (_session && Date.now() - _session.at < 50 * 60 * 1000) return _session;
  const { json, setCookie } = await _gw('deezer.getUserData', '', {}, `arl=${ARL}`);
  const res = json?.results;
  const licenseToken = res?.USER?.OPTIONS?.license_token;
  const apiToken = res?.checkForm;
  const userId = res?.USER?.USER_ID;
  if (!licenseToken || !apiToken || !userId || userId === 0) {
    throw new Error('Deezer ARL invalid/expired (no license_token)');
  }
  const sidMatch = /\bsid=([^;]+)/.exec(setCookie);
  const sid = sidMatch ? sidMatch[1] : '';
  _session = { licenseToken, apiToken, sid, at: Date.now() };
  console.log('[deezer] session ok (user', userId + ')');
  return _session;
}

async function getTrackToken(sngId, s) {
  const cookie = `arl=${ARL}${s.sid ? '; sid=' + s.sid : ''}`;
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
function decryptStripe(buf, key) {
  const out = Buffer.alloc(buf.length);
  let pos = 0, i = 0;
  while (pos < buf.length) {
    const chunk = buf.subarray(pos, pos + 2048);
    if (i % 3 === 0 && chunk.length === 2048) {
      const d = crypto.createDecipheriv('bf-cbc', key, BF_IV);
      d.setAutoPadding(false);
      const dec = Buffer.concat([d.update(chunk), d.final()]);
      dec.copy(out, pos);
    } else {
      chunk.copy(out, pos);
    }
    pos += 2048; i++;
  }
  return out;
}

/** Resolve + decrypt a Deezer track to plain mp3 bytes. @returns Buffer|null */
export async function getDeezerMp3(sngId) {
  const c = _mp3Cache.get(String(sngId));
  if (c && Date.now() - c.at < 30 * 60 * 1000) return c.buf;
  try {
    const s = await getSession();
    const token = await getTrackToken(sngId, s);
    if (!token) { console.warn('[deezer] no track token for', sngId); return null; }
    const url = await getEncryptedUrl(token, s);
    if (!url) { console.warn('[deezer] no stream url (rights?) for', sngId); return null; }
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
  if (!ARL || !sngId) return false;
  if (_hasCache.has(String(sngId))) return _hasCache.get(String(sngId));
  let ok = false;
  try {
    const s = await getSession();
    const token = await getTrackToken(sngId, s);
    if (token) ok = !!(await getEncryptedUrl(token, s));
  } catch {}
  _hasCache.set(String(sngId), ok);
  if (_hasCache.size > 400) _hasCache.delete(_hasCache.keys().next().value);
  return ok;
}

// Lightweight diagnostic (no audio): is the ARL valid + can we get a stream url?
export async function deezerDiag(sngId = '3135556') { // 3135556 = "Harder Better Faster Stronger"
  const out = { arlSet: !!ARL };
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
