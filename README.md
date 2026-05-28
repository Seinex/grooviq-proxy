# Grooviq Cloud Stream Proxy

Gives every Android tester desktop-quality songs — full original recordings,
not 30s previews — from any WiFi, any country.

## Deploy to Render.com (free, 5 minutes)

1. **Push this folder to GitHub** (or the whole NexlvalMobile repo)

2. **Sign up at render.com** (free, use GitHub login — no credit card)

3. **New → Web Service → connect your GitHub repo**
   - Root directory: `cloud-proxy`
   - Runtime: **Node**
   - Build command: `npm install`
   - Start command: `node server.js`
   - Plan: **Free**

4. **Add environment variables:**
   - `CLOUD_TOKEN` = `grooviq-cloud-2026`

5. **Click Deploy** — takes ~2 min to build

6. **Copy your Render URL** (e.g. `grooviq-proxy.onrender.com`)

7. **Update piped.js** in the Android app:
   ```js
   const CLOUD_PROXY_HOST  = 'grooviq-proxy.onrender.com';
   ```
   Then rebuild the APK.

## Notes

- Free tier sleeps after 15 min inactivity. First request after sleep takes ~30s to wake.
  After waking, all requests are fast (< 5s).
- To keep it always warm: add a Render Cron Job that hits `/ping?token=grooviq-cloud-2026` every 10 min.
- Token `grooviq-cloud-2026` is hardcoded in the APK — fine for testing.

## Endpoints

| Endpoint | Description |
|---|---|
| `/ping?token=...` | Health check — returns `{"ok":true}` |
| `/stream?token=...&title=...&artist=...&isrc=...&duration=...` | YouTube Music stream URL |
| `/saavn?token=...&title=...&artist=...` | JioSaavn 320kbps with DES decryption |
