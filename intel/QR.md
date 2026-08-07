# PhisDetect — QR Scanner: Complete Reference

> Everything about how a QR code gets scanned: the client-side decode (image upload → jsQR
> → URL extraction), the two-step UI (decode → analyze), the backend reuse of the URL
> pipeline, the API calls, the result rendering, and the verification results.
>
> The QR scanner is **100% frontend for decoding** and **100% URL pipeline for analysis**.
> There is no QR-specific backend code: the decoded URL is sent to the existing
> `POST /api/scan/url` endpoint. All the URL-layer logic (models, heuristics, enrichment,
> page scan, gates) is documented in `URL.md`; this document covers the QR-specific parts
> and how they plug in.
>
> Code lives in `/home/aditya/AI project/Code/frontend/`. Function names below match
> `index.html` / `js/scanner.js` exactly.

---

## 1. The one-minute summary

Scanning a QR code produces a **URL verdict** exactly like typing the URL into the URL
scanner — because it *is* the URL scanner:

1. **Upload / drop an image** of the QR code (`#qrUploadArea`, accepts any `image/*`).
2. **Decode client-side** with the jsQR library: the image is drawn to a `<canvas>`, the raw
   RGBA pixel buffer is handed to `jsQR()`, and the decoded string is shown in
   `#extractedUrl`.
3. **If the payload is a valid `http://` / `https://` URL**, the user clicks **Analyze URL**,
   which POSTs it to `http://localhost:3000/api/scan/url` (`scanUrl` reuse, no new backend
   endpoint).
4. The **result panel** (`#qrResults`) renders the same risk tiers, confidence gauge, and
   detail stats as the URL scanner (domain age, SSL, redirect, blacklist) plus the
   `indicators` list in `#qrIndicators`.

Everything the backend does (RF model, URL-text model, heuristics, allowlist/blocklist,
WHOIS/SSL/DNS enrichment, landing-page scan, enrichment veto) applies unchanged. The QR
scanner is purely a *transport* that turns pixels into a URL.

---

## 2. Why client-side decoding?

The decode happens **in the browser**, not on the server. Design rationale:

- **No backend change** — the QR tab is a thin client that reuses `/api/scan/url`. Adding a
  server-side QR decode would have required an image-upload endpoint and an image library
  (e.g. OpenCV/Pillow + zxing) for zero analysis benefit.
- **Privacy** — the QR image itself never leaves the machine; only the extracted URL is
  sent (and only when the user clicks "Analyze URL").
- **Speed** — decoding is instant and offline; only the URL analysis hits the network.
- **jsQR is loaded from a CDN** (`https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js`,
  `index.html:489`). **Consequence: the decode step requires an internet connection and the
  CDN to be reachable** — the library is not vendored locally. If the CDN is down, `jsQR` is
  undefined and `processQrImage()` throws (caught only by the UI flow; see §7 limitations).

---

## 3. UI layout (`index.html`)

The QR panel (`#panel-qr`, tab `#tab-qr`) contains, in order:

| Element | ID | Role |
|---------|----|------|
| Status badge | `#qrStatusBadge` | `Ready` → `Safe/Suspicious/Threat` after analysis |
| Upload area | `#qrUploadArea` | click, drag-and-drop, or hidden `#qrFileInput` (`accept="image/*"`) |
| Hidden file input | `#qrFileInput` | the actual `<input type="file">` behind the button |
| Choose Image button | `#qrUploadBtn` | opens the file picker (stopPropagation so it doesn't double-fire the area click) |
| Extracted URL box | `#qrResult` + `#extractedUrl` | shows the decoded payload (hidden until a decode) |
| Actions row | `#qrActions` | `#analyzeQrBtn` (Analyze URL) + `#clearQrBtn` (Clear) |
| Results | `#qrResults` | `#qrRiskLabel` verdict banner + `#qrConfidence` + stat rows `#qrDomainAge` `#qrSslStatus` `#qrRedirection` `#qrBlacklist` + `#qrIndicators` + `#reportQrBtn` |

Three display states are toggled via `display`:
- **Upload state** — upload area visible, `qrResult`/`qrActions`/`qrResults` hidden.
- **Decoded state** — upload area hidden, extracted URL + Analyze/Clear visible.
- **Analyzed state** — results panel revealed on top of the same page (the tab never
  navigates away).

**Key gotcha fixed in this project:** the URL scanner's `renderIndicators('url', …)` writes
into `#urlIndicators`, but the QR tab originally had **no `#qrIndicators` container**, so the
generic `renderIndicators()` silently returned and QR scans never showed any indicators. The
fix was adding `<div id="qrIndicators"></div>` to the QR panel (`index.html:423`).

---

## 4. Decode flow (`processQrImage(file)`)

`scanner.js`, lines 217–252:

1. **File guard** — `file.type.startsWith('image/')` or a warning toast.
2. **FileReader → Image** — `reader.readAsDataURL(file)`; on load a browser `Image` object is
   created with `src = dataURL`.
3. **Canvas draw** — the image is painted 1:1 onto an offscreen canvas
   (`canvas.width/height = image.width/height`).
4. **Pixel buffer** — `ctx.getImageData(0, 0, w, h)` gives the raw RGBA `Uint8ClampedArray`.
5. **Decode** — `const code = jsQR(imageData.data, imageData.width, imageData.height);`
   - Success → `code.data` is the decoded payload string.
   - Failure → `code` is `null` → payload shown as `"No URL found in QR code"`.
6. **Validate** — `isValidUrl(payload)` = `new URL(string)` parses **and** the protocol is
   `http:` or `https:`. Anything else (plain text, `mailto:`, phone numbers, wifi configs…)
   is decoded and *displayed* but **not analyzable** — the Analyze button warns instead of
   scanning.
7. **UI switch** — on success hide `#qrUploadArea`, show `#qrResult` + `#qrActions`, toast
   "QR code decoded successfully!".

Note the decode runs on the main thread (synchronous jsQR call) — fine for typical images,
but very large/high-res images add a few frames of jank because the full buffer is scanned.

---

## 5. Analyze flow (`scanQrUrl(url)`)

`scanner.js`, lines 254–258:

```js
scanQrUrl(url) {
    this.runScanWithOverlay('qr', () => this.callBackend('/api/scan/url', { url }))
        .then(result => this.updateAnalysis('qr', result))
        .catch(err => this.showAlert(`Backend error: ${err.message}`, 'error'));
}
```

- **`callBackend`** (line 545): `fetch('http://localhost:3000' + endpoint)` POST JSON, throws
  on non-2xx or `{error}` payload. `BACKEND_URL = 'http://localhost:3000'` (`scanner.js:6`) —
  the frontend assumes the Flask server on localhost:3000 (CORS is enabled server-side).
- **`runScanWithOverlay('qr', …)`** (line 596): shows the inline terminal-log progress
  overlay with the **URL scan step list** — `getScanSteps('qr')` falls into the default
  (URL) branch: *Extracting URL features → Querying DNS records → Running machine learning
  model → Checking domain registration age → Verifying SSL certificate → Tracing redirect
  chain → Checking blocklists → Computing risk verdict*. These are cosmetic; they animate
  while the single fetch completes.
- **`updateAnalysis('qr', result)`** — the **same renderer as the URL tab**:
  - Verdict banner: `risk-label <risk>` + `verdict.label`.
  - Confidence: `result.confidence%`, colored by tier.
  - Detail stats: `getDetailConfig('qr')` returns the **URL branch** (`type !== 'email'`):
    `domainAge` (danger if "hour"/"day", warning if "Unknown"), `sslStatus` (Valid=safe),
    `redirection` (Detected=danger), `blacklist` (Flagged=danger).
  - **Indicators:** `renderIndicators('qr', result)` writes `result.indicators` into
    `#qrIndicators` (the container that was missing and got added).
  - **Report button:** `#reportQrBtn` appears for non-safe verdicts → `submitReport('qr', …)`
    (frontend mock: confirm dialog → toast → +10 points; no backend report API yet).
  - **Points:** non-safe verdict → `addPoints(5)` client-side (localStorage profile; will
    become server-authoritative with auth).
  - Status badge flips to `green/amber/red`.

Because the backend endpoint is identical, the QR verdict can diverge slightly from typing
the URL only in **server-side cache state** (enrichment/auth results are cached per
host/url), never in logic.

---

## 6. Security considerations

- **Attacker-controlled strings:** the decoded payload (and the URL-scanner indicators,
  which may embed content from the target site's own HTML) are rendered into the DOM.
  `scanner.js` passes everything through `escapeHtml()` before inserting — the QR payload
  shown in `#extractedUrl` and all indicator text are escaped. The `escapeHtml()` mapping
  covers `& < > " '`.
- **`file.type.startsWith('image/')`** is a client-side guard, not a security boundary —
  the file is never uploaded anywhere, only decoded in-memory.
- **QR payloads are untrusted input** that become *URLs to scan*. They are NOT followed by
  the scanner itself; `scan_url` only analyzes (and optionally fetches the page server-side
  for the landing-page scan, bounded to 1 MB / 4s — see `URL.md` §9). The user decides
  whether to actually visit.

---

## 7. Known limitations (be honest about these)

- **CDN dependency for decoding:** jsQR loads from jsdelivr; without network access to that
  CDN, `jsQR` is undefined and decoding fails (no local fallback copy). Analysis of an
  already-decoded URL would still work.
- **Payload types:** only `http://` / `https://` URLs are analyzable. `mailto:`, phone,
  wifi, and plain-text QR codes are decoded and displayed but cannot be scanned. (A future
  version could run non-URL payloads through a different analyzer.)
- **Image quality matters:** blurry, low-contrast, partially cropped, or heavily stylized QR
  codes often decode to `null` ("No URL found in QR code"). jsQR is a pure-JS decoder with
  no perspective/rotation preprocessing beyond what the QR spec allows.
- **No live camera feed:** this is an **image-upload** scanner, not a real-time camera
  scanner (no `getUserMedia`). Scanning a code means photographing it first.
- **Main-thread decode:** large images are decoded synchronously on the UI thread (brief
  freeze possible); no downscaling is applied before `jsQR`.
- **One QR per scan:** no batch/multi-code detection.
- **Backend reuse carries the URL pipeline's limits** (see `URL.md` §15) and its latency:
  enrichment/page-scan bound the request (~up to WHOIS window). Caches make repeat scans
  fast.
- **`BACKEND_URL` is hard-coded to `http://localhost:3000`** — fine for local dev, but the
  frontend must be served from a host allowed by the server's CORS, and a production deploy
  would need a relative/configurable base URL.

---
## 8. Verification results

Verified end-to-end in headless Firefox (selenium + geckodriver, `/tmp/opencode/e2e.py`,
frontend served via `python -m http.server 8090` on `Code/frontend`, backend on :3000).
Test images generated with the `qrcode` + `pillow` pip packages
(`/tmp/opencode/qr_phish.png`, `/tmp/opencode/qr_clean.png`).

| Test | Decode | Verdict |
|------|--------|---------|
| `https://paypol-verify.com` QR | decoded to URL, displayed in `#extractedUrl` | **Threat 67%** + "Suspicious keyword 'verify'" indicator rendered in `#qrIndicators` |
| `https://www.youtube.com` QR | decoded | **Safe 75%**, no indicators |

The `#qrIndicators` container fix (missing → added at `index.html:423`) was the observable
change: before it, QR scans produced the right verdict but **no indicator list** because
`renderIndicators('qr', …)` targeted a nonexistent element and silently returned.

Note: URL-scan baseline results for the same inputs are in `URL.md` §14
(paypol danger 67%, youtube safe ~75–77%) — identical because the QR path calls the same
endpoint.

---

## 9. Verification checklist (after any QR/frontend change)

1. Serve frontend (`python -m http.server 8090` in `Code/frontend`), keep the backend on
   :3000.
2. Upload a QR containing `https://paypol-verify.com` → decoded, Analyze enabled.
3. Click Analyze → Threat 67% + verify-keyword indicator listed.
4. Upload a QR containing `https://www.youtube.com` → Safe 75%, no indicators.
5. Upload a non-URL QR (e.g. plain text) → decoded & shown, Analyze warns "No valid URL
   found in QR code to analyze."
6. Upload a non-image file → warning toast, nothing else happens.
7. Clear → back to upload state, results reset to `--`.
8. Confirm `#qrIndicators` exists in `index.html` (regression guard for the fixed bug).

---

## 10. Data flow summary

```
QR image (user)                         FRONTEND (all client-side)
   │ file picker / drag-drop
   ▼
processQrImage(file)          jsQR(imageData)  ──►  code.data = payload string
   │                                                #extractedUrl.textContent = payload
   ▼
isValidUrl(payload)?  ──  http/https?  ── no ─►  toast warning (not analyzable)
   │ yes
   ▼
scanQrUrl(payload)         POST http://localhost:3000/api/scan/url  { "url": payload }
   │                                                                │
   │                                                     ┌─────────▼───────────────┐
   │                                                     │  scan_url() (server.py) │
   │                                                     │  RF + URL-text + heur.  │
   │                                                     │  + enrich + page scan   │
   │                                                     │  + gates + veto         │
   │                                                     │  (see URL.md for all)   │
   │                                                     └─────────┬───────────────┘
   ▼                                                                │ JSON
updateAnalysis('qr', result)  ── verdict banner, confidence,        │
   │                              detail stats, indicators list,    │
   │                              report btn, +5 points             │
   ▼
User sees Safe / Suspicious / Threat / Critical verdict
```

No files beyond the frontend are involved in QR. Relevant code:

- `Code/frontend/index.html` — QR panel `#panel-qr` (lines ~349–432), jsQR CDN script tag
  (line 489), `#qrIndicators` container (line 423).
- `Code/frontend/js/scanner.js` — `setupQrScanner()` (156), `processQrImage()` (217),
  `scanQrUrl()` (254), `resetQrScanner()` (260), `isValidUrl()` (272), `callBackend()` (545),
  `runScanWithOverlay()` (596), `updateAnalysis()` (377), `renderIndicators()` (440),
  `getDetailConfig()` (360 — 'qr' uses the URL branch).
- `Code/frontend/css/components.css` — QR styles (`.qr-upload-area`, `.qr-extracted`,
  `.qr-actions`, §16) + `responsive.css` + `[data-theme="light"]` overrides.
- `Code/frontend/js/app.js` — wires `setupQrScanner()` on boot.

The backend is shared and unchanged: `POST /api/scan/url` only. That is the whole point of
the QR design — zero server-side QR logic.
