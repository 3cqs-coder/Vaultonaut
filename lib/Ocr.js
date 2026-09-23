'use strict';
// lib/Ocr.js — optical character recognition for content search, so a SCANNED PDF or a photographed/screenshot image
// (which carry no text layer) becomes searchable instead of indexing as empty. It runs ONLY inside the isolated,
// resource-capped extraction child process (lib/ExtractProcess.js), one document at a time, so its heavy transient
// memory (page bitmaps, the recognition engine) is contained and reclaimed per file and never blocks the app.
//
// Everything here is pure JavaScript or WebAssembly — no native addon, nothing to compile — so it behaves identically
// on macOS, Windows, and Linux (the "nothing to compile" invariant the rest of the indexer keeps). Three pieces, each
// loaded lazily on first use:
//   • rasterize a PDF page to a bitmap with a WebAssembly PDF engine (no native canvas dependency),
//   • normalize the bitmap (grayscale, contrast, deskew, right-size) with a pure-JavaScript image library,
//   • recognize the text with a WebAssembly OCR engine, behind a small SWAPPABLE recognizer interface so a different
//     or better engine can replace it later without changing any caller.
//
// It performs NO network I/O. The recognizer needs its language data present locally (langDir); if the data is
// missing or the engine cannot load, recognition degrades to "skip this file" (returns empty) rather than reaching
// out to a network or throwing — the same fail-soft contract lib/Extract.js keeps for its document readers.

const path = require('path');

// ── Tunable constants (a working OCR front end, not guesses) ──────────────────────────────────────────────────────
const RENDER_SCALE = 3;            // rasterize a PDF page at ~3x (≈216 DPI for US Letter): recognition accuracy tracks
                                   // effective resolution, and a moderate scale keeps the transient bitmap bounded.
const MAX_WIDTH = 2000;            // cap the width fed to the recognizer; wider gains little and costs memory/time.
const UPSCALE_TO = 1000;           // upscale a narrow image (a small photo/screenshot) so characters are tall enough
const MAX_UPSCALE = 4;             // to segment — but never blow a thumbnail up past this factor (it is just blur then).
const MAX_SLICE_HEIGHT = 3000;     // split a very tall image; recognition accuracy and memory both degrade past this.
const OCR_MAX_PAGES = 50;          // hard ceiling on scanned-PDF pages OCR'd (OCR is expensive; bound the work).
const SKEW_DETECT_WIDTH = 600;     // detect skew on a cheap downscale; the angle is scale-invariant.
const SKEW_MAX_DEG = 10;           // correct only small text-line tilt (±10°); a larger rotation is not a skew.
const SKEW_MIN_GAIN = 1.25;        // rotate only if the best angle beats level by this factor — never over-correct a
                                   // clean page (whose best angle is already 0, so it is left untouched).

// ── Lazy engine handles ───────────────────────────────────────────────────────────────────────────────────────────
let _pdfium = null;
async function pdfium() {
	if (_pdfium) return _pdfium;
	const { PDFiumLibrary } = require('@hyzyla/pdfium');
	_pdfium = await PDFiumLibrary.init();
	return _pdfium;
}
function Jimp() { return require('jimp').Jimp; }

// ── Rasterize: PDF buffer → per-page RGBA bitmaps, bounded ────────────────────────────────────────────────────────
// Renders up to `maxPages` from the START of the document (a truncated tail is better than OCR'ing the wrong end of a
// long scan). Yields { width, height, data } one page at a time so only one page's pixels are ever held at once.
async function* rasterizePdf(buffer, { maxPages = OCR_MAX_PAGES } = {}) {
	const lib = await pdfium();
	const doc = await lib.loadDocument(new Uint8Array(buffer));
	try {
		const count = Math.min(typeof doc.getPageCount === 'function' ? doc.getPageCount() : doc.pages().length, maxPages);
		for (let i = 0; i < count; i++) {
			const page = doc.getPage(i);
			const img = await page.render({ scale: RENDER_SCALE, render: 'bitmap' }); // { width, height, data: RGBA }
			yield { width: img.width, height: img.height, data: Buffer.from(img.data.buffer || img.data) };
		}
	} finally { try { doc.destroy(); } catch (_) {} }
}

// ── Preprocess: normalize a bitmap for the recognizer ─────────────────────────────────────────────────────────────
// Grayscale + contrast, deskew a small text-line tilt, then right-size (upscale a too-small image, cap a too-wide
// one). Returns an array of PNG buffers — one, or several horizontal slices when the page is very tall. Pure jimp, so
// it runs the same everywhere.
async function preprocess({ width, height, data }) {
	const J = Jimp();
	let img = new J({ width, height, data: Buffer.from(data) });
	img.greyscale();
	try { img.contrast(0.15); } catch (_) {}

	// Deskew: measure the tilt on a cheap grayscale downscale, and rotate to correct it only when it is a real,
	// small skew — a clean page measures 0 and is left untouched.
	const angle = detectSkew(img);
	if (angle) { try { img.rotate(-angle); } catch (_) {} }

	// Right-size for the recognizer.
	let w = img.bitmap.width;
	if (w < UPSCALE_TO) { const f = Math.min(MAX_UPSCALE, UPSCALE_TO / w); img.resize({ w: Math.round(w * f) }); }
	else if (w > MAX_WIDTH) { img.resize({ w: MAX_WIDTH }); }

	// Slice a very tall image into horizontal bands so no single image degrades recognition or spikes memory.
	const H = img.bitmap.height, bands = [];
	if (H > MAX_SLICE_HEIGHT) {
		for (let y = 0; y < H; y += MAX_SLICE_HEIGHT) {
			const bh = Math.min(MAX_SLICE_HEIGHT, H - y);
			const band = img.clone().crop({ x: 0, y, w: img.bitmap.width, h: bh });
			bands.push(await band.getBuffer('image/png'));
		}
	} else {
		bands.push(await img.getBuffer('image/png'));
	}
	return bands;
}

// Projection-profile skew detection: text lines are horizontal when the variance of the per-row darkness sums peaks.
// The sampling coordinate is rotated (not the image), so no buffer is allocated per candidate angle. Runs on a small
// grayscale copy for speed. Returns the correcting angle in degrees, or 0 to leave the image as-is.
function detectSkew(img) {
	try {
		const small = img.clone();
		if (small.bitmap.width > SKEW_DETECT_WIDTH) small.resize({ w: SKEW_DETECT_WIDTH });
		const { width, height, data } = small.bitmap; // RGBA; grayscale so R==G==B
		if (!width || height < 40) return 0;
		const gray = (x, y) => data[(y * width + x) * 4]; // red channel = gray value
		const rowVarAt = (deg) => {
			const rad = deg * Math.PI / 180, cos = Math.cos(rad), sin = Math.sin(rad), cx = width / 2, cy = height / 2;
			const rowSum = new Float64Array(height);
			for (let y = 0; y < height; y += 2) for (let x = 0; x < width; x += 2) {
				const ry = ((x - cx) * sin + (y - cy) * cos + cy) | 0;
				if (ry >= 0 && ry < height) rowSum[ry] += 255 - gray(x, y);
			}
			let mean = 0; for (let i = 0; i < height; i++) mean += rowSum[i]; mean /= height;
			let v = 0; for (let i = 0; i < height; i++) { const d = rowSum[i] - mean; v += d * d; } return v / height;
		};
		const base = rowVarAt(0); let best = 0, bestVar = base;
		for (let a = -SKEW_MAX_DEG; a <= SKEW_MAX_DEG; a += 0.5) { if (!a) continue; const v = rowVarAt(a); if (v > bestVar) { bestVar = v; best = a; } }
		return bestVar >= base * SKEW_MIN_GAIN ? best : 0;
	} catch (_) { return 0; }
}

// ── Language data (fetched once, on explicit enable, over a verified channel) ─────────────────────────────────────
// The recognizer needs a trained-data file per language. It is NOT bundled (it would bloat every install for a feature
// that is off by default); instead it is downloaded ONCE, checksum-verified, into the local langDir when the user
// turns OCR on — never at recognition time, and never touching the network again once present. Each entry is pinned by
// URL and SHA-256 so the exact bytes are reproducible and a tampered or truncated download is rejected.
const LANG_DATA = {
	eng: { url: 'https://github.com/tesseract-ocr/tessdata_fast/raw/main/eng.traineddata', sha256: '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2' },
};
// Ensure <langDir>/<lang>.traineddata is present and intact, downloading it (verified) if not. Idempotent — a present,
// checksum-matching file is reused with no network access. Run from the MAIN thread on enable, never from the scrubbed
// extraction child. Returns the file path; throws if the language is unknown or the (one-time) download fails.
async function ensureLangData(langDir, lang = 'eng') {
	const meta = LANG_DATA[lang];
	if (!meta) throw new Error('No pinned OCR language data for "' + lang + '".');
	const fs = require('fs'), fsp = fs.promises, Net = require('./Net');
	const dest = path.join(langDir, lang + '.traineddata');
	try { if (fs.existsSync(dest) && (await Net.sha256File(dest)) === meta.sha256) return dest; } catch (_) {}
	await fsp.mkdir(langDir, { recursive: true });
	await Net.download(meta.url, dest, { expectedSha256: meta.sha256 }); // writes to a temp sibling, verifies, moves into place, deletes on mismatch
	return dest;
}

// ── Recognizer: swappable interface, one WebAssembly engine shipped ───────────────────────────────────────────────
// A recognizer is opened once per document and reused across its pages (creating the engine is the expensive part), so
// the caller must close() it. It performs no network I/O: the language data must be present in `langDir`; if the engine
// cannot load, open() throws and the caller treats the file as un-recognizable (indexes it by name).
async function openRecognizer({ engine = 'tesseract', lang = 'eng', langDir } = {}) {
	if (engine !== 'tesseract') throw new Error('Unknown OCR engine: ' + engine);
	// Fail CLOSED, before touching the engine: the local <langDir>/<lang>.traineddata must already exist. tesseract.js
	// silently falls back to its default CDN whenever it cannot load a local model (a missing file, an unset langPath),
	// which would make recognition reach out to the network — exactly what this module forbids. By refusing here we
	// keep the "no network at recognition time" contract, and the caller (ocrImage/ocrPdf) treats the throw as fail-soft.
	const fs = require('fs');
	if (!langDir || !fs.existsSync(path.join(path.isAbsolute(langDir) ? langDir : path.resolve(langDir), lang + '.traineddata'))) {
		throw new Error('OCR language data not present locally for "' + lang + '"; refusing to fetch it at recognition time.');
	}
	const { createWorker, OEM } = require('tesseract.js');
	// langPath is a LOCAL directory holding <lang>.traineddata. We verified the file above, so the engine loads it from
	// disk and never reaches its default CDN.
	const worker = await createWorker(lang, OEM.LSTM_ONLY, {
		langPath: path.isAbsolute(langDir) ? langDir : path.resolve(langDir),
		cachePath: langDir,          // read/write the cached traineddata beside the source data, never a temp/home dir
		gzip: false,                 // the data is stored UNCOMPRESSED locally (ensureLangData fetched the plain .traineddata)
		logger: () => {}, errorHandler: () => {},
	});
	return {
		async recognize(pngBuffer) { const { data } = await worker.recognize(pngBuffer); return { text: (data && data.text) || '', confidence: (data && data.confidence) || 0 }; },
		async close() { try { await worker.terminate(); } catch (_) {} },
	};
}

// ── Decode: image bytes -> recognizer-ready bands (pluggable, future-proof) ───────────────────────────────────────
// Turning arbitrary image bytes into something the recognizer can read is the one fragile, format-specific step, so it
// is isolated here as an ORDERED chain that degrades gracefully. Each tier is tried in turn; the FIRST that succeeds
// wins, so a new format is added by dropping in one more RGBA decoder, with no change to any caller:
//
//   1. Pure-JavaScript image library (jimp): broad raster support (PNG, JPEG, BMP, TIFF, GIF). Decoding to RGBA lets
//      us run the full preprocessing (grayscale, contrast, deskew, right-size, slice), which sharpens recognition.
//   2. [extension point] Additional RGBA decoders for formats jimp cannot read (a WebAssembly WEBP/AVIF/HEIC decoder,
//      say). Each need only yield { width, height, data } for preprocess(), and that format then ALSO gets the
//      preprocessing above. None is bundled today; this is where one slots in without touching the recognizer or the
//      callers.
//   3. Recognizer's own decoder (Leptonica, WebAssembly, already loaded): hand it the raw bytes. It reads WEBP and
//      several formats jimp cannot, so the file is still recognized — just without the preprocessing — instead of
//      being silently skipped and indexed as empty. Any format a future recognizer engine learns is covered here for
//      free.
//
// Returns an array of "bands" (each a PNG buffer from preprocessing, or the raw image buffer at tier 3) for the
// recognizer to read in turn.
async function imageToBands(buffer) {
	try {
		const src = await Jimp().read(buffer);
		return await preprocess({ width: src.bitmap.width, height: src.bitmap.height, data: src.bitmap.data });
	} catch (_) { /* fall through to the next decoder tier */ }
	// Tier 2 decoders would be tried here (see above) before the recognizer-decodes-it-itself fallback.
	return [buffer];
}

// ── High-level entry points used by lib/Extract.js ────────────────────────────────────────────────────────────────
// Recognize a list of bands (preprocessed page slices, or a raw image buffer), appending each one's text to `out` and
// stopping once the accumulated text reaches `cap`. Shared by ocrImage and ocrPdf so the cap-and-newline accounting
// lives in exactly one place.
async function recognizeBands(rec, bands, out, cap) {
	for (const band of bands) {
		const { text } = await rec.recognize(band);
		if (text) out += (out ? '\n' : '') + text;
		if (out.length >= cap) break;
	}
	return out;
}

// Recognize the text in a single image file's bytes. Returns text up to `cap`, or '' if recognition is unavailable.
async function ocrImage(buffer, { cap = Infinity, lang = 'eng', langDir, engine } = {}) {
	let rec = null;
	try {
		const bands = await imageToBands(buffer);
		rec = await openRecognizer({ engine, lang, langDir });
		const out = await recognizeBands(rec, bands, '', cap);
		return out.slice(0, cap === Infinity ? undefined : cap);
	} catch (_) { return ''; } finally { if (rec) await rec.close(); }
}

// Recognize the text across a scanned PDF's pages. One recognizer is reused for the whole document; pages are read one
// at a time and accumulation stops at `cap`. Returns '' if recognition is unavailable.
async function ocrPdf(buffer, { cap = Infinity, lang = 'eng', langDir, engine, maxPages = OCR_MAX_PAGES } = {}) {
	let rec = null;
	try {
		rec = await openRecognizer({ engine, lang, langDir });
		let out = '';
		for await (const bitmap of rasterizePdf(buffer, { maxPages })) {
			out = await recognizeBands(rec, await preprocess(bitmap), out, cap);
			if (out.length >= cap) break;
		}
		return out.slice(0, cap === Infinity ? undefined : cap);
	} catch (_) { return ''; } finally { if (rec) await rec.close(); }
}

module.exports = { rasterizePdf, preprocess, detectSkew, openRecognizer, ocrImage, ocrPdf, ensureLangData, LANG_DATA, RENDER_SCALE, MAX_WIDTH, OCR_MAX_PAGES };
