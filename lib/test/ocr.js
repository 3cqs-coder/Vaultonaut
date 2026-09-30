'use strict';
// lib/test/ocr.js — optical character recognition for content search (lib/Ocr.js) and its wiring into the extractor.
// The parts that need no language model and no network run always: PDF page rasterization (WebAssembly), image
// preprocessing (pure JS), skew detection, the OCR-setting allowlist gate, the fail-soft contract when the model is
// absent, and source-level invariants that keep OCR non-blocking, opt-in, and verified. The full recognition check
// runs only when the language data is already present locally, so CI stays offline and deterministic (like the
// engine-gated tests) instead of downloading a model.
//
// Run:  node lib/test/ocr.js

const fs = require('fs');
const os = require('os');
const path = require('path');
const Ocr = require('../Ocr');
const D = require('../SearchDefs');

let failures = 0;
function ok(name, cond) { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; }
const read = (rel) => { try { return fs.readFileSync(path.join(__dirname, '..', '..', rel), 'utf8'); } catch (_) { return ''; } };

async function main() {
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vdisk-ocr-'));
	try {
		// 1. Rasterize a PDF page to a bitmap (WebAssembly PDFium — no model, no native binding). The committed fixture
		//    is a tiny one-page PDF.
		const pdf = fs.readFileSync(path.join(__dirname, 'fixtures', 'ocr-sample.pdf'));
		let pages = 0, firstOk = false;
		for await (const bmp of Ocr.rasterizePdf(pdf, { maxPages: 3 })) {
			pages++;
			if (pages === 1) firstOk = bmp.width > 0 && bmp.height > 0 && bmp.data.length === bmp.width * bmp.height * 4;
		}
		ok('rasterizePdf renders the PDF to a bitmap (WebAssembly, no native)', pages >= 1 && firstOk);

		// 2. Preprocess a synthetic bitmap: grayscale/contrast/deskew/right-size, returning PNG buffer(s). A narrow
		//    image is upscaled, so the output is a valid, non-empty PNG.
		const w = 300, h = 120, data = Buffer.alloc(w * h * 4, 0xff); // a blank white RGBA image
		const bands = await Ocr.preprocess({ width: w, height: h, data });
		ok('preprocess returns at least one PNG image', Array.isArray(bands) && bands.length >= 1 && Buffer.isBuffer(bands[0]) && bands[0].length > 8 && bands[0][0] === 0x89 && bands[0][1] === 0x50);

		// 3. Skew detection is conservative: a uniform (untilted) image measures no skew, so a clean page is never
		//    needlessly rotated.
		const { Jimp } = require('jimp');
		const flat = new Jimp({ width: 400, height: 200, color: 0xffffffff });
		ok('detectSkew reports no skew for a clean, untilted image', Ocr.detectSkew(flat) === 0);

		// 4. The OCR-setting allowlist gate: an image is content-indexable ONLY when OCR is on; a normal document always
		//    is. This is what stops an OCR-off build from ever spawning an extractor for an image.
		ok('an image is NOT extractable with OCR off', D.isExtractable('scan.png', false) === false && D.isIndexable('scan.png', false) === false);
		ok('an image IS extractable with OCR on', D.isExtractable('scan.png', true) === true && D.isIndexable('scan.png', true) === true);
		ok('a normal document is extractable regardless of OCR', D.isExtractable('report.pdf', false) === true && D.isExtractable('sheet.xlsx', false) === true);

		// 5. Unknown language is refused (no silent wrong-language recognition).
		let unknownThrew = false;
		try { await Ocr.ensureLangData(tmp, 'zzz'); } catch (_) { unknownThrew = true; }
		ok('ensureLangData refuses an unknown language', unknownThrew);

		// 6. Fail-soft with NO network: recognizing an image when the language data is absent returns '' (the file is
		//    indexed by name only) instead of throwing OR reaching out to a network — the recognizer is pointed at a
		//    local, empty langDir, so it can only fail locally.
		const emptyLang = path.join(tmp, 'no-model');
		fs.mkdirSync(emptyLang, { recursive: true });
		const imgBuf = await new Jimp({ width: 80, height: 40, color: 0xffffffff }).getBuffer('image/png');
		const t = await Ocr.ocrImage(imgBuf, { langDir: emptyLang });
		ok('ocrImage returns empty (fail-soft) when the language data is missing', t === '');

		// 7. Full recognition — only when the model is already present locally, so CI never downloads it. When present,
		//    OCR the fixture PDF, and also a WEBP image. The WEBP matters specifically: the pure-JavaScript image library
		//    cannot decode WEBP, so this exercises the decode fallback (the recognizer's own decoder) end to end and
		//    proves a WEBP is recognized rather than silently skipped.
		const modelDir = path.join(require('../Common').dataDir(), 'tessdata');
		if (fs.existsSync(path.join(modelDir, 'eng.traineddata'))) {
			const recognized = (await Ocr.ocrPdf(pdf, { langDir: modelDir })).toLowerCase();
			ok('ocrPdf recognizes text in the fixture when the model is present', recognized.includes('vaultonaut') || recognized.includes('searchable'));
			const webp = fs.readFileSync(path.join(__dirname, 'fixtures', 'ocr-sample.webp'));
			const wtext = await Ocr.ocrImage(webp, { langDir: modelDir });
			ok('ocrImage recognizes a WEBP through the decode fallback (the library cannot decode WEBP)', wtext.includes('71938'));
		} else {
			console.log('  skip  full recognition (no local language model — CI runs offline)');
		}

		// 8. Per-page render-scale clamp (anti-OOM for one pathological page). A normal page renders at the full
		//    RENDER_SCALE; an unusually large or very tall/narrow page box is scaled down so the rendered bitmap never
		//    exceeds MAX_WIDTH across or MAX_RENDER_PIXELS in area — the transient one-page bitmap stays bounded before
		//    preprocess ever runs. Uses a fake page exposing getOriginalSize(), so it needs no giant fixture.
		const fakePage = (ow, oh) => ({ getOriginalSize: () => ({ originalWidth: ow, originalHeight: oh }) });
		ok('renderScaleFor leaves a normal page at the full render scale (output unchanged)', Ocr.renderScaleFor(fakePage(612, 792)) === Ocr.RENDER_SCALE);
		const bw = 8000, bh = 6000, bs = Ocr.renderScaleFor(fakePage(bw, bh));
		ok('renderScaleFor clamps a huge page so the rendered width stays within MAX_WIDTH', bs < Ocr.RENDER_SCALE && bw * bs <= Ocr.MAX_WIDTH + 1);
		const tw = 500, th = 40000, ts = Ocr.renderScaleFor(fakePage(tw, th));
		ok('renderScaleFor clamps a very tall/narrow page by pixel area (not just width)', ts < Ocr.RENDER_SCALE && (tw * ts) * (th * ts) <= Ocr.MAX_RENDER_PIXELS + 8);
		ok('renderScaleFor falls back to the full scale when the page size is unavailable', Ocr.renderScaleFor({}) === Ocr.RENDER_SCALE);

		// 9. Orientation retry: a single image/page whose first read is low-confidence is retried at 90/180/270 and the
		//    best-scoring orientation is kept; a confident first read is never retried. A stub recognizer makes this
		//    deterministic and offline (no language model), and the rotation itself is real jimp.
		const oneBand = await new Jimp({ width: 60, height: 40, color: 0xffffffff }).getBuffer('image/png');
		const seqRec = (seq) => { let i = 0; return { n: () => i, recognize: async () => seq[Math.min(i++, seq.length - 1)] }; };
		const r1 = seqRec([{ text: 'orig', confidence: 20 }, { text: 'r90', confidence: 30 }, { text: 'r180', confidence: 80 }, { text: 'r270', confidence: 10 }]);
		const best = await Ocr.recognizeOriented(r1, oneBand);
		ok('recognizeOriented keeps the highest-confidence orientation for a turned image', best === 'r180' && r1.n() === 3);
		const r2 = seqRec([{ text: 'level', confidence: 90 }]);
		const kept = await Ocr.recognizeOriented(r2, oneBand);
		ok('recognizeOriented does no extra work when the first read is already confident', kept === 'level' && r2.n() === 1);

		// 9b. A wrong turn that only marginally outscores a faint-but-correct upright read must NOT overwrite it (the
		//     ROTATE_MIN_GAIN guard, mirroring deskew's over-correction discipline). Upright scores 45; the best turn
		//     scores 52 — above upright but below the 1.25x margin — so the upright text is kept.
		const rMargin = seqRec([{ text: 'upright', confidence: 45 }, { text: 'turn90', confidence: 52 }, { text: 'turn180', confidence: 50 }, { text: 'turn270', confidence: 40 }]);
		const marginKept = await Ocr.recognizeOriented(rMargin, oneBand);
		ok('recognizeOriented keeps faint-but-correct upright text over a marginally-higher wrong turn', marginKept === 'upright');

		// 9c. A blank / figure-only page (no readable text) is left alone — rotating it recovers nothing, so the three
		//     extra recognitions are skipped. This is what keeps a long scan with blank pages within its time budget.
		const rBlank = seqRec([{ text: '   ', confidence: 0 }]);
		const blankOut = await Ocr.recognizeOriented(rBlank, oneBand);
		ok('recognizeOriented skips the retry on a blank page (no wasted recognitions)', blankOut.trim() === '' && rBlank.n() === 1);

		// 9d. Per-document orientation learning: once a page reads confidently, the rest of a uniform document is read
		//     at that angle only — no repeated four-way search — so a 50-page scan does not multiply its OCR work.
		const orient = { angle: null };
		const rDoc = seqRec([{ text: 'page1', confidence: 80 }, { text: 'page2', confidence: 20 }, { text: 'x', confidence: 10 }, { text: 'x', confidence: 10 }, { text: 'x', confidence: 10 }]);
		await Ocr.recognizeOriented(rDoc, oneBand, orient);   // page 1: confident upright → learns angle 0
		const p2 = await Ocr.recognizeOriented(rDoc, oneBand, orient); // page 2: faint, but read once at the learned angle
		ok('recognizeOriented learns a confident orientation and reuses it (bounded work per page)', orient.angle === 0 && p2 === 'page2' && rDoc.n() === 2);

		// 10. recognizeBands applies the orientation retry ONLY to a lone band (a whole image / normal page), never to
		//     the slices of a tall page (each a fragment for which a per-slice rotation would be meaningless).
		const rSingle = seqRec([{ text: 'a', confidence: 20 }, { text: 'b', confidence: 80 }]);
		await Ocr.recognizeBands(rSingle, [oneBand], '', Infinity);
		ok('recognizeBands runs the orientation retry for a single band', rSingle.n() === 2);
		const rMulti = seqRec([{ text: 'm', confidence: 10 }]);
		await Ocr.recognizeBands(rMulti, [oneBand, oneBand], '', Infinity);
		ok('recognizeBands does NOT rotate a multi-band (tall, sliced) page', rMulti.n() === 2);

		// ── Source invariants (always run) ──────────────────────────────────────────────────────────────────────────
		// The heavy OCR libraries must load LAZILY, only when recognition actually runs — so an OCR-off build never
		// pays for them. lib/Extract.js must therefore reference lib/Ocr only inside a function body (a lazy require),
		// never at module top level.
		const extract = read('lib/Extract.js');
		ok('Extract.js requires ./Ocr lazily (inside a handler), never at module load', /require\('\.\/Ocr'\)/.test(extract) && !/^const\s+\w+\s*=\s*require\('\.\/Ocr'\)/m.test(extract));

		// The untrusted-PDF parse must disable script execution and eval-based code paths in the bundled PDF engine
		// (defense in depth, matching the mobile viewer), so a malicious PDF can never reach a scripting/eval path.
		ok('the backend PDF parse disables eval and scripting (getDocumentProxy hardened)', /getDocumentProxy\([\s\S]{0,160}isEvalSupported:\s*false[\s\S]{0,40}enableScripting:\s*false/.test(extract));

		// OCR runs only when the user has turned it on: contentReindex resolves the OCR options from settings through
		// ocrOptions(), which returns disabled unless the setting is enabled, and never OCRs when allowOcr is not set.
		const vault = read('lib/Vault.js');
		ok('OCR is gated on the setting being on (contentReindex resolves it through ocrOptions)', /allowOcr\s*\?\s*await ocrOptions\(\)\s*:\s*\{\s*enabled:\s*false\s*\}/.test(vault));
		// The automatic refresh on mount can now OCR newly added scans, but must stay non-blocking: it is DETACHED
		// (started with .then, not awaited) so it never delays the mount, and indexing is incremental so it never
		// re-reads the whole vault. This asserts the refresh calls contentReindex from a detached .then, not inline.
		ok('the on-mount content refresh is detached, so OCR never blocks opening a vault', /\.then\(\(\)\s*=>\s*contentReindex\(vault,\s*\{\s*allowOcr:\s*true\s*\}\)/.test(vault));

		// The one-time language-data fetch is checksum-VERIFIED (a pinned SHA-256 through the shared verified downloader),
		// never an unverified blob — the same standard the engine binary is held to.
		const ocrSrc = read('lib/Ocr.js');
		ok('the language-data fetch is checksum-verified (expectedSha256 through Net.download)', /expectedSha256:\s*meta\.sha256/.test(ocrSrc) && /sha256:\s*'[0-9a-f]{64}'/.test(ocrSrc));

		// Image decode is a pluggable chain that degrades gracefully: when the pure-JavaScript library cannot decode a
		// format, the raw bytes are handed to the recognizer's own decoder instead of being dropped. This is what stops
		// a format such as WEBP from silently indexing as empty, and it is the extension point where a future decoder
		// slots in. Assert the fallback (returning the raw buffer) is present in the decode helper.
		ok('image decode falls back to the recognizer for formats the library cannot read (no silent skip)', /return\s*\[\s*buffer\s*\]/.test(ocrSrc));

		// The PDF rasterizer must render each page at the per-page CLAMPED scale (renderScaleFor), never a fixed
		// RENDER_SCALE — otherwise a page with a huge media box would materialize an oversized bitmap before the width
		// cap in preprocess, the one-page OOM risk this guards against.
		ok('rasterizePdf renders at the per-page clamped scale, not a fixed one', /page\.render\(\{\s*scale:\s*renderScaleFor\(page\)/.test(ocrSrc) && /Math\.sqrt\(MAX_RENDER_PIXELS/.test(ocrSrc));
		// A lone image/page is recognized through the orientation retry, so a sideways or upside-down scan is read the
		// right way up; the retry is confidence-gated (a clean page pays nothing) and tries the three quarter-turns.
		ok('a single band is recognized with a confidence-gated orientation retry', /recognizeOriented\(rec,\s*band,\s*orient\)/.test(ocrSrc) && /ROTATE_RETRY_CONFIDENCE/.test(ocrSrc) && /\[90,\s*180,\s*270\]/.test(ocrSrc));
		// The retry must never hurt the common case: a rotation replaces upright only past a gain margin (so a faint
		// correct page is not overwritten by a noisier turn), a blank page is left alone (no wasted recognitions), and
		// the winning orientation is learned per document (so a uniform multi-page scan is searched once, not per page).
		ok('the orientation retry keeps upright unless a turn beats it by ROTATE_MIN_GAIN', /best\.conf\s*\*\s*ROTATE_MIN_GAIN/.test(ocrSrc));
		ok('the orientation retry skips a blank page (returns before rotating when there is no text)', /if\s*\(!best\.text\.trim\(\)\)\s*return best\.text/.test(ocrSrc));
		ok('the orientation is learned once per document and reused (orient.angle across pages)', /orient\.angle\s*=\s*bestAngle/.test(ocrSrc) && /const orient = \{ angle: null \}/.test(ocrSrc));

		console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OCR CHECKS PASSED'));
	} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
