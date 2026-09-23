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
		//    OCR the fixture PDF and confirm a known phrase is read.
		const modelDir = path.join(require('../Common').dataDir(), 'tessdata');
		if (fs.existsSync(path.join(modelDir, 'eng.traineddata'))) {
			const recognized = (await Ocr.ocrPdf(pdf, { langDir: modelDir })).toLowerCase();
			ok('ocrPdf recognizes text in the fixture when the model is present', recognized.includes('vaultonaut') || recognized.includes('searchable'));
		} else {
			console.log('  skip  full recognition (no local language model — CI runs offline)');
		}

		// ── Source invariants (always run) ──────────────────────────────────────────────────────────────────────────
		// The heavy OCR libraries must load LAZILY, only when recognition actually runs — so an OCR-off build never
		// pays for them. lib/Extract.js must therefore reference lib/Ocr only inside a function body (a lazy require),
		// never at module top level.
		const extract = read('lib/Extract.js');
		ok('Extract.js requires ./Ocr lazily (inside a handler), never at module load', /require\('\.\/Ocr'\)/.test(extract) && !/^const\s+\w+\s*=\s*require\('\.\/Ocr'\)/m.test(extract));

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

		console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL OCR CHECKS PASSED'));
	} finally { fs.rmSync(tmp, { recursive: true, force: true }); }
	process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
