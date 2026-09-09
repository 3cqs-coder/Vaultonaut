/* rclone-reader.js — a faithful, DECRYPTION-ONLY reimplementation of the stock rclone "crypt" format,
 * in portable JavaScript, so a phone can open a vault's files entirely in the browser with no server and
 * no engine. It decrypts; it never encrypts. The desktop tool remains the only writer.
 *
 * Why this exists: the vault format is stock rclone crypt, and a web-scoped read capability already carries
 * everything a decryptor needs (the read key, the salt, and the filename mode). A browser cannot run the
 * engine binary, so the ONE thing that must be reimplemented is decryption — and it is reimplemented once,
 * here, on top of audited primitives (the NaCl secretbox, scrypt, and an AES block cipher), never with any
 * home-grown cryptography. It is validated byte-for-byte against ciphertext produced by the real engine.
 *
 * The exact same file runs under Node.js (for that validation test) and in the browser (for the mobile
 * client), so the code a phone runs is the code the test proves correct.
 *
 * Format facts it implements (all from the rclone crypt spec):
 *   - Key derivation: scrypt(N=16384, r=8, p=1) over the UTF-8 bytes of the read key and the salt string,
 *     80 bytes out, split dataKey[0:32] / nameKey[32:64] / nameTweak[64:80]. An empty salt uses rclone's
 *     fixed default salt.
 *   - File contents: a 32-byte header ("RCLONE\0\0" + a 24-byte nonce), then 64 KiB plaintext blocks each
 *     sealed with the NaCl secretbox (XSalsa20-Poly1305, 16-byte tag). The nonce is a little-endian counter
 *     incremented by one after every block.
 *   - File names (standard mode): AES-256 in EME (ECB-Mix-ECB) under nameKey with nameTweak, PKCS#7 padded
 *     to the 16-byte block, rendered with base32 (RFC 4648 extended-hex alphabet, lower-case, unpadded).
 *     Path segments are decrypted independently; with directory-name encryption off, only the last segment
 *     (the file name) is encrypted and parent folders are plain.
 */
(function (root, factory) {
	if (typeof module === 'object' && module.exports) {
		module.exports = factory(require('./vendor/nacl.min.js'), require('./vendor/scrypt.js'), require('./vendor/aes-js.js'));
	} else {
		root.RcloneReader = factory(root.nacl, root.scrypt, root.aesjs);
	}
})(typeof self !== 'undefined' ? self : this, function (nacl, scrypt, aesjs) {
	'use strict';

	// ---- constants (verbatim from the rclone crypt format) ----
	var FILE_MAGIC = [0x52, 0x43, 0x4c, 0x4f, 0x4e, 0x45, 0x00, 0x00]; // "RCLONE\0\0"
	var FILE_NONCE_SIZE = 24;
	var FILE_HEADER_SIZE = FILE_MAGIC.length + FILE_NONCE_SIZE; // 32
	var BLOCK_DATA_SIZE = 65536;      // plaintext bytes per block
	var BLOCK_TAG_SIZE = 16;          // Poly1305 tag (secretbox overhead)
	var BLOCK_SIZE = BLOCK_TAG_SIZE + BLOCK_DATA_SIZE; // 65552 ciphertext bytes per full block
	var AES_BLOCK = 16;
	// rclone's default salt, used when a vault configures no salt (no password2).
	var DEFAULT_SALT = new Uint8Array([0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1]);
	// base32 extended-hex alphabet (RFC 4648 §7), NOT the standard base32 alphabet.
	var B32HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

	function utf8(s) {
		// This file runs in the browser and the service worker, where TextEncoder/TextDecoder are always present but
		// Node's Buffer is NOT — a Buffer fallback would throw "Buffer is not defined" rather than degrade, so require
		// the Web API and fail with a clear message if a runtime somehow lacks it.
		if (typeof TextEncoder === 'undefined') throw new Error('This browser is too old to open a vault here (no TextEncoder).');
		return new TextEncoder().encode(s);
	}
	function fromUtf8(bytes) {
		if (typeof TextDecoder === 'undefined') throw new Error('This browser is too old to open a vault here (no TextDecoder).');
		return new TextDecoder().decode(bytes);
	}

	// ---- key derivation ----
	// Both inputs are the UTF-8 bytes of the revealed strings, exactly as the engine feeds scrypt.
	function deriveKeys(readKey, salt) {
		var pw = utf8(String(readKey));
		var saltBytes = (salt == null || salt === '') ? DEFAULT_SALT : utf8(String(salt));
		var out = scrypt.syncScrypt(pw, saltBytes, 16384, 8, 1, 80);
		return { dataKey: out.slice(0, 32), nameKey: out.slice(32, 64), nameTweak: out.slice(64, 80) };
	}

	// ---- file contents ----
	function incrementNonce(nonce) {
		for (var i = 0; i < nonce.length; i++) {
			var prev = nonce[i];
			nonce[i] = (prev + 1) & 0xff;
			if (nonce[i] >= prev) break; // no wrap past 0xff -> no carry -> done
		}
	}
	function decryptContent(dataKey, cipherBytes) {
		var buf = cipherBytes instanceof Uint8Array ? cipherBytes : new Uint8Array(cipherBytes);
		if (buf.length < FILE_HEADER_SIZE) throw new Error('The encrypted file is too short to be valid.');
		for (var i = 0; i < FILE_MAGIC.length; i++) if (buf[i] !== FILE_MAGIC[i]) throw new Error('This does not look like an encrypted vault file.');
		var nonce = buf.slice(FILE_MAGIC.length, FILE_HEADER_SIZE); // 24 bytes, mutable counter
		var parts = [];
		var total = 0;
		var off = FILE_HEADER_SIZE;
		while (off < buf.length) {
			var end = Math.min(off + BLOCK_SIZE, buf.length);
			var block = buf.subarray(off, end);
			if (block.length <= BLOCK_TAG_SIZE) throw new Error('The encrypted file has a malformed block.');
			var plain = nacl.secretbox.open(block, nonce, dataKey);
			if (!plain) throw new Error('The vault file could not be decrypted — wrong key or the file was altered.');
			parts.push(plain);
			total += plain.length;
			incrementNonce(nonce);
			off = end;
		}
		var outBytes = new Uint8Array(total);
		var p = 0;
		for (var k = 0; k < parts.length; k++) { outBytes.set(parts[k], p); p += parts[k].length; }
		return outBytes;
	}
	// The decrypted size of an encrypted file, without decrypting it (for range math / progress).
	function decryptedSize(cipherLen) {
		var size = cipherLen - FILE_HEADER_SIZE;
		if (size < 0) return 0;
		var blocks = Math.floor(size / BLOCK_SIZE);
		var residue = size % BLOCK_SIZE;
		var out = blocks * BLOCK_DATA_SIZE;
		if (residue !== 0) { residue -= BLOCK_TAG_SIZE; if (residue <= 0) return out; out += residue; }
		return out;
	}

	// ---- streaming: decrypt only the blocks covering a byte range (for large media, no whole-file decrypt) ----
	// Extract and validate the 24-byte nonce from a file's 32-byte header.
	function parseHeaderNonce(headerBytes) {
		var buf = headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes);
		if (buf.length < FILE_HEADER_SIZE) throw new Error('The encrypted header is too short.');
		for (var i = 0; i < FILE_MAGIC.length; i++) if (buf[i] !== FILE_MAGIC[i]) throw new Error('This does not look like an encrypted vault file.');
		return buf.slice(FILE_MAGIC.length, FILE_HEADER_SIZE);
	}
	// Advance a copy of the header nonce to the little-endian counter value for block `n`. Adds `n` to the LE counter
	// arithmetically (O(nonce length)) instead of looping incrementNonce n times (O(n)), so a range request deep into
	// a very large media file does not spin. Byte-identical to repeated incrementNonce, and validated as such.
	function nonceForBlock(headerNonce, n) {
		var nonce = headerNonce.slice();
		var add = n, carry = 0;
		for (var i = 0; i < nonce.length; i++) {
			var total = nonce[i] + (add % 256) + carry;
			nonce[i] = total & 0xff;
			carry = total > 0xff ? 1 : 0;
			add = Math.floor(add / 256);
			if (add === 0 && carry === 0) break;
		}
		return nonce;
	}
	// Decrypt a contiguous run of whole ciphertext blocks (each BLOCK_SIZE; the last may be short) beginning at
	// block index `firstBlockIndex`, returning the concatenated plaintext. The caller then slices to the exact
	// byte range it wanted. This is what lets a media player fetch and decrypt only the part it is playing.
	function decryptBlocks(dataKey, headerNonce, cipherBlocks, firstBlockIndex) {
		var buf = cipherBlocks instanceof Uint8Array ? cipherBlocks : new Uint8Array(cipherBlocks);
		var nonce = nonceForBlock(headerNonce, firstBlockIndex);
		var parts = [], total = 0, off = 0;
		while (off < buf.length) {
			var end = Math.min(off + BLOCK_SIZE, buf.length);
			var block = buf.subarray(off, end);
			if (block.length <= BLOCK_TAG_SIZE) break;
			var plain = nacl.secretbox.open(block, nonce, dataKey);
			if (!plain) throw new Error('A media block could not be decrypted — wrong key or altered data.');
			parts.push(plain); total += plain.length;
			incrementNonce(nonce);
			off = end;
		}
		var out = new Uint8Array(total), p = 0;
		for (var k = 0; k < parts.length; k++) { out.set(parts[k], p); p += parts[k].length; }
		return out;
	}
	// Map a wanted PLAINTEXT range [plainStart, plainEnd) to the ciphertext it needs. Returns which block to
	// start at, the (whole-block-aligned) ciphertext byte range to fetch, and where the wanted range sits inside
	// the decrypted result. `cipherLen` is the whole encrypted file length.
	function rangeToBlocks(plainStart, plainEnd, cipherLen) {
		var firstBlock = Math.floor(plainStart / BLOCK_DATA_SIZE);
		var lastBlock = Math.floor((plainEnd - 1) / BLOCK_DATA_SIZE);
		var cipherStart = FILE_HEADER_SIZE + firstBlock * BLOCK_SIZE;
		var cipherEnd = Math.min(cipherLen, FILE_HEADER_SIZE + (lastBlock + 1) * BLOCK_SIZE); // exclusive
		var sliceStart = plainStart - firstBlock * BLOCK_DATA_SIZE;
		return { firstBlock: firstBlock, cipherStart: cipherStart, cipherEnd: cipherEnd, sliceStart: sliceStart, sliceEnd: sliceStart + (plainEnd - plainStart) };
	}

	// ---- base32 (extended-hex) ----
	function b32hexDecode(s) {
		var up = String(s).toUpperCase();
		var bits = 0, value = 0, out = [];
		for (var i = 0; i < up.length; i++) {
			var idx = B32HEX.indexOf(up[i]);
			if (idx < 0) continue; // skip any stray padding
			value = (value << 5) | idx;
			bits += 5;
			if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff); }
		}
		return new Uint8Array(out);
	}

	// ---- AES + EME (filename decryption) ----
	function aesEncBlock(aes, src) { return new Uint8Array(aes.encrypt(src)); }
	function aesDecBlock(aes, src) { return new Uint8Array(aes.decrypt(src)); }
	function multByTwo(inBlk) {
		var out = new Uint8Array(16);
		out[0] = ((inBlk[0] << 1) & 0xff) ^ (135 & (0 - (inBlk[15] >> 7) & 0xff));
		for (var j = 1; j < 16; j++) out[j] = ((inBlk[j] << 1) & 0xff) + (inBlk[j - 1] >> 7);
		return out;
	}
	function xorInto(out, a, b) { for (var i = 0; i < 16; i++) out[i] = a[i] ^ b[i]; }
	function tabulateL(aes, m) {
		var Li = aesEncBlock(aes, new Uint8Array(16));
		var table = [];
		for (var i = 0; i < m; i++) { Li = multByTwo(Li); table.push(Li.slice()); }
		return table;
	}
	// EME transform. Decryption uses the block cipher's DECRYPT for the two data passes; the L table always
	// uses ENCRYPT. Faithful to the reference EME (Halevi-Rogaway) that the engine uses for crypt names.
	function emeTransform(aes, tweak, data, decrypt) {
		var m = data.length / 16;
		if (m === 0 || m > 128 || data.length % 16 !== 0) throw new Error('Bad name block length.');
		var C = new Uint8Array(data.length);
		var LTable = tabulateL(aes, m);
		var PPj = new Uint8Array(16);
		for (var j = 0; j < m; j++) {
			var Pj = data.subarray(j * 16, j * 16 + 16);
			xorInto(PPj, Pj, LTable[j]);
			var t = decrypt ? aesDecBlock(aes, PPj) : aesEncBlock(aes, PPj);
			C.set(t, j * 16);
		}
		var MP = new Uint8Array(16);
		xorInto(MP, C.subarray(0, 16), tweak);
		for (var j2 = 1; j2 < m; j2++) for (var b = 0; b < 16; b++) MP[b] ^= C[j2 * 16 + b];
		var MC = decrypt ? aesDecBlock(aes, MP) : aesEncBlock(aes, MP);
		var M = new Uint8Array(16);
		xorInto(M, MP, MC);
		for (var j3 = 1; j3 < m; j3++) {
			M = multByTwo(M);
			for (var b2 = 0; b2 < 16; b2++) C[j3 * 16 + b2] = C[j3 * 16 + b2] ^ M[b2];
		}
		var CCC1 = new Uint8Array(16);
		xorInto(CCC1, MC, tweak);
		for (var j4 = 1; j4 < m; j4++) for (var b3 = 0; b3 < 16; b3++) CCC1[b3] ^= C[j4 * 16 + b3];
		C.set(CCC1, 0);
		for (var j5 = 0; j5 < m; j5++) {
			var seg = C.subarray(j5 * 16, j5 * 16 + 16);
			var tt = decrypt ? aesDecBlock(aes, seg) : aesEncBlock(aes, seg);
			for (var b4 = 0; b4 < 16; b4++) C[j5 * 16 + b4] = tt[b4] ^ LTable[j5][b4];
		}
		return C;
	}
	function pkcs7Unpad(data) {
		if (data.length === 0 || data.length % AES_BLOCK !== 0) throw new Error('Bad name padding.');
		var pad = data[data.length - 1];
		if (pad === 0 || pad > AES_BLOCK) throw new Error('Bad name padding length.');
		for (var i = data.length - pad; i < data.length; i++) if (data[i] !== pad) throw new Error('Bad name padding bytes.');
		return data.subarray(0, data.length - pad);
	}
	// Decrypt one encrypted name segment (standard filename mode).
	function decryptSegment(nameKey, nameTweak, encName) {
		var raw = b32hexDecode(encName);
		var aes = new aesjs.AES(nameKey);
		var eme = emeTransform(aes, nameTweak, raw, true);
		return fromUtf8(pkcs7Unpad(eme));
	}
	// Decrypt a whole relative path. With directory-name encryption off, only the last segment is encrypted.
	function decryptPath(nameKey, nameTweak, encPath, dirNameEncrypt) {
		var segments = String(encPath).split('/');
		for (var i = 0; i < segments.length; i++) {
			if (!segments[i]) continue;
			if (dirNameEncrypt === false && i !== segments.length - 1) continue;
			segments[i] = decryptSegment(nameKey, nameTweak, segments[i]);
		}
		return segments.join('/');
	}

	return {
		deriveKeys: deriveKeys,
		decryptContent: decryptContent,
		decryptedSize: decryptedSize,
		decryptSegment: decryptSegment,
		decryptPath: decryptPath,
		// streaming (large media): decrypt only the blocks covering a byte range
		parseHeaderNonce: parseHeaderNonce,
		decryptBlocks: decryptBlocks,
		rangeToBlocks: rangeToBlocks,
		HEADER_SIZE: FILE_HEADER_SIZE,
		BLOCK_SIZE: BLOCK_SIZE,
		BLOCK_DATA_SIZE: BLOCK_DATA_SIZE,
		_internals: { b32hexDecode: b32hexDecode, emeTransform: emeTransform, incrementNonce: incrementNonce, DEFAULT_SALT: DEFAULT_SALT }
	};
});
