# Vendored third-party libraries

The mobile client decrypts vault files in the browser, where the engine binary cannot run. It does this
on top of three small, widely used, audited cryptographic primitives, vendored here unmodified so the
mobile client is self-contained and needs no build step or network fetch. No cryptography is home-grown;
these libraries provide the NaCl secretbox, scrypt, and the AES block cipher, and the vault's decryption
is built on them and validated byte-for-byte against ciphertext the real engine produced.

One further library, PDF.js, is vendored to render PDF pages to a canvas, so a PDF displays the same in
the desktop app's embedded browser (which does not paint a PDF inside a sub-frame) as in every browser.
It is loaded only when a PDF is first opened and decodes only the already-decrypted bytes it is handed.

## tweetnacl (`nacl.min.js`)

Version 1.0.3. The NaCl secretbox (XSalsa20-Poly1305) used to decrypt file contents. Released into the
public domain (Unlicense):

> This is free and unencumbered software released into the public domain. Anyone is free to copy, modify,
> publish, use, compile, sell, or distribute this software, either in source code form or as a compiled
> binary, for any purpose, commercial or non-commercial, and by any means. THE SOFTWARE IS PROVIDED "AS
> IS", WITHOUT WARRANTY OF ANY KIND. For more information, please refer to <http://unlicense.org>.

## scrypt-js (`scrypt.js`)

Version 3.0.1. The scrypt key-derivation function. MIT License:

> The MIT License (MIT). Copyright (c) 2016 Richard Moore. Permission is hereby granted, free of charge,
> to any person obtaining a copy of this software and associated documentation files (the "Software"), to
> deal in the Software without restriction... The above copyright notice and this permission notice shall
> be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
> WITHOUT WARRANTY OF ANY KIND.

## aes-js (`aes-js.js`)

Version 3.1.2. The AES block cipher, used inside EME to decrypt file names. MIT License:

> The MIT License (MIT). Copyright (c) 2015 Richard Moore. Permission is hereby granted, free of charge,
> to any person obtaining a copy of this software and associated documentation files (the "Software"), to
> deal in the Software without restriction... The above copyright notice and this permission notice shall
> be included in all copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS",
> WITHOUT WARRANTY OF ANY KIND.

## PDF.js (`pdfjs/pdf.min.mjs`, `pdfjs/pdf.worker.min.mjs`)

Version 4.10.38, the legacy build. Renders PDF pages to a canvas in the mobile viewer. Apache License 2.0,
copyright the PDF.js contributors and Mozilla Foundation:

> Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
> compliance with the License. You may obtain a copy of the License at
> <http://www.apache.org/licenses/LICENSE-2.0>. Unless required by applicable law or agreed to in writing,
> software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
> CONDITIONS OF ANY KIND, either express or implied.
