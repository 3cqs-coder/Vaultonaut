'use strict';
// lib/test/reachhelper.js — pins the in-app reach helper. It is deliberately NOT a second guide: a short line in the
// phone dialog names the outside-access paths and a link opens the existing built-in guide (the README). The text
// lives in the shared UI catalog so it is translation-ready, and it names no port — the dialog shows the live address,
// so a port change cannot drift here. Static only; no engine, no network.
//
// Run:  node -r ./lib/test/_setup.js lib/test/reachhelper.js

const fs = require('fs');
const path = require('path');
const REPO = path.join(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(REPO, p), 'utf8');
const UI = require(path.join(REPO, 'lib', 'webserver', 'public', 'shared', 'ui-strings.js'));
let failures = 0;
const ok = (name, cond) => { console.log((cond ? '  ok   ' : '  FAIL ') + name); if (!cond) failures++; };

const en = UI.STRINGS.en;
ok('the reach helper has a catalog hint', typeof en.mobileOutsideHint === 'string' && en.mobileOutsideHint.length > 0);
ok('the reach helper has a catalog button label', typeof en.mobileOutsideHelp === 'string' && en.mobileOutsideHelp.length > 0);
ok('the hint names the outside-access paths', /VPN, tunnel, or reverse proxy/.test(en.mobileOutsideHint));
ok('the hint names no port (the dialog shows the live address)', !/\b74\d\d\b/.test(en.mobileOutsideHint));
ok('the hint sends family sharing to a team vault or a read link', /team vault or a read link/.test(en.mobileOutsideHint));

const html = read(path.join('lib', 'webserver', 'public', 'views', 'index.ejs'));
ok('the phone dialog renders the reach hint', /id="mobileOutsideHint"/.test(html));
ok('the phone dialog renders the guide link', /id="mobileOutsideHelp"/.test(html));

const app = read(path.join('lib', 'webserver', 'public', 'js', 'app.js'));
ok('the helper text is filled from the shared catalog', /mobileOutsideHint/.test(app) && /mobileOutsideHelp/.test(app));
ok('the helper link opens the existing built-in guide', /\$\('#mobileOutsideHelp'\)[\s\S]{0,320}showSection\('guide'\)/.test(app));
ok('the helper does not add a second guide document', !fs.existsSync(path.join(REPO, 'docs', 'REACH-GUIDE.md')) && !fs.existsSync(path.join(REPO, 'docs', 'REMOTE-ACCESS.md')));

console.log('\n' + (failures ? failures + ' CHECK(S) FAILED' : 'ALL REACH-HELPER CHECKS PASSED'));
process.exit(failures ? 1 : 0);
