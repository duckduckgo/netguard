// Tests for the overview's model and page: node --test tools/release-status/test/*.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const lib = require('../lib');

const sha = n => String(n).repeat(40).slice(0, 40);

// main: c5 (newest, not in the snapshot), c4 (in the snapshot), c3 (released in 1.11.0, in no app yet),
// c2 (released in 1.10.0, shipped), c1 (released in 1.9.0, shipped)
function inputs(overrides = {}) {
    return {
        generatedAt: '2026-11-08T12:00:00Z',
        head: { sha: sha(5), date: '2026-11-08', subject: 'Newest' },
        commits: [
            { sha: sha(5), date: '2026-11-08', subject: 'Newest', release: null, inSnapshot: false },
            { sha: sha(4), date: '2026-11-07', subject: 'Fix <b>SNI</b> parsing', release: null, inSnapshot: true },
            { sha: sha(3), date: '2026-11-01', subject: 'Released, not shipped', release: '1.11.0', inSnapshot: true },
            { sha: sha(2), date: '2026-10-01', subject: 'Shipped', release: '1.10.0', inSnapshot: true },
            { sha: sha(1), date: '2026-09-01', subject: 'Shipped long ago', release: '1.9.0', inSnapshot: true },
        ],
        releases: [
            { version: '1.11.0', commit: sha(3), date: '2026-11-02T00:00:00Z' },
            { version: '1.10.0', commit: sha(2), date: '2026-10-02T00:00:00Z' },
            { version: '1.9.0', commit: sha(1), date: '2026-09-02T00:00:00Z' },
        ],
        snapshot: { version: '1.12.0-SNAPSHOT', build: '1.12.0-20261107.100000-1', date: '2026-11-07T10:00:00Z', commit: sha(4), behind: 1 },
        // Newest first; 5.300.0 skipped 1.10.0's predecessor and went straight to 1.10.0
        app: [
            { app: '5.301.0', date: '2026-11-03', netguard: '1.10.0' },
            { app: '5.300.0', date: '2026-10-10', netguard: '1.10.0' },
            { app: '5.299.0', date: '2026-09-10', netguard: '1.9.0' },
            { app: '5.298.0', date: '2026-08-10', netguard: '1.8.0' },
        ],
        ...overrides,
    };
}

test('compares versions, snapshots before their release', () => {
    assert.ok(lib.compareVersions('1.10.0', '1.9.0') > 0);
    assert.ok(lib.compareVersions('1.11.0-SNAPSHOT', '1.11.0') < 0);
    assert.ok(lib.compareVersions('1.11.0-SNAPSHOT', '1.10.2') > 0);
    assert.strictEqual(lib.compareVersions('2.0.0', '2.0.0'), 0);
});

test('reads Maven metadata, POMs and the app\'s versions.properties', () => {
    assert.deepStrictEqual(lib.metadataVersions('<versions><version>1.9.0</version><version>1.10.2</version></versions>'), ['1.9.0', '1.10.2']);
    const snapshot = `<versioning><snapshot><timestamp>20261108.120359</timestamp><buildNumber>2</buildNumber></snapshot>
      <snapshotVersions><snapshotVersion><extension>aar</extension><value>1.11.0-20261108.120359-2</value></snapshotVersion>
      <snapshotVersion><extension>pom</extension><value>1.11.0-20261108.120359-2</value></snapshotVersion></snapshotVersions></versioning>`;
    assert.deepStrictEqual(lib.latestSnapshotBuild(snapshot), { value: '1.11.0-20261108.120359-2', date: '2026-11-08T12:03:59Z' });
    assert.strictEqual(lib.latestSnapshotBuild('<metadata/>'), null);
    assert.strictEqual(lib.pomCommit(`<scm><url>x</url><tag>${sha('a')}</tag></scm>`), sha('a'));
    assert.strictEqual(lib.pomCommit('<scm><url>x</url></scm>'), null, 'builds from before commits were recorded');
    assert.strictEqual(lib.appNetguardVersion('a=1\nversion.com.duckduckgo.netguard..netguard-android=1.10.2\nb=2'), '1.10.2');
    assert.strictEqual(lib.appNetguardVersion('a=1'), null);
});

test('puts every commit at its stage', () => {
    const m = lib.buildModel(inputs());
    const stage = n => m.commits.find(c => c.sha === sha(n));
    assert.strictEqual(stage(5).stage, 'main');
    assert.strictEqual(stage(4).stage, 'snapshot');
    assert.deepStrictEqual([stage(3).stage, stage(3).release], ['released', '1.11.0']);
    assert.deepStrictEqual([stage(2).stage, stage(2).app.app], ['shipped', '5.300.0'], 'the first app release with it');
    assert.deepStrictEqual([stage(1).stage, stage(1).app.app], ['shipped', '5.299.0']);
    assert.match(lib.describeStage(stage(2), m), /^On users' phones since app 5\.300\.0 \(2026-10-10\), in netguard 1\.10\.0\.$/);
    assert.match(lib.describeStage(stage(4), m), /^In the snapshot \(1\.12\.0-SNAPSHOT, built 2026-11-07\)/);
});

test('lists each release with the first and latest app releases shipping it', () => {
    const m = lib.buildModel(inputs());
    const r = v => m.releases.find(x => x.version === v);
    assert.strictEqual(r('1.11.0').firstApp, null);
    assert.deepStrictEqual([r('1.10.0').firstApp.app, r('1.10.0').inLatestApp], ['5.300.0', true]);
    assert.deepStrictEqual([r('1.9.0').firstApp.app, r('1.9.0').inLatestApp], ['5.299.0', false]);
    assert.strictEqual(lib.buildModel(inputs({ shownReleases: 2 })).releases.length, 2);
});

test('says when the snapshot\'s commit isn\'t recorded, instead of guessing', () => {
    const commits = inputs().commits.map(c => ({ ...c, inSnapshot: c.release ? true : null }));
    const m = lib.buildModel(inputs({ commits, snapshot: { ...inputs().snapshot, commit: null, behind: null } }));
    assert.strictEqual(m.commits[0].stage, 'unknown');
    assert.match(lib.describeStage(m.commits[0], m), /unknown/);
    const page = lib.renderPage(m);
    assert.match(page, /built 2026-11-07 from an unrecorded commit/);
    assert.doesNotMatch(page, /behind main/);
});

test('flags the snapshot when it\'s behind main', () => {
    const page = lib.renderPage(lib.buildModel(inputs()));
    assert.match(page, /<div class="box flag">/);
    assert.match(page, /1 commit behind main/);
    assert.match(lib.renderPage(lib.buildModel(inputs({ snapshot: { ...inputs().snapshot, behind: 0 } }))), /up to date with main/);
});

test('shows a source that couldn\'t be read, and still renders the rest', () => {
    const m = lib.buildModel(inputs({ releases: [], app: [], errors: { central: 'down', app: 'rate limited' } }));
    const page = lib.renderPage(m);
    assert.match(page, /Couldn't read Maven Central at 2026-11-08T12:00:00Z/);
    assert.match(page, /Couldn't read the app&#39;s releases/);
    assert.match(page, /1\.12\.0-SNAPSHOT/);
    assert.match(lib.renderSummary(m), /couldn't read: down/);
});

test('escapes what comes from git, and allows only its own script', () => {
    const commits = inputs().commits.map((c, i) => (i === 0 ? { ...c, subject: '</script><img src=x onerror=alert(1)>' } : c));
    const page = lib.renderPage(lib.buildModel(inputs({ commits })));
    assert.doesNotMatch(page, /<img src=x/);
    assert.strictEqual((page.match(/<script/g) || []).length, 2, 'the data and the lookup');
    const script = /<script>([\s\S]*?)<\/script>/.exec(page)[1];
    const hash = crypto.createHash('sha256').update(script).digest('base64');
    assert.match(page, new RegExp(`script-src 'sha256-${hash.replace(/[+/]/g, '\\$&')}'`));
    assert.match(page, /default-src 'none'/);
});

test('writes the pipeline as a table for the run summary', () => {
    const summary = lib.renderSummary(lib.buildModel(inputs()));
    assert.match(summary, /\| main \| snapshot \| Maven Central \| app \(Play Store\) \|/);
    assert.match(summary, /1\.12\.0-SNAPSHOT, built 2026-11-07 from `4444444`, \*\*1 behind main\*\*/);
    assert.match(summary, /5\.301\.0, ships netguard 1\.10\.0/);
});
