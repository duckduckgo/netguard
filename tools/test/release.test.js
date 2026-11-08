// Tests for tools/release on a throwaway origin and clone, without the network: node --test tools/test/*.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const RELEASE = path.join(__dirname, '..', 'release');

// origin with main: c1 (tagged 1.10.3), then c2, c3, c4; plus a clone to run the command in
function repos() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'release-test-'));
    const origin = path.join(dir, 'origin.git');
    const clone = path.join(dir, 'clone');
    const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    git(dir, 'init', '-q', '--bare', '-b', 'main', origin);
    git(dir, 'clone', '-q', origin, clone);
    git(clone, 'config', 'user.email', 'dev@example.com');
    git(clone, 'config', 'user.name', 'Dev');
    git(clone, 'checkout', '-q', '-b', 'main');
    const commit = message => {
        fs.writeFileSync(path.join(clone, 'file'), message);
        git(clone, 'add', 'file');
        git(clone, 'commit', '-q', '-m', message);
        return git(clone, 'rev-parse', 'HEAD');
    };
    const c1 = commit('First');
    git(clone, 'tag', '-a', '1.10.3', '-m', '1.10.3');
    const c2 = commit('Second');
    const c3 = commit('Third');
    const c4 = commit('Fourth');
    git(clone, 'push', '-q', 'origin', 'main', '--tags');
    return { dir, origin, clone, git, c1, c2, c3, c4 };
}

function release(cwd, ...args) {
    const result = spawnSync('sh', [RELEASE, ...args], {
        cwd, encoding: 'utf8', env: { ...process.env, RELEASE_OFFLINE: '1', NO_COLOR: '1' }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: result.status, out: result.stdout, err: result.stderr };
}

test('a minor release goes out from the newest commit on main, with every commit since the last release', () => {
    const r = repos();
    const { code, out } = release(r.clone, 'minor', '--dry-run');
    assert.strictEqual(code, 0);
    assert.match(out, new RegExp(`Release 1\\.11\\.0 from ${r.c4.slice(0, 7)}`));
    assert.match(out, /3 commits since 1\.10\.3:\n {2}\w+ Fourth\n {2}\w+ Third\n {2}\w+ Second\n/);
    assert.match(out, /Dry run: would tag 1\.11\.0/);
});

test('a patch release, or an explicit version', () => {
    const r = repos();
    assert.match(release(r.clone, 'patch', '--dry-run').out, /Release 1\.10\.4 from/);
    assert.match(release(r.clone, '2.0.0', '--dry-run').out, /Release 2\.0\.0 from/);
});

test('releasing an earlier commit leaves the later ones out', () => {
    const r = repos();
    const { code, out } = release(r.clone, 'minor', '--commit', r.c2.slice(0, 7), '--dry-run');
    assert.strictEqual(code, 0);
    assert.match(out, /1 commit since 1\.10\.3:\n {2}\w+ Second\n/);
    assert.doesNotMatch(out, /Third|Fourth/);
});

test('refuses commits that aren\'t on main or are already released, and versions that exist', () => {
    const r = repos();
    r.git(r.clone, 'checkout', '-q', '-b', 'feature');
    fs.writeFileSync(path.join(r.clone, 'file'), 'feature');
    r.git(r.clone, 'commit', '-q', '-am', 'Feature');
    const feature = r.git(r.clone, 'rev-parse', 'HEAD');
    assert.match(release(r.clone, 'minor', '--commit', feature, '--dry-run').err, /isn't on origin\/main/);
    assert.match(release(r.clone, 'minor', '--commit', r.c1, '--dry-run').err, /is already released, in 1\.10\.3/);
    assert.match(release(r.clone, '1.10.3', '--dry-run').err, /1\.10\.3 already exists/);
    assert.match(release(r.clone, '1.11', '--dry-run').err, /Unknown argument: 1\.11/);
    assert.match(release(r.clone, 'minor', '--commit', 'nope', '--dry-run').err, /Unknown commit: nope/);
});

test('says so when there\'s nothing to release', () => {
    const r = repos();
    r.git(r.clone, 'tag', '-a', '1.11.0', '-m', '1.11.0', r.c4);
    r.git(r.clone, 'push', '-q', 'origin', '1.11.0');
    assert.match(release(r.clone, 'minor', '--dry-run').err, /Nothing to release: main has no commits since 1\.11\.0/);
});

test('warns when the version is lower than the latest release', () => {
    const r = repos();
    assert.match(release(r.clone, '1.9.9', '--dry-run').out, /1\.9\.9 is lower than 1\.10\.3: it will be a release, but not the latest one/);
});

test('tags the commit and pushes only the tag, leaving the working copy alone', () => {
    const r = repos();
    r.git(r.clone, 'checkout', '-q', '-b', 'elsewhere', r.c2);
    fs.writeFileSync(path.join(r.clone, 'uncommitted'), 'work in progress');
    const { code, out, err } = release(r.clone, 'minor', '--yes');
    assert.strictEqual(code, 0, err);
    assert.match(out, /Pushed 1\.11\.0/);
    assert.strictEqual(r.git(r.origin, 'rev-parse', '1.11.0^{commit}'), r.c4, 'the tag is on origin, on the newest commit of main');
    assert.strictEqual(r.git(r.origin, 'cat-file', '-t', '1.11.0'), 'tag', 'an annotated tag');
    assert.strictEqual(r.git(r.clone, 'rev-parse', '--abbrev-ref', 'HEAD'), 'elsewhere');
    assert.ok(fs.existsSync(path.join(r.clone, 'uncommitted')));
    assert.strictEqual(r.git(r.origin, 'branch', '--list', 'elsewhere'), '', 'no branch pushed');
});

test('retry needs an existing tag', () => {
    const r = repos();
    assert.match(release(r.clone, 'retry', '9.9.9', '--dry-run').err, /There's no 9\.9\.9 tag/);
    assert.match(release(r.clone, 'retry', '1.10.3', '--dry-run').out, /Would re-run the release workflow for 1\.10\.3/);
});

test('prints its usage', () => {
    const { code, out } = release(os.tmpdir(), '--help');
    assert.strictEqual(code, 0);
    assert.match(out, /tools\/release minor\|patch\|X\.Y\.Z/);
});
