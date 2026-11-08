#!/usr/bin/env node
// Generates the overview of what's published: which commits on main are in the snapshot, in a release on Maven
// Central, and in a DuckDuckGo Android app release. See README.md.
//
// Usage: node tools/release-status/generate.js [--out <file.html>] [--summary <file.md>] [--ref <git ref>] [--open]
'use strict';

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const lib = require('./lib');

const ARTIFACT = 'com/duckduckgo/netguard/netguard-android';
const CENTRAL = `https://repo1.maven.org/maven2/${ARTIFACT}`;
const SNAPSHOTS = `https://central.sonatype.com/repository/maven-snapshots/${ARTIFACT}`;
const APP_RELEASES = 'https://api.github.com/repos/duckduckgo/Android/releases';
const APP_RAW = 'https://raw.githubusercontent.com/duckduckgo/Android';
const SHOWN_RELEASES = 10;
const SHOWN_COMMITS = 200;
const MAX_APP_RELEASES = 200;

function args() {
    const options = { out: null, summary: null, ref: null, open: false };
    const argv = process.argv.slice(2);
    for (let i = 0; i < argv.length; i++) {
        const name = argv[i].replace(/^--/, '');
        if (name === 'open') options.open = true;
        else if (name in options && argv[i + 1]) options[name] = argv[++i];
        else throw new Error(`unknown or incomplete option ${argv[i]}`);
    }
    return options;
}

const git = (...argv) => execFileSync('git', argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim();
const lines = text => text.split('\n').filter(Boolean);

async function get(url, { optional = false } = {}) {
    const headers = { 'User-Agent': 'netguard-release-status' };
    if (url.startsWith('https://api.github.com/') && process.env.GITHUB_TOKEN) {
        headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(30000) });
    if (optional && response.status === 404) return null;
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return response;
}

// main's recent commits, which release first has each, and the release tags with their commits and dates
function readGit(ref, snapshotCommit) {
    const head = git('rev-parse', ref);
    const commits = lines(git('log', '--first-parent', `-${SHOWN_COMMITS}`, '--format=%H%x09%cI%x09%s', head))
        .map(line => { const [sha, date, ...subject] = line.split('\t'); return { sha, date, subject: subject.join('\t') }; });
    const releases = lines(git('tag', '--list', '[0-9]*', '--sort=-v:refname'))
        .filter(tag => lib.RELEASE_TAG.test(tag))
        .map(tag => ({ version: tag, commit: git('rev-parse', `${tag}^{commit}`), date: git('log', '-1', '--format=%cI', `${tag}^{commit}`) }));
    // Each commit's release is the oldest release containing it
    const releaseOf = new Map();
    for (const release of [...releases].reverse()) {
        for (const sha of lines(git('rev-list', release.commit))) {
            if (!releaseOf.has(sha)) releaseOf.set(sha, release.version);
        }
    }
    let inSnapshot = () => null;
    let behind = null;
    if (snapshotCommit) {
        try {
            const snapshotHas = new Set(lines(git('rev-list', snapshotCommit)));
            inSnapshot = sha => snapshotHas.has(sha);
            behind = Number(git('rev-list', '--count', '--first-parent', `${snapshotCommit}..${head}`));
        } catch (e) {
            // A snapshot built from a commit this checkout doesn't have
        }
    }
    return {
        head: commits[0],
        commits: commits.map(c => ({ ...c, release: releaseOf.get(c.sha) || null, inSnapshot: inSnapshot(c.sha) })),
        releases,
        behind,
    };
}

// The latest snapshot: { version, build, date, commit } or null when none is published
async function readSnapshot() {
    const versions = lib.metadataVersions(await (await get(`${SNAPSHOTS}/maven-metadata.xml`)).text());
    const version = versions.filter(v => v.endsWith('-SNAPSHOT')).sort(lib.compareVersions).pop();
    if (!version) return null;
    const build = lib.latestSnapshotBuild(await (await get(`${SNAPSHOTS}/${version}/maven-metadata.xml`)).text());
    if (!build) return null;
    const pom = await get(`${SNAPSHOTS}/${version}/netguard-android-${build.value}.pom`, { optional: true });
    return { version, build: build.value, date: build.date, commit: pom ? lib.pomCommit(await pom.text()) : null };
}

// Release dates on Maven Central, from each POM's Last-Modified (versions not on Central are left out)
async function readCentral(releases) {
    const onCentral = new Set(lib.metadataVersions(await (await get(`${CENTRAL}/maven-metadata.xml`)).text()));
    const shown = releases.filter(r => onCentral.has(r.version)).slice(0, SHOWN_RELEASES);
    return Promise.all(shown.map(async r => {
        const response = await fetch(`${CENTRAL}/${r.version}/netguard-android-${r.version}.pom`, { method: 'HEAD', signal: AbortSignal.timeout(30000) });
        const modified = response.headers.get('last-modified');
        return { ...r, date: modified ? new Date(modified).toISOString() : r.date };
    }));
}

// The app's store releases, newest first, back to the first one shipping the oldest shown netguard release
async function readApp(oldestShown) {
    const app = [];
    for (let page = 1; app.length < MAX_APP_RELEASES; page++) {
        const releases = (await (await get(`${APP_RELEASES}?per_page=100&page=${page}`)).json())
            .filter(r => !r.draft && !r.prerelease && lib.RELEASE_TAG.test(r.tag_name));
        if (!releases.length) break;
        // Ten at a time, in order
        for (let i = 0; i < releases.length; i += 10) {
            const batch = await Promise.all(releases.slice(i, i + 10).map(async r => {
                const properties = await get(`${APP_RAW}/${r.tag_name}/versions.properties`, { optional: true });
                return { app: r.tag_name, date: r.published_at, netguard: properties ? lib.appNetguardVersion(await properties.text()) : null };
            }));
            app.push(...batch);
            const last = app[app.length - 1];
            if (oldestShown && last.netguard && lib.RELEASE_TAG.test(last.netguard) && lib.compareVersions(last.netguard, oldestShown) < 0) {
                return app;
            }
        }
    }
    return app;
}

async function main() {
    const options = args();
    const root = git('rev-parse', '--show-toplevel');
    process.chdir(root);
    const ref = options.ref || (git('branch', '-r', '--list', 'origin/main') ? 'origin/main' : 'HEAD');
    const errors = {};
    const failed = (source, e) => { errors[source] = e.message; console.error(`Couldn't read ${source}: ${e.message}`); return null; };

    const snapshot = await readSnapshot().catch(e => failed('snapshot', e));
    const fromGit = readGit(ref, snapshot && snapshot.commit);
    const releases = await readCentral(fromGit.releases).catch(e => failed('central', e)) || [];
    const oldestShown = releases.length ? releases[releases.length - 1].version : null;
    const app = await readApp(oldestShown).catch(e => failed('app', e)) || [];

    const model = lib.buildModel({
        generatedAt: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
        head: fromGit.head,
        commits: fromGit.commits,
        releases,
        snapshot: snapshot && { ...snapshot, behind: fromGit.behind },
        app,
        errors,
        shownReleases: SHOWN_RELEASES,
    });

    const out = path.resolve(options.out || path.join(root, 'tools/release-status/build/index.html'));
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, lib.renderPage(model));
    console.log(out);
    if (options.summary) fs.appendFileSync(options.summary, lib.renderSummary(model));
    if (options.open) execFileSync(process.platform === 'darwin' ? 'open' : 'xdg-open', [out]);
}

main().catch(e => {
    console.error(e.message);
    process.exit(1);
});
