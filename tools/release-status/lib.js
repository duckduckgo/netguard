// The overview of what's published: the data model and the page, with no I/O, so they can be tested on fixtures.
// generate.js reads git, Maven Central and the app's releases, and passes them here.
'use strict';

const crypto = require('crypto');

const RELEASE_TAG = /^\d+\.\d+\.\d+$/;

// Compares X.Y.Z versions (a -SNAPSHOT suffix sorts before its release); negative when a < b
function compareVersions(a, b) {
    const parse = v => {
        const [core, pre] = String(v).split('-');
        return { parts: core.split('.').map(Number), snapshot: pre !== undefined };
    };
    const x = parse(a), y = parse(b);
    for (let i = 0; i < 3; i++) {
        if ((x.parts[i] || 0) !== (y.parts[i] || 0)) return (x.parts[i] || 0) - (y.parts[i] || 0);
    }
    return (x.snapshot ? -1 : 0) - (y.snapshot ? -1 : 0);
}

// The <version> entries of a maven-metadata.xml
function metadataVersions(xml) {
    return [...String(xml).matchAll(/<version>([^<]+)<\/version>/g)].map(m => m[1]);
}

// The newest build of a snapshot version, from its maven-metadata.xml: { value, date } or null
function latestSnapshotBuild(xml) {
    const value = /<snapshotVersion>\s*<extension>pom<\/extension>\s*<value>([^<]+)<\/value>/.exec(xml)?.[1]
        || /<extension>aar<\/extension>\s*<value>([^<]+)<\/value>/.exec(xml)?.[1];
    const stamp = /<timestamp>(\d{8})\.(\d{6})<\/timestamp>/.exec(xml);
    if (!value || !stamp) return null;
    const [, d, t] = stamp;
    return { value, date: `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6)}T${t.slice(0, 2)}:${t.slice(2, 4)}:${t.slice(4)}Z` };
}

// The commit in a POM's <scm><tag>, or null for builds from before commits were recorded
function pomCommit(pom) {
    return /<scm>[\s\S]*?<tag>([0-9a-f]{40})<\/tag>[\s\S]*?<\/scm>/.exec(String(pom))?.[1] || null;
}

// The netguard version an app release pins in its versions.properties, or null
function appNetguardVersion(properties) {
    return /^version\.com\.duckduckgo\.netguard\.\.netguard-android=(\S+)$/m.exec(String(properties))?.[1] || null;
}

/**
 * Builds the page's model.
 * - head: { sha, date, subject } of main
 * - commits: main's recent commits, newest first: { sha, date, subject, release, inSnapshot }, where release is the
 *   first X.Y.Z tag containing it (or null) and inSnapshot is true, false or null (snapshot commit not recorded)
 * - releases: { version, commit, date, published }, newest first; published is false for a tag Maven Central doesn't
 *   serve (its release failed or is still running)
 * - snapshot: { version, build, date, commit, behind } or null; behind is main's commits after it, or null
 * - app: store releases, newest first: { app, date, netguard }
 * - errors: { central, snapshot, app }: why a source couldn't be read, or absent
 */
function buildModel({ generatedAt, head, commits, releases, snapshot, app, errors = {}, shownReleases = 10 }) {
    const latestApp = app[0] || null;
    // The first app release shipping this netguard version or a later one (app releases only move netguard forward)
    const firstApp = version => {
        let first = null;
        for (const a of app) {
            if (a.netguard && RELEASE_TAG.test(a.netguard) && compareVersions(a.netguard, version) >= 0) first = a;
        }
        return first;
    };
    const stage = c => {
        if (c.release) {
            const shipped = firstApp(c.release);
            return shipped ? { stage: 'shipped', release: c.release, app: shipped } : { stage: 'released', release: c.release };
        }
        if (c.inSnapshot === null || !snapshot) return { stage: 'unknown' };
        return { stage: c.inSnapshot ? 'snapshot' : 'main' };
    };
    return {
        generatedAt,
        head,
        snapshot,
        latestApp,
        releases: releases.slice(0, shownReleases).map(r => ({
            ...r,
            published: r.published !== false,
            firstApp: r.published === false ? null : firstApp(r.version),
            inLatestApp: !!latestApp && latestApp.netguard === r.version,
            commits: commits.filter(c => c.release === r.version).length,
        })),
        commits: commits.map(c => ({ sha: c.sha, date: c.date, subject: c.subject, ...stage(c) })),
        errors,
    };
}

// What a commit's stage means, in one sentence
function describeStage(c, model) {
    switch (c.stage) {
    case 'shipped': return `On users' phones since app ${c.app.app} (${day(c.app.date)}), in netguard ${c.release}.`;
    case 'released': return `Released in netguard ${c.release}, but no app release ships it yet.`;
    case 'snapshot': return `In the snapshot (${model.snapshot.version}, built ${day(model.snapshot.date)}), not released yet.`;
    case 'main': return 'On main only: not in the snapshot yet.';
    default: return 'Not released. Whether the snapshot has it is unknown: its build doesn\'t record its commit.';
    }
}

const STAGE_LABELS = { main: 'main only', snapshot: 'in snapshot', released: 'released', shipped: 'in app', unknown: 'not released' };

const esc = s => String(s ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
const day = iso => String(iso || '').slice(0, 10);
const short = sha => String(sha || '').slice(0, 7);
const COMMIT_URL = 'https://github.com/duckduckgo/netguard/commit/';

function pill(c) {
    const label = c.stage === 'shipped' ? `in app ${c.app.app}` : c.stage === 'released' ? `released ${c.release}` : STAGE_LABELS[c.stage];
    return `<span class="pill p-${c.stage}">${esc(label)}</span>`;
}

function box(kind, title, body, flagged) {
    return `<div class="box${flagged ? ' flag' : ''}"><span class="pill p-${kind}">${esc(title)}</span>${body}</div>`;
}

function renderBoxes(m) {
    const commit = sha => `<a class="mono" href="${COMMIT_URL}${esc(sha)}">${esc(short(sha))}</a>`;
    const unread = what => `<div class="v">?</div><div class="muted">Couldn't read ${esc(what)} at ${esc(m.generatedAt)}.</div>`;
    const latest = m.releases.find(r => r.published);
    const s = m.snapshot;
    return `<div class="boxes">
${box('main', 'main', `<div class="v">${commit(m.head.sha)}</div><div class="muted">${esc(m.head.subject)}</div>`)}
${box('snapshot', 'snapshot', m.errors.snapshot ? unread('the snapshot') : !s ? '<div class="v">none</div><div class="muted">No snapshot published.</div>'
        : `<div class="v">${esc(s.version)}</div><div class="muted">built ${esc(day(s.date))} from ${s.commit ? commit(s.commit) : 'an unrecorded commit'}${
            s.behind === null ? '' : s.behind ? `<br><b>${s.behind} commit${s.behind > 1 ? 's' : ''} behind main</b>` : '<br>up to date with main'}</div>`,
        !!(s && s.behind))}
${box('released', 'Maven Central', m.errors.central ? unread('Maven Central') : latest
        ? `<div class="v">${esc(latest.version)}</div><div class="muted">released ${esc(day(latest.date))}, ${commit(latest.commit)}</div>`
        : '<div class="v">none</div>')}
${box('shipped', 'app (Play Store)', m.errors.app ? unread("the app's releases") : m.latestApp
        ? `<div class="v">${esc(m.latestApp.app)}</div><div class="muted">${esc(day(m.latestApp.date))}, ships netguard <b>${esc(m.latestApp.netguard || '?')}</b></div>`
        : '<div class="v">?</div>')}
</div>`;
}

function renderVersions(m) {
    const rows = [];
    if (m.snapshot) {
        const n = m.commits.filter(c => c.stage === 'snapshot').length;
        rows.push(`<tr><td><b>${esc(m.snapshot.version)}</b></td><td class="mono">${m.snapshot.commit ? esc(short(m.snapshot.commit)) : 'not recorded'}</td>
<td>${esc(day(m.snapshot.date))}</td><td>snapshot repository</td><td class="muted">none</td><td></td><td>${n} unreleased commit${n === 1 ? '' : 's'}</td></tr>`);
    }
    for (const r of m.releases) {
        if (!r.published) {
            rows.push(`<tr><td><b>${esc(r.version)}</b></td><td class="mono"><a href="${COMMIT_URL}${esc(r.commit)}">${esc(short(r.commit))}</a></td>
<td>${esc(day(r.date))}</td><td colspan="4"><b>Tagged, not on Maven Central</b>: its <a href="https://github.com/duckduckgo/netguard/actions/workflows/release.yml">release</a> failed or is still running.</td></tr>`);
            continue;
        }
        rows.push(`<tr><td><b>${esc(r.version)}</b></td><td class="mono"><a href="${COMMIT_URL}${esc(r.commit)}">${esc(short(r.commit))}</a></td>
<td>${esc(day(r.date))}</td><td><a href="https://central.sonatype.com/artifact/com.duckduckgo.netguard/netguard-android/${esc(r.version)}">Maven Central</a></td>
<td>${r.firstApp ? `${esc(r.firstApp.app)} <span class="muted">${esc(day(r.firstApp.date))}</span>` : '<span class="muted">none yet</span>'}</td>
<td>${r.inLatestApp ? `<span class="pill p-shipped">${esc(m.latestApp.app)}</span>` : ''}</td>
<td><a href="https://github.com/duckduckgo/netguard/releases/tag/${esc(r.version)}">notes</a></td></tr>`);
    }
    return `<table><tr><th>netguard</th><th>Commit</th><th>Published</th><th>Where</th><th>First app with it</th><th>Latest app</th><th></th></tr>
${rows.join('\n')}</table>`;
}

const STYLE = `:root{color-scheme:light dark;--bg:#fff;--fg:#1d1d1f;--muted:#6e6e73;--line:#e3e3e6;--panel:#f6f6f8;--main:#6e6e73;
--snapshot:#b26a00;--released:#1565c0;--shipped:#2e7d32;--unknown:#6e6e73;--mono:ui-monospace,Menlo,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#ececf0;--muted:#9a9aa2;--line:#2c2c31;--panel:#1f1f23;--snapshot:#e0a040;
--released:#64a8f0;--shipped:#6cc070}}
*{box-sizing:border-box}body{margin:0 auto;max-width:1100px;padding:20px 16px 40px;font:14px/1.45 -apple-system,system-ui,sans-serif;
background:var(--bg);color:var(--fg)}a{color:inherit}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:26px 0 8px}
.muted{color:var(--muted)}.mono{font-family:var(--mono);font-size:12.5px}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}
${['main', 'snapshot', 'released', 'shipped', 'unknown'].map(k => `.p-${k}{background:color-mix(in srgb,var(--${k}) 18%,transparent);color:var(--${k})}`).join('')}
.boxes{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}@media(max-width:800px){.boxes{grid-template-columns:1fr 1fr}}
.box{border:1px solid var(--line);border-radius:10px;padding:12px;background:var(--panel);min-width:0}.box.flag{border-color:var(--snapshot)}
.v{font-size:20px;font-weight:700;margin:4px 0;overflow-wrap:anywhere}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}.scroll{overflow-x:auto}
input{width:100%;font:inherit;font-size:16px;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
.answer{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0;background:var(--panel)}
.steps{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.step{padding:2px 10px;border-radius:12px;font-size:12px;border:1px dashed var(--line);color:var(--muted)}`;

// The commit lookup: searches the commits embedded in the page and says in one sentence where each match is
const LOOKUP_SCRIPT = `
const model = JSON.parse(document.getElementById('model').textContent);
const esc = s => String(s ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const order = ['main', 'snapshot', 'released', 'shipped'];
const input = document.getElementById('q'), out = document.getElementById('answers');
function show() {
  const q = input.value.trim().toLowerCase();
  if (!q) { out.innerHTML = ''; return; }
  const hits = model.commits.filter(c => c.sha.startsWith(q) || c.subject.toLowerCase().includes(q)).slice(0, 5);
  out.innerHTML = hits.length ? hits.map(c => '<div class="answer"><span class="mono">' + esc(c.sha.slice(0, 7)) + '</span> ' + esc(c.subject) +
    '<br><b>' + esc(c.sentence) + '</b><div class="steps">' + order.map((s, i) => '<span class="step' +
    (order.indexOf(c.stage) >= i ? ' pill p-' + s : '') + '">' + ['main', 'snapshot', 'released', 'in app'][i] + '</span>').join('') +
    '</div></div>').join('') : '<p class="muted">No recent commit on main matches.</p>';
}
input.addEventListener('input', show);
`;

function renderPage(m) {
    const model = { commits: m.commits.map(c => ({ sha: c.sha, subject: c.subject, stage: c.stage, sentence: describeStage(c, m) })) };
    // "<" escaped so the commits can't end the script element
    const json = JSON.stringify(model).replace(/</g, '\\u003c');
    // The page contacts nothing and runs only its own script
    const scriptHash = `sha256-${crypto.createHash('sha256').update(LOOKUP_SCRIPT).digest('base64')}`;
    const appNote = m.errors.app ? '' : `App releases are read from duckduckgo/Android's GitHub Releases.`;
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src '${scriptHash}'; base-uri 'none'; form-action 'none'">
<title>netguard releases</title><style>${STYLE}</style></head><body>
<h1>netguard: what's published</h1>
<p class="muted">Generated ${esc(m.generatedAt)} from git, Maven Central and the DuckDuckGo Android app's store releases. ${appNote}
How releases work: <a href="https://github.com/duckduckgo/netguard/blob/main/android/RELEASING.md">RELEASING.md</a>.</p>
${renderBoxes(m)}
<h2>Where is my commit?</h2>
<input id="q" type="search" placeholder="Commit sha, or words from its message" aria-label="Commit sha or message" autocomplete="off">
<div id="answers"></div>
<div class="scroll"><table>${m.commits.slice(0, 25).map(c => `<tr><td class="mono"><a href="${COMMIT_URL}${esc(c.sha)}">${esc(short(c.sha))}</a></td>
<td>${esc(c.subject)}</td><td>${pill(c)}</td></tr>`).join('\n')}</table></div>
<h2>Versions</h2>
<div class="scroll">${m.errors.central ? `<p class="muted">Couldn't read Maven Central at ${esc(m.generatedAt)}.</p>` : renderVersions(m)}</div>
<script type="application/json" id="model">${json}</script>
<script>${LOOKUP_SCRIPT}</script>
</body></html>
`;
}

// The run summary: the pipeline in a table
function renderSummary(m) {
    const s = m.snapshot;
    const latest = m.releases.find(r => r.published);
    const cell = (error, text) => (error ? `couldn't read: ${error}` : text).replace(/\|/g, '\\|');
    return `### netguard: what's published

| main | snapshot | Maven Central | app (Play Store) |
|---|---|---|---|
| \`${short(m.head.sha)}\` ${cell(null, m.head.subject)} | ${cell(m.errors.snapshot, s ? `${s.version}, built ${day(s.date)} from ${s.commit ? '`' + short(s.commit) + '`' : 'an unrecorded commit'}${
        s.behind ? `, **${s.behind} behind main**` : ''}` : 'none')} | ${cell(m.errors.central, latest ? `${latest.version} (${day(latest.date)})` : 'none')} | ${
    cell(m.errors.app, m.latestApp ? `${m.latestApp.app}, ships netguard ${m.latestApp.netguard}` : '?')} |
`;
}

module.exports = {
    RELEASE_TAG, compareVersions, metadataVersions, latestSnapshotBuild, pomCommit, appNetguardVersion,
    buildModel, describeStage, renderPage, renderSummary,
};
