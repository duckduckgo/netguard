#!/usr/bin/env node
// Checks that the agent docs (AGENTS.md and the skills in .claude/skills) still match the repo: the files, links and
// C names they mention exist, the native tests they list are the Makefile's, and the log text they tell agents to grep
// for is still logged. Prose about behavior can't be checked this way; keep it rare in the docs.
//
// Usage: node tools/check-docs/check-docs.js [--root <repo>]
'use strict';

const fs = require('fs');
const path = require('path');

// Log text the skill counts with grep: if the code stops logging it, the count is 0 and looks like a pass
const LOG_TEXT = ['NetGuard.JNI', 'TLS server name not found', 'UDP new session', 'UDP blocked session'];

// Names from Android, not this repo
const EXTERNAL_NAMES = new Set(['NOT_VPN']);

const SKIPPED_DIRS = new Set(['.git', '.gradle', '.idea', '.cxx', 'build', 'node_modules', 'out']);
const FILE_EXTENSIONS = /\.(c|h|md|sh|js|mjs|txt|gradle|yml|yaml|properties|py|go|kt|java)$/;

function walk(dir, files = []) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (SKIPPED_DIRS.has(entry.name)) continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full, files);
        else files.push(full);
    }
    return files;
}

function docs(root) {
    const skills = path.join(root, '.claude', 'skills');
    const found = fs.existsSync(skills) ? walk(skills).filter(f => f.endsWith('.md')) : [];
    return [path.join(root, 'AGENTS.md'), ...found].filter(f => fs.existsSync(f));
}

// Inline `code` spans outside fenced blocks, and the text of fenced blocks
function parse(text) {
    const spans = [];
    const fenced = [];
    let block = null;
    for (const line of text.split('\n')) {
        if (/^\s*```/.test(line)) {
            if (block === null) block = [];
            else { fenced.push(block.join('\n')); block = null; }
        } else if (block !== null) {
            block.push(line);
        } else {
            for (const match of line.matchAll(/`([^`]+)`/g)) spans.push(match[1]);
        }
    }
    const links = [...text.matchAll(/\]\(([^)\s]+)\)/g)].map(m => m[1]);
    return { spans, fenced, links };
}

function looksLikePath(span) {
    // Absolute paths are on the device or another machine (/sdcard/...), never in the repo
    if (/[\s<>$*~|"'(]/.test(span) || span.startsWith('-') || span.startsWith('/')) return false;
    // ./name runs a program from the current directory, often a built one (./test_tls): only a script is a file to find
    if (/^\.\/[^/]+$/.test(span)) return /\.(sh|js|py)$/.test(span);
    return span.includes('/') || FILE_EXTENSIONS.test(span);
}

function makefileTests(root) {
    const makefile = path.join(root, 'src', 'test', 'Makefile');
    if (!fs.existsSync(makefile)) return null;
    // The same rule as src/test/run-tests.sh: every *EXECUTABLE variable is a test
    return [...fs.readFileSync(makefile, 'utf8').matchAll(/^[A-Z_]*EXECUTABLE *= *(\S+)/gm)].map(m => m[1]);
}

function check(root) {
    const problems = [];
    const files = walk(root);
    const basenames = new Set(files.map(f => path.basename(f)));
    const sourceFiles = files.filter(f => f.startsWith(path.join(root, 'src') + path.sep) && /\.(c|h|go)$/.test(f));
    const source = sourceFiles.map(f => fs.readFileSync(f, 'utf8')).join('\n');
    const tests = makefileTests(root);

    for (const doc of docs(root)) {
        const name = path.relative(root, doc);
        const { spans, fenced, links } = parse(fs.readFileSync(doc, 'utf8'));

        for (const span of spans) {
            if (looksLikePath(span)) {
                const relative = span.replace(/^\.\//, '').replace(/\/$/, '');
                const exists = span.includes('/')
                    ? fs.existsSync(path.join(root, relative))
                    : basenames.has(relative);
                if (!exists) problems.push(`${name} mentions \`${span}\`, which doesn't exist`);
                continue;
            }
            for (const [identifier] of span.matchAll(/\b[A-Za-z]\w*_\w*\b/g)) {
                // Test names are checked against the Makefile below
                if (EXTERNAL_NAMES.has(identifier) || basenames.has(identifier) || identifier.startsWith('test_')) continue;
                if (!new RegExp(`\\b${identifier}\\b`).test(source)) {
                    problems.push(`${name} mentions \`${identifier}\`, which isn't in src/`);
                }
            }
        }

        // Scripts run in fenced blocks, e.g. ./publish_local.sh
        for (const block of fenced) {
            for (const [, script] of block.matchAll(/(?:^|\s)\.\/([\w.-]+\.(?:sh|js|py))\b/g)) {
                if (!basenames.has(script)) problems.push(`${name} runs \`./${script}\`, which doesn't exist`);
            }
        }

        for (const link of links) {
            if (/^[a-z]+:/.test(link) || link.startsWith('#')) continue;
            const target = path.resolve(path.dirname(doc), link.split('#')[0]);
            if (!fs.existsSync(target)) problems.push(`${name} links to ${link}, which doesn't exist`);
        }

        if (tests) {
            const text = fs.readFileSync(doc, 'utf8');
            for (const [listed] of text.matchAll(/\btest_[a-z0-9_]+\b/g)) {
                if (!tests.includes(listed)) {
                    problems.push(`${name} lists the test \`${listed}\`, which src/test/Makefile doesn't build`);
                }
            }
            if (name === 'AGENTS.md') {
                for (const test of tests) {
                    if (!text.includes(test)) problems.push(`AGENTS.md doesn't list the test \`${test}\` from src/test/Makefile`);
                }
            }
        }
    }

    for (const text of LOG_TEXT) {
        if (!source.includes(text)) problems.push(`the docs grep for "${text}", which src/ no longer logs`);
    }

    return [...new Set(problems)];
}

module.exports = { check };

if (require.main === module) {
    const argv = process.argv.slice(2);
    const root = argv[0] === '--root' && argv[1] ? path.resolve(argv[1]) : path.resolve(__dirname, '..', '..');
    const problems = check(root);
    for (const problem of problems) console.error(problem);
    if (problems.length) {
        console.error(`\n${problems.length} problem(s). Update the docs in the same change as the code they describe.`);
        process.exit(1);
    }
    console.log('The agent docs match the repo.');
}
