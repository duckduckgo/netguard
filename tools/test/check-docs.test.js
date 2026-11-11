// Tests for tools/check-docs on a throwaway repo: node --test tools/test/*.test.js
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { check } = require('../check-docs/check-docs');

// A repo whose docs match it; each test breaks one thing
function repo(changes = {}) {
    const files = {
        'AGENTS.md': [
            'The SNI parser is in `src/netguard/tls.c`, see `tls.c`. Callbacks go through `is_pkt_allowed`.',
            'Read [the skill](.claude/skills/verify/SKILL.md).',
            '```bash',
            './publish_local.sh',
            'make   # Build test_tls, test_tcp_window',
            '```',
        ].join('\n'),
        '.claude/skills/verify/SKILL.md': 'Count `TLS server name not found` under the `NetGuard.JNI` tag; see [SNI](references/sni.md).',
        '.claude/skills/verify/references/sni.md': 'Run `./test_tls`. A plain `grep VPN` also matches `NOT_VPN`. Remove `/sdcard/ui.xml`.',
        'android/publish_local.sh': '',
        'src/netguard/tls.c': 'log_print(PLATFORM_LOG_PRIORITY_INFO, "TLS server name not found"); // NetGuard.JNI',
        'src/wireguard/jni.c': 'int is_pkt_allowed(const uint8_t *buffer, int length) {}',
        'src/test/Makefile': 'EXECUTABLE = test_tls\nTCP_WINDOW_EXECUTABLE = test_tcp_window\n',
        ...changes,
    };
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'check-docs-test-'));
    for (const [name, content] of Object.entries(files)) {
        if (content === null) continue;
        fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
        fs.writeFileSync(path.join(root, name), content);
    }
    return root;
}

test('docs that match the repo pass', () => {
    assert.deepStrictEqual(check(repo()), []);
});

test('a moved file is reported', () => {
    const root = repo({ 'src/netguard/tls.c': null, 'src/netguard/sni.c': 'is_pkt_allowed TLS server name not found NetGuard.JNI' });
    assert.ok(check(root).some(p => p.includes('`src/netguard/tls.c`')));
    assert.ok(check(root).some(p => p.includes('`tls.c`')));
});

test('a renamed script is reported', () => {
    const root = repo({ 'android/publish_local.sh': null, 'android/publish-local.sh': '' });
    assert.ok(check(root).some(p => p.includes('`./publish_local.sh`')));
});

test('a renamed C function is reported', () => {
    const root = repo({ 'src/wireguard/jni.c': 'int is_packet_allowed(const uint8_t *buffer, int length) {}' });
    assert.ok(check(root).some(p => p.includes('`is_pkt_allowed`')));
});

test('a broken link is reported', () => {
    const root = repo({ '.claude/skills/verify/references/sni.md': null });
    assert.ok(check(root).some(p => p.includes('links to references/sni.md')));
});

test('log text the docs grep for must still be logged', () => {
    const root = repo({ 'src/netguard/tls.c': 'log_print(PLATFORM_LOG_PRIORITY_INFO, "no SNI"); // NetGuard.JNI' });
    assert.ok(check(root).some(p => p.includes('"TLS server name not found"')));
});

test('the listed native tests must be the Makefile\'s', () => {
    const renamed = repo({ 'src/test/Makefile': 'EXECUTABLE = test_tls\nTCP_WINDOW_EXECUTABLE = test_window\n' });
    const problems = check(renamed);
    assert.ok(problems.some(p => p.includes('lists the test `test_tcp_window`')));
    assert.ok(problems.some(p => p.includes("doesn't list the test `test_window`")));
});
