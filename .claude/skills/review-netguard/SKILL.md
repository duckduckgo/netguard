---
name: review-netguard
description: Review a netguard PR as an independent reviewer - read the diff for netguard's known failure modes, prove each finding with a run, verify on a device, and post a PASS / PASS+NOTES / FAIL / INCOMPLETE verdict. Use when asked to review a netguard PR, or a branch someone else wrote.
---

# Review netguard

A review by an agent that didn't write the code. It reports what it can prove, not what it suspects: a finding counts only when a run shows it. It comments; a human approves and merges.

**Independence.** If this session wrote or changed the PR's code, stop and tell the user to start a fresh session for the review. An author reviewing their own change is not a review.

## 1. Set up

Review in a separate worktree, never in the user's checkout:

```bash
N=<PR number>
gh pr view $N --json title,body,baseRefName,headRefName,headRefOid,author
git fetch origin "pull/$N/head" "<baseRefName>"
WT=<a new directory outside the repo>
git worktree add --detach $WT <headRefOid>
BASE=$(git merge-base origin/<baseRefName> <headRefOid>)
git diff $BASE <headRefOid> | git patch-id --stable | cut -d' ' -f1   # the patch the verdict covers
```

Record the base SHA, head SHA and patch-id: the verdict is for this patch. Remove the worktree at the end (`git worktree remove $WT`).

**Intent.** In two or three sentences, write what the PR means to change and why, from its title, description and commits. Every finding is judged against it. If you can't tell what it intends, ask the user before reviewing.

## 2. Read the diff for netguard's failure modes

Read the whole diff, then each changed function in full, with its callers. Check each area the diff touches:

- **Packet bounds.** Every read of a header or payload is within the bytes actually received. Lengths come from the buffer, not only from a header field: a packet can claim more than it has. Subtractions of lengths can't go negative (`size_t` wraps). Parsers in scope: `ip.c`, `tcp.c`, `udp.c`, `icmp.c`, `dns.c`, `tls_parser.c`, and `is_pkt_allowed` in `src/wireguard/jni.c`.
- **JNI references.** Each `NewGlobalRef` has one `DeleteGlobalRef`, and nothing uses the reference after it. Local references created in a loop are deleted in the loop. Every call into Java is followed by `jniCheckException` or equivalent. A reference shared between threads is read under its lock.
- **Threads and locks.** Name every thread that touches each piece of shared state the diff changes: the event loop, JNI callbacks, Go goroutines. Each read and write is under the same lock (`pthread_mutex_lock`, or `sync.Mutex` on the Go side). No lock is held across a call into Java or a blocking call, and two locks are always taken in the same order.
- **Resources.** Every error path closes the sockets it opened, removes them from epoll, and frees what it allocated (`ng_malloc` / `ng_calloc` with `ng_free`). Follow each early `return` and `goto`.
- **Sessions.** State changes in `session.c` and the protocol files go only between valid states, and a closed session can't be used again by a later packet.
- **Blocking decisions.** When parsing fails, the code allows or blocks the same way the code around it does. A change from allowing to blocking (or the reverse) is called out in the PR.
- **Logging.** Logs respect the log level (`log_print`). No domains or other user data are logged at a level release builds keep.
- **Tests and docs.** New behavior has a test in `src/test` that fails without the change. If the PR changes how to build, test or verify, `AGENTS.md` and the skills are updated, and `node tools/check-docs/check-docs.js` passes.

Write down each suspected problem with the file, line, and the input or sequence that would trigger it. These are suspects, not findings.

## 3. Prove each suspect

For each suspect, write a repro that runs the PR's code and shows the wrong behavior. Keep repros in the review worktree; never commit them to the PR.

- **C code:** a small test program in the worktree's `src/test`, built with the Makefile's sanitizers, so an out-of-bounds read or use-after-free crashes with a stack trace:

  ```bash
  cd $WT/src/test
  cc -Wall -I../netguard/include -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g \
    repro.c stubs.c ../netguard/<file under test>.c -o repro && ./repro
  ```

  Feed the code the input from the suspect: a truncated packet, a lying length field, a sequence of calls.
- **Thread or lifecycle bugs:** drive the calls in the bad order from a test, or with two threads and a loop; or on the device (step 4).
- **Behavior on the wire:** the device check from `verify-netguard`, with a trigger that hits the suspect.

Run the same repro against the base. A finding that also fails on the base is an existing bug, not this PR's: report it separately as a note.

Keep a finding only when the run's output shows the failure and the failure breaks the intent or the code around it. Drop the rest, and count them for the report. Style, naming and "could be risky later" are not findings.

**Second opinion.** Give an independent reviewer the same diff, intent and this brief, in its own worktree, without your suspects. Use a subagent with a fresh context, on a different model from yours when one is available (e.g. another Claude model, or the Codex CLI if it's installed and signed in):

> Break this change. Prove each finding with a run against the real code: a failing test, a repro, or command output that shows the wrong behavior. Report the exact command, its output, and what the intent requires instead. Leave out anything you did not run. No findings is a valid result.

With Codex: `codex exec -C <its own worktree> -s workspace-write -o <report file> "<the brief, intent and PR number>"`.

Rerun each of its findings yourself; keep only what reproduces. A finding both reviewers found independently is the strongest signal. Say in the verdict which models reviewed; with only one, say so.

## 4. Verify on a device

Follow "Reviewing a PR" in the `verify-netguard` skill: the PR's own test steps first, then the feature check, comparing with the base branch. Run its "Check netguard is handling the traffic" first: most inconclusive device runs are a setup that never reached netguard. If no phone is available, say the device check wasn't run; the verdict can't be `PASS` without it for a change that affects runtime behavior.

When a device result is inconclusive, explain it from the code before reporting it: read both sides of the path (netguard and the app's callbacks, in the DuckDuckGo Android repository) rather than guessing which side drops the traffic. An explanation you didn't check is a guess; label it so.

## 5. Verdict

- **`PASS`:** no findings, and every required check passed.
- **`PASS+NOTES`:** no findings that block merging; notes for the author (existing bugs found on the base, a weak or missing test, a stale doc).
- **`FAIL`:** at least one proven finding: a run shows the change is wrong.
- **`INCOMPLETE`:** no proven findings, but a required check couldn't run or was inconclusive (no phone, a setup that didn't reach netguard, a flaky trigger). Say what's missing and what it would take. This says nothing against the change; don't use `FAIL` for it.

A weakness in the PR's test steps or tools (a probe that reports OK without exercising the fix) is a note, not a finding, unless a run shows the change itself is wrong.

Draft the comment and show it to the user. Post it only after they confirm, as a comment, never as an approval. Before posting `INCOMPLETE`, ask the user whether to fix the gap first; a review that can still be completed is usually worth finishing:

```text
Review verdict: <PASS | PASS+NOTES | FAIL | INCOMPLETE>
Reviewed by: <agent and model> (did not write this change)
Base: <SHA> · Head: <SHA> · Patch-id: <patch-id>

Intent: <the restatement>

Findings:
<per finding: what breaks, the file and line, the exact command, its output, and what the intent requires>
or: No proven findings (<n> suspects dropped: <why, in a few words>).

Device check: <the side-by-side result, as in verify-netguard step 5, or "not run: <why>">
Not checked: <what this review didn't cover>
```

```bash
gh pr comment $N --body-file <the confirmed comment>
```

netguard is a public repository: no internal links, task text, user data or internal app details in the comment.

**After new commits.** Compute the patch-id again. If it's unchanged (a rebase onto a newer base), the verdict still applies: say so in a new comment with the new head SHA. If it changed, review the new diff and verify again.
