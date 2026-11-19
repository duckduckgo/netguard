#!/usr/bin/env bash
# Checks the TLS server-name parser with CBMC for every packet whose TCP payload is MAX_TLS bytes or fewer: one CBMC
# run per payload length, run in parallel. See features/apptp-sni.md, "Formal check".
#
#   run.sh                              check src/netguard/tls_parser.c, payloads of 0..MAX_TLS bytes (default 64)
#   run.sh --reach                      sanity: proves the bound reaches a found name (must say "reach: ok")
#   MAX_TLS=68 run.sh                   a larger bound (each extra byte costs more than the last)
#   TLS_PARSER=/path/to/copy.c run.sh   check another copy of the parser, e.g. a scratch mutation
#   LOG_DIR=/some/dir run.sh            keep each length's CBMC output there (default: a temporary directory)
#   JOBS=4 run.sh                       CBMC runs at once (default: half the CPUs)
#
# Exit codes: 0 every property holds (or only the known finding below fails), 10 a property fails, 2 the check
# didn't run. The failing properties and one counterexample trace are printed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
TLS_PARSER="${TLS_PARSER:-$REPO/src/netguard/tls_parser.c}"
UTIL="${UTIL:-$REPO/src/netguard/util.c}"
MAX_TLS="${MAX_TLS:-64}"
JOBS="${JOBS:-$(( $(getconf _NPROCESSORS_ONLN) / 2 > 0 ? $(getconf _NPROCESSORS_ONLN) / 2 : 1 ))}"
CBMC_VERSION="6.11.0"
# A finding reported when this check was written and left in the product code on purpose (features/apptp-sni.md, "Formal check").
# It is still checked and still printed on every run; only the exit code ignores it. Delete this line once it's fixed.
KNOWN_FINDING="no NUL inside the name (strlen(sn) is the whole name)"

# One length, run by the loop below through xargs: check <tls_len> <work dir> <log dir> [extra cbmc args]
if [ "${1:-}" = "--one" ]; then
  n="$2"; work="$3"; logs="$4"; shift 4
  # Loop bounds from the bytes left for extensions (a ClientHello has 49 bytes before them). --unwinding-assertions
  # fails the run if a bound is too small, so a wrong number here can't hide a path.
  ext=$(( n > 49 ? n - 49 : 0 ))
  unwindset="parse_extensions.0:$(( ext / 4 + 2 )),parse_server_name_extension.3:$(( ext / 3 + 2 ))"
  unwindset+=",is_valid_utf8.0:$(( ext + 2 )),strlen.0:$(( ext + 2 ))"
  set +e
  # _FORTIFY_SOURCE=0: macOS headers otherwise turn memcpy into __builtin___memcpy_chk and bypass recorded_memcpy.
  cbmc "$HERE/harness.c" "$TLS_PARSER" "$work/utf8.c" \
    -I "$REPO/src/netguard/include" \
    -DTLS_LEN="$n" -D_FORTIFY_SOURCE=0 -Dmemcpy=recorded_memcpy "$@" \
    --bounds-check --pointer-check --pointer-overflow-check --signed-overflow-check --unsigned-overflow-check \
    --conversion-check --undefined-shift-check \
    --unwind 2 --unwindset "$unwindset" --unwinding-assertions \
    --trace --compact-trace > "$logs/len-$n.log" 2>&1
  echo $? > "$logs/len-$n.exit"
  exit 0
fi

command -v cbmc >/dev/null || { echo "cbmc isn't on PATH: brew install cbmc (confirmed with $CBMC_VERSION)" >&2; exit 2; }
found="$(cbmc --version | awk '{print $1}')"
[ "$found" = "$CBMC_VERSION" ] || echo "note: cbmc $found; this check was confirmed with $CBMC_VERSION" >&2

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
LOG_DIR="${LOG_DIR:-$work/logs}"
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/len-*.log "$LOG_DIR"/len-*.exit

# is10x() and is_valid_utf8() verbatim from util.c: the rest of util.c needs JNI.
{
  echo '#include <stdbool.h>'
  echo '#include <string.h>'
  awk '/^static int is10x\(/{on=1} on{print} on && /^int is_valid_utf8\(/{utf=1} utf && /^}/{exit}' "$UTIL"
} > "$work/utf8.c"
if ! grep -q '^int is_valid_utf8(' "$work/utf8.c" || ! grep -q '^static int is10x(' "$work/utf8.c"; then
  echo "couldn't find is10x() and is_valid_utf8() in $UTIL: update run.sh's extraction" >&2; exit 2
fi

if [ "${1:-}" = "--reach" ]; then
  # 60 bytes: 49 before the extensions, 11 for a server_name extension carrying a 2-byte name.
  "$0" --one 60 "$work" "$LOG_DIR" -DREACH
  if [ "$(cat "$LOG_DIR/len-60.exit")" = 10 ] && grep -q 'REACH: no name is ever found: FAILURE' "$LOG_DIR/len-60.log"; then
    echo "reach: ok, the harness finds a name within the bound"; exit 0
  fi
  echo "reach: FAILED, the harness never finds a name; see below" >&2
  tail -20 "$LOG_DIR/len-60.log" >&2; exit 2
fi

seq "$MAX_TLS" -1 0 | xargs -P "$JOBS" -I{} "$0" --one {} "$work" "$LOG_DIR"

new="" known=""
for n in $(seq 0 "$MAX_TLS"); do
  code="$(cat "$LOG_DIR/len-$n.exit" 2>/dev/null || echo missing)"
  case "$code" in
    0) ;;
    10)
      # Captured instead of piped: under pipefail, grep -q closing the pipe early would count a new failure as known.
      fails="$(grep ': FAILURE$' "$LOG_DIR/len-$n.log")"
      if grep -qvF "$KNOWN_FINDING" <<<"$fails"; then new="$new $n"; else known="$known $n"; fi ;;
    *) echo "length $n: CBMC didn't run (exit $code)"; tail -20 "$LOG_DIR/len-$n.log" >&2; exit 2 ;;
  esac
done

show() {   # show <length>: its failing properties and the trace of the first one (values only)
  grep -E ': FAILURE$' "$LOG_DIR/len-$1.log"
  awk '/^Trace for/{n++} n==1' "$LOG_DIR/len-$1.log" | grep -E '^Trace for|^ +[0-9]+: [a-z_]+(\[[^]]*\])?=' \
    | grep -v -e 'goto_symex' -e '={' || true
}

if [ -n "$known" ]; then
  first="${known# }"; first="${first%% *}"
  echo "KNOWN FINDING still present (payload lengths:$known): $KNOWN_FINDING. Length $first:"
  show "$first"
fi
if [ -n "$new" ]; then
  first="${new# }"; first="${first%% *}"
  echo
  echo "FAIL: a property fails for payload lengths:$new. Length $first:"
  show "$first"
  exit 10
fi
echo "PASS: every other property holds for every payload of 0..$MAX_TLS bytes"
