#!/bin/bash
set -u
SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd -P)" || exit 1
case "$(uname -m)" in
  arm64) DEMO_NODE="$SCRIPT_DIR/runtime/mac-arm64/node" ;;
  x86_64) DEMO_NODE="$SCRIPT_DIR/runtime/mac-x64/node" ;;
  *) echo "Supported: Apple Silicon or Intel Mac."; exit 1 ;;
esac
chmod u+x "$DEMO_NODE" || exit 1
export UWS_USE_FALLBACK=1
"$DEMO_NODE" "$SCRIPT_DIR/verify-package.mjs" --integrity &&
"$DEMO_NODE" --test "$SCRIPT_DIR/app/test/delivery-flow.test.mjs"
DEMO_RESULT=$?
if [ "$DEMO_RESULT" -eq 0 ]; then
  echo "PASS: package integrity, real payment, two modes and idempotency checks."
else
  echo "CHECK FAILED. Keep this output for diagnosis."
fi
read -r -p "Press Return to close... " _
exit "$DEMO_RESULT"
