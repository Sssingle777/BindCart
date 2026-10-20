#!/bin/bash
set -u
SCRIPT_DIR="$(cd -- "$(dirname "$0")" && pwd -P)" || exit 1
case "$(uname -m)" in
  arm64) DEMO_NODE="$SCRIPT_DIR/runtime/mac-arm64/node" ;;
  x86_64) DEMO_NODE="$SCRIPT_DIR/runtime/mac-x64/node" ;;
  *) echo "This bundle supports Apple Silicon and Intel Macs."; exit 1 ;;
esac
if [ ! -f "$DEMO_NODE" ]; then
  echo "The bundled Mac runtime is missing. Extract the whole ZIP first."
  read -r -p "Press Return to close... " _
  exit 1
fi
chmod u+x "$DEMO_NODE" || exit 1
"$DEMO_NODE" "$SCRIPT_DIR/portable.mjs" start "$@"
DEMO_RESULT=$?
if [ "$DEMO_RESULT" -ne 0 ]; then
  echo "Startup failed. Read the message and log paths above."
  read -r -p "Press Return to close... " _
fi
exit "$DEMO_RESULT"
