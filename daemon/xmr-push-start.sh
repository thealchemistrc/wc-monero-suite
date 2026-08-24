#!/bin/bash
# xmr-push-start.sh — Start the Monero Push daemon inside tmux. Works on any Linux box -
# including Android/Termux, where the wake-lock is acquired automatically.
#
# Place this in the same directory as xmr-pushd.py and xmr-pushd.conf.
# Run:  bash xmr-push-start.sh
#
# Keeps running across terminal closes via tmux + termux-wake-lock.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SESSION="xmr-push"

# Check Termux
if command -v termux-wake-lock &>/dev/null; then
  termux-wake-lock acquire 2>/dev/null || true
  echo "[*] Termux wake-lock acquired (CPU sleep resisted)."
else
  echo "[!] termux-wake-lock not found — script may be killed when Termux is backgrounded."
fi

if ! command -v tmux &>/dev/null; then
  echo "[*] Installing tmux..."
  apt update -qq && apt install -y tmux
fi

if ! tmux has-session -t "$SESSION" 2>/dev/null; then
  echo "[*] Creating new tmux session '$SESSION'..."
  tmux new-session -d -s "$SESSION" -c "$SCRIPT_DIR" \
    "cd '$SCRIPT_DIR' && exec python3 xmr-pushd.py"
  echo "[*] Session started. Attach with:  tmux attach -t $SESSION"
else
  echo "[*] Session '$SESSION' already exists."
  echo "[*] Attach with:  tmux attach -t $SESSION"
  echo "[*] Or kill with:  tmux kill-session -t $SESSION"
fi
