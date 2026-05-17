#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRAVE="${BRAVE_APP_NAME:-Brave Browser}"

open_url() {
  local url="$1"
  open -a "$BRAVE" "$url"
}

open_url "file://$ROOT/docs/hackathon-0g/ai-submission-production-package.md"
open_url "file://$ROOT/docs/hackathon-0g/final-demo-video-script.md"
open_url "file://$ROOT/docs/hackathon-0g/submission-form-fields.md"
open_url "https://gemini.google.com/app"
open_url "https://flow.google/"
open_url "https://www.hackquest.io/hackathons/0G-APAC-Hackathon"
open_url "https://arigatoexpress.github.io/0guard/"
open_url "https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed"

echo "Opened 0guard AI submission workspace in $BRAVE."
