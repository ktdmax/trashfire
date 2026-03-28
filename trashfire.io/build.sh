#!/usr/bin/env bash
# Build the trashfire.io site by injecting current leaderboard data
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

node -e "
const fs = require('fs');
const tmpl = fs.readFileSync('$ROOT/trashfire.io/index.html', 'utf-8');
let data = '[]';
try { data = fs.readFileSync('$ROOT/_results/results-index.json', 'utf-8').trim(); } catch {}
const out = tmpl.replace('%RESULTS_DATA%', data);
fs.writeFileSync('$ROOT/trashfire.io/index.html', out);
const count = JSON.parse(data).length;
console.log('Site built with ' + count + ' results');
"
