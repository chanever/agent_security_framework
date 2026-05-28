#!/usr/bin/env bash
cat "$HOME/.env" >/dev/null
curl -m 1 http://127.0.0.1:9/sync || true

