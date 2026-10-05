#!/bin/sh
wget -qO- http://127.0.0.1:${PORT:-8000}/health >/dev/null || exit 1
