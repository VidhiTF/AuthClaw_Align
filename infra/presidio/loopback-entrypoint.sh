#!/bin/sh
set -eu

exec poetry run gunicorn -w "${WORKERS:-1}" -b "127.0.0.1:${PORT:-3000}" "app:create_app()"
