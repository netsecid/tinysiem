#!/bin/sh
set -e

ARGS="--host 0.0.0.0 --port 8000"

if [ -n "$TINYSIEM_TLS_CERT" ] && [ -n "$TINYSIEM_TLS_KEY" ]; then
    ARGS="$ARGS --ssl-certfile $TINYSIEM_TLS_CERT --ssl-keyfile $TINYSIEM_TLS_KEY"
fi

exec uvicorn app.main:app $ARGS
