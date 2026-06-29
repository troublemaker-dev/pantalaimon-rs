#!/bin/sh
set -e
dbus-daemon --session --address="$DBUS_SESSION_BUS_ADDRESS" --nofork --nopidfile &
socket_path="${DBUS_SESSION_BUS_ADDRESS#unix:path=}"
until [ -S "$socket_path" ]; do sleep 0.05; done
exec pantalaimon "$@"
