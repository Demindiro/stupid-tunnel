#!/bin/sh

su david -c './build.sh' || exit $?
exec target/release/stupid_tunnel client
