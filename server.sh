#!/bin/sh

./build.sh || exit $?
exec target/release/stupid_tunnel server
