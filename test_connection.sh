#!/usr/bin/env bash

set -ex

curl -v telnet://0.0.0.0:8888 <<<"Hello, World"
