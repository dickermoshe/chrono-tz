#!/usr/bin/env bash

set -euxo pipefail

export RUST_BACKTRACE=1
export CHRONO_TZ_TIME_RANGE='1577836800..1577923200'

cd chrono-tz/tests/check-range-filtering

cargo test --color=always -- --color=always
