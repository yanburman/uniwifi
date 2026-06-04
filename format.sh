#!/bin/sh

cargo fmt --all
cargo clippy -j 32 --workspace --all-targets --fix --allow-dirty -- -D warnings
