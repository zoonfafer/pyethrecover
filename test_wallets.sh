#!/usr/bin/env bash

# Rudimentary wallet tests.

python pyethrecover.py -p password123 -w test_wallets/ico.json &&
python pyethrecover.py -p password123 -w test_wallets/mew.json
