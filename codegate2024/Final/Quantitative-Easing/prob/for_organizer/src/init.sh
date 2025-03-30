#!/bin/sh
python3 pow.py ask 2000
if [ $? -ne 0 ]; then
  exit 1
fi
python3 MW.py
