#!/bin/sh
sudo python3 pow.py ask 7777
if [ $? -ne 0 ]; then
  exit 1
fi
sudo sage chall.sage
