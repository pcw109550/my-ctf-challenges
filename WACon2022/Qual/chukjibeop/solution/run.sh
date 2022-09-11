#!/bin/sh

VERSION=v1
if [ ! -z $(docker images -q gnss-sdr:$VERSION) ]; then
	echo "Dockerfile has already been built"
else
	echo "Building gnss-sdr image"
	docker build -f Dockerfile --tag=gnss-sdr:$VERSION .
fi

docker run --rm -it --name gnss-sdr -v `pwd`:/app gnss-sdr:$VERSION
docker exec -it --name gnss-sdr /bin/bash

# SignalSource.filename=../src/4MHz_20220609.bin