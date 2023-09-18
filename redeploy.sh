#!/bin/sh

git pull
docker build -t bbtel .

docker rm -f battlebit-telemetry
docker run --name battlebit-telemetry -p 65500:65500 -p 65501:65501 bbtel -verbose
