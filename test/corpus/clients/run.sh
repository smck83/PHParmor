#!/bin/sh
# Sends the synthetic benign requests from each client library to the capture
# server (see README.md). Run from the repository root.
set -eu
NET=phparmor-corpus
BASE=http://phparmor-capture:8080
DIR="$(pwd)/test/corpus/clients"
run() { docker run --rm --network "$NET" -e BASE="$BASE" -v "$DIR:/clients:ro" "$@"; }

run curlimages/curl:8.11.1 sh /clients/curl.sh
run golang:1.27-alpine sh -c 'cd /tmp && cp /clients/go_client.go main.go && go run main.go'
run python:3.13-slim sh -c 'pip install -q requests==2.32.3 && python /clients/python_requests.py'
run node:22-alpine sh -c 'cd /tmp && npm i -s axios@1.7.9 && cp /clients/axios.mjs . && node axios.mjs'
run composer:2.8 sh -c 'cd /tmp && composer require -q guzzlehttp/guzzle:7.9.2 && php /clients/guzzle.php'
run eclipse-temurin:21-jdk sh /clients/java.sh
run mcr.microsoft.com/dotnet/sdk:8.0 sh /clients/dotnet.sh
