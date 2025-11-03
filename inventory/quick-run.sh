#!/bin/env bash

set -euo


./yellow --help || make

./yellow -d ${1}

./yellow osint -d ${1}

./yellow prune -f ${1}/scans/domains.txt -o ${1}/scans/active-web-panels.txt

./yellow scan -d ${1}/scans/infra --file ${1}/scans/active-web-panels.txt
