#!/bin/env bash

set -euo


./yellow --help || make

./yellow -d ${1}

./yellow osint -d ${1}

./yellow scan -d ${1}/scans --file ${1}/scans/domains.txt
