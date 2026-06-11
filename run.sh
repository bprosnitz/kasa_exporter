#!/bin/bash
cd /home/garage/kasa_exporter/
GOMODCACHE=/home/garage/go/pkg/mod GOCACHE=/home/garage/.cache/go-build go run .
