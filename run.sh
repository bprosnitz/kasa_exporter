#!/bin/bash
cd /home/garage/openuv_exporter/
GOMODCACHE=/home/garage/go/pkg/mod GOCACHE=/home/garage/.cache/go-build go run /home/garage/kasa_exporter/main.go
