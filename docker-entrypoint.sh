#!/bin/bash

YELLOW="\e[0;93m"
NC="\e[0m"

echo -e "$YELLOW\n\n Launching Startup Script...$NC"

export DISPLAY=:0.0

echo -e "$YELLOW\n\n Launching Startup Script Completed.$NC"

./wiz-semgrep-connector