#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

curl -L https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip -o floss.zip \
    && unzip floss.zip -d /opt \
    && chmod +x /opt/floss \
    && rm floss.zip
