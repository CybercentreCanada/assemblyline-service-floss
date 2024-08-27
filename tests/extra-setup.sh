#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

curl -L https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip -o floss.zip \
    && unzip floss.zip -d /opt \
    && chmod +x /opt/floss \
    && rm floss.zip
