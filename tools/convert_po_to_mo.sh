#!/bin/bash

cd ../locales/
for file in *.po; do
    if [ -f "$file" ]; then
        output="${file%.po}.mo"
        msgfmt "$file" -o "$output"
        echo "Created: $output"
    fi
done
