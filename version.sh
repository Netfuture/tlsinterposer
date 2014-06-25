#!/bin/sh
# Try go get the version from git; fall back to CHANGES.txt
version=`sed -n -e 's/^\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/p' CHANGES.txt | tail -1`
if which git > /dev/null; then
        gitv=`git describe --tags | sed -e 's/^v\([0-9.]*\)-*.*/\1/'`
        if [ x$gitv != x$version ]; then
                echo $gitv
                echo "WARNING: git and CHANGES.txt versions disagree" >&2
                exit 0
        fi
fi
echo $version
