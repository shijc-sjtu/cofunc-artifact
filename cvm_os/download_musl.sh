#!/bin/bash -e

path=user/system-services/chcore-libc/musl-libc
url=git://git.musl-libc.org/musl
branch=v1.2.3

sudo rm -rf $path
git clone --depth=1 -b $branch $url $path
