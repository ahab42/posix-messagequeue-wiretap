#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
mkdir -p dist
rm -f dist/* 2>/dev/null

TRIPLES="x86_64-linux-gnu x86-linux-gnu aarch64-linux-gnu aarch64_be-linux-gnu arm-linux-gnueabi arm-linux-gnueabihf armeb-linux-gnueabi armeb-linux-gnueabihf mips-linux-gnu mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 powerpc-linux-gnu powerpc64-linux-gnu powerpc64le-linux-gnu riscv64-linux-gnu s390x-linux-gnu loongarch64-linux-gnu sparc64-linux-gnu"
for t in $TRIPLES; do
  if zig cc -target "$t.2.4" -shared -fPIC -O2 -Wall -Wextra \
            -fno-builtin -fno-stack-protector -pthread \
            hook.c -o "dist/libhook-$t.so"; then
    echo "$t -> glibc 2.4"
  else
    echo "SKIP $t (glibc 2.4 unsupported)"
  fi
done

TARGETS="x86_64-linux-musl x86-linux-musl aarch64-linux-musl arm-linux-musleabihf arm-linux-musleabi armeb-linux-musleabihf armeb-linux-musleabi mips-linux-musleabihf mipsel-linux-musleabihf"
for t in $TARGETS; do
  if zig cc -target "$t" -static -O2 -Wall -Wextra -pthread \
            -Ivendor/sqlite listener.c vendor/sqlite/sqlite3.c \
            -o "dist/listener-$t"; then
    echo "built listener-$t"
  else
    echo "SKIP listener-$t"
  fi
done
echo ALL-DONE
