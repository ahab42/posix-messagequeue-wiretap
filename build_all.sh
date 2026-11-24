#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
mkdir -p dist
rm -f dist/* 2>/dev/null

# every glibc-capable triple, glibc version embedded per arch
# (2.4 where that arch ever existed; arch-specific zig floor otherwise)
# note: zig has no glibc at all for 32-bit powerpc -> omitted
TRIPLES="x86_64-linux-gnu.2.4 \
         x86-linux-gnu.2.4 \
         aarch64-linux-gnu.2.17 \
         aarch64_be-linux-gnu.2.17 \
         arm-linux-gnueabi.2.4 \
         arm-linux-gnueabihf.2.4 \
         armeb-linux-gnueabi.2.4 \
         armeb-linux-gnueabihf.2.4 \
         mips-linux-gnueabi.2.4 \
         mipsel-linux-gnueabi.2.4 \
         mips64-linux-gnuabi64.2.4 \
         mips64el-linux-gnuabi64.2.4 \
         powerpc64le-linux-gnu.2.19 \
         riscv64-linux-gnu.2.27 \
         s390x-linux-gnu.2.4 \
         loongarch64-linux-gnu.2.36 \
         sparc64-linux-gnu.2.4"
for t in $TRIPLES; do
  if zig cc -target "$t" -shared -fPIC -O2 -Wall -Wextra \
            -fno-builtin -fno-stack-protector -pthread \
            hook.c -o "dist/libhook-$t.so"; then
    echo "built libhook-$t.so"
  else
    echo "SKIP $t"
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
