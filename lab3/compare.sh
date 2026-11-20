#!/bin/sh
# Собирает libcryptolab.so и crypto с -O2 и с -O2 -flto, сравнивает размер и скорость.
set -e
cd "$(dirname "$0")"
LIBSRC="vars.cpp idea.cpp gost.cpp modes.cpp kuznyechik.cpp rc2.cpp"
APPSRC="main.cpp selftest.cpp"
WARN="-std=c++17 -Wall -Wextra -Wpedantic"

build() {  # $1 - имя каталога, $2 - флаги оптимизации
    mkdir -p "$1"
    g++ $WARN $2 -fPIC -shared -o "$1/libcryptolab.so" $LIBSRC
    g++ $WARN $2 -o "$1/crypto" $APPSRC -L"$1" -lcryptolab -Wl,-rpath,'$ORIGIN'
}

build build-O2 "-O2"
build build-O2-flto "-O2 -flto"

echo "=== Размер (байт) ==="
printf "%-28s %12s %12s\n" "" "-O2" "-O2 -flto"
printf "%-28s %12s %12s\n" "libcryptolab.so" "$(stat -c%s build-O2/libcryptolab.so)" "$(stat -c%s build-O2-flto/libcryptolab.so)"
printf "%-28s %12s %12s\n" "crypto (приложение)" "$(stat -c%s build-O2/crypto)" "$(stat -c%s build-O2-flto/crypto)"
printf "%-28s %12s %12s\n" ".text libcryptolab.so" "$(size build-O2/libcryptolab.so | awk 'NR==2{print $1}')" "$(size build-O2-flto/libcryptolab.so | awk 'NR==2{print $1}')"

echo
echo "=== Скорость (МБ/с, лучшее из 3 прогонов; больше - лучше) ==="
build-O2/crypto -B       > build-O2/bench.txt
build-O2-flto/crypto -B  > build-O2-flto/bench.txt
printf "%-24s %10s %10s\n" "" "-O2" "-O2 -flto"
paste -d'|' build-O2/bench.txt build-O2-flto/bench.txt | while IFS='|' read a b; do
    name=$(echo "$a" | sed 's/ *[0-9.]* МБ\/с$//')
    va=$(echo "$a" | awk '{print $(NF-1)}')
    vb=$(echo "$b" | awk '{print $(NF-1)}')
    printf "%-24s %10s %10s\n" "$name" "$va" "$vb"
done
