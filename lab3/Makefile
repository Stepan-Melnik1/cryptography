# Лабораторная 03: IDEA, ГОСТ/Магма, Кузнечик (C++17)
CXX    ?= g++
WARN   = -std=c++17 -Wall -Wextra -Wpedantic
LIBSRC = vars.cpp idea.cpp gost.cpp modes.cpp kuznyechik.cpp rc2.cpp
APPSRC = main.cpp selftest.cpp
HDRS   = crypto-lab.h selftest.h

all: crypto

# криптографическое ядро - динамическая библиотека
libcryptolab.so: $(LIBSRC) $(HDRS)
	$(CXX) $(WARN) -O2 -fPIC -shared -o $@ $(LIBSRC)

# приложение вызывает ядро через crypto-lab.h; -rpath, чтобы .so находилась рядом с программой
crypto: $(APPSRC) libcryptolab.so $(HDRS)
	$(CXX) $(WARN) -O2 -o $@ $(APPSRC) -L. -lcryptolab -Wl,-rpath,'$$ORIGIN'

test: crypto
	./crypto -T

# сравнение -O2 и -O2 -flto (размер и скорость)
compare:
	./compare.sh

clean:
	rm -rf crypto libcryptolab.so build-O2 build-O2-flto

.PHONY: all test compare clean
